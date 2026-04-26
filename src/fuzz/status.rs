//! AFL++ status collection and terminal rendering for the live fuzzing screen.

use anyhow::{Context as _, Result};
use std::{
    fs,
    io::{IsTerminal as _, Write},
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub(super) trait FuzzerStatsProvider {
    fn snapshot(&self, live_instances: usize, runtime: Duration) -> CampaignSnapshot;
}

#[derive(Debug, Clone)]
pub(super) struct AflStatsProvider {
    target_name: String,
    afl_dir: PathBuf,
    expected_instances: Vec<String>,
    binary_counts: Vec<BinaryInstanceCount>,
    campaign_start_unix: u64,
}

impl AflStatsProvider {
    pub(super) fn new(
        target_name: String,
        afl_dir: PathBuf,
        expected_instances: Vec<String>,
        binary_counts: Vec<BinaryInstanceCount>,
    ) -> Result<Self> {
        Ok(Self {
            target_name,
            afl_dir,
            expected_instances,
            binary_counts,
            campaign_start_unix: current_unix()?.saturating_sub(5),
        })
    }

    fn instance_stats(&self, instance_name: &str) -> Option<AflInstanceStats> {
        let stats_path = self.afl_dir.join(instance_name).join("fuzzer_stats");
        let text = fs::read_to_string(stats_path).ok()?;
        let stats = AflInstanceStats::parse(instance_name, &text);

        if stats.last_update < self.campaign_start_unix {
            return None;
        }

        Some(stats)
    }
}

impl FuzzerStatsProvider for AflStatsProvider {
    fn snapshot(&self, live_instances: usize, runtime: Duration) -> CampaignSnapshot {
        let stats = self
            .expected_instances
            .iter()
            .filter_map(|instance| self.instance_stats(instance))
            .collect::<Vec<_>>();
        let status = if live_instances == 0 {
            CampaignStatus::Stopped
        } else if stats.len() < self.expected_instances.len() {
            CampaignStatus::Starting
        } else {
            CampaignStatus::Running
        };

        let now = current_unix().unwrap_or(0);
        let last_find = stats
            .iter()
            .filter_map(|stats| (stats.last_find > 0).then_some(stats.last_find))
            .max();

        let best_edges = stats
            .iter()
            .filter_map(|stats| Some((stats.edges_found?, stats.total_edges?)))
            .max_by_key(|(edges_found, _)| *edges_found);

        CampaignSnapshot {
            target_name: self.target_name.clone(),
            runtime,
            status,
            live_instances,
            expected_instances: self.expected_instances.len(),
            stats_instances: stats.len(),
            binary_counts: self.binary_counts.clone(),
            total_execs: stats.iter().map(|stats| stats.execs_done).sum(),
            execs_per_sec: stats.iter().map(|stats| stats.execs_per_sec).sum(),
            best_map_density: stats
                .iter()
                .filter_map(|stats| stats.bitmap_cvg)
                .max_by(f64::total_cmp),
            best_edges,
            pending_favs: stats.iter().map(|stats| stats.pending_favs).sum(),
            saved_crashes: stats.iter().map(|stats| stats.saved_crashes).sum(),
            saved_hangs: stats.iter().map(|stats| stats.saved_hangs).sum(),
            last_find_age: last_find
                .map(|last_find| Duration::from_secs(now.saturating_sub(last_find))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct BinaryInstanceCount {
    pub(super) name: String,
    pub(super) count: usize,
}

#[derive(Debug, Default)]
struct AflInstanceStats {
    last_update: u64,
    execs_done: u64,
    execs_per_sec: f64,
    pending_favs: u64,
    bitmap_cvg: Option<f64>,
    saved_crashes: u64,
    saved_hangs: u64,
    last_find: u64,
    edges_found: Option<u64>,
    total_edges: Option<u64>,
}

impl AflInstanceStats {
    fn parse(_instance_name: &str, text: &str) -> Self {
        let mut stats = Self::default();
        for line in text.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            let key = key.trim();
            let value = value.trim();
            match key {
                "last_update" => stats.last_update = parse_u64(value),
                "execs_done" => stats.execs_done = parse_u64(value),
                "execs_per_sec" => stats.execs_per_sec = parse_f64(value),
                "pending_favs" => stats.pending_favs = parse_u64(value),
                "bitmap_cvg" => stats.bitmap_cvg = Some(parse_percent(value)),
                "saved_crashes" => stats.saved_crashes = parse_u64(value),
                "saved_hangs" => stats.saved_hangs = parse_u64(value),
                "last_find" => stats.last_find = parse_u64(value),
                "edges_found" => stats.edges_found = Some(parse_u64(value)),
                "total_edges" => stats.total_edges = Some(parse_u64(value)),
                _ => {}
            }
        }
        stats
    }
}

fn parse_u64(value: &str) -> u64 {
    value.parse().unwrap_or(0)
}

fn parse_f64(value: &str) -> f64 {
    value.parse().unwrap_or(0.0)
}

fn parse_percent(value: &str) -> f64 {
    parse_f64(value.trim_end_matches('%'))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CampaignStatus {
    Starting,
    Running,
    Stopped,
}

impl CampaignStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Stopped => "stopped",
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct CampaignSnapshot {
    target_name: String,
    runtime: Duration,
    status: CampaignStatus,
    live_instances: usize,
    expected_instances: usize,
    stats_instances: usize,
    binary_counts: Vec<BinaryInstanceCount>,
    total_execs: u64,
    execs_per_sec: f64,
    best_map_density: Option<f64>,
    best_edges: Option<(u64, u64)>,
    pending_favs: u64,
    saved_crashes: u64,
    saved_hangs: u64,
    last_find_age: Option<Duration>,
}

impl CampaignSnapshot {
    fn render_screen(&self) -> String {
        let reset = "\x1b[0m";
        let gray = "\x1b[1;90m";
        let red = "\x1b[1;91m";
        let green = "\x1b[1;92m";
        let yellow = "\x1b[1;93m";
        let purple = "\x1b[1;95m";
        let blue = "\x1b[1;96m";
        let white = "\x1b[1;37m";

        let run_time = format_duration(self.runtime);
        let status_color = match self.status {
            CampaignStatus::Starting => yellow,
            CampaignStatus::Running => green,
            CampaignStatus::Stopped => red,
        };
        let instances = format!(
            "{}/{} live, {} stats",
            self.live_instances, self.expected_instances, self.stats_instances
        );
        let coverage = self
            .best_map_density
            .map(|density| format!("{density:.2}%"))
            .unwrap_or_default();
        let edges = self
            .best_edges
            .map(|(found, total)| format!("{found}/{total}"))
            .unwrap_or_default();
        let crashes = format_count(self.saved_crashes);
        let timeouts = format_count(self.saved_hangs);
        let new_finds = self
            .last_find_age
            .map(format_duration)
            .unwrap_or("No data yet".to_string());
        let faves = format_count(self.pending_favs);
        let total_execs = format_count(self.total_execs);
        let speed = format_rate(self.execs_per_sec);
        let mut screen = String::new();

        screen += "\x1B[1;1H\x1B[2J";
        screen += &top_border_with_title(
            self.status.as_str(),
            &self.target_name,
            blue,
            status_color,
            purple,
            reset,
        );
        screen += &full_metric_row("run time :", &run_time, gray, white, reset);
        screen += &section_header(self.status.as_str(), blue, status_color, reset);
        screen += &instances_row(&instances, gray, blue, reset);
        for binary_count in &self.binary_counts {
            screen += &binary_count_row(binary_count, gray, blue, reset);
        }
        screen += &status_row(
            "cumulative speed :",
            &speed,
            white,
            "map density :",
            &coverage,
            purple,
            gray,
            reset,
        );
        screen += &status_row(
            "total execs :",
            &total_execs,
            white,
            "edges covered :",
            &edges,
            blue,
            gray,
            reset,
        );
        screen += &status_row(
            "top inputs todo :",
            &faves,
            white,
            "crashes saved :",
            &crashes,
            if self.saved_crashes > 0 { red } else { white },
            gray,
            reset,
        );
        screen += &status_row(
            "no find for :",
            &new_finds,
            white,
            "timeouts saved :",
            &timeouts,
            if self.saved_hangs > 0 { red } else { white },
            gray,
            reset,
        );
        screen += &bottom_border();
        screen
    }

    fn render_line(&self) -> String {
        let binary_counts = self
            .binary_counts
            .iter()
            .map(|binary| format!("{}:{}", binary.name, binary.count))
            .collect::<Vec<_>>()
            .join(",");

        format!(
            "[{}] {} live {}/{} stats {}/{} binaries=[{}] execs={} rate={} cov={} crashes={} timeouts={}",
            format_duration(self.runtime),
            self.status.as_str(),
            self.live_instances,
            self.expected_instances,
            self.stats_instances,
            self.expected_instances,
            binary_counts,
            format_count(self.total_execs),
            format_rate(self.execs_per_sec),
            self.best_map_density
                .map(|density| format!("{density:.2}%"))
                .unwrap_or_else(|| "n/a".to_string()),
            format_count(self.saved_crashes),
            format_count(self.saved_hangs),
        )
    }
}

const BOX_INNER_WIDTH: usize = 72;
const LEFT_CELL_WIDTH: usize = 36;
const RIGHT_CELL_WIDTH: usize = 33;

fn top_border_with_title(
    status: &str,
    target_name: &str,
    brand_color: &str,
    status_color: &str,
    target_color: &str,
    reset: &str,
) -> String {
    let target_name = truncate_chars(target_name, 25);
    let prefix_width = 2 + "fuzzd".len() + 1 + status.len() + 1;
    let target_width = target_name.chars().count() + 2;
    let fill = BOX_INNER_WIDTH.saturating_sub(prefix_width + target_width);
    let left_fill = fill / 2;
    let right_fill = fill - left_fill;

    format!(
        "┌─ {brand_color}fuzzd{reset} {status_color}{status}{reset} {} {target_color}{target_name}{reset} {}┐\n",
        "─".repeat(left_fill),
        "─".repeat(right_fill)
    )
}

fn bottom_border() -> String {
    format!(
        "└{}┴{}┘\n",
        "─".repeat(LEFT_CELL_WIDTH + 1),
        "─".repeat(RIGHT_CELL_WIDTH + 1)
    )
}

fn section_header(status: &str, brand_color: &str, status_color: &str, reset: &str) -> String {
    let prefix = format!("─ afl++ {status} ");
    let fill = BOX_INNER_WIDTH.saturating_sub(prefix.chars().count());
    format!(
        "├─ {brand_color}afl++{reset} {status_color}{status}{reset} {}┤\n",
        "─".repeat(fill)
    )
}

fn full_metric_row(
    label: &str,
    value: &str,
    label_color: &str,
    value_color: &str,
    reset: &str,
) -> String {
    let label_width = 11;
    let value_width = BOX_INNER_WIDTH - label_width - 1;
    let label = fit_cell(label, label_width);
    let value = fit_cell(value, value_width);
    format!("│{label_color}{label}{reset} {value_color}{value}{reset}│\n")
}

fn status_row(
    left_label: &str,
    left_value: &str,
    left_value_color: &str,
    right_label: &str,
    right_value: &str,
    right_value_color: &str,
    label_color: &str,
    reset: &str,
) -> String {
    let left = metric_cell(
        left_label,
        left_value,
        LEFT_CELL_WIDTH,
        18,
        label_color,
        left_value_color,
        reset,
    );
    let right = metric_cell(
        right_label,
        right_value,
        RIGHT_CELL_WIDTH,
        16,
        label_color,
        right_value_color,
        reset,
    );
    format!("│{left} │ {right}│\n")
}

fn instances_row(value: &str, label_color: &str, value_color: &str, reset: &str) -> String {
    let label = "instances :";
    let label_width = label.chars().count();
    let value_width = LEFT_CELL_WIDTH.saturating_sub(label_width + 1);
    let value = fit_cell(value, value_width);
    let right = " ".repeat(RIGHT_CELL_WIDTH);

    format!("│{label_color}{label}{reset} {value_color}{value}{reset} │ {right}│\n")
}

fn binary_count_row(
    binary_count: &BinaryInstanceCount,
    name_color: &str,
    count_color: &str,
    reset: &str,
) -> String {
    let count = binary_count.count.to_string();
    let name_width = LEFT_CELL_WIDTH.saturating_sub(4 + count.chars().count());
    let name = truncate_chars(&binary_count.name, name_width);
    let visible_width = 2 + name.chars().count() + 2 + count.chars().count();
    let padding = " ".repeat(LEFT_CELL_WIDTH.saturating_sub(visible_width));
    let right = " ".repeat(RIGHT_CELL_WIDTH);

    format!("│  {name_color}{name}{reset}: {count_color}{count}{reset}{padding} │ {right}│\n")
}

fn metric_cell(
    label: &str,
    value: &str,
    width: usize,
    label_width: usize,
    label_color: &str,
    value_color: &str,
    reset: &str,
) -> String {
    if label.is_empty() && value.is_empty() {
        return " ".repeat(width);
    }

    let value_width = width.saturating_sub(label_width + 1);
    let label = fit_cell_left(label, label_width);
    let value = fit_cell(value, value_width);
    format!("{label_color}{label}{reset} {value_color}{value}{reset}")
}

fn fit_cell(value: &str, width: usize) -> String {
    let value = truncate_chars(value, width);
    let value_width = value.chars().count();
    format!("{value}{}", " ".repeat(width - value_width))
}

fn fit_cell_left(value: &str, width: usize) -> String {
    let value = truncate_chars(value, width);
    let value_width = value.chars().count();
    format!("{}{}", " ".repeat(width - value_width), value)
}

fn truncate_chars(value: &str, width: usize) -> String {
    value.chars().take(width).collect()
}

pub(super) struct StatusScreen {
    is_tty: bool,
}

impl StatusScreen {
    pub(super) fn new() -> Self {
        Self {
            is_tty: std::io::stderr().is_terminal(),
        }
    }

    pub(super) fn draw(&mut self, snapshot: &CampaignSnapshot) {
        if self.is_tty {
            let mut stderr = std::io::stderr();
            let _ = write!(stderr, "\x1b[?25l\x1b[H\x1b[2J{}", snapshot.render_screen());
            let _ = stderr.flush();
        } else {
            eprintln!("{}", snapshot.render_line());
        }
    }

    pub(super) fn finish(&mut self) {
        if self.is_tty {
            let mut stderr = std::io::stderr();
            let _ = write!(stderr, "\x1b[?25h");
            let _ = stderr.flush();
        }
    }
}

fn format_count(value: u64) -> String {
    let value = value.to_string();
    let mut out = String::with_capacity(value.len() + value.len() / 3);
    for (index, ch) in value.chars().rev().enumerate() {
        if index > 0 && index % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out.chars().rev().collect()
}

fn format_rate(value: f64) -> String {
    let value = if value.abs() < 0.05 { 0.0 } else { value };
    if value >= 1_000_000.0 {
        format!("{:.1}M/sec", value / 1_000_000.0)
    } else if value >= 1_000.0 {
        format!("{:.1}k/sec", value / 1_000.0)
    } else {
        format!("{value:.1}/sec")
    }
}

fn format_duration(duration: Duration) -> String {
    let total = duration.as_secs();
    let days = total / 86_400;
    let hours = (total % 86_400) / 3_600;
    let minutes = (total % 3_600) / 60;
    let seconds = total % 60;

    if days > 0 {
        format!("{days}d {hours:02}h {minutes:02}m {seconds:02}s")
    } else if hours > 0 {
        format!("{hours}h {minutes:02}m {seconds:02}s")
    } else if minutes > 0 {
        format!("{minutes}m {seconds:02}s")
    } else {
        format!("{seconds}s")
    }
}

fn current_unix() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time before Unix epoch")?
        .as_secs())
}
