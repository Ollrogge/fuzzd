//! AFL++ campaign management: path setup, instance planning, process supervision, and artifact sync.

use super::status::{AflStatsProvider, BinaryInstanceCount, FuzzerStatsProvider, StatusScreen};
use crate::{
    cli::FuzzArgs,
    util::{hash_file, render_campaign_path, target_name_from_binary},
};
use anyhow::{Context as _, Result, bail};
use std::{
    ffi::{OsStr, OsString},
    fs::{self, File},
    io::{ErrorKind, Write},
    path::{Path, PathBuf},
    process::{self, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub fn run(args: FuzzArgs) -> Result<()> {
    validate_args(&args)?;

    let paths = OutputPaths::new(&args)?;
    let variants = BinaryVariants::from_args(&args);
    let instances = plan_afl_instances(&variants, args.jobs.get());
    let commands = build_afl_commands(&args, &paths, &instances);

    if args.dry_run {
        print_campaign_summary(&args, &paths, &variants, &instances, &commands);
        return Ok(());
    }

    fs::create_dir_all(&paths.corpus).context("creating corpus directory")?;
    fs::create_dir_all(&paths.logs).context("creating logs directory")?;
    fs::create_dir_all(&paths.queue).context("creating queue directory")?;
    fs::create_dir_all(&paths.afl).context("creating AFL++ output directory")?;
    fs::create_dir_all(&paths.crashes).context("creating crash directory")?;
    fs::create_dir_all(&paths.timeouts).context("creating timeout directory")?;
    seed_corpus_if_empty(&paths.corpus)?;

    let fuzzers = spawn_afl_fuzzers(&commands)?;

    let stats_provider = AflStatsProvider::new(
        paths.target_name.clone(),
        paths.afl.clone(),
        instances
            .iter()
            .map(|instance| instance.name.clone())
            .collect(),
        count_instance_binaries(&instances),
    )?;
    supervise_fuzzers(
        fuzzers,
        stats_provider,
        CampaignSync::new(
            paths,
            Duration::from_secs(args.corpus_sync_interval.saturating_mul(60)),
        ),
    )
}

fn validate_args(args: &FuzzArgs) -> Result<()> {
    if args.min_length > args.max_length {
        bail!(
            "--minlength ({}) cannot be greater than --maxlength ({})",
            args.min_length,
            args.max_length
        );
    }

    reject_known_wrapper(&args.afl_fuzz, "--afl-fuzz")?;
    reject_known_wrapper(&args.afl_whatsup, "--afl-whatsup")?;

    if let Some(dictionary) = &args.dict
        && !dictionary.is_file()
    {
        bail!("dictionary file not found `{}`", dictionary.display());
    }

    if let Some(initial_corpus) = &args.initial_corpus
        && !initial_corpus.is_dir()
    {
        bail!(
            "initial corpus directory not found `{}`",
            initial_corpus.display()
        );
    }

    for foreign_sync in &args.foreign_sync {
        if !foreign_sync.is_dir() {
            bail!(
                "foreign sync directory not found `{}`",
                foreign_sync.display()
            );
        }
    }

    Ok(())
}

fn reject_known_wrapper(tool: &Path, option: &str) -> Result<()> {
    let file_name = tool
        .file_name()
        .unwrap_or_else(|| tool.as_os_str())
        .to_string_lossy()
        .to_ascii_lowercase();

    if matches!(
        file_name.as_str(),
        "cargo" | "cargo-afl" | "cargo-hfuzz" | "cargo-fuzz"
    ) {
        bail!("{option} must point directly to an AFL++ tool");
    }

    Ok(())
}

#[derive(Debug, Clone)]
struct OutputPaths {
    target_name: String,
    output_target: PathBuf,
    corpus: PathBuf,
    logs: PathBuf,
    queue: PathBuf,
    afl: PathBuf,
    crashes: PathBuf,
    timeouts: PathBuf,
}

impl OutputPaths {
    fn new(args: &FuzzArgs) -> Result<Self> {
        let target_name = target_name_from_binary(&args.binary);
        let output_target = args.output_root.join(&target_name);
        let corpus = render_campaign_path(&args.corpus, &args.output_root, &target_name);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system time before Unix epoch")?
            .as_millis()
            .to_string();

        Ok(Self {
            target_name,
            logs: output_target.join("logs"),
            queue: output_target.join("queue"),
            afl: output_target.join("afl"),
            crashes: output_target.join("crashes").join(&timestamp),
            timeouts: output_target.join("timeouts").join(timestamp),
            output_target,
            corpus,
        })
    }
}

fn seed_corpus_if_empty(corpus: &Path) -> Result<()> {
    if fs::read_dir(corpus)
        .with_context(|| format!("reading corpus directory `{}`", corpus.display()))?
        .next()
        .is_some()
    {
        return Ok(());
    }

    let init_path = corpus.join("init");
    let mut init = File::create(&init_path)
        .with_context(|| format!("creating initial corpus seed `{}`", init_path.display()))?;
    writeln!(&mut init, "00000000")
        .with_context(|| format!("writing initial corpus seed `{}`", init_path.display()))?;
    Ok(())
}

#[derive(Debug, Clone)]
struct BinaryVariants {
    normal: PathBuf,
    cmplog: Option<PathBuf>,
    sanitizer: Option<PathBuf>,
    laf: Option<PathBuf>,
    cfisan: Option<PathBuf>,
}

impl BinaryVariants {
    fn from_args(args: &FuzzArgs) -> Self {
        Self {
            normal: args.binary.clone(),
            cmplog: args.cmplog_binary.clone(),
            sanitizer: args.sanitizer_binary.clone(),
            laf: args.laf_binary.clone(),
            cfisan: args.cfisan_binary.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AflMode {
    Main,
    Secondary,
}

impl AflMode {
    fn flag(self) -> &'static str {
        match self {
            Self::Main => "-M",
            Self::Secondary => "-S",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AflInstance {
    name: String,
    mode: AflMode,
    binary: PathBuf,
    cmplog_binary: Option<PathBuf>,
    extra_flags: Vec<String>,
    disable_trim: bool,
    final_sync: bool,
    power_schedule: &'static str,
}

fn plan_afl_instances(variants: &BinaryVariants, jobs: usize) -> Vec<AflInstance> {
    let mut instances = Vec::with_capacity(jobs);
    instances.push(AflInstance {
        name: "mainaflfuzzer".to_string(),
        mode: AflMode::Main,
        binary: variants.normal.clone(),
        cmplog_binary: None,
        extra_flags: Vec::new(),
        disable_trim: false,
        final_sync: true,
        power_schedule: "explore",
    });

    let mut remaining = jobs.saturating_sub(1);
    if let Some(cmplog_binary) = variants.cmplog.as_ref() {
        let cmplog_count = (jobs / 5).max(1).min(remaining);
        let cmplog_l_flags = ["2", "2AT", "3"];
        let cmplog_schedules = ["fast", "explore", "coe"];

        for i in 0..cmplog_count {
            instances.push(AflInstance {
                name: format!("cmplog{i:02}"),
                mode: AflMode::Secondary,
                binary: variants.normal.clone(),
                cmplog_binary: Some(cmplog_binary.clone()),
                extra_flags: vec!["-l".into(), cmplog_l_flags[i % cmplog_l_flags.len()].into()],
                disable_trim: false,
                final_sync: false,
                power_schedule: cmplog_schedules[i % cmplog_schedules.len()],
            });
        }

        remaining -= cmplog_count;
    }

    if remaining > 0
        && let Some(binary) = variants.sanitizer.as_ref()
    {
        instances.push(AflInstance {
            name: "san01".to_string(),
            mode: AflMode::Secondary,
            binary: binary.clone(),
            cmplog_binary: None,
            extra_flags: Vec::new(),
            disable_trim: false,
            final_sync: false,
            power_schedule: "explore",
        });
        remaining -= 1;
    }

    if remaining > 0
        && jobs >= 6
        && let Some(binary) = variants.laf.as_ref()
    {
        instances.push(AflInstance {
            name: "laf01".to_string(),
            mode: AflMode::Secondary,
            binary: binary.clone(),
            cmplog_binary: None,
            extra_flags: Vec::new(),
            disable_trim: false,
            final_sync: false,
            power_schedule: "fast",
        });
        remaining -= 1;
    }

    if remaining > 0
        && jobs >= 8
        && let Some(binary) = variants.cfisan.as_ref()
    {
        instances.push(AflInstance {
            name: "cfisan01".to_string(),
            mode: AflMode::Secondary,
            binary: binary.clone(),
            cmplog_binary: None,
            extra_flags: Vec::new(),
            disable_trim: false,
            final_sync: false,
            power_schedule: "fast",
        });
        remaining -= 1;
    }

    let power_schedules = ["explore", "fast", "coe", "lin", "quad", "exploit", "rare"];
    for i in 0..remaining {
        let mut extra_flags = Vec::new();
        if i % 10 == 0 {
            extra_flags.extend(["-L".into(), "0".into()]);
        }
        if i % 10 == 1 {
            extra_flags.push("-Z".into());
        }
        if i % 5 < 2 {
            extra_flags.extend(["-P".into(), "explore".into()]);
        } else if i % 5 == 2 {
            extra_flags.extend(["-P".into(), "exploit".into()]);
        }

        instances.push(AflInstance {
            name: format!("sec{i:02}"),
            mode: AflMode::Secondary,
            binary: variants.normal.clone(),
            cmplog_binary: None,
            extra_flags,
            disable_trim: i % 5 != 0,
            final_sync: false,
            power_schedule: power_schedules[i % power_schedules.len()],
        });
    }

    instances
}

fn count_instance_binaries(instances: &[AflInstance]) -> Vec<BinaryInstanceCount> {
    let mut counts: Vec<BinaryInstanceCount> = Vec::new();

    for instance in instances {
        let name = instance
            .cmplog_binary
            .as_ref()
            .map(|binary| format!("{} (cmplog)", target_name_from_binary(binary)))
            .unwrap_or_else(|| target_name_from_binary(&instance.binary));
        if let Some(existing) = counts.iter_mut().find(|count| count.name == name) {
            existing.count += 1;
        } else {
            counts.push(BinaryInstanceCount { name, count: 1 });
        }
    }

    counts
}

#[derive(Debug, Clone)]
struct AflCommandSpec {
    instance_name: String,
    program: PathBuf,
    args: Vec<OsString>,
    envs: Vec<(OsString, OsString)>,
    log_path: Option<PathBuf>,
}

impl AflCommandSpec {
    fn display_command(&self) -> String {
        std::iter::once(format_os(self.program.as_os_str()))
            .chain(self.args.iter().map(|arg| format_os(arg)))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

fn build_afl_commands(
    args: &FuzzArgs,
    paths: &OutputPaths,
    instances: &[AflInstance],
) -> Vec<AflCommandSpec> {
    let timeout_option_afl = args.timeout.map(|t| format!("-t{}", t * 1000));
    let memory_option_afl = args.memory_limit.as_ref().map(|m| format!("-m{m}"));
    let dictionary_option = args.dict.as_ref().map(|d| format!("-x{}", d.display()));
    let input_format_option = args.config.input_format_flag();

    instances
        .iter()
        .map(|instance| {
            let mut command_args = vec![
                OsString::from(instance.mode.flag()),
                OsString::from(&instance.name),
                OsString::from(format!("-i{}", paths.corpus.display())),
                OsString::from(format!("-p{}", instance.power_schedule)),
                OsString::from(format!("-o{}", paths.afl.display())),
                OsString::from(format!("-g{}", args.min_length)),
                OsString::from(format!("-G{}", args.max_length)),
            ];

            if matches!(instance.mode, AflMode::Main) {
                if let Some(initial_corpus) = &args.initial_corpus {
                    command_args.push(OsString::from(format!("-F{}", initial_corpus.display())));
                }

                for path in &args.foreign_sync {
                    command_args.push(OsString::from(format!("-F{}", path.display())));
                }
            }

            if let Some(timeout_option_afl) = &timeout_option_afl {
                command_args.push(OsString::from(timeout_option_afl));
            }
            if let Some(memory_option_afl) = &memory_option_afl {
                command_args.push(OsString::from(memory_option_afl));
            }
            if let Some(dictionary_option) = &dictionary_option {
                command_args.push(OsString::from(dictionary_option));
            }
            if let Some(input_format_option) = input_format_option {
                command_args.push(OsString::from(input_format_option));
            }
            if let Some(cmplog_binary) = &instance.cmplog_binary {
                command_args.push(OsString::from("-c"));
                command_args.push(cmplog_binary.as_os_str().to_owned());
            }

            command_args.extend(instance.extra_flags.iter().map(OsString::from));
            command_args.extend(args.afl_flags.iter().map(OsString::from));
            command_args.push(OsString::from("--"));
            command_args.push(instance.binary.as_os_str().to_owned());

            let mut envs = vec![
                ("AFL_AUTORESUME", "1"),
                ("AFL_TESTCACHE_SIZE", "500"),
                ("AFL_FAST_CAL", "1"),
                ("AFL_TRY_AFFINITY", "1"),
                ("AFL_FORCE_UI", "1"),
                ("AFL_IGNORE_UNKNOWN_ENVS", "1"),
                ("AFL_CMPLOG_ONLY_NEW", "1"),
                ("AFL_NO_WARN_INSTABILITY", "1"),
                ("AFL_FUZZER_STATS_UPDATE_INTERVAL", "10"),
                ("AFL_IMPORT_FIRST", "1"),
                ("AFL_IGNORE_SEED_PROBLEMS", "1"),
                ("AFL_PIZZA_MODE", "-1"),
            ]
            .into_iter()
            .map(|(key, value)| (OsString::from(key), OsString::from(value)))
            .collect::<Vec<_>>();

            if instance.final_sync {
                envs.push((OsString::from("AFL_FINAL_SYNC"), OsString::from("1")));
            }
            if instance.disable_trim {
                envs.push((OsString::from("AFL_DISABLE_TRIM"), OsString::from("1")));
            }

            let log_path = match instance.name.as_str() {
                "mainaflfuzzer" => Some(paths.logs.join("afl.log")),
                "cmplog00" => Some(paths.logs.join("afl_1.log")),
                _ => None,
            };

            AflCommandSpec {
                instance_name: instance.name.clone(),
                program: args.afl_fuzz.clone(),
                args: command_args,
                envs,
                log_path,
            }
        })
        .collect()
}

fn format_os(value: &OsStr) -> String {
    let value = value.to_string_lossy();
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '/' | ':' | '='))
    {
        value.into_owned()
    } else {
        format!("{value:?}")
    }
}

fn print_campaign_summary(
    args: &FuzzArgs,
    paths: &OutputPaths,
    variants: &BinaryVariants,
    instances: &[AflInstance],
    commands: &[AflCommandSpec],
) {
    eprintln!("resolved fuzz campaign for `{}`", paths.target_name);
    eprintln!("  binary: {}", variants.normal.display());
    eprintln!(
        "  cmplog binary: {}",
        display_optional_path(variants.cmplog.as_ref())
    );
    eprintln!(
        "  sanitizer binary: {}",
        display_optional_path(variants.sanitizer.as_ref())
    );
    eprintln!(
        "  laf binary: {}",
        display_optional_path(variants.laf.as_ref())
    );
    eprintln!(
        "  cfisan binary: {}",
        display_optional_path(variants.cfisan.as_ref())
    );
    eprintln!("  output root: {}", args.output_root.display());
    eprintln!("  output target: {}", paths.output_target.display());
    eprintln!("  corpus: {}", paths.corpus.display());
    eprintln!("  logs: {}", paths.logs.display());
    eprintln!("  queue: {}", paths.queue.display());
    eprintln!("  afl output: {}", paths.afl.display());
    eprintln!("  crashes: {}", paths.crashes.display());
    eprintln!("  timeouts: {}", paths.timeouts.display());
    eprintln!("  afl-fuzz: {}", args.afl_fuzz.display());
    eprintln!("  afl-whatsup: {}", args.afl_whatsup.display());
    eprintln!("  jobs: {}", args.jobs);

    eprintln!("\nplanned AFL++ instances:");
    for instance in instances {
        let cmplog = instance
            .cmplog_binary
            .as_ref()
            .map(|path| format!(", cmplog={}", path.display()))
            .unwrap_or_default();
        let flags = if instance.extra_flags.is_empty() {
            "none".to_string()
        } else {
            instance.extra_flags.join(" ")
        };
        let env = match (instance.final_sync, instance.disable_trim) {
            (true, true) => "AFL_FINAL_SYNC=1 AFL_DISABLE_TRIM=1",
            (true, false) => "AFL_FINAL_SYNC=1",
            (false, true) => "AFL_DISABLE_TRIM=1",
            (false, false) => "none",
        };
        eprintln!(
            "  {} {} schedule={} binary={}{} flags={} env={}",
            instance.mode.flag(),
            instance.name,
            instance.power_schedule,
            instance.binary.display(),
            cmplog,
            flags,
            env
        );
    }

    eprintln!("\nAFL++ launch commands:");
    for command in commands {
        eprintln!("  {}", command.display_command());
        if let Some(log_path) = &command.log_path {
            eprintln!("    log: {}", log_path.display());
        }
    }
}

fn display_optional_path(path: Option<&PathBuf>) -> String {
    path.map(|path| path.display().to_string())
        .unwrap_or_else(|| "not provided".to_string())
}

fn spawn_afl_fuzzers(commands: &[AflCommandSpec]) -> Result<Vec<RunningFuzzer>> {
    commands
        .iter()
        .map(|spec| {
            let mut log_destination = spec
                .log_path
                .as_ref()
                .map(File::create)
                .transpose()
                .with_context(|| {
                    format!(
                        "creating log file for AFL++ instance `{}`",
                        spec.instance_name
                    )
                })?;

            let mut command = process::Command::new(&spec.program);
            command
                .args(&spec.args)
                .envs(spec.envs.iter().map(|(key, value)| (key, value)))
                .stdin(Stdio::null())
                .stdout(
                    log_destination
                        .as_ref()
                        .map(File::try_clone)
                        .transpose()?
                        .map_or_else(Stdio::null, Into::into),
                )
                .stderr(log_destination.take().map_or_else(Stdio::null, Into::into));

            let child = command
                .spawn()
                .with_context(|| format!("spawning `{}`", spec.display_command()))?;

            Ok(RunningFuzzer {
                name: spec.instance_name.clone(),
                child,
            })
        })
        .collect()
}

#[derive(Debug)]
struct RunningFuzzer {
    name: String,
    child: process::Child,
}

#[derive(Debug)]
struct CampaignSync {
    paths: OutputPaths,
    corpus_interval: Duration,
    last_corpus_sync: Option<SystemTime>,
    last_corpus_tick: Instant,
}

impl CampaignSync {
    fn new(paths: OutputPaths, corpus_interval: Duration) -> Self {
        Self {
            paths,
            corpus_interval,
            last_corpus_sync: None,
            last_corpus_tick: Instant::now(),
        }
    }

    fn sync_periodic(&mut self) -> Result<()> {
        self.sync_crashes_and_timeouts()?;

        if self.corpus_interval.is_zero() || self.last_corpus_tick.elapsed() >= self.corpus_interval
        {
            self.sync_corpus_now()?;
            self.last_corpus_tick = Instant::now();
        }

        Ok(())
    }

    fn sync_final(&mut self) -> Result<()> {
        self.sync_corpus_now()?;
        self.sync_crashes_and_timeouts()
    }

    fn sync_corpus_now(&mut self) -> Result<()> {
        let sync_started = SystemTime::now();
        sync_main_queue_to_corpus(&self.paths, self.last_corpus_sync)?;
        self.last_corpus_sync = Some(sync_started);
        Ok(())
    }

    fn sync_crashes_and_timeouts(&self) -> Result<()> {
        sync_afl_artifacts(&self.paths.afl, "crashes", &self.paths.crashes)?;
        sync_afl_artifacts(&self.paths.afl, "hangs", &self.paths.timeouts)
    }
}

fn sync_main_queue_to_corpus(paths: &OutputPaths, last_sync: Option<SystemTime>) -> Result<()> {
    let queue_dir = paths.afl.join("mainaflfuzzer").join("queue");
    let entries = match fs::read_dir(&queue_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("reading AFL++ main queue `{}`", queue_dir.display()));
        }
    };

    fs::create_dir_all(&paths.corpus)
        .with_context(|| format!("creating corpus directory `{}`", paths.corpus.display()))?;

    for entry in entries {
        let Ok(entry) = entry else {
            continue;
        };
        let path = entry.path();
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        if !metadata.is_file() || !was_modified_after_last_sync(&metadata, last_sync) {
            continue;
        }

        copy_hashed_seed(&path, &paths.corpus)
            .with_context(|| format!("syncing AFL++ queue entry `{}`", path.display()))?;
    }

    Ok(())
}

fn was_modified_after_last_sync(metadata: &fs::Metadata, last_sync: Option<SystemTime>) -> bool {
    let Some(last_sync) = last_sync else {
        return true;
    };

    metadata
        .modified()
        .map(|modified| last_sync < modified || modified.elapsed().is_err())
        .unwrap_or(true)
}

fn copy_hashed_seed(source: &Path, corpus_dir: &Path) -> Result<()> {
    let hash = hash_file(source)?;

    for offset in 0..1024u64 {
        let candidate = corpus_dir.join(format!("{:x}", hash.wrapping_add(offset)));
        if !candidate.exists() {
            fs::copy(source, &candidate).with_context(|| {
                format!(
                    "copying corpus seed `{}` to `{}`",
                    source.display(),
                    candidate.display()
                )
            })?;
            return Ok(());
        }

        if files_have_same_content(source, &candidate)? {
            return Ok(());
        }
    }

    bail!(
        "could not resolve corpus filename collision for `{}`",
        source.display()
    );
}

fn sync_afl_artifacts(afl_dir: &Path, artifact_dir_name: &str, target_dir: &Path) -> Result<()> {
    let instances = match fs::read_dir(afl_dir) {
        Ok(instances) => instances,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| {
                format!("reading AFL++ output directory `{}`", afl_dir.display())
            });
        }
    };

    fs::create_dir_all(target_dir)
        .with_context(|| format!("creating sync directory `{}`", target_dir.display()))?;

    for instance in instances {
        let Ok(instance) = instance else {
            continue;
        };
        let Ok(metadata) = instance.metadata() else {
            continue;
        };
        if !metadata.is_dir() {
            continue;
        }

        let instance_name = instance.file_name();
        let source_dir = instance.path().join(artifact_dir_name);
        copy_artifacts_from_dir(&source_dir, target_dir, &instance_name).with_context(|| {
            format!(
                "syncing AFL++ `{artifact_dir_name}` from `{}`",
                source_dir.display()
            )
        })?;
    }

    Ok(())
}

fn copy_artifacts_from_dir(
    source_dir: &Path,
    target_dir: &Path,
    instance_name: &OsStr,
) -> Result<()> {
    let entries = match fs::read_dir(source_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "reading AFL++ artifact directory `{}`",
                    source_dir.display()
                )
            });
        }
    };

    for entry in entries {
        let Ok(entry) = entry else {
            continue;
        };
        let path = entry.path();
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        if !metadata.is_file() {
            continue;
        }

        copy_artifact(&path, target_dir, instance_name)?;
    }

    Ok(())
}

fn copy_artifact(source: &Path, target_dir: &Path, instance_name: &OsStr) -> Result<()> {
    let Some(file_name) = source.file_name() else {
        return Ok(());
    };

    let target = target_dir.join(file_name);
    if copy_if_missing_or_same(source, &target)? {
        return Ok(());
    }

    let file_name = file_name.to_string_lossy();
    let instance_name = instance_name.to_string_lossy();
    for offset in 0..1024 {
        let target = target_dir.join(format!("{instance_name}-{offset}-{file_name}"));
        if copy_if_missing_or_same(source, &target)? {
            return Ok(());
        }
    }

    bail!(
        "could not resolve artifact filename collision for `{}`",
        source.display()
    );
}

fn copy_if_missing_or_same(source: &Path, target: &Path) -> Result<bool> {
    if !target.exists() {
        fs::copy(source, target).with_context(|| {
            format!(
                "copying AFL++ artifact `{}` to `{}`",
                source.display(),
                target.display()
            )
        })?;
        return Ok(true);
    }

    files_have_same_content(source, target)
}

fn files_have_same_content(left: &Path, right: &Path) -> Result<bool> {
    let left_metadata =
        fs::metadata(left).with_context(|| format!("reading metadata `{}`", left.display()))?;
    let right_metadata =
        fs::metadata(right).with_context(|| format!("reading metadata `{}`", right.display()))?;

    if left_metadata.len() != right_metadata.len() {
        return Ok(false);
    }

    Ok(
        fs::read(left).with_context(|| format!("reading `{}`", left.display()))?
            == fs::read(right).with_context(|| format!("reading `{}`", right.display()))?,
    )
}

fn supervise_fuzzers(
    mut fuzzers: Vec<RunningFuzzer>,
    stats_provider: impl FuzzerStatsProvider,
    mut sync: CampaignSync,
) -> Result<()> {
    let terminated = Arc::new(AtomicBool::new(false));
    for signal in signal_hook::consts::TERM_SIGNALS {
        signal_hook::flag::register(*signal, Arc::clone(&terminated))
            .context("installing shutdown signal handler")?;
    }

    let start_time = Instant::now();
    let mut screen = StatusScreen::new();

    loop {
        if terminated.load(Ordering::Acquire) {
            screen.finish();
            eprintln!("\nShutting down AFL++ campaign...");
            stop_fuzzers(&mut fuzzers);
            wait_for_fuzzers(&mut fuzzers);
            sync.sync_final()
                .context("performing final corpus/crash/timeout sync")?;
            return Ok(());
        }

        for index in 0..fuzzers.len() {
            if let Some(status) = fuzzers[index]
                .child
                .try_wait()
                .with_context(|| format!("checking AFL++ instance `{}`", fuzzers[index].name))?
            {
                let name = fuzzers[index].name.clone();
                screen.finish();
                stop_fuzzers(&mut fuzzers);
                wait_for_fuzzers(&mut fuzzers);
                sync.sync_final()
                    .context("performing final corpus/crash/timeout sync")?;
                bail!("AFL++ instance `{name}` exited with status `{status}`");
            }
        }

        if let Err(error) = sync.sync_periodic() {
            screen.finish();
            stop_fuzzers(&mut fuzzers);
            wait_for_fuzzers(&mut fuzzers);
            let _ = sync.sync_final();
            return Err(error.context("syncing AFL++ corpus/crashes/timeouts"));
        }

        let snapshot = stats_provider.snapshot(fuzzers.len(), start_time.elapsed());
        screen.draw(&snapshot);
        thread::sleep(Duration::from_secs(1));
    }
}

fn stop_fuzzers(fuzzers: &mut [RunningFuzzer]) {
    for fuzzer in fuzzers.iter_mut() {
        if matches!(fuzzer.child.try_wait(), Ok(None)) {
            request_child_stop(&mut fuzzer.child);
        }
    }

    let graceful_deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < graceful_deadline {
        if fuzzers
            .iter_mut()
            .all(|fuzzer| !matches!(fuzzer.child.try_wait(), Ok(None)))
        {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }

    for fuzzer in fuzzers {
        if matches!(fuzzer.child.try_wait(), Ok(None)) {
            let _ = fuzzer.child.kill();
        }
    }
}

#[cfg(unix)]
fn request_child_stop(child: &mut process::Child) {
    unsafe extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }

    const SIGTERM: i32 = 15;
    let _ = unsafe { kill(child.id() as i32, SIGTERM) };
}

#[cfg(not(unix))]
fn request_child_stop(child: &mut process::Child) {
    let _ = child.kill();
}

fn wait_for_fuzzers(fuzzers: &mut [RunningFuzzer]) {
    for fuzzer in fuzzers {
        let _ = fuzzer.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(name: &str) -> Result<Self> {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("system time before Unix epoch")?
                .as_nanos();
            let root = std::env::temp_dir()
                .join(format!("fuzzd-{name}-{}-{timestamp}", std::process::id()));
            fs::create_dir_all(&root)?;
            Ok(Self(root))
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn variants() -> BinaryVariants {
        BinaryVariants {
            normal: "target_normal".into(),
            cmplog: Some("target_cmplog".into()),
            sanitizer: Some("target_asan_ubsan".into()),
            laf: Some("target_laf".into()),
            cfisan: Some("target_cfisan".into()),
        }
    }

    fn names(instances: &[AflInstance]) -> Vec<&str> {
        instances
            .iter()
            .map(|instance| instance.name.as_str())
            .collect()
    }

    fn binary_counts(instances: &[AflInstance]) -> Vec<(String, usize)> {
        count_instance_binaries(instances)
            .into_iter()
            .map(|count| (count.name, count.count))
            .collect()
    }

    fn test_paths(root: &Path) -> OutputPaths {
        OutputPaths {
            target_name: "target_normal".to_string(),
            output_target: root.to_path_buf(),
            corpus: root.join("corpus"),
            logs: root.join("logs"),
            queue: root.join("queue"),
            afl: root.join("afl"),
            crashes: root.join("crashes").join("1234"),
            timeouts: root.join("timeouts").join("1234"),
        }
    }

    #[test]
    fn plans_single_main_instance() {
        let instances = plan_afl_instances(&variants(), 1);
        assert_eq!(names(&instances), ["mainaflfuzzer"]);
        assert_eq!(instances[0].mode, AflMode::Main);
        assert!(instances[0].final_sync);
    }

    #[test]
    fn plans_four_jobs_like_binary_mode() {
        let instances = plan_afl_instances(&variants(), 4);
        assert_eq!(
            names(&instances),
            ["mainaflfuzzer", "cmplog00", "san01", "sec00"]
        );
        assert_eq!(
            instances[1].cmplog_binary,
            Some(PathBuf::from("target_cmplog"))
        );
        assert_eq!(instances[1].extra_flags, ["-l", "2"]);
        assert_eq!(instances[3].extra_flags, ["-L", "0", "-P", "explore"]);
    }

    #[test]
    fn plans_eight_jobs_with_specialized_workers() {
        let instances = plan_afl_instances(&variants(), 8);
        assert_eq!(
            names(&instances),
            [
                "mainaflfuzzer",
                "cmplog00",
                "san01",
                "laf01",
                "cfisan01",
                "sec00",
                "sec01",
                "sec02",
            ]
        );
        assert_eq!(instances[3].binary, PathBuf::from("target_laf"));
        assert_eq!(instances[4].binary, PathBuf::from("target_cfisan"));
        assert_eq!(instances[7].extra_flags, ["-P", "exploit"]);
        assert!(instances[6].disable_trim);
    }

    #[test]
    fn counts_planned_instances_by_binary() {
        let instances = plan_afl_instances(&variants(), 8);
        assert_eq!(
            binary_counts(&instances),
            [
                ("target_normal".to_string(), 4),
                ("target_cmplog (cmplog)".to_string(), 1),
                ("target_asan_ubsan".to_string(), 1),
                ("target_laf".to_string(), 1),
                ("target_cfisan".to_string(), 1),
            ]
        );
    }

    #[test]
    fn counts_cmplog_workers_separately() {
        let instances = plan_afl_instances(&variants(), 16);
        assert_eq!(
            binary_counts(&instances),
            [
                ("target_normal".to_string(), 10),
                ("target_cmplog (cmplog)".to_string(), 3),
                ("target_asan_ubsan".to_string(), 1),
                ("target_laf".to_string(), 1),
                ("target_cfisan".to_string(), 1),
            ]
        );
    }

    #[test]
    fn syncs_main_queue_entries_into_hashed_corpus() -> Result<()> {
        let temp = TestDir::new("queue-sync")?;
        let paths = test_paths(temp.path());
        let queue_dir = paths.afl.join("mainaflfuzzer").join("queue");
        fs::create_dir_all(&queue_dir)?;
        fs::create_dir_all(&paths.corpus)?;

        let queue_entry = queue_dir.join("id:000001,src:000000,+cov");
        fs::write(&queue_entry, b"interesting seed")?;

        let mut sync = CampaignSync::new(paths.clone(), Duration::from_secs(0));
        sync.sync_periodic()?;

        let expected = paths.corpus.join(format!("{:x}", hash_file(&queue_entry)?));
        assert_eq!(fs::read(expected)?, b"interesting seed");
        Ok(())
    }

    #[test]
    fn syncs_crashes_and_hangs_into_timestamped_dirs() -> Result<()> {
        let temp = TestDir::new("artifact-sync")?;
        let paths = test_paths(temp.path());
        let crash_dir = paths.afl.join("sec00").join("crashes");
        let hang_dir = paths.afl.join("sec00").join("hangs");
        fs::create_dir_all(&crash_dir)?;
        fs::create_dir_all(&hang_dir)?;

        fs::write(crash_dir.join("id:000000,sig:11"), b"crash")?;
        fs::write(hang_dir.join("id:000000,timeout"), b"hang")?;

        let mut sync = CampaignSync::new(paths.clone(), Duration::from_secs(60));
        sync.sync_final()?;

        assert_eq!(fs::read(paths.crashes.join("id:000000,sig:11"))?, b"crash");
        assert_eq!(fs::read(paths.timeouts.join("id:000000,timeout"))?, b"hang");
        Ok(())
    }
}
