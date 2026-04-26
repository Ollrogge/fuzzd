//! Coverage replay and report generation for prebuilt LLVM-instrumented C/C++ binaries.

use crate::{
    cli::{CoverArgs, DEFAULT_LLVM_COV, DEFAULT_LLVM_PROFDATA, ReportType},
    util::render_campaign_path,
};
use anyhow::{Context as _, Result, bail};
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    process::{self, Stdio},
    sync::Mutex,
};

#[derive(Debug, Clone)]
struct CoverageConfig {
    runner: PathBuf,
    profile_template: PathBuf,
    llvm_profdata: PathBuf,
    llvm_cov: PathBuf,
}

impl CoverageConfig {
    fn profile_input(&self, input: &Path) -> ReplayResult {
        let output = process::Command::new(&self.runner)
            .arg(input)
            .stdin(Stdio::null())
            .env("LLVM_PROFILE_FILE", &self.profile_template)
            .output();

        match output {
            Ok(output) => ReplayResult {
                input: input.to_path_buf(),
                success: output.status.success(),
                status: Some(output.status.to_string()),
                stdout: output.stdout,
                stderr: output.stderr,
                spawn_error: None,
            },
            Err(error) => ReplayResult {
                input: input.to_path_buf(),
                success: false,
                status: None,
                stdout: Vec::new(),
                stderr: Vec::new(),
                spawn_error: Some(error.to_string()),
            },
        }
    }

    fn merge_profraw(&self, profile_dir: &Path, output: &Path, jobs: Option<usize>) -> Result<()> {
        let profiles = collect_profraw(profile_dir)?;
        if profiles.is_empty() {
            bail!(
                "no .profraw files produced under `{}`; check `{}`",
                profile_dir.display(),
                profile_dir
                    .parent()
                    .unwrap_or(profile_dir)
                    .join("logs")
                    .join("coverage.log")
                    .display()
            );
        }

        let mut command = process::Command::new(&self.llvm_profdata);
        command
            .arg("merge")
            .arg("-sparse")
            .arg("--failure-mode=warn")
            .args(&profiles)
            .arg("-o")
            .arg(output);

        if let Some(jobs) = jobs {
            command.arg(format!("--num-threads={jobs}"));
        }

        let status = command
            .status()
            .with_context(|| format!("spawning `{}`", self.llvm_profdata.display()))?;
        if !status.success() {
            bail!("llvm-profdata failed with status `{status}`");
        }

        Ok(())
    }

    fn report_coverage(
        &self,
        merged_profile: &Path,
        output: &Path,
        format: ReportType,
        jobs: Option<usize>,
    ) -> Result<()> {
        use ReportType::{Html, Json, Lcov, Text};

        fs::create_dir_all(output)
            .with_context(|| format!("creating coverage output `{}`", output.display()))?;

        let mut command = process::Command::new(&self.llvm_cov);
        match format {
            Html => {
                command.args(["show", "-format=html"]);
                command.arg("-output-dir").arg(output);
                command.args([
                    "-show-directory-coverage",
                    "-show-line-counts-or-regions",
                    "-show-branches=count",
                ]);
            }
            Text => {
                command.args(["show", "-format=text"]);
                command.stdout(
                    fs::File::create(output.join("coverage.txt"))
                        .context("creating text coverage report")?,
                );
            }
            Json => {
                command.args(["export", "-format=text"]);
                command.stdout(
                    fs::File::create(output.join("coverage.json"))
                        .context("creating JSON coverage report")?,
                );
            }
            Lcov => {
                command.args(["export", "-format=lcov"]);
                command.stdout(
                    fs::File::create(output.join("coverage.lcov"))
                        .context("creating LCOV coverage report")?,
                );
            }
        }

        let status = command
            .arg("-instr-profile")
            .arg(merged_profile)
            .arg(&self.runner)
            .args(jobs.map(|jobs| format!("--num-threads={jobs}")))
            .status()
            .with_context(|| format!("spawning `{}`", self.llvm_cov.display()))?;
        if !status.success() {
            bail!("llvm-cov failed with status `{status}`");
        }

        Ok(())
    }
}

#[derive(Debug)]
struct ReplayResult {
    input: PathBuf,
    success: bool,
    status: Option<String>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    spawn_error: Option<String>,
}

impl ReplayResult {
    fn success(&self) -> bool {
        self.spawn_error.is_none() && self.success
    }

    fn write_log(&self, mut log: impl Write) -> Result<()> {
        writeln!(log, "=== {} ===", self.input.display())?;
        if let Some(error) = &self.spawn_error {
            writeln!(log, "spawn error: {error}")?;
        }
        if let Some(status) = &self.status {
            writeln!(log, "status: {status}")?;
        }
        if !self.stdout.is_empty() {
            writeln!(log, "--- stdout ---")?;
            log.write_all(&self.stdout)?;
            if !self.stdout.ends_with(b"\n") {
                writeln!(log)?;
            }
        }
        if !self.stderr.is_empty() {
            writeln!(log, "--- stderr ---")?;
            log.write_all(&self.stderr)?;
            if !self.stderr.ends_with(b"\n") {
                writeln!(log)?;
            }
        }
        writeln!(log)?;
        Ok(())
    }
}

pub fn run(args: CoverArgs) -> Result<()> {
    let target_name = resolve_target_name(args.target.as_deref(), &args.output_root)?;
    let input = render_campaign_path(&args.input, &args.output_root, &target_name);
    let report_output = render_campaign_path(&args.report_output, &args.output_root, &target_name);
    let output_target = args.output_root.join(&target_name);
    let profile_dir = output_target.join("coverage-profraw");
    let log_dir = output_target.join("logs");
    let llvm_profdata = resolve_tool(
        args.llvm_profdata.as_ref(),
        "LLVM_PROFDATA",
        DEFAULT_LLVM_PROFDATA,
    );
    let llvm_cov = resolve_tool(args.llvm_cov.as_ref(), "LLVM_COV", DEFAULT_LLVM_COV);
    validate_llvm_tools(&llvm_profdata, &llvm_cov)?;
    let coverage_binary = args
        .coverage_binary
        .canonicalize()
        .with_context(|| format!("canonicalizing `{}`", args.coverage_binary.display()))?;

    if !args.keep {
        remove_dir_if_exists(&profile_dir)?;
    }
    remove_dir_if_exists(&report_output)?;
    fs::create_dir_all(&profile_dir)
        .with_context(|| format!("creating profile directory `{}`", profile_dir.display()))?;
    fs::create_dir_all(&log_dir)
        .with_context(|| format!("creating log directory `{}`", log_dir.display()))?;

    let corpus = collect_inputs(&input)?;
    if corpus.is_empty() {
        bail!("no coverage inputs found at `{}`", input.display());
    }

    eprintln!("generating coverage for `{target_name}`");
    eprintln!("  coverage binary: {}", coverage_binary.display());
    eprintln!("  input: {}", input.display());
    eprintln!("  report output: {}", report_output.display());
    eprintln!("  profraw dir: {}", profile_dir.display());
    eprintln!("  llvm-profdata: {}", llvm_profdata.display());
    eprintln!("  llvm-cov: {}", llvm_cov.display());
    eprintln!("  inputs: {}", corpus.len());

    let cfg = CoverageConfig {
        runner: coverage_binary,
        profile_template: profile_dir.join("coverage-%p-%m.profraw"),
        llvm_profdata,
        llvm_cov,
    };

    profile_corpus(
        &cfg,
        &corpus,
        &log_dir.join("coverage.log"),
        args.jobs.map(usize::from),
    )?;

    let merged_profile = report_output.join("coverage.profraw");
    fs::create_dir_all(&report_output).with_context(|| {
        format!(
            "creating coverage report directory `{}`",
            report_output.display()
        )
    })?;

    eprintln!("  merging profiles");
    cfg.merge_profraw(&profile_dir, &merged_profile, args.jobs.map(usize::from))?;

    eprintln!("  generating {} report", args.output_type);
    cfg.report_coverage(
        &merged_profile,
        &report_output,
        args.output_type,
        args.jobs.map(usize::from),
    )?;
    eprintln!("coverage report written to {}", report_output.display());

    Ok(())
}

fn profile_corpus(
    cfg: &CoverageConfig,
    corpus: &[PathBuf],
    log_path: &Path,
    jobs: Option<usize>,
) -> Result<()> {
    let log_file = Mutex::new(
        fs::File::create(log_path)
            .with_context(|| format!("creating coverage log `{}`", log_path.display()))?,
    );
    let progress = ProgressBar::new(corpus.len() as u64);
    progress.set_style(
        ProgressStyle::with_template("  [{elapsed_precise}] [{wide_bar}] {pos}/{len} ({eta})")
            .expect("valid progress template")
            .progress_chars("#--"),
    );

    let replay = || {
        corpus
            .par_iter()
            .map(|input| {
                let result = cfg.profile_input(input);
                {
                    let mut log = log_file.lock().expect("coverage log lock poisoned");
                    let _ = result.write_log(&mut *log);
                }
                progress.inc(1);
                result
            })
            .collect::<Vec<_>>()
    };

    let results = if let Some(jobs) = jobs {
        rayon::ThreadPoolBuilder::new()
            .num_threads(jobs)
            .build()
            .context("building coverage replay thread pool")?
            .install(replay)
    } else {
        replay()
    };

    progress.finish_and_clear();

    let spawn_failures = results
        .iter()
        .filter(|result| result.spawn_error.is_some())
        .count();
    let failed_replays = results
        .iter()
        .filter(|result| result.spawn_error.is_none() && !result.success())
        .count();

    if spawn_failures > 0 {
        bail!(
            "{spawn_failures} coverage inputs could not be spawned; see `{}`",
            log_path.display()
        );
    }

    if failed_replays > 0 {
        eprintln!("  warning: {failed_replays} inputs exited non-zero; continuing with profiles");
    }

    Ok(())
}

fn collect_inputs(input: &Path) -> Result<Vec<PathBuf>> {
    if input.is_file() {
        return Ok(vec![input.to_path_buf()]);
    }
    if !input.is_dir() {
        bail!("coverage input path not found `{}`", input.display());
    }

    let mut inputs = fs::read_dir(input)
        .with_context(|| format!("reading coverage input directory `{}`", input.display()))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();
    inputs.sort();
    Ok(inputs)
}

fn collect_profraw(profile_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut profiles = fs::read_dir(profile_dir)
        .with_context(|| format!("reading profile directory `{}`", profile_dir.display()))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().is_some_and(|ext| ext == "profraw"))
        .collect::<Vec<_>>();
    profiles.sort();
    Ok(profiles)
}

fn resolve_target_name(explicit: Option<&str>, output_root: &Path) -> Result<String> {
    if let Some(target) = explicit {
        return Ok(target.to_string());
    }

    let Some(entries) = fs::read_dir(output_root).ok() else {
        bail!("could not infer target name; pass TARGET explicitly");
    };

    let mut targets = entries
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().join("corpus").is_dir())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect::<Vec<_>>();
    targets.sort();

    match targets.as_slice() {
        [target] => Ok(target.clone()),
        [] => bail!("could not infer target name; pass TARGET explicitly"),
        _ => bail!("multiple targets found; pass TARGET explicitly"),
    }
}

fn remove_dir_if_exists(path: &Path) -> Result<()> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("removing `{}`", path.display())),
    }
}

fn resolve_tool(explicit: Option<&PathBuf>, env_name: &str, default_command: &str) -> PathBuf {
    explicit
        .cloned()
        .or_else(|| env::var_os(env_name).map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(default_command))
}

fn validate_llvm_tools(llvm_profdata: &Path, llvm_cov: &Path) -> Result<()> {
    let mut missing = Vec::new();

    if !command_exists(llvm_profdata) {
        missing.push(format!(
            "  llvm-profdata: `{}` was not found",
            llvm_profdata.display()
        ));
    }
    if !command_exists(llvm_cov) {
        missing.push(format!(
            "  llvm-cov: `{}` was not found",
            llvm_cov.display()
        ));
    }

    if !missing.is_empty() {
        bail!(
            "required LLVM coverage tool{} not found:\n{}\nSet LLVM_PROFDATA/LLVM_COV or pass --llvm-profdata/--llvm-cov.",
            if missing.len() == 1 { "" } else { "s" },
            missing.join("\n")
        );
    }

    Ok(())
}

fn command_exists(command: &Path) -> bool {
    if command.components().count() > 1 {
        return command.is_file();
    }

    env::var_os("PATH")
        .is_some_and(|path| env::split_paths(&path).any(|dir| dir.join(command).is_file()))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(name: &str) -> Result<Self> {
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .context("system time before Unix epoch")?
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "fuzzd-coverage-{name}-{}-{timestamp}",
                std::process::id()
            ));
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

    #[test]
    fn infers_single_target_from_output_root() -> Result<()> {
        let temp = TestDir::new("infer-one")?;
        fs::create_dir_all(temp.path().join("target_normal").join("corpus"))?;

        assert_eq!(
            resolve_target_name(None, temp.path())?,
            "target_normal".to_string()
        );
        Ok(())
    }

    #[test]
    fn rejects_ambiguous_target_inference() -> Result<()> {
        let temp = TestDir::new("infer-many")?;
        fs::create_dir_all(temp.path().join("one").join("corpus"))?;
        fs::create_dir_all(temp.path().join("two").join("corpus"))?;

        let error = resolve_target_name(None, temp.path()).unwrap_err();
        assert!(error.to_string().contains("multiple targets"));
        Ok(())
    }

    #[test]
    fn collects_files_from_input_directory() -> Result<()> {
        let temp = TestDir::new("collect")?;
        fs::write(temp.path().join("b"), b"b")?;
        fs::write(temp.path().join("a"), b"a")?;
        fs::create_dir_all(temp.path().join("nested"))?;

        let inputs = collect_inputs(temp.path())?;
        assert_eq!(
            inputs
                .iter()
                .map(|path| path.file_name().unwrap().to_string_lossy().to_string())
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
        Ok(())
    }

    #[test]
    fn reports_missing_llvm_tools_without_guessing_versioned_names() {
        let error = validate_llvm_tools(
            Path::new("definitely-not-real-llvm-profdata"),
            Path::new("definitely-not-real-llvm-cov"),
        )
        .unwrap_err();
        let message = error.to_string();

        assert!(message.contains("llvm-profdata"));
        assert!(message.contains("llvm-cov"));
        assert!(message.contains("LLVM_PROFDATA/LLVM_COV"));
    }
}
