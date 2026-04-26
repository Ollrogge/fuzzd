//! Command-line definitions, defaults, and validation hooks for `fuzzd` subcommands.

use crate::util::existing_file;
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::{fmt, num::NonZeroUsize, path::PathBuf};

pub const DEFAULT_OUTPUT_ROOT: &str = "./output";
pub const DEFAULT_CORPUS_DIR: &str = "{output}/{target_name}/corpus/";
pub const DEFAULT_COVERAGE_DIR: &str = "{output}/{target_name}/coverage/";
pub const DEFAULT_AFL_FUZZ: &str = "afl-fuzz";
pub const DEFAULT_AFL_WHATSUP: &str = "afl-whatsup";
pub const DEFAULT_LLVM_PROFDATA: &str = "llvm-profdata";
pub const DEFAULT_LLVM_COV: &str = "llvm-cov";

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "AFL++ campaign orchestrator for prebuilt C/C++ fuzzing binaries",
    long_about = "fuzzd orchestrates AFL++ campaigns for prebuilt C/C++ fuzzing binaries. It invokes AFL++ and LLVM tools directly; it does not build targets and does not route commands through cargo afl, cargo hfuzz, or Rust fuzzing wrappers."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Launch a prebuilt AFL++ binary campaign.
    Fuzz(FuzzArgs),

    /// Parse options for replaying a corpus with a prebuilt LLVM coverage binary.
    Cover(CoverArgs),
}

#[derive(Debug, Args)]
pub struct FuzzArgs {
    /// Required normal AFL++-instrumented target binary.
    #[arg(long, value_name = "PATH", value_parser = existing_file)]
    pub binary: PathBuf,

    /// Optional AFL++ CmpLog binary used with afl-fuzz -c.
    #[arg(long = "cmplog-binary", value_name = "PATH", value_parser = existing_file)]
    pub cmplog_binary: Option<PathBuf>,

    /// Optional ASAN binary.
    #[arg(long = "asan-binary", value_name = "PATH", value_parser = existing_file)]
    pub asan_binary: Option<PathBuf>,

    /// Optional UBSAN binary, used only if ASAN is absent.
    #[arg(long = "ubsan-binary", value_name = "PATH", value_parser = existing_file)]
    pub ubsan_binary: Option<PathBuf>,

    /// Optional laf-intel binary.
    #[arg(long = "laf-binary", value_name = "PATH", value_parser = existing_file)]
    pub laf_binary: Option<PathBuf>,

    /// Optional CFISAN binary.
    #[arg(long = "cfisan-binary", value_name = "PATH", value_parser = existing_file)]
    pub cfisan_binary: Option<PathBuf>,

    /// Campaign output root.
    #[arg(short = 'z', long = "output-root", value_name = "DIR", default_value = DEFAULT_OUTPUT_ROOT)]
    pub output_root: PathBuf,

    /// Shared corpus directory.
    #[arg(short = 'c', long, value_name = "DIR", default_value = DEFAULT_CORPUS_DIR)]
    pub corpus: PathBuf,

    /// Optional read-only seed corpus imported by the main AFL++ instance.
    #[arg(short = 'i', long = "initial-corpus", value_name = "DIR")]
    pub initial_corpus: Option<PathBuf>,

    /// Total AFL++ instances to plan.
    #[arg(short = 'j', long, value_name = "NUM", default_value_t = NonZeroUsize::new(1).expect("non-zero default"))]
    pub jobs: NonZeroUsize,

    /// Per-exec AFL++ timeout in seconds; later phases translate it to milliseconds.
    #[arg(short = 't', long, value_name = "SECS")]
    pub timeout: Option<u64>,

    /// AFL++ memory limit passed to afl-fuzz -m.
    #[arg(short = 'm', long = "memory-limit", value_name = "STRING")]
    pub memory_limit: Option<String>,

    /// AFL++ dictionary file.
    #[arg(short = 'x', long = "dict", value_name = "FILE")]
    pub dict: Option<PathBuf>,

    /// AFL++ maximum input length.
    #[arg(
        short = 'G',
        long = "maxlength",
        value_name = "NUM",
        default_value_t = 1_048_576
    )]
    pub max_length: u64,

    /// AFL++ minimum input length.
    #[arg(
        short = 'g',
        long = "minlength",
        value_name = "NUM",
        default_value_t = 1
    )]
    pub min_length: u64,

    /// AFL++ input format configuration.
    #[arg(short = 'C', long, value_enum, default_value_t = FuzzConfig::Generic)]
    pub config: FuzzConfig,

    /// afl-fuzz executable path or command name.
    #[arg(long = "afl-fuzz", value_name = "PATH", default_value = DEFAULT_AFL_FUZZ)]
    pub afl_fuzz: PathBuf,

    /// afl-whatsup executable path or command name.
    #[arg(long = "afl-whatsup", value_name = "PATH", default_value = DEFAULT_AFL_WHATSUP)]
    pub afl_whatsup: PathBuf,

    /// Repeatable AFL++ -F directory for the main instance.
    #[arg(long = "foreign-sync", value_name = "DIR")]
    pub foreign_sync: Vec<PathBuf>,

    /// Repeatable raw AFL++ passthrough flag.
    #[arg(long = "afl-flags", value_name = "FLAG", allow_hyphen_values = true)]
    pub afl_flags: Vec<String>,

    /// Corpus sync interval in minutes.
    #[arg(long = "corpus-sync-interval", value_name = "MIN", default_value_t = 5)]
    pub corpus_sync_interval: u64,

    /// Print the resolved campaign plan and AFL++ commands without launching anything.
    #[arg(
        long = "dry-run",
        visible_alias = "debug-plan",
        default_value_t = false
    )]
    pub dry_run: bool,
}

#[derive(Debug, Args)]
pub struct CoverArgs {
    /// Required prebuilt LLVM coverage replay binary.
    #[arg(long = "coverage-binary", value_name = "PATH", value_parser = existing_file)]
    pub coverage_binary: PathBuf,

    /// Campaign output root.
    #[arg(short = 'z', long = "output-root", value_name = "DIR", default_value = DEFAULT_OUTPUT_ROOT)]
    pub output_root: PathBuf,

    /// Corpus directory or single input file to replay.
    #[arg(short = 'i', long = "input", value_name = "DIR", default_value = DEFAULT_CORPUS_DIR)]
    pub input: PathBuf,

    /// Coverage report output directory.
    #[arg(short = 'o', long = "report-output", value_name = "DIR", default_value = DEFAULT_COVERAGE_DIR)]
    pub report_output: PathBuf,

    /// Coverage output type.
    #[arg(short = 't', long = "output-type", value_enum, default_value_t = ReportType::Html)]
    pub output_type: ReportType,

    /// Parallel replay/llvm jobs.
    #[arg(short = 'j', long, value_name = "NUM")]
    pub jobs: Option<NonZeroUsize>,

    /// Keep existing profraw files.
    #[arg(short = 'k', long, default_value_t = false)]
    pub keep: bool,

    /// llvm-profdata executable path or command name. Defaults to LLVM_PROFDATA or llvm-profdata.
    #[arg(long = "llvm-profdata", value_name = "PATH")]
    pub llvm_profdata: Option<PathBuf>,

    /// llvm-cov executable path or command name. Defaults to LLVM_COV or llvm-cov.
    #[arg(long = "llvm-cov", value_name = "PATH")]
    pub llvm_cov: Option<PathBuf>,

    /// Explicit campaign target name.
    #[arg(value_name = "TARGET")]
    pub target: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum FuzzConfig {
    Generic,
    Binary,
    Text,
}

impl fmt::Display for FuzzConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Generic => f.write_str("generic"),
            Self::Binary => f.write_str("binary"),
            Self::Text => f.write_str("text"),
        }
    }
}

impl FuzzConfig {
    pub(crate) fn input_format_flag(self) -> Option<&'static str> {
        match self {
            Self::Generic => None,
            Self::Binary => Some("-abinary"),
            Self::Text => Some("-atext"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum ReportType {
    Html,
    Text,
    Json,
    Lcov,
}

impl fmt::Display for ReportType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Html => f.write_str("html"),
            Self::Text => f.write_str("text"),
            Self::Json => f.write_str("json"),
            Self::Lcov => f.write_str("lcov"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser, error::ErrorKind};

    #[test]
    fn top_level_help_builds() {
        Cli::command().debug_assert();
    }

    #[test]
    fn fuzz_requires_binary() {
        let err = Cli::try_parse_from(["fuzzd", "fuzz"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn fuzz_rejects_missing_binary() {
        let err = Cli::try_parse_from(["fuzzd", "fuzz", "--binary", "does-not-exist"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ValueValidation);
    }

    #[test]
    fn cover_requires_coverage_binary() {
        let err = Cli::try_parse_from(["fuzzd", "cover"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn cover_rejects_missing_coverage_binary() {
        let err = Cli::try_parse_from(["fuzzd", "cover", "--coverage-binary", "does-not-exist"])
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ValueValidation);
    }
}
