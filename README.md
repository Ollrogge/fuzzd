# fuzzd
**Note**: This is a work in progress. More features will be added over time.

`fuzzd` is an AFL++ campaign orchestrator for prebuilt C/C++ fuzzing binaries.
It supervises multi-instance fuzzing runs, keeps campaign output organized, and
generates LLVM coverage reports from an existing corpus.

The intended workflow is:

1. Build the target variants yourself.
2. Run `fuzzd fuzz` to supervise a multi-instance AFL++ campaign.
3. Run `fuzzd cover` to replay the shared corpus with a prebuilt LLVM coverage
   binary and generate a report.

## Quick Start

The `tests/binary_only` directory is a small local example campaign.

Build the example binaries:

```sh
make -C tests/binary_only
```

This produces:

```text
tests/binary_only/target_normal      # normal AFL++ binary
tests/binary_only/target_cmplog      # AFL++ CmpLog binary
tests/binary_only/target_asan_ubsan  # ASAN+UBSAN sanitizer binary
tests/binary_only/target_laf         # laf-intel binary
tests/binary_only/target_cfisan      # CFISAN binary
tests/binary_only/target_coverage    # LLVM coverage replay binary
```

Launch a campaign:

```sh
cargo run -- fuzz \
  --binary tests/binary_only/target_normal \
  --cmplog-binary tests/binary_only/target_cmplog \
  --sanitizer-binary tests/binary_only/target_asan_ubsan \
  --laf-binary tests/binary_only/target_laf \
  --cfisan-binary tests/binary_only/target_cfisan \
  -j 8 \
  -m none
```

`fuzzd` opens a live status screen for the running campaign. Stop the campaign
with `Ctrl-C`; `fuzzd` will stop children and perform a final
corpus/crash/timeout sync.

Generate coverage from the synchronized corpus:

```sh
LLVM_PROFDATA=llvm-profdata-20 LLVM_COV=llvm-cov-20 \
cargo run -- cover \
  --coverage-binary tests/binary_only/target_coverage \
  target_normal
```

If your LLVM tools are available as unversioned `llvm-profdata` and `llvm-cov`,
the environment variables are not needed. You can also pass
`--llvm-profdata <PATH>` and `--llvm-cov <PATH>` explicitly.

## Output Layout

By default, campaigns write to `./output/<target_name>/`, where
`<target_name>` is the file stem of `--binary`.

```text
output/target_normal/
  corpus/             # shared hash-named corpus
  queue/              # reserved shared queue directory
  logs/
    afl.log           # main AFL++ instance log
    afl_1.log         # first CmpLog worker log, when present
    coverage.log      # coverage replay log
  afl/
    mainaflfuzzer/
    cmplog00/
    san01/
    laf01/
    cfisan01/
    sec00/
  crashes/<timestamp>/
  timeouts/<timestamp>/
  coverage/
  coverage-profraw/
```

## Useful Commands

Print the AFL++ launch plan without spawning anything:

```sh
cargo run -- fuzz \
  --binary tests/binary_only/target_normal \
  --cmplog-binary tests/binary_only/target_cmplog \
  --sanitizer-binary tests/binary_only/target_asan_ubsan \
  --laf-binary tests/binary_only/target_laf \
  --cfisan-binary tests/binary_only/target_cfisan \
  -j 8 \
  -m none \
  --debug-plan
```

Generate a text coverage report instead of HTML:

```sh
LLVM_PROFDATA=llvm-profdata-20 LLVM_COV=llvm-cov-20 \
cargo run -- cover \
  --coverage-binary tests/binary_only/target_coverage \
  -t text \
  target_normal
```

## Limitations (for now)

- AFL++ only.
- Prebuilt C/C++ binaries only.
- No target building.
- No `@@` file-input replacement or target argument passthrough yet.
- No minimization.
- No crash triage.
- No Honggfuzz support.
