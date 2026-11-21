# ci-failure-triage

[![ci](https://github.com/santoshmyakala/ci-failure-triage/actions/workflows/ci.yml/badge.svg)](https://github.com/santoshmyakala/ci-failure-triage/actions/workflows/ci.yml)
![Rust](https://img.shields.io/badge/rust-stable-000000?logo=rust)
![Tests](https://img.shields.io/badge/tests-20%20passing-2ea44f)

A fast, single-binary CLI, written in Rust, that reads a CI job log and tells you **why it failed** and **whether a retry is worth it**.

On-call engineers spend a lot of time scrolling thousands of log lines to answer two questions:
- Is this my code, or the platform?
- Should I re-run it?

`ci-failure-triage` answers both, cites the evidence lines, and suggests the next step. It works with GitHub Actions, GitLab CI and Jenkins logs.

```console
$ gh run view 123456 --log-failed | ci-failure-triage
verdict: rate-limit (retryable: true, confidence: 100%)
  line      2  rate-limit.http-429   Error response from daemon: toomanyrequests: You have reached your pull rate limit…
next step: Rate-limited by a registry or API (Docker Hub, GitHub, npm). Authenticate, cache, or mirror; retry after the reset window.
$ echo $?
3
```

## What it classifies

The 35 default rules are in [`rules/default.toml`](rules/default.toml):

| Category | Examples | Retry? |
|---|---|---|
| `infrastructure` | disk full, connection reset, DNS, runner lost, registry 5xx, no Docker daemon | yes |
| `rate-limit` | Docker Hub `toomanyrequests`, GitHub secondary rate limit, HTTP 429 | yes |
| `flaky-test` | passed on retry, timing-dependent test timeouts | yes |
| `out-of-memory` | OOMKilled / exit 137, JVM `OutOfMemoryError`, Node heap | no |
| `timeout` | job exceeded its maximum execution time | no |
| `test-failure` | pytest, JUnit/Surefire, go test, Jest, cargo test, `terraform test` | no |
| `compile-error` | rustc, javac, Go, TypeScript, linters and formatters | no |
| `dependency` | Maven, npm/pnpm, pip, Cargo, Go modules | no |
| `security-gate` | Trivy HIGH/CRITICAL, gitleaks, Semgrep blocking, image signature / admission policy | no |
| `configuration` | missing token permission or IAM/RBAC role, missing secret | no |

### How the verdict is chosen

- **Root causes outweigh symptoms.** Each rule has a weight. A Maven build that runs out of heap and then reports 40 failing tests is classified as `out-of-memory`, not `test-failure`.
- **Repetition doesn't win.** Only the first 3 matches of a rule count, so 500 identical lines can't drown out the one line that matters.
- **Ties go to the earliest failure.** If two categories score the same, the one whose first match appeared earlier in the log wins.
- **Lines are normalised before matching.** The tool strips the `gh run view` job/step prefixes, timestamps, ANSI colours, GitLab section markers, `\r` progress bars and `##[error]` commands.

## Exit codes

You can use the tool as a gate in a pipeline:

| Code | Meaning |
|---|---|
| `0` | No failure signature found (or `--no-exit-code`) |
| `2` | Failure that needs a fix |
| `3` | Retryable failure: infrastructure, rate limit or flaky test |
| `1` | Tool error: unreadable file or invalid rule |

## Usage

```bash
ci-failure-triage job.log                          # human-readable
ci-failure-triage job.log --format json            # machine-readable report
ci-failure-triage job.log --format markdown        # PR comment / job summary
ci-failure-triage job.log --format github          # ::error / ::notice annotations
kubectl logs job/build | ci-failure-triage         # stdin
ci-failure-triage step1.log step2.log              # several files read as one log
ci-failure-triage job.log --rules team.toml        # add your own rules
ci-failure-triage job.log --rules team.toml --no-default-rules
```

### Your own rules

Teams can encode their own failure signatures. A rule's pattern is a [Rust regex](https://docs.rs/regex) matched against each normalised line. For example, a hardware-in-the-loop bench:

```toml
[[rule]]
id = "hil.flash-failed"
category = "hardware-in-the-loop"
pattern = 'ECU flash (failed|timeout)'
weight = 15
retryable = true
hint = "The test bench could not flash the ECU. Re-seat the bench and retry."
```

The tool validates rules at start-up: an invalid regex or a duplicate id fails with exit code 1 and names the rule.

## In GitHub Actions

### As an action

```yaml
- name: Triage the failure
  if: failure()
  id: triage
  uses: santoshmyakala/ci-failure-triage@v1
- if: failure() && steps.triage.outputs.retryable == 'true'
  run: echo "Platform failure (${{ steps.triage.outputs.category }}); safe to re-run."
```

The composite action:
- downloads the release binary for the runner and **verifies it against `SHA256SUMS`**;
- triages the current run's failed job logs, or a `log-file` you pass;
- writes the Markdown report to the job summary and adds annotations;
- exposes `category` and `retryable` as step outputs.

### Workflows in this repository

| Workflow | What it does |
|---|---|
| [`ci.yml`](.github/workflows/ci.yml) | `fmt`, `clippy -D warnings` and tests on Linux, macOS and Windows; `cargo deny` checks licences and RustSec advisories; gitleaks; dogfooding: every fixture is triaged into the job summary |
| [`release.yml`](.github/workflows/release.yml) | On a `v*` tag: static binaries for Linux (musl), macOS (Apple silicon) and Windows, `SHA256SUMS`, **signed SLSA build provenance**, GitHub release |
| [`triage-failed-runs.yml`](.github/workflows/triage-failed-runs.yml) | When `ci` fails on `main`, fetches the failed logs and publishes the verdict. The tool is built from `main`; logs are only treated as data |

All actions are pinned to commit SHAs, and the workflow token is read-only unless a job needs more.

To verify a downloaded release:

```bash
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify ci-failure-triage-*-x86_64-unknown-linux-musl.tar.gz --repo santoshmyakala/ci-failure-triage
```

## Performance

The tool streams the log: one pass, one `RegexSet` evaluation per line, and constant memory however large the log is.

Measured on a 4 vCPU Intel Xeon @ 2.10 GHz with a release build, best of 3 runs:

| Input | Time | Throughput |
|---|---|---|
| 500 MiB: the test fixtures repeated, 8.1 M lines. Nearly every line is a failure line, so this is a worst case | ~5.9 s | ~84 MiB/s, single-threaded |

Real CI logs are a few MB and mostly ordinary output, so triage takes milliseconds.

One tuning detail matters for custom rules too. Write word boundaries as `(?-u:\b)`, not `\b`: a Unicode `\b` makes the regex engine fall back to a slower matcher on every line with non-ASCII text. On this input that made the scan **6× slower** (37 s). A unit test keeps the default rules ASCII-only.

To reproduce:

```bash
cargo build --release
yes "$(cat tests/fixtures/*.log)" | head -c 500M > /tmp/big.log
time ./target/release/ci-failure-triage /tmp/big.log --no-exit-code > /dev/null
```

## Tests

```bash
cargo test
```

- **10 unit tests** cover:
  - rule validation: invalid regexes, duplicate ids, ASCII word boundaries;
  - normalisation: `gh` prefixes, timestamps, ANSI codes;
  - scoring: root cause beats symptom, one noisy rule cannot dominate, retryability, clean logs;
  - Markdown and annotation escaping.
- **10 end-to-end tests** run the binary against [realistic logs](tests/fixtures): a Trivy gate, Semgrep blocking findings, a `terraform test` failure, a Docker Hub rate limit, Maven OOM followed by test failures, a Go compile error, pytest, a lost GitLab runner (with ANSI and section markers), a full Jenkins disk and a clean run. They also cover stdin, every output format, custom rules, multiple files and the error paths.

## Licence

MIT
