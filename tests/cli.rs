//! End-to-end tests of the binary against realistic CI logs.

use assert_cmd::Command;
use predicates::prelude::*;

fn bin() -> Command {
    Command::cargo_bin("ci-failure-triage").unwrap()
}

fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

/// (fixture, expected category, expected exit code)
const CASES: &[(&str, &str, i32)] = &[
    ("github-trivy-gate.log", "security-gate", 2),
    ("github-semgrep-blocking.log", "security-gate", 2),
    ("terraform-test-failure.log", "test-failure", 2),
    ("docker-pull-rate-limit.log", "rate-limit", 3),
    ("maven-oom-then-test-failures.log", "out-of-memory", 2),
    ("go-compile-error.log", "compile-error", 2),
    ("pytest-failure.log", "test-failure", 2),
    ("gitlab-runner-lost.log", "infrastructure", 3),
    ("jenkins-disk-full.log", "infrastructure", 3),
    ("clean-success.log", "unclassified", 0),
];

#[test]
fn classifies_real_world_logs() {
    for (file, category, code) in CASES {
        let out = bin()
            .args([&fixture(file), "--format", "json"])
            .output()
            .unwrap();
        let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
            panic!(
                "{file}: invalid JSON ({e}): {}",
                String::from_utf8_lossy(&out.stdout)
            )
        });
        assert_eq!(
            report["verdict"]["category"], *category,
            "{file}: wrong category\n{report:#}"
        );
        assert_eq!(out.status.code(), Some(*code), "{file}: wrong exit code");
    }
}

#[test]
fn evidence_points_at_the_right_line() {
    let out = bin()
        .args([&fixture("jenkins-disk-full.log"), "--format", "json"])
        .output()
        .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let f = &report["findings"][0];
    assert_eq!(f["rule"], "infrastructure.disk-full");
    assert_eq!(f["line"], 3);
    assert!(
        f["text"]
            .as_str()
            .unwrap()
            .contains("no space left on device")
    );
}

#[test]
fn reads_stdin() {
    bin()
        .args(["--format", "text"])
        .write_stdin(
            "FATAL ERROR: Reached heap limit Allocation failed - JavaScript heap out of memory\n",
        )
        .assert()
        .code(2)
        .stdout(predicate::str::contains("verdict: out-of-memory"));
}

#[test]
fn markdown_is_ready_for_a_pr_comment() {
    bin()
        .args([
            &fixture("docker-pull-rate-limit.log"),
            "--format",
            "markdown",
        ])
        .assert()
        .code(3)
        .stdout(predicate::str::contains(
            "### CI failure triage: `rate-limit`",
        ))
        .stdout(predicate::str::contains("**Next step:**"))
        .stdout(predicate::str::contains(
            "| Line | Category | Rule | Evidence |",
        ));
}

#[test]
fn github_format_emits_annotations() {
    bin()
        .args([&fixture("github-trivy-gate.log"), "--format", "github"])
        .assert()
        .stdout(predicate::str::starts_with(
            "::error title=CI failure triage::",
        ))
        .stdout(predicate::str::contains(
            "::notice title=security-gate.trivy::",
        ));
}

#[test]
fn custom_rules_extend_or_replace_the_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let rules = dir.path().join("team.toml");
    std::fs::write(
        &rules,
        r#"
[[rule]]
id = "hil.flash-failed"
category = "hardware-in-the-loop"
pattern = 'ECU flash (failed|timeout)'
weight = 15
retryable = true
hint = "The test bench could not flash the ECU. Re-seat the bench and retry."
"#,
    )
    .unwrap();
    let log = dir.path().join("job.log");
    std::fs::write(
        &log,
        "flashing image.bin\nECU flash timeout after 120s\n--- FAIL: TestBoot\n",
    )
    .unwrap();

    bin()
        .args([
            log.to_str().unwrap(),
            "--rules",
            rules.to_str().unwrap(),
            "--format",
            "text",
        ])
        .assert()
        .code(3)
        .stdout(predicate::str::contains("verdict: hardware-in-the-loop"));

    bin()
        .args([
            log.to_str().unwrap(),
            "--rules",
            rules.to_str().unwrap(),
            "--no-default-rules",
        ])
        .assert()
        .code(3)
        .stdout(predicate::str::contains("test-failure").not());
}

#[test]
fn several_files_are_one_log() {
    bin()
        .args([
            &fixture("clean-success.log"),
            &fixture("jenkins-disk-full.log"),
            "--format",
            "json",
        ])
        .assert()
        .code(3)
        .stdout(predicate::str::contains("\"lines_scanned\": 8"));
}

#[test]
fn report_only_mode_always_exits_zero() {
    bin()
        .args([
            &fixture("maven-oom-then-test-failures.log"),
            "--no-exit-code",
        ])
        .assert()
        .code(0);
}

#[test]
fn bad_rule_file_is_a_tool_error() {
    let dir = tempfile::tempdir().unwrap();
    let rules = dir.path().join("bad.toml");
    std::fs::write(
        &rules,
        "[[rule]]\nid='x'\ncategory='y'\npattern='('\nweight=1\nretryable=false\nhint='h'\n",
    )
    .unwrap();
    bin()
        .args([
            &fixture("clean-success.log"),
            "--rules",
            rules.to_str().unwrap(),
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("rule x: invalid pattern"));
}

#[test]
fn missing_file_is_a_tool_error() {
    bin()
        .arg("/does/not/exist.log")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("opening"));
}
