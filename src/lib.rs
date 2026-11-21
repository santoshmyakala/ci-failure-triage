//! Classify CI job failures from their logs.
//!
//! The engine streams a log line by line, normalises CI-specific noise (ANSI colours, GitHub
//! timestamps and `gh run view` prefixes, GitLab section markers), matches each line against a set
//! of rules and scores categories. Root causes (out-of-memory, runner loss, rate limits) carry more
//! weight than the symptoms they produce (failing tests), so the verdict points at what to fix.

use std::collections::BTreeMap;
use std::io::BufRead;
use std::sync::LazyLock;

use anyhow::{Context, Result, bail};
use regex::{Regex, RegexSet};
use serde::{Deserialize, Serialize};

/// The default rule set, compiled into the binary.
pub const DEFAULT_RULES: &str = include_str!("../rules/default.toml");

/// Maximum matches of a single rule that count towards the score (one noisy line can't dominate).
const MAX_COUNTED_MATCHES_PER_RULE: usize = 3;
const MAX_EVIDENCE_CHARS: usize = 300;

#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub id: String,
    pub category: String,
    pub pattern: String,
    pub weight: u32,
    pub retryable: bool,
    pub hint: String,
}

#[derive(Debug, Deserialize)]
struct RuleFile {
    #[serde(default)]
    rule: Vec<Rule>,
}

/// Parse a TOML rule file.
pub fn parse_rules(toml_text: &str) -> Result<Vec<Rule>> {
    let file: RuleFile = toml::from_str(toml_text).context("invalid rule file")?;
    Ok(file.rule)
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Finding {
    pub rule: String,
    pub category: String,
    pub line: usize,
    pub text: String,
    pub hint: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Verdict {
    /// Most likely root-cause category, or "unclassified" when nothing matched.
    pub category: String,
    /// Whether re-running the job is a reasonable first response.
    pub retryable: bool,
    /// Share of the total score held by the winning category (0–1).
    pub confidence: f64,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub verdict: Verdict,
    pub scores: BTreeMap<String, u32>,
    pub findings: Vec<Finding>,
    pub lines_scanned: usize,
    pub bytes_scanned: usize,
}

pub struct Triage {
    rules: Vec<Rule>,
    set: RegexSet,
    max_evidence_per_rule: usize,
}

impl Triage {
    pub fn new(rules: Vec<Rule>, max_evidence_per_rule: usize) -> Result<Self> {
        if rules.is_empty() {
            bail!("no rules loaded");
        }
        let mut seen = std::collections::HashSet::new();
        for r in &rules {
            if !seen.insert(r.id.as_str()) {
                bail!("duplicate rule id: {}", r.id);
            }
        }
        // Compile each pattern on its own first, so an error names the offending rule.
        for r in &rules {
            Regex::new(&r.pattern).with_context(|| format!("rule {}: invalid pattern", r.id))?;
        }
        let set = RegexSet::new(rules.iter().map(|r| r.pattern.as_str()))?;
        Ok(Self {
            rules,
            set,
            max_evidence_per_rule,
        })
    }

    pub fn with_default_rules() -> Result<Self> {
        Self::new(parse_rules(DEFAULT_RULES)?, 3)
    }

    /// Scan a log stream. Lines are decoded lossily, so binary noise never aborts a triage.
    pub fn scan<R: BufRead>(&self, mut reader: R) -> Result<Report> {
        let mut buf = Vec::with_capacity(4096);
        let mut line_no = 0usize;
        let mut bytes = 0usize;
        let mut per_rule: Vec<usize> = vec![0; self.rules.len()];
        let mut findings = Vec::new();

        loop {
            buf.clear();
            let n = reader.read_until(b'\n', &mut buf)?;
            if n == 0 {
                break;
            }
            bytes += n;
            line_no += 1;
            let raw = String::from_utf8_lossy(&buf);
            let line = normalise(&raw);
            if line.is_empty() {
                continue;
            }
            for idx in self.set.matches(&line).iter() {
                per_rule[idx] += 1;
                if per_rule[idx] <= self.max_evidence_per_rule {
                    let rule = &self.rules[idx];
                    findings.push(Finding {
                        rule: rule.id.clone(),
                        category: rule.category.clone(),
                        line: line_no,
                        text: truncate(&line, MAX_EVIDENCE_CHARS),
                        hint: rule.hint.clone(),
                    });
                }
            }
        }

        let mut scores: BTreeMap<String, u32> = BTreeMap::new();
        let mut first_line: BTreeMap<String, usize> = BTreeMap::new();
        for (idx, count) in per_rule.iter().enumerate() {
            if *count == 0 {
                continue;
            }
            let rule = &self.rules[idx];
            let counted = (*count).min(MAX_COUNTED_MATCHES_PER_RULE) as u32;
            *scores.entry(rule.category.clone()).or_default() += rule.weight * counted;
        }
        for f in &findings {
            first_line.entry(f.category.clone()).or_insert(f.line);
        }

        let verdict = self.verdict(&scores, &first_line);
        Ok(Report {
            verdict,
            scores,
            findings,
            lines_scanned: line_no,
            bytes_scanned: bytes,
        })
    }

    fn verdict(
        &self,
        scores: &BTreeMap<String, u32>,
        first_line: &BTreeMap<String, usize>,
    ) -> Verdict {
        let total: u32 = scores.values().sum();
        // Highest score wins; on a tie, the category that appeared first in the log (closer to the
        // root cause) wins.
        let best = scores.iter().max_by(|(a_cat, a), (b_cat, b)| {
            a.cmp(b)
                .then_with(|| first_line.get(*b_cat).cmp(&first_line.get(*a_cat)))
        });
        match best {
            None => Verdict {
                category: "unclassified".into(),
                retryable: false,
                confidence: 0.0,
                summary: "No known failure signature found.".into(),
            },
            Some((category, score)) => {
                let retryable = self
                    .rules
                    .iter()
                    .any(|r| &r.category == category && r.retryable);
                Verdict {
                    category: category.clone(),
                    retryable,
                    confidence: (*score as f64 / total as f64 * 100.0).round() / 100.0,
                    summary: format!(
                        "Most likely cause: {category}{}",
                        if retryable {
                            " (retryable)"
                        } else {
                            " (needs a fix, not a retry)"
                        }
                    ),
                }
            }
        }
    }
}

static ANSI: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\x1b\[[0-9;?]*[A-Za-z]").unwrap());
static GITLAB_SECTION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"section_(start|end):\d+:[\w.\-]+(\[[^\]]*\])?").unwrap());
static ISO_TS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z ?").unwrap());
static GHA_COMMAND: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^##\[(error|warning|group|endgroup)\]").unwrap());

/// Remove CI decoration so rules match the message itself.
///
/// Handles `gh run view --log` lines (`job<TAB>step<TAB>timestamp message`), GitHub Actions
/// timestamps and `##[error]` commands, GitLab `section_start:` markers and ANSI colour codes.
pub fn normalise(raw: &str) -> String {
    let mut s = raw.trim_end_matches(['\n', '\r']);
    // gh run view --log: the message is after the second tab
    if s.matches('\t').count() >= 2 {
        let mut parts = s.splitn(3, '\t');
        let (_, _, rest) = (parts.next(), parts.next(), parts.next());
        if let Some(rest) = rest {
            s = rest;
        }
    }
    let s = ANSI.replace_all(s, "");
    let s = GITLAB_SECTION.replace_all(&s, "");
    let s = s.rsplit('\r').next().unwrap_or("").to_string(); // keep what a terminal would show
    let s = ISO_TS.replace(&s, "");
    let s = GHA_COMMAND.replace(&s, "");
    s.trim().to_string()
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max).collect();
        format!("{cut}…")
    }
}

/// Render a report as Markdown (for PR comments and `$GITHUB_STEP_SUMMARY`).
pub fn to_markdown(report: &Report) -> String {
    let v = &report.verdict;
    let mut out = String::new();
    out.push_str(&format!("### CI failure triage: `{}`\n\n", v.category));
    out.push_str(&format!(
        "{} · confidence {:.0}% · {} lines scanned\n\n",
        v.summary,
        v.confidence * 100.0,
        report.lines_scanned
    ));
    if report.findings.is_empty() {
        return out;
    }
    if let Some(top) = report.findings.iter().find(|f| f.category == v.category) {
        out.push_str(&format!("**Next step:** {}\n\n", top.hint));
    }
    out.push_str("| Line | Category | Rule | Evidence |\n|---:|---|---|---|\n");
    for f in &report.findings {
        let text = f.text.replace('|', "\\|").replace('`', "'");
        out.push_str(&format!(
            "| {} | {} | `{}` | `{}` |\n",
            f.line, f.category, f.rule, text
        ));
    }
    out
}

/// Render a report as GitHub Actions workflow commands (annotations on the run).
pub fn to_github_annotations(report: &Report) -> String {
    let v = &report.verdict;
    let level = if v.retryable { "warning" } else { "error" };
    let mut out = format!(
        "::{level} title=CI failure triage::{}\n",
        escape_annotation(&v.summary)
    );
    for f in report.findings.iter().filter(|f| f.category == v.category) {
        out.push_str(&format!(
            "::notice title={}::line {}: {} — {}\n",
            f.rule,
            f.line,
            escape_annotation(&f.text),
            escape_annotation(&f.hint)
        ));
    }
    out
}

fn escape_annotation(s: &str) -> String {
    s.replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

/// Render a short human-readable report.
pub fn to_text(report: &Report) -> String {
    let v = &report.verdict;
    let mut out = format!(
        "verdict: {} (retryable: {}, confidence: {:.0}%)\n",
        v.category,
        v.retryable,
        v.confidence * 100.0
    );
    for f in &report.findings {
        out.push_str(&format!(
            "  line {:>6}  {:<36} {}\n",
            f.line, f.rule, f.text
        ));
    }
    if let Some(top) = report.findings.iter().find(|f| f.category == v.category) {
        out.push_str(&format!("next step: {}\n", top.hint));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn triage(log: &str) -> Report {
        Triage::with_default_rules()
            .unwrap()
            .scan(log.as_bytes())
            .unwrap()
    }

    #[test]
    fn default_rules_compile_and_ids_are_unique() {
        let rules = parse_rules(DEFAULT_RULES).unwrap();
        assert!(rules.len() >= 30);
        Triage::new(rules, 3).unwrap();
    }

    /// A Unicode `\b` forces the regex crate off its lazy DFA on any line with non-ASCII text,
    /// which measured ~6x slower on a 100 MiB log. Default rules must use `(?-u:\b)`.
    #[test]
    fn default_rules_use_ascii_word_boundaries() {
        for rule in parse_rules(DEFAULT_RULES).unwrap() {
            let unicode_b = rule.pattern.replace("(?-u:\\b)", "");
            assert!(!unicode_b.contains("\\b"), "{}: use (?-u:\\b)", rule.id);
        }
    }

    #[test]
    fn strips_github_timestamps_ansi_and_gh_cli_prefixes() {
        assert_eq!(
            normalise("2026-11-20T23:13:57.4807801Z \x1b[31merror\x1b[0m: boom\n"),
            "error: boom"
        );
        assert_eq!(
            normalise("build\tRun tests\t2026-11-20T23:13:57.1Z ##[error]Process completed"),
            "Process completed"
        );
        assert_eq!(
            normalise("section_start:1700000000:build_script\r\x1b[0Kcompiling"),
            "compiling"
        );
        assert_eq!(normalise("progress 10%\rprogress 100%"), "progress 100%");
    }

    #[test]
    fn root_cause_outweighs_symptoms() {
        // OOM kills the test runner, which then reports failing tests: the verdict is the OOM.
        let log = "running 120 tests\n\
                   java.lang.OutOfMemoryError: Java heap space\n\
                   Tests run: 120, Failures: 7, Errors: 3\n\
                   [ERROR] There are test failures.\n";
        let r = triage(log);
        assert_eq!(r.verdict.category, "out-of-memory");
        assert!(!r.verdict.retryable);
    }

    #[test]
    fn rate_limit_is_retryable() {
        let r = triage(
            "Error response from daemon: toomanyrequests: You have reached your pull rate limit.\n",
        );
        assert_eq!(r.verdict.category, "rate-limit");
        assert!(r.verdict.retryable);
    }

    #[test]
    fn one_noisy_rule_cannot_dominate() {
        let mut log = String::new();
        for _ in 0..1000 {
            log.push_str("--- FAIL: TestSomething (0.01s)\n");
        }
        log.push_str("no space left on device\n");
        let r = triage(&log);
        // 3 counted go-test matches × 6 = 18 vs disk-full 12: disk-full doesn't win here, but the
        // test-failure score is capped instead of growing to 6000.
        assert_eq!(r.scores["test-failure"], 18);
        assert_eq!(
            r.findings
                .iter()
                .filter(|f| f.rule == "test-failure.go")
                .count(),
            3
        );
    }

    #[test]
    fn clean_log_is_unclassified() {
        let r = triage("Compiling foo v0.1.0\nFinished `release` profile\n");
        assert_eq!(r.verdict.category, "unclassified");
        assert!(r.findings.is_empty());
    }

    #[test]
    fn invalid_patterns_and_duplicate_ids_are_rejected() {
        let bad = parse_rules(
            "[[rule]]\nid='a'\ncategory='x'\npattern='('\nweight=1\nretryable=false\nhint='h'\n",
        )
        .unwrap();
        assert!(Triage::new(bad, 3).is_err());
        let dup = parse_rules(
            "[[rule]]\nid='a'\ncategory='x'\npattern='a'\nweight=1\nretryable=false\nhint='h'\n\
             [[rule]]\nid='a'\ncategory='x'\npattern='b'\nweight=1\nretryable=false\nhint='h'\n",
        )
        .unwrap();
        assert!(Triage::new(dup, 3).is_err());
    }

    #[test]
    fn markdown_escapes_table_pipes() {
        let r = triage("error[E0308]: mismatched types | expected `u32`\n");
        let md = to_markdown(&r);
        assert!(md.contains("\\|"));
        assert!(md.contains("compile-error"));
    }

    #[test]
    fn annotations_escape_newlines_and_percent() {
        assert_eq!(escape_annotation("50%\nnext"), "50%25%0Anext");
    }
}
