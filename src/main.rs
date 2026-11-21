use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use ci_failure_triage::{
    DEFAULT_RULES, Triage, parse_rules, to_github_annotations, to_markdown, to_text,
};
use clap::{Parser, ValueEnum};

/// Classify why a CI job failed, from its log.
///
/// Exit codes: 0 = no failure signature found, 2 = failure that needs a fix,
/// 3 = retryable failure (infrastructure, rate limit, flaky test), 1 = tool error.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    /// Log files to scan ("-" or none = stdin). Multiple files are treated as one log.
    files: Vec<PathBuf>,

    /// Output format.
    #[arg(short, long, value_enum, default_value_t = Format::Text)]
    format: Format,

    /// Extra rule files (TOML), added to the defaults.
    #[arg(short, long = "rules")]
    rules: Vec<PathBuf>,

    /// Use only the rules given with --rules.
    #[arg(long)]
    no_default_rules: bool,

    /// Evidence lines kept per rule.
    #[arg(long, default_value_t = 3)]
    max_evidence: usize,

    /// Always exit 0 (report only).
    #[arg(long)]
    no_exit_code: bool,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum Format {
    Text,
    Json,
    Markdown,
    Github,
}

fn run(cli: Cli) -> Result<u8> {
    let mut rules = if cli.no_default_rules {
        Vec::new()
    } else {
        parse_rules(DEFAULT_RULES)?
    };
    for path in &cli.rules {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        rules.extend(parse_rules(&text).with_context(|| format!("in {}", path.display()))?);
    }
    let triage = Triage::new(rules, cli.max_evidence)?;

    let report = if cli.files.is_empty() || cli.files.iter().any(|f| f.as_os_str() == "-") {
        triage.scan(BufReader::new(io::stdin().lock()))?
    } else {
        let mut chain: Box<dyn Read> = Box::new(io::empty());
        for path in &cli.files {
            let f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
            chain = Box::new(chain.chain(f));
        }
        triage.scan(BufReader::with_capacity(1 << 16, chain))?
    };

    let rendered = match cli.format {
        Format::Text => to_text(&report),
        Format::Json => serde_json::to_string_pretty(&report)? + "\n",
        Format::Markdown => to_markdown(&report),
        Format::Github => to_github_annotations(&report),
    };
    io::stdout().lock().write_all(rendered.as_bytes())?;

    Ok(
        match (
            cli.no_exit_code,
            report.verdict.category.as_str(),
            report.verdict.retryable,
        ) {
            (true, _, _) | (_, "unclassified", _) => 0,
            (_, _, true) => 3,
            _ => 2,
        },
    )
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            eprintln!("ci-failure-triage: {err:#}");
            ExitCode::from(1)
        }
    }
}
