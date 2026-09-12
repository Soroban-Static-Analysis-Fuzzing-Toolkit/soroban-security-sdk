//! `soroban-sec`: command-line front end for the Soroban security analyser.
//!
//! ```text
//! soroban-sec [PATH] [--wasm FILE] [--format text|json|sarif]
//!             [--fail-on SEVERITY] [--list-rules] [--explain RULE]
//! ```

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, ValueEnum};
use soroban_security_sdk::prelude::*;

/// Exit status used when `--fail-on` is tripped.
const EXIT_FINDINGS: u8 = 1;
/// Exit status used for usage and I/O failures.
const EXIT_ERROR: u8 = 2;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Format {
    /// Human-readable summary and findings.
    Text,
    /// Machine-readable findings, diagnostics and budget.
    Json,
    /// SARIF 2.1.0 for code-scanning dashboards.
    Sarif,
    /// Markdown rule catalogue. Only valid together with `--list-rules`.
    Markdown,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum FailOn {
    /// Fail on any finding.
    Info,
    /// Fail on low or above.
    Low,
    /// Fail on medium or above.
    Medium,
    /// Fail on high or above.
    High,
    /// Fail only on critical findings.
    Critical,
}

impl From<FailOn> for Severity {
    fn from(value: FailOn) -> Self {
        match value {
            FailOn::Info => Severity::Info,
            FailOn::Low => Severity::Low,
            FailOn::Medium => Severity::Medium,
            FailOn::High => Severity::High,
            FailOn::Critical => Severity::Critical,
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "soroban-sec",
    version,
    about = "Static analysis for Soroban smart contracts",
    long_about = "Detects Soroban-specific vulnerability patterns (missing authorization, \
                  storage-tier confusion, unchecked arithmetic, resource-budget overruns, \
                  TTL and upgrade mistakes) in a contract's Rust source and compiled wasm."
)]
struct Cli {
    /// Contract crate or single source file to analyse.
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Compiled contract to analyse alongside the source.
    #[arg(long, value_name = "WASM")]
    wasm: Option<PathBuf>,

    /// Configuration file. Defaults to `.soroban-sec.toml` next to the source.
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Output format.
    #[arg(long, value_enum, default_value = "text")]
    format: Format,

    /// Write the report to a file instead of stdout.
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Accepted findings, by fingerprint. One per line; `#` starts a comment.
    #[arg(long, value_name = "FILE")]
    baseline: Option<PathBuf>,

    /// Write the fingerprints of the current findings to `FILE` and exit successfully.
    #[arg(long, value_name = "FILE")]
    write_baseline: Option<PathBuf>,

    /// Exit non-zero when a finding at or above this severity exists.
    #[arg(long, value_enum)]
    fail_on: Option<FailOn>,

    /// Analyse `#[cfg(test)]` code too.
    #[arg(long)]
    include_tests: bool,

    /// Print the rule catalogue and exit.
    #[arg(long)]
    list_rules: bool,

    /// Print details for a single rule and exit.
    #[arg(long, value_name = "RULE")]
    explain: Option<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(EXIT_ERROR)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    if cli.list_rules {
        if matches!(cli.format, Format::Sarif) {
            return Err(anyhow!(
                "`--format sarif` cannot render the rule catalogue; use `text`, `json` or `markdown`"
            ));
        }
        let rendered = render_catalogue(cli.format);
        write_output(&cli, &rendered)?;
        return Ok(ExitCode::SUCCESS);
    }
    if let Some(rule) = &cli.explain {
        return explain(rule);
    }
    if matches!(cli.format, Format::Markdown) {
        return Err(anyhow!(
            "`--format markdown` only applies to `--list-rules`"
        ));
    }

    let config = load_config(&cli)?;
    let project = Project::from_dir(&cli.path)
        .with_context(|| format!("loading `{}`", cli.path.display()))?;
    let report = analyze(&project, &config);

    let rendered = match cli.format {
        Format::Text => render_text(&report, std::io::stdout().is_terminal()),
        Format::Json => render_json(&report)?,
        Format::Sarif => to_sarif_string(&report),
        Format::Markdown => unreachable!("rejected before analysis"),
    };
    write_output(&cli, &rendered)?;

    // Writing a baseline always succeeds: the point is to record the current state
    // so that later runs can fail on *new* findings only.
    if let Some(path) = &cli.write_baseline {
        let count = write_baseline(path, &report)?;
        eprintln!("wrote {count} fingerprint(s) to `{}`", path.display());
        return Ok(ExitCode::SUCCESS);
    }

    if let Some(threshold) = cli.fail_on {
        if report.has_findings_at_or_above(threshold.into()) {
            return Ok(ExitCode::from(EXIT_FINDINGS));
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Write rendered output to `--output` or stdout.
fn write_output(cli: &Cli, rendered: &str) -> Result<()> {
    match &cli.output {
        Some(path) => std::fs::write(path, rendered)
            .with_context(|| format!("writing `{}`", path.display()))?,
        None => print!("{rendered}"),
    }
    Ok(())
}

/// Load configuration from `--config`, a sibling `.soroban-sec.toml`, or defaults.
fn load_config(cli: &Cli) -> Result<AnalysisConfig> {
    let mut config = match &cli.config {
        Some(path) => AnalysisConfig::load(path)
            .with_context(|| format!("reading config `{}`", path.display()))?,
        None => match discover_config(&cli.path) {
            Some(path) => AnalysisConfig::load(&path)
                .with_context(|| format!("reading config `{}`", path.display()))?,
            None => AnalysisConfig::default(),
        },
    };
    config = config.with_env_overrides();
    if let Some(wasm) = &cli.wasm {
        config.wasm_path = Some(wasm.clone());
    }
    if let Some(baseline) = &cli.baseline {
        config.baseline.extend(read_baseline(baseline)?);
    }
    config.include_tests |= cli.include_tests;
    Ok(config)
}

/// Read accepted fingerprints from a baseline file.
///
/// The format is deliberately plain: one fingerprint per line, blank lines and
/// `#` comments ignored, so it merges cleanly in review.
fn read_baseline(path: &Path) -> Result<Vec<String>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading baseline `{}`", path.display()))?;
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect())
}

/// Write the sorted, de-duplicated fingerprints of `report` to `path`.
fn write_baseline(path: &Path, report: &AnalysisReport) -> Result<usize> {
    let mut fingerprints: Vec<String> = report.findings.iter().map(Finding::fingerprint).collect();
    fingerprints.sort();
    fingerprints.dedup();

    let mut contents = String::from(
        "# soroban-sec baseline: findings listed here are accepted and not reported.\n\
         # Regenerate with `soroban-sec --write-baseline .soroban-sec.baseline`.\n",
    );
    for fingerprint in &fingerprints {
        contents.push_str(fingerprint);
        contents.push('\n');
    }
    std::fs::write(path, contents)
        .with_context(|| format!("writing baseline `{}`", path.display()))?;
    Ok(fingerprints.len())
}

/// Find a `.soroban-sec.toml` next to the analysed path.
fn discover_config(path: &Path) -> Option<PathBuf> {
    let directory = if path.is_dir() {
        path
    } else {
        path.parent().unwrap_or(Path::new("."))
    };
    let candidate = directory.join(".soroban-sec.toml");
    candidate.is_file().then_some(candidate)
}

/// Render the rule catalogue in the requested format.
fn render_catalogue(format: Format) -> String {
    let registry = DetectorRegistry::from_inventory();
    match format {
        Format::Json => catalogue_json(&registry),
        Format::Markdown => catalogue_markdown(&registry),
        _ => catalogue_text(&registry),
    }
}

fn catalogue_text(registry: &DetectorRegistry) -> String {
    let mut out = format!("{} rules\n\n", registry.len());
    for meta in registry.metas() {
        out.push_str(&format!(
            "{}  {:<4}  {:<38}  {}\n",
            meta.id,
            meta.severity.badge(),
            meta.name,
            meta.summary
        ));
    }
    out
}

/// The catalogue as JSON. Field names come from `DetectorMeta`'s serialisation and
/// are asserted by `tests/catalogue.rs`, so they are a deliberate interface.
fn catalogue_json(registry: &DetectorRegistry) -> String {
    let rules = registry.metas();
    serde_json::to_string_pretty(&rules).expect("detector metadata always serialises to JSON")
}

/// The catalogue as Markdown, committed as `docs/rules.md` and kept in sync by
/// `tests/catalogue.rs`.
fn catalogue_markdown(registry: &DetectorRegistry) -> String {
    let mut out = String::new();
    out.push_str("# Rule catalogue\n\n");
    out.push_str(&format!(
        "soroban-sec ships {} rules. This file is generated from detector metadata.\n\
         Regenerate it with `cargo run -p soroban-sec -- --list-rules --format markdown > docs/rules.md`.\n\n",
        registry.len()
    ));
    out.push_str("| id | rule | severity | confidence | category | default |\n");
    out.push_str("|----|------|----------|------------|----------|---------|\n");
    for meta in registry.metas() {
        out.push_str(&format!(
            "| `{}` | `{}` | {} | {} | {} | {} |\n",
            meta.id,
            meta.name,
            meta.severity.as_str(),
            meta.confidence.as_str(),
            meta.category.as_str(),
            if meta.default_enabled { "on" } else { "off" },
        ));
    }
    for meta in registry.metas() {
        out.push_str(&format!("\n## {} - `{}`\n\n", meta.id, meta.name));
        out.push_str(&format!(
            "- **Severity:** {}\n- **Confidence:** {}\n- **Category:** {}\n",
            meta.severity.as_str(),
            meta.confidence.as_str(),
            meta.category.as_str(),
        ));
        if meta.requires_wasm {
            out.push_str("- **Requires:** a compiled `.wasm` module\n");
        }
        out.push_str(&format!("\n{}\n", meta.summary));
        if !meta.description.is_empty() {
            out.push_str(&format!("\n{}\n", meta.description));
        }
        if !meta.tags.is_empty() {
            let tags: Vec<String> = meta.tags.iter().map(|tag| format!("`{tag}`")).collect();
            out.push_str(&format!("\n**Tags:** {}\n", tags.join(", ")));
        }
        if !meta.references.is_empty() {
            out.push_str("\n**References:**\n");
            for reference in meta.references {
                out.push_str(&format!("- [{}]({})\n", reference.label, reference.url));
            }
        }
    }
    out
}

fn explain(rule: &str) -> Result<ExitCode> {
    let id = RuleId::parse(rule).map_err(|_| anyhow!("`{rule}` is not a valid rule id"))?;
    let registry = DetectorRegistry::from_inventory();
    let Some(meta) = registry.meta(&id) else {
        return Err(anyhow!("unknown rule `{rule}`"));
    };
    println!("{}  {}", meta.id, meta.name);
    println!("severity:    {}", meta.severity);
    println!("confidence:  {}", meta.confidence);
    println!("category:    {}", meta.category);
    println!(
        "default:     {}",
        if meta.default_enabled {
            "enabled"
        } else {
            "disabled"
        }
    );
    if meta.requires_wasm {
        println!("requires:    a compiled .wasm module");
    }
    println!("\n{}\n", meta.summary);
    if !meta.description.is_empty() {
        println!("{}\n", meta.description);
    }
    if !meta.tags.is_empty() {
        println!("tags: {}", meta.tags.join(", "));
    }
    for reference in meta.references {
        println!("ref:  {} <{}>", reference.label, reference.url);
    }
    Ok(ExitCode::SUCCESS)
}

/// Render a human-readable report. `color` is only true on an interactive terminal.
fn render_text(report: &AnalysisReport, color: bool) -> String {
    let mut out = String::new();
    out.push_str(&format!("soroban-sec: {}\n", report.summary()));
    if report.findings.is_empty() {
        out.push_str("\nNo findings.\n");
    }

    for finding in &report.findings {
        let badge = finding.severity.badge();
        let badge = if color {
            format!("{}{badge}\u{1b}[0m", finding.severity.ansi_color())
        } else {
            badge.to_string()
        };
        let function = finding
            .primary_location()
            .and_then(|location| location.function.as_deref())
            .map(|name| format!(" in `{name}`"))
            .unwrap_or_default();
        out.push_str(&format!(
            "\n{}  {}  {}{}\n",
            badge,
            finding.rule,
            finding.headline_location(),
            function
        ));
        out.push_str(&format!(
            "    {} ({}: {}, confidence {})\n",
            finding.message, finding.rule_name, finding.category, finding.confidence
        ));
        for note in &finding.notes {
            out.push_str(&format!("    note: {note}\n"));
        }
        if let Some(help) = &finding.help {
            out.push_str(&format!("    help: {help}\n"));
        }
    }

    if !report.suppressed.is_empty() {
        out.push_str(&format!(
            "\n{} finding(s) suppressed inline.\n",
            report.suppressed.len()
        ));
    }
    if !report.diagnostics.is_empty() {
        out.push_str("\ndiagnostics:\n");
        for diagnostic in &report.diagnostics {
            out.push_str(&format!("  {}: {diagnostic}\n", diagnostic.kind.as_str()));
        }
    }
    out
}

fn render_json(report: &AnalysisReport) -> Result<String> {
    let value = serde_json::json!({
        "summary": report.summary(),
        "findings": serde_json::to_value(&report.findings)?,
        "suppressed": serde_json::to_value(&report.suppressed)?,
        "diagnostics": serde_json::to_value(&report.diagnostics)?,
        "budget": serde_json::to_value(&report.budget)?,
        "rules": serde_json::to_value(&report.rules)?,
    });
    Ok(serde_json::to_string_pretty(&value)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_definition_is_valid() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    #[test]
    fn fail_on_maps_to_severity() {
        assert_eq!(Severity::from(FailOn::High), Severity::High);
        assert_eq!(Severity::from(FailOn::Critical), Severity::Critical);
    }

    #[test]
    fn discover_config_handles_files_and_directories() {
        assert!(discover_config(Path::new("/nonexistent/path")).is_none());
    }

    #[test]
    fn read_baseline_ignores_comments_and_blanks() {
        let path = std::env::temp_dir().join("soroban-sec-read-baseline-test.txt");
        std::fs::write(&path, "# a comment\n\nabc123\n  def456  \n").unwrap();
        let fingerprints = read_baseline(&path).unwrap();
        assert_eq!(
            fingerprints,
            vec!["abc123".to_string(), "def456".to_string()]
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn catalogue_is_rendered_in_every_format() {
        let registry = DetectorRegistry::from_inventory();
        assert!(catalogue_text(&registry).contains("SSDK001"));
        assert!(catalogue_json(&registry).contains("\"id\": \"SSDK001\""));
        assert!(catalogue_markdown(&registry).contains("## SSDK001"));
    }
}
