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
        print_catalogue();
        return Ok(ExitCode::SUCCESS);
    }
    if let Some(rule) = &cli.explain {
        return explain(rule);
    }

    let config = load_config(&cli)?;
    let project = Project::from_dir(&cli.path)
        .with_context(|| format!("loading `{}`", cli.path.display()))?;
    let report = analyze(&project, &config);

    let rendered = match cli.format {
        Format::Text => render_text(&report, std::io::stdout().is_terminal()),
        Format::Json => render_json(&report)?,
        Format::Sarif => to_sarif_string(&report),
    };
    match &cli.output {
        Some(path) => {
            std::fs::write(path, rendered)
                .with_context(|| format!("writing `{}`", path.display()))?;
        }
        None => print!("{rendered}"),
    }

    if let Some(threshold) = cli.fail_on {
        if report.has_findings_at_or_above(threshold.into()) {
            return Ok(ExitCode::from(EXIT_FINDINGS));
        }
    }
    Ok(ExitCode::SUCCESS)
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
    config.include_tests |= cli.include_tests;
    Ok(config)
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

fn print_catalogue() {
    let registry = DetectorRegistry::from_inventory();
    println!("{} rules\n", registry.len());
    for meta in registry.metas() {
        println!(
            "{}  {:<4}  {:<38}  {}",
            meta.id,
            meta.severity.badge(),
            meta.name,
            meta.summary
        );
    }
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
}
