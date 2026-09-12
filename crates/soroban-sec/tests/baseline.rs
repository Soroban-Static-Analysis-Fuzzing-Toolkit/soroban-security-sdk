//! Baseline workflow: record the current findings once, then fail only on new ones.

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../soroban-security-sdk/tests/fixtures")
}

fn scratch(name: &str) -> PathBuf {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_file(&path);
    path
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_soroban-sec"))
        .args(args)
        .output()
        .expect("run soroban-sec")
}

#[test]
fn baseline_silences_recorded_findings() {
    let fixtures = fixtures_dir();
    let fixtures = fixtures.to_str().expect("fixtures path is UTF-8");
    let baseline = scratch("soroban-sec-baseline.txt");
    let baseline_arg = baseline.to_str().expect("path is UTF-8");

    // Without a baseline the vulnerable corpus trips a high-severity threshold.
    let unfiltered = run(&[fixtures, "--fail-on", "high", "--output", "/dev/null"]);
    assert_eq!(
        unfiltered.status.code(),
        Some(1),
        "the vulnerable corpus should fail `--fail-on high`"
    );

    // Recording the baseline always succeeds and writes a readable file.
    let written = run(&[
        fixtures,
        "--write-baseline",
        baseline_arg,
        "--output",
        "/dev/null",
    ]);
    assert!(
        written.status.success(),
        "writing a baseline should succeed"
    );
    let contents = std::fs::read_to_string(&baseline).expect("baseline file exists");
    let entries: Vec<&str> = contents
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    assert!(!entries.is_empty(), "baseline should record fingerprints");

    // Re-running with the baseline reports nothing and passes the threshold.
    let filtered = run(&[
        fixtures,
        "--baseline",
        baseline_arg,
        "--fail-on",
        "high",
        "--output",
        "/dev/null",
    ]);
    assert!(
        filtered.status.success(),
        "a fully baselined run should pass: {}",
        String::from_utf8_lossy(&filtered.stderr)
    );

    let report = run(&[fixtures, "--baseline", baseline_arg]);
    assert!(
        String::from_utf8_lossy(&report.stdout).contains("no findings"),
        "stdout: {}",
        String::from_utf8_lossy(&report.stdout)
    );
}
