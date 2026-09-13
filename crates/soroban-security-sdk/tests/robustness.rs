//! Robustness fuzzing for the source parser and the contract model.
//!
//! A security analyser runs on code it does not control, and often on code that
//! does not even compile. A panic on malformed input is therefore a denial of
//! service against the tool's users, not just an awkward error. These tests feed
//! the parser and the model builder generated and mutated input and assert that
//! they either reject it or analyse it — never unwrap, index out of bounds or
//! recurse without bound.
//!
//! Everything is deterministic: the PRNG is seeded, so a failure always
//! reproduces from the same input.
#![cfg(feature = "detectors")]

use soroban_security_sdk::prelude::*;

/// Tiny deterministic xorshift64* PRNG, so the corpus is reproducible without a
/// dependency.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        // Avoid the all-zero state, which xorshift cannot leave.
        Rng(seed | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next_u64() % bound as u64) as usize
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

/// Tokens chosen to steer generated code into every model-builder path:
/// contracts, storage tiers, arithmetic, loops, authorization and deliberately
/// malformed syntax.
const VOCABULARY: &[&str] = &[
    "fn",
    "pub",
    "impl",
    "struct",
    "enum",
    "Contract",
    "Token",
    "#[contractimpl]",
    "#[contracttype]",
    "#[cfg(test)]",
    "{",
    "}",
    "(",
    ")",
    "[",
    "]",
    "<",
    ">",
    ";",
    ":",
    "::",
    "->",
    "let",
    "mut",
    "x",
    "amount",
    "i128",
    "u32",
    "=",
    "0",
    "1",
    "10",
    "..",
    "..=",
    "+",
    "-",
    "*",
    "as",
    "env",
    "storage()",
    "instance()",
    "persistent()",
    "temporary()",
    "set",
    "get",
    "has",
    "remove",
    "extend_ttl",
    "bump",
    "&K",
    "require_auth",
    "for",
    "while",
    "in",
    "loop",
    "if",
    "else",
    "match",
    "return",
    "unwrap",
    "expect",
    "checked_add",
    "wrapping_add",
    "ledger()",
    "timestamp()",
    "sequence()",
    "ed25519_verify",
    "__check_auth",
    "update_current_contract_wasm",
    "deploy",
    "\"",
    "'",
    "\\",
    "\u{0}",
    "é",
];

/// Sample of existing fixtures used as mutation seeds, so the fuzzer also
/// explores near-miss versions of realistic contracts.
const SEEDS: &[&str] = &[
    include_str!("fixtures/clean/token.rs"),
    include_str!("fixtures/clean/bounded_storage.rs"),
    include_str!("fixtures/vulnerable/insecure_vault.rs"),
    include_str!("fixtures/vulnerable/unbounded_growth.rs"),
];

/// Parse `text` and, when it parses, run the full catalogue and touch every
/// rendering path. A panic anywhere in the pipeline fails the test.
fn exercise(text: &str) {
    let Ok(file) = SourceFile::parse(FileId(0), "fuzz.rs", "fuzz.rs", text) else {
        // A rejected parse is a correct outcome for malformed input.
        return;
    };
    let project = Project::from_sources(vec![file]);
    let report = analyze(&project, &AnalysisConfig::default());
    let _ = report.summary();
    let _ = report.highest_severity();
    let _ = report.count_by_severity();
    let _ = report.count_by_category();
    for finding in &report.findings {
        let _ = finding.headline_location();
        let _ = finding.fingerprint();
    }
    // Suppression and baseline handling must also survive arbitrary comments.
    let _ = to_sarif_string(&report);
}

fn generated_source(rng: &mut Rng) -> String {
    let length = 1 + rng.below(48);
    let mut source = String::new();
    for _ in 0..length {
        // The element type is annotated so the call resolves the same way on every
        // supported toolchain; inference alone picked `T = str` on older rustc.
        source.push_str(rng.pick::<&str>(VOCABULARY));
        source.push(' ');
    }
    source
}

#[test]
fn parser_survives_generated_token_soup() {
    let mut rng = Rng::new(0x9E37_79B9_7F4A_7C15);
    for _ in 0..3_000 {
        exercise(&generated_source(&mut rng));
    }
}

#[test]
fn parser_survives_mutated_fixtures() {
    // Truncation: every prefix of a real contract is plausibly a half-written
    // file on disk while a user is editing.
    for seed in SEEDS {
        for (offset, _) in seed.char_indices().step_by(7) {
            exercise(&seed[..offset]);
        }
    }

    // Byte flips: corruption that keeps the input mostly parseable.
    let mut rng = Rng::new(0xDEAD_BEEF_CAFE_F00D);
    for seed in SEEDS {
        for _ in 0..500 {
            let mut bytes = seed.as_bytes().to_vec();
            let flips = 1 + rng.below(4);
            for _ in 0..flips {
                if bytes.is_empty() {
                    break;
                }
                let index = rng.below(bytes.len());
                bytes[index] = (rng.next_u64() & 0xFF) as u8;
            }
            exercise(&String::from_utf8_lossy(&bytes));
        }
    }

    // Splice: delete a random run of bytes, which often breaks block structure.
    for seed in SEEDS {
        for _ in 0..200 {
            let mut bytes = seed.as_bytes().to_vec();
            if bytes.len() > 4 {
                let start = rng.below(bytes.len() - 1);
                let len = 1 + rng.below(bytes.len() - start);
                bytes.drain(start..start + len);
            }
            exercise(&String::from_utf8_lossy(&bytes));
        }
    }
}

#[test]
fn valid_fixtures_still_analyse() {
    // Guards against the fuzzer's vocabulary drifting away from real syntax: the
    // seeds must parse and produce a report.
    for seed in SEEDS {
        let file = SourceFile::parse(FileId(0), "fixture.rs", "fixture.rs", *seed)
            .expect("fixture must parse");
        let project = Project::from_sources(vec![file]);
        let report = analyze(&project, &AnalysisConfig::default());
        let _ = report.summary();
    }
}
