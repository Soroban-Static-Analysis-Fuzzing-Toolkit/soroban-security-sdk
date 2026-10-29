# Security policy

## Reporting a vulnerability in soroban-sec

If you find a security issue in soroban-sec itself, report it privately through
[GitHub security advisories](https://github.com/Soroban-Static-Analysis-Fuzzing-Toolkit/soroban-security-sdk/security/advisories/new),
not in a public issue. For example: a crafted contract that makes the analyser
execute code, read files outside the scanned tree, or crash a CI job.

We aim to acknowledge reports within three working days.

## Missed vulnerabilities in contracts

A Soroban bug that the scanner *fails to detect* is not a vulnerability in
soroban-sec. Open a "Missed vulnerability" issue so it can become a fixture and a
rule improvement. If the example comes from a live, unpatched contract, contact
that contract's maintainers first and share only a minimal reproduction here.

## Scope of the tool

soroban-sec is a static analyser. A clean report does not mean a contract is
secure, and it does not replace an audit. See
[`docs/real-world-evaluation.md`](docs/real-world-evaluation.md) for what it does
and does not find on production code.
