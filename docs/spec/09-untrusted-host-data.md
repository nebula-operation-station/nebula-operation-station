<!-- Source: Nebula Operation Station Technical Specification v2.2 (Decision-Frozen). Edits need an architecture revision. -->

# Untrusted host data and log safety

Everything a managed host returns is untrusted input: hostnames, facts, service, package and container names, `inventory.json`, `state.json`, `result.json` and log output. A compromised host must not be able to attack Nebula or the admin's browser.

- Strict schemas per capability contract (for example `package.list_updates@1`); unknown fields are dropped.
- UTF-8 validation, maximum field length, maximum object count, maximum payload size.
- Default limits, configurable: `result.json` 1 MB, `state.json` 64 KB, `inventory.json` 1 MB, execution log 10 MB per host and run.
- The UI renders host data as text only: no raw HTML, no host-provided templates, a strict Content Security Policy without inline scripts.
- Logs are stored in chunks with a size limit and a visible truncation marker, escaped on display and redacted for known secret values.
- Parsers for host data get fuzz tests before the beta (Go native fuzzing).
