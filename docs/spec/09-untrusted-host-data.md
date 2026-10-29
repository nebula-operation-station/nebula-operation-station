<!-- Source: Nebula Operation Station Technical Specification v2.2 (Decision-Frozen). Edits need an architecture revision. -->

# Untrusted host data and log safety

<a id="v23-09-01"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-09-01 -->
Everything a managed host, PVE endpoint, registry, collector spool or host-local scanner returns is untrusted input: hostnames, facts, service, package and container names, `inventory.json`, `state.json`, `result.json` and log output. A compromised host must not be able to attack Nebula or the admin's browser.

- Strict schemas per capability contract (for example `package.list_updates@1`); unknown fields are dropped.
- UTF-8 validation, maximum field length, maximum object count, maximum payload size.
- Default limits, configurable: `result.json` 1 MB, `state.json` 64 KB, `inventory.json` 1 MB, execution log 10 MB per host and run.
- The UI renders host data as text only: no raw HTML, no host-provided templates, a strict Content Security Policy without inline scripts.
- Logs are stored in chunks with a size limit and a visible truncation marker, escaped on display and redacted for known secret values.
- Parsers for host data get fuzz tests before the beta (Go native fuzzing).

<a id="v23-09-02"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-09-02 -->
**Provider and spool limits.** Enforce named limits of 1 MiB decoded per response/spool page, 1,000 objects/page, 10,000 guests/remote, 128 interfaces/guest and 4 KiB/text field, with bounded nesting and pagination. Validate schemas, UTF-8, identifiers and numeric ranges, dropping unknown fields. Mark oversize/incomplete data as such, never as a complete empty dataset. Exact nesting/page-count limits are unresolved and must be specified before readers ship. These limits also apply to the new SSH observation contracts; runtime/action-specific limits must additionally bound expensive work.

<a id="v23-09-03"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-09-03 -->
**Allowlisted observations only.** Discard Cloud-Init passwords, SSH keys, snippets, descriptions, hook scripts, storage credentials and other non-allowlisted fields before spooling. Never persist raw API responses/errors, image configuration/files, raw scanner findings or secrets; phase 1 excludes PVE task logs/command output. Any phase-2 task-log excerpts must be bounded and sanitized. Registry auth challenges and pagination links cannot choose arbitrary origins/private addresses. Keep output redaction as an extra safeguard and render all labels, task actors, registry/image metadata and scanner summaries through escaped text templates.

<a id="v23-09-04"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-09-04 -->
**Spool integrity.** Separate server-written request and collector-written result directories enforce ownership; use bounded reads, no symlink following, atomic writes and collection IDs. Revalidate schemas, identity/generation, sizes and collection completeness at server ingestion. Do not accept URLs, raw API paths or raw commands in poll/visible-target requests. Spool content is presentation/input to executor checks, never trust, credential custody or mutation authority.

<a id="v23-09-05"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-09-05 -->
**Browser presentation.** The chart/details enhancement uses only self-hosted external scripts/styles, no inline handlers/styles, module JavaScript or host/registry HTML, under the existing strict CSP. Deep links are built from approved endpoint metadata and encoded identifiers with `noopener noreferrer`; release-note links need a reviewed HTTPS upstream/template and validated version. An untrusted URL or label cannot select a new dial target or rendered template.
