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

<a id="v23-09-06"></a>
<!-- Spec v2.3 (ADR 0009): v23-09-06 -->
**`net.facts` fields and limits.** The built-in read-only `net.facts` action (ADR 0009 D1, `internal/executions/actions/scripts/net_facts.sh`) returns one JSON document — `format` `net-facts-v1`, `phase` `done` — with one base64 section per fixed read-only command, in this order: `addr` (`ip -j addr`), `link` (`ip -j -d link`), `route` (`ip -j route`), `route6` (`ip -j -6 route`), `neigh` (`ip -j neigh`), `neigh6` (`ip -j -6 neigh`), `bridge_vlan` (`bridge -j vlan`), `lldp` (`lldpcli -f json show neighbors`), `sockets` (`ss -tinuaH`) and `conntrack` (`conntrack -L`). Each section is an object `{status, truncated, data}` where `data` is base64; the schema is strict, so unknown fields and any data after the document are rejected.
- **Size limits.** Each section's decoded data is at most 256 KiB; all sections together at most 720 KiB; the raw document at most 1 MiB (the executor result limit), so the base64 document always fits. A section cut at its cap is `truncated: true`; once the 720 KiB total budget is spent, the remaining commands do not run and their sections are `skipped` (`truncated: true`, no data).
- **Section statuses.** `ok` (the command ran and exited 0; `data` is its stdout), `absent` (the tool is not installed; no data), `failed` (the command exited non-zero, e.g. `conntrack` without `CAP_NET_ADMIN`; no data), `skipped` (the total budget was spent; `truncated: true`, no data) and `unavailable` (an IPv6 section whose command failed because the host has IPv6 disabled, `ipv6.disable=1`, "Address family not supported"; no data). Only `route6` and `neigh6` may be `unavailable`; any other `ip -6` failure stays `failed`. `absent`, `failed` and `unavailable` carry no data and are not truncated.
- **`truncated` and `invalid`.** `truncated` is set when a section was cut at its cap or skipped. `invalid` is set when an `ok` section's data is rejected by its parser (for example JSON cut by truncation), when raw `lldp` or `conntrack` text is not valid UTF-8 or carries a control character other than newline or tab, or when the `sockets` section carries a `users:((…))` column.
- **Incomplete.** A result is incomplete when any section is truncated, invalid or skipped, when a required section is absent or failed, or when a parsed table dropped entries; it must be presented as incomplete, never as an empty table. `bridge_vlan`, `lldp` and `conntrack` are optional: their absence or failure is not a loss of data. `unavailable` sections do not by themselves make the result incomplete, so a host with IPv6 disabled (both `route6` and `neigh6` `unavailable`) still yields a complete result.
- **`ss` without `-p`.** `net.facts` runs `ss -tinuaH` without `-p`, so process names are never collected (they need root and are off unless the admin installs the documented sudo rule, ADR 0009 Q3). `Sockets.Process` is always empty; a `sockets` section carrying a `users:((…))` column did not come from that command (a wrapped or replaced `ss`) and is refused as `invalid` with an empty table.
- **Unparsed sections.** `lldp` and `conntrack` have no parser yet and are kept as raw, bounded, untrusted bytes that are valid UTF-8 with no control characters other than newline and tab; a cut section drops a trailing incomplete UTF-8 sequence.
