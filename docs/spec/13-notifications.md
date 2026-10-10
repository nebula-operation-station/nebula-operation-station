<!-- Source: Nebula Operation Station Technical Specification v2.2 (Decision-Frozen). Edits need an architecture revision. -->

# Notifications and integrations

Nebula tells the admin when something needs attention, because nobody keeps an operations UI open all day. Notifications and the API are read-only paths and can never trigger an execution.

**Notification events.**

- Ops State gets worse or recovers (transitions only, never repeats).
- Execution or stage finished with WARNING or FAILED.
- Stage gate waiting for manual continue.
- Host-key mismatch (always sent, cannot be muted).
- Executor locked after a restart, so scheduled checks are paused.
- Optional daily digest of open updates, reboots pending and hosts not READY.

Per-host mute with expiry. Messages carry host, state, reason and execution ID, not log content; including the last log lines is opt-in, because logs are untrusted and may be sensitive.

**Providers in V1.** Generic webhook (JSON, HMAC-signed), ntfy, Telegram. Provider tokens are low-privilege, so they live in the server configuration (owner `nebula-server`, mode 0600), not in the executor vault; the docs say so.

**Read-only API.** `/api/v1`, disabled by default. When enabled: token authentication, scopes `inventory.read`, `operations.read`, `execution_logs.read` (separate, because logs can be sensitive), no anonymous access. This is how Home Assistant, a status page or a script reads Ops State.

**Later (1.1).** An OpenMetrics endpoint behind the same scopes, so Prometheus or Telegraf can scrape Ops State and update counts into an existing monitoring stack.
