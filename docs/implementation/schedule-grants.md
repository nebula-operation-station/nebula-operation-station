# Scheduled read-only checks: schedule grants

Decision 5 of the M6 plan (option a, 2026-10-15): scheduled read-only
work (update checks, facts) runs under a **standing, executor-held grant**
that the admin creates with the security key, for a fixed set of actions
and hosts, with an expiry, revocable and audited, limited to actions the
executor itself rates LOW.

## Grant

The server proposes a grant document; the executor canonicalizes it
(RFC 8785) and the approval binds its SHA-256:

```json
{"grant": "read-schedule-v1",
 "id": "<uuid>",
 "actions": [{"action_id": "package.list_updates", "module_version": "1.0.0",
              "artifact_sha256": "<hex>", "parameters_hash": "<hex>"}],
 "targets": [{"host_id": "web-01", "host_key_fingerprint": "SHA256:..."}],
 "min_interval_s": 3600,
 "expiry_unix": 1790000000}
```

At proposal the executor checks, from its own data only:

- 1 to 10 actions, 1 to 100 targets, no duplicates;
- every target is pinned with exactly that fingerprint and not blocked;
- every action's artifact is trusted for exactly that action and version,
  and the executor's minimum risk for it on every target is LOW (an
  artifact trusted as LOW is read-only by the admin's declaration, see
  `internal/riskpolicy`);
- `min_interval_s` is 15 minutes to 7 days, the expiry at most 90 days
  ahead (the UI proposes 30).

Approval: a user-verified WebAuthn assertion over
SHA-256("nebula-schedule-grant-v1" 0 ‖ digest ‖ nonce ‖ expiry) inside
the privileged session, or `nebula schedule approve` in hardened mode.
The approved grant is stored in `executor.db`; unlike a permit it survives
a restart (runs still need `nebula unlock`). Revoking needs no approval.

## Runs

`RunScheduled` (server role) names the grant and one host run. The
executor runs it only if the grant is approved, not revoked or expired,
the action, version, artifact bytes and parameters hash to one entry, the
host and its pinned key are a target, the minimum risk for this host is
still LOW (trust withdrawn or criticality raised stops it), and the last
run of this action on this host under this grant is at least
`min_interval_s` ago (recorded before the run). The run is attached, with a
fresh execution ID, and audited like any run.

What a compromised server can do with a grant: run the approved LOW,
read-only actions on the approved hosts, at most once per interval. It
cannot add actions, hosts, parameters or frequency, and cannot extend the
expiry.
