<!-- Source: Nebula Operation Station Technical Specification v2.2 (Decision-Frozen). Edits need an architecture revision. -->

# Milestones

The first usable release (0.1) is safe patching of Debian/Ubuntu hosts; inventory breadth, Docker and IPAM follow. Each milestone ends with a tagged release and counts as done only when its acceptance criteria pass in CI or in the reference lab.

0. **Security prototype.** UID separation, socket with `SO_PEERCRED` method sets, canonical request with RFC 8785, permit digest, executor-side artifact hashing, executor-side WebAuthn verification, CLI unlock into the in-process keyring.
   - Accept: the server user cannot read executor files; an unknown UID is rejected; a script, host list or parameter swapped after approval is rejected; a replayed assertion is rejected.
1. **Core.** Repository, four binaries, gRPC over the socket, SQLite schemas with migrations, UI shell, structured logs, CI with `govulncheck`.
   - Accept: clean install from tarball on Debian 12 starts all services locked.
2. **Auth and credentials.** Admin setup, WebAuthn login, TOTP recovery, privileged sessions, vault, SSH key handling, `nebula unlock`, `lock`, `approve`.
   - Accept: after reboot nothing executes until `nebula unlock`; recovery forces a new WebAuthn registration.
3. **Managed hosts.** Host CRUD, endpoints and ports, host-key pinning, enrollment with fingerprint review and `known_hosts` import, connection tests, facts, environment, criticality, CSV import.
   - Accept: a host with LAN and VPN endpoints falls back on TCP failure; a changed host key stops it and notifies.
4. **Execution engine and notifications.** Permits, attached and durable jobs, reconciliation, logs, error and retry classes, tmpfs secrets, input limits, webhook, ntfy and Telegram.
   - Accept: killing Nebula during a durable job and restarting it reconciles the result without re-running the job.
5. **os-debian, patching, services. Release 0.1.**
   - Accept: security updates installed on Debian 12 and Ubuntu 24.04; a held dpkg lock ends as `precheck_failed`; a Proxmox node gets `full-upgrade`; reboot waits and reports `host_not_returned` on timeout.
6. **Stage engine. Release 0.2.** Presets, gates, thresholds, permit scope across stages, Retry, Skip, Abort.
   - Accept: a failing canary stops the rollout; a HIGH gate demands a fresh assertion.
7. **Runbooks and modules. Release 0.3.** Manifest, immutable versions, secret slots, trust states, SSH signatures, advisory scanner, declarative UI, module state isolation.
   - Accept: an unverified root script is at least HIGH; a module UI cannot inject script.
8. **Docker. Release 0.4.** Detection, standalone and Compose inventory, logs, start/stop/restart, digest checks, manual Compose update with postflight.
9. **Network inventory, IPAM, discovery. Release 0.5.** Assets, networks, reservations, free-IP suggestion, Nmap helper, staging, “add to managed hosts”.
10. **Hardening. Release 0.9 beta.** Executor-signed events, optional audit hash chain, backup and restore, APT repository, container images, fuzzing, documentation, threat model, all pre-1.0 security tests.

After 1.0: Proxmox provider, managed-host backup module, OpenMetrics endpoint (target 1.1).
