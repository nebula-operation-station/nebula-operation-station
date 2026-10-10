<!-- Source: Nebula Operation Station Technical Specification v2.2 (Decision-Frozen). Edits need an architecture revision. -->

# Operations: patching, services, Docker

V1 covers Debian/Ubuntu patching, systemd services and Docker inspection with a manual Compose update. Nothing here runs automatically.

**Supported targets for 0.1.** Official support covers **Debian 12, Ubuntu 22.04 LTS and Ubuntu 24.04 LTS**. **Proxmox VE 8 and 9** are additionally supported as Debian-based managed hosts with adapter-specific behavior such as `full-upgrade`. Other Debian derivatives are best-effort/unsupported until explicitly added to the support matrix.

**Patching.** Per host: normal, security and kernel updates, reboot required, last refresh, last patch. Actions: refresh metadata, check updates, install security updates, install all updates, check reboot required, reboot. Release upgrades are not patch actions.

- Security updates are the packages whose candidate comes from the security archive (`-security` on Ubuntu, `debian-security` on Debian); they are installed with `apt-get install --only-upgrade`. Dependencies from other archives can come along, and the result lists them.
- All apt calls use `DEBIAN_FRONTEND=noninteractive`, `--force-confold` and `DPkg::Lock::Timeout=600`. On apt older than 1.9.11 the adapter waits for the lock itself. A lock still held after 10 minutes, for example by unattended-upgrades, ends as `precheck_failed` with the reason.
- Proxmox VE nodes are detected by `os.facts`: “install all” becomes `full-upgrade`, as Proxmox requires, and the host's default criticality is HIGH.
- Prechecks: free space on `/` and `/var`, package lock, `dpkg --audit` clean, filesystem writable.
- Postchecks: `dpkg --audit` clean, reboot required, failed systemd units compared before and after, Docker state if present, host reachable.
- Reboot is a separate durable action. The executor waits for SSH and fresh facts; past the timeout the result is `host_not_returned`. No reboot after patching in V1.

**Services.** list, status, start, stop, restart, reload, recent journal lines (capped). Risk comes from core metadata and host criticality, not from the UI.

**Docker.**

- Standalone containers: inventory, state, health, image and tag, current and available digest, ports, mounts, logs, start, stop, restart. Nebula only reports “update available” and never recreates a container from `docker inspect`, because devices, GPU bindings, capabilities, ulimits, sysctls, log drivers, health checks and networking are easily lost.
- Digest checks use manifest HEAD requests against the registry, which do not count against Docker Hub pull limits; scheduled at most daily by default.
- Compose stacks are found through the labels `com.docker.compose.project.working_dir` and `com.docker.compose.project.config_files`. Manual update: check digests, preflight, `docker compose pull`, `docker compose up -d`, postflight.
- Postflight compares running containers, health, published ports and container count before and after; a regression gives WARNING or FAILED.
