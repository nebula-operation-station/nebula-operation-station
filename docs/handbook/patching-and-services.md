# Patching and services

Keeping hosts updated, rebooting them safely, operating systemd services,
and running your own scripts. Reference: admin guide
[9.1 to 9.6](../admin/guide.md#9-daily-operation).

Every operation follows the same pattern: plan it, check what the executor
will run, approve it with your security key (or on the machine in hardened
mode), read the result. Nothing runs on a host without that approval.

## Check which updates a host needs

**Goal:** see the number of security and total updates, and whether a
reboot is required.

**Prerequisites:** host enrolled and pinned ([Hosts](hosts.md)); executor
unlocked; built-ins trusted
([Getting started](getting-started.md#trust-the-built-in-actions-after-install-or-upgrade)).

**Steps:**

1. Dashboard → **Open privileged session** (security key). *Check updates*
   is LOW and runs within the session without a further prompt.
2. *Operations → New operation* (`/operations/new`), choose **Check
   updates** (`package.list_updates`), select the hosts, plan and approve.

From the inventory chart (`/inventory/chart`) you can also select hosts
and use **Refresh updates, containers, services**.

**Expected result:** the inventory shows something like
`2 security / 9 total, reboot required, checked …` per host.

**Common errors:** without trusted built-ins, or on a host without a
criticality record, even this read-only check needs a security key with
user verification (it counts as HIGH).

## Install security updates or all updates

**Goal:** patch hosts with prechecks and postchecks.

**Prerequisites:** a recent *Check updates* result; your security key.

**Steps:**

1. *Operations → New operation*, choose **Install security updates**
   (`package.install_security`) or **Install all updates**
   (`package.install_all`), select hosts. (On the inventory chart: select
   hosts → **Install updates…**.)
2. Optional: choose a rollout under *Rollout* (see
   [Roll out in stages](#roll-out-an-operation-in-stages-canary-waves-dev--qa--prod)).
3. Review the plan and **Approve with security key**.

The job runs on the host under systemd. Prechecks: free space on `/` and
`/var`, `dpkg` state, writable disk, apt lock. Postchecks: `dpkg` state,
reboot required, newly failed units. On Proxmox VE nodes, *Install all
updates* uses `full-upgrade`.

**Expected result:** the operation page (`/operations/<id>`) shows each
host's result; the inventory's update counts drop after the next check.

**Common errors:**

- `precheck_failed`: nothing was installed. The reason is on the page
  (disk space, `dpkg` state, apt lock held by another apt run, read-only
  disk). Fix it on the host and plan again.
- `network_unreachable`: no endpoint answered and nothing was sent. Plan
  again once the host is reachable.

## Reboot hosts that need it

**Goal:** reboot and confirm the host came back.

**Prerequisites:** a result saying *reboot required*; your security key
(reboot is HIGH: user verification).

**Steps:**

1. *Operations → New operation* → **Reboot** (`system.reboot`), or on the
   inventory chart select hosts → **Reboot…**.
2. For several hosts, prefer a staged rollout (**Plan a staged reboot…**).
3. Approve.

**Expected result:** Nebula waits until the host reports a new boot ID.

**Common errors:** `host_not_returned`: the host did not come back within
20 minutes. Check its console.

## Roll out an operation in stages (canary, waves, DEV → QA → PROD)

**Goal:** limit the damage of a bad update to a few hosts.

**Prerequisites:** hosts with an environment set in the inventory (for
DEV → QA → PROD).

**Steps:**

1. On the planning page (`/operations/new`), under *Rollout*, choose:
   all at once (default), *canary first* (first N hosts alone), *in waves*
   of N hosts, or *DEV → QA → PROD*.
2. Set how many failed and unreachable hosts a stage tolerates (a canary
   tolerates none).
3. Approve. The stages are part of what you approve; the executor enforces
   them.
4. After each stage: **Continue to stage N**. LOW and MEDIUM operations can
   continue by themselves if you chose so. HIGH and CRITICAL stages need your
   security key again (hardened mode: `nebula approve --stage N <digest>`).

**Expected result:** a stage with too many failures stops the rollout for
good; later hosts do not run. **Abort rollout** stops all hosts that have
not run.

**Common errors:** an unreachable host can be retried or skipped (skipping
needs the same approval as opening a stage; hardened mode:
`nebula approve --skip HOST <digest>`). A restart of the executor ends the
rollout.

## Approve on the machine in hardened mode

**Goal:** approve HIGH and CRITICAL operations where the executor itself
shows what will run, not the web server.

**Prerequisites:** the executor runs with `-hardened` (admin guide
[6.2](../admin/guide.md#62-executor-flags)); an admin login on the Nebula
machine.

**Steps:**

```
nebula pending                    # lists permits waiting for approval
nebula approve <digest>           # a unique prefix is enough
```

`nebula approve` shows the Safety Scanner's findings and the script's
first 40 lines (at most 4 KiB) before you confirm. Batches:
`nebula batch review DIGEST`, then `nebula batch approve DIGEST`.

**Expected result:** the operation starts; its page shows the progress.

## Restart, start, stop or reload a systemd service

**Goal:** operate one unit on one or more hosts.

**Prerequisites:** host enrolled with sudo; your security key (these are
MEDIUM).

**Steps:**

1. *Operations → New operation* → **Service status** (`service.status`,
   LOW) with the unit name, for example `nginx.service`. It shows the unit
   and the last journal lines.
2. Plan **Restart service** (`service.restart`), or start, stop or reload
   (`service.start`, `service.stop`, `service.reload`) with the same unit
   name, and approve.

**Expected result:** the result shows the unit's state; check it again with
*Service status*.

**Common errors:** a unit name that does not exist on the host fails on
that host only. Without sudo (`--no-sudo` at enrollment) only the read-only
service actions work.

## Run read-only checks on a schedule (read lease)

**Goal:** *Check updates*, *List services* and similar reads run every 15
minutes by themselves.

**Prerequisites:** the actions are trusted built-ins rated LOW, and every
chosen host has a criticality record on the executor (`nebula host pin
--criticality` or `nebula host criticality`). Otherwise the executor refuses
the lease.

**Steps:**

1. *Operations → Read leases → New read lease* (`/leases/new`).
2. Choose the scope (all hosts, a tag or an environment), the read-only
   actions (for example `package.list_updates`, `service.list`,
   `docker.list`) and 7 or 30 days.
3. Approve with your security key. Hardened mode:
   `nebula read-grant pending`, then `nebula read-grant approve <digest>`
   with the **full** 64-hex digest. (The proposal page may print
   `nebula lease approve`; that command does not exist, use
   `nebula read-grant approve`.)

**Expected result:** results appear as operations created by "schedule".
Each host runs at most 24 times per rolling hour by default.

**Managing it:** *Refresh* on a lease proposes a new lease with the same
scope (it needs a fresh approval). *Revoke* on the lease page, or
`nebula read-grant revoke <id>`, stops it at once. Nothing runs while the
executor is locked; missed runs are not caught up. Details: admin guide
[9.4](../admin/guide.md#94-read-leases-and-scheduled-checks).

**Common errors:** "A schedule is refused": an action is not LOW on every
host. Trust the built-in and record the host's criticality. `package.refresh`,
`docker.logs` and actions with secrets can never be leased.

## Write and run your own runbook

**Goal:** run your own POSIX `sh` script on hosts, with typed parameters.

**Prerequisites:** logged in; for trust on the machine, an admin login.

**Steps:**

1. *Runbooks → New runbook* (`/runbooks/new`).
2. Give it a name (its action becomes `runbook.<name>`), a declared risk, a
   timeout, attached or durable, and parameters (`name`, `int`, `path` or
   `choice`). The script reads them as `$NEBULA_P_<NAME>`.
3. Save. Each save creates a new, unchangeable version.
4. Trust the version, or every run needs a security key with user
   verification (HIGH): download the script from its page, read it, and run
   the `nebula artifact trust …` command shown there; or use *Trust this
   version* on the runbook page with your security key (standard mode only).
5. Plan it like any operation (*Plan operation* on the runbook page).

**Expected result:** the output appears in the operation log.

**Common errors:** a script that fails `sh -n`, or contains control or
invisible formatting characters, is refused on save. An attached run is
limited to 10 minutes; use durable for longer work (up to 6 hours).

## Use a secret in a runbook

**Goal:** give a runbook a token or password without it showing up in
arguments or logs.

**Prerequisites:** vault initialised (`nebula vault init`) and unlocked;
for attached runs, `$XDG_RUNTIME_DIR` (a tmpfs) for the SSH user on the
host.

**Steps:**

1. On the Nebula machine: `nebula secret set influx-token`. The value comes
   from the terminal or stdin, never from an argument.
2. In the runbook, declare a secret slot, for example `influx_token`.
3. When you plan the operation, name the vault secret for the slot.
4. The script reads the value from the file named by
   `$NEBULA_SECRET_INFLUX_TOKEN`.

**Expected result:** the run sees the value; known secret values are removed
from its log and result. `nebula secret list` shows IDs and versions, never
values. `nebula secret rm ID` deletes one.

**Common errors:** `vault_locked`: run `nebula unlock`.
`secret_unavailable: no vault secret …`: check `nebula secret list`. A run
with secrets is at least MEDIUM and cannot be scheduled.
