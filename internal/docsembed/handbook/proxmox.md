# Proxmox VE

A read-only view of your Proxmox VE clusters and hosts: nodes, guests,
storage, tasks and live values. Reference: the
[Proxmox VE operator guide](../operator/proxmox.md) and admin guide
[9.4, "Live values"](../admin/guide.md#live-values-for-proxmox-nodes-and-guests).

**What works today:** remote management on the CLI, inventory collection,
the PVE pages (`/pve`, `/pve/<id>`), read leases and live values, linking
guests to managed hosts, deploy profiles (presets only).

**Not available yet:** guest provisioning (the pages exist, every
proposal is refused; ADR 0008), guest power and snapshots (routes answer
404), guest backup, migration, node reboot and configuration changes
(planned, ADR 0006 phase 2). NOS changes nothing on PVE today. See
[What you can use today](../operator/proxmox.md#what-you-can-use-today).

Patching a Proxmox VE node itself works like any other host: enroll it as
in [Hosts](hosts.md); *Install all updates* uses `full-upgrade` there.

## Create a least-privilege read-only PVE token

**Goal:** a PVE API token the executor accepts for reads.

**Prerequisites:** root shell on a PVE node (or its web shell).

**Steps:** follow
[Read-only token (required)](../operator/proxmox.md#read-only-token-required).
In short: four roles with one audit privilege each (`Sys.Audit` on `/`,
`VM.Audit` on `/vms`, `Datastore.Audit` on `/storage`, `Pool.Audit` on
`/pool`), a non-interactive user such as `nos-read@pve` with an expiry, a
token with `--privsep 1` and an expiry, and the same ACLs for the user
**and** the token. Note the token secret; PVE prints it once.

**Expected result:** a token of the form `nos-read@pve!nosread1=<secret>`.

**Common errors:** the executor rejects the token if it has any other
privilege or path (`PVEAuditor` is too broad), no expiry, no `privsep`, or
belongs to a `*@pam`, `Administrator@*` or `PVEVMAdmin@*` user.

## Add a Proxmox remote

**Goal:** the executor knows a PVE cluster or standalone host, pinned to
its TLS identity, with the read token in its vault.

**Prerequisites:** the read token; executor unlocked (`nebula unlock`);
admin login on the Nebula machine with a terminal.

**Steps:**

```
nebula pve remote add pve-lab --kind cluster \
  --endpoint pve1.lab:8006 --endpoint pve2.lab:8006 --name "Lab cluster"
```

Use `--kind standalone` and one `--endpoint` for a single host. The order of
`--endpoint` is the failover order. `--action-token` also asks for an
action token (nothing uses it yet). For a cluster whose nodes serve only
their leaf certificate, add `--ca-file pve-root-ca.pem` (copied out of band
from `/etc/pve/pve-root-ca.pem`).

1. The command probes the endpoints without credentials and prints the
   leaf and CA fingerprints.
2. Compare the fingerprint out of band (PVE console) and type it back.
3. Paste the read token at the prompt (no echo; never an argument).

**Expected result:**
`remote pve-lab added: active, pin generation 1, read credential <ref>@1`.
`nebula pve remote list` shows it.

**Common errors:** `confirmation does not match the presented trust
identity; nothing stored`: wrong fingerprint typed, run again. A refusal to
run at all: the vault is locked, run `nebula unlock`.

## Approve a read lease so data appears

**Goal:** the collector may read the remote, and `/pve` fills with data.

**Prerequisites:** remote added and `active`; `nebula-pve-collector`
running; your security key.

**Steps:**

1. Open `/pve/<id>` → **Request read lease** (or *Operations → Read
   leases → New read lease* with scope **Proxmox remote**).
2. Keep the default methods (`nodes`, `guests`, `storage`, `cluster`,
   `tasks`). Add `guest_config` if you want MAC-based guest-to-host
   suggestions; `guest_agent`, `snapshots` and `backups` are optional.
3. Choose 7 or 30 days, **Preview**, and approve with your security key.

**Expected result:** within a few minutes the remote appears on `/pve` with
nodes and guests; the PVE part of the inventory chart fills.

**Common errors:** datasets `unavailable` or `partial` and
`read_grant_does_not_cover` in `journalctl -u nebula-executor`: no active
lease covers the remote and method (expired, revoked, or invalidated by a
re-pin or token rotation). The page then offers **Renew read lease**.
Details: [Read lease for a remote](../operator/proxmox.md#read-lease-for-a-remote).

## See live values on node and guest boxes

**Goal:** 10-second live metrics on the chart's PVE node and guest boxes.

**Prerequisites:** a read lease with the `on_demand` trigger that lists the
box; `nebula-pve-collector` running.

**Steps:** request the live-values lease as described in
[Live values and their lease](../operator/proxmox.md#live-values-and-their-lease)
and approve it. Then keep the box visible in the browser.

**Expected result:** values refresh about every 10 seconds while the box is
on screen. At most four live boxes per remote.

**Common errors:** no values: check `systemctl status nebula-pve-collector`
and `journalctl -u nebula-pve-collector` for `live leases refused` (no lease
covers the box) or `live lease refresh` (executor locked). The full
checklist is in admin guide
[9.4](../admin/guide.md#live-values-for-proxmox-nodes-and-guests).

## Link a Proxmox guest to its managed host

**Goal:** the PVE guest and the NOS host are shown as the same machine.

**Prerequisites:** the guest and the host both exist; for MAC suggestions,
the read lease includes `guest_config` and the host's IPAM asset has the
MAC.

**Steps:** on `/pve/<remote>`, in the guest table's **Managed host** column,
pick the suggested host (MAC match or POSSIBLE MATCH by IP) and link it.

**Expected result:** the column shows the link, since when and by whom.

**Note:** an IP match is never more than a possible match, and conflicts
(for example a cloned VM with the same MAC) are shown, never resolved for
you. See [Linking guests to hosts](../operator/proxmox.md#linking-guests-to-hosts).

## Rotate a PVE token

**Goal:** replace the read token before it expires.

**Prerequisites:** a new token created in PVE with the same ACLs; executor
unlocked.

**Steps:**

```
nebula pve remote rotate-token pve-lab --purpose read
```

Paste the new token at the prompt. Afterwards revoke the old token in PVE.

**Expected result:** the new token is validated before anything changes.
Read leases bound to the old credential version are revoked, so request a
new lease on `/pve/<id>` (**Renew read lease**).

## Re-pin a remote after a certificate change

**Goal:** bring a `blocked` remote back after a CA or certificate change.

**Steps:** verify the new certificate out of band, then
`nebula pve remote repin pve-lab` and type the new fingerprint. A renewal
that keeps the same CA needs no re-pin.

**Expected result:** the remote is `active` again; approve a new read
lease. Details:
[Re-pinning the trust identity](../operator/proxmox.md#re-pinning-the-trust-identity).

## Remove a Proxmox remote

**Steps:** `nebula pve remote remove pve-lab`. It disables the remote,
revokes dependent leases, deletes its vault secrets and leaves a tombstone.
Then delete the token in PVE.

## Deploy a new guest from a profile (planned)

**Status:** not available. Deploy profiles (`/deploy`) can be saved, and the
wizard (`/deployments/new`) exists, but every proposal is refused with
`the template is not prepared or changed; prepare it again`, because no
release can prepare a template yet (ADR 0008). PVE is not changed. See
[Guest provisioning](../operator/proxmox.md#guest-provisioning).
