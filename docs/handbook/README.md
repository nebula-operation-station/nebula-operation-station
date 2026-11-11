# Operator handbook

Task-oriented how-tos for running Nebula Operation Station (NOS), plus a
FAQ. Each page answers "how do I …" questions; each `##` section is one
task and can be read on its own. It covers this goal, what you need first,
the steps with the exact command or UI path, what you should see, and the
errors people usually run into.

The handbook does not repeat the reference material. Flags, file
modes, configuration keys and the full error table live in the
[installation and operations guide](../admin/guide.md) ("admin guide"
below). The how-tos link to the exact section.

## Chapters

| Chapter | Tasks |
| --- | --- |
| [Getting started](getting-started.md) | Install, create the SSH key, unlock, first login, register a YubiKey, set up TOTP recovery, lock |
| [Hosts](hosts.md) | Add a host, import a CSV, run the enrollment script, pin host keys, test a login, set criticality, handle a changed host key, release a host |
| [Patching and services](patching-and-services.md) | Check and install updates, reboot, rollouts in stages, restart a service, scheduled checks, runbooks with secrets |
| [Containers](containers.md) | List containers and logs, check image updates, update a Compose project, container updates with rollback |
| [Proxmox VE](proxmox.md) | Create a read-only token, add a remote, approve a read lease, live values, link guests to hosts, rotate a token |
| [Network](network.md) | IPAM networks and assets, discovery scans, the traffic map, register a Cisco CBS switch or a PAN-OS firewall with a `nos-read` account |
| [Vulnerabilities](vulnerabilities.md) | Set up the Hermes agent token, read the findings pages, understand states and labels, export findings |
| [Backup and restore](backup-restore.md) | Create a backup key, back up, restore, container volumes, upgrade safely |
| [Troubleshooting](troubleshooting.md) | Symptom-first fixes for the most common problems |
| [FAQ](faq.md) | Short answers to frequent questions |

## Conventions

- `nebula …` commands run on the **Nebula machine** as an **admin user**
  (a login listed in the executor's `-admin-users` and member of the group
  `nebula-rpc`), not as root. `nebula backup` and `nebula restore` are the
  exceptions: they run through `sudo` from an admin login.
- In a container install, prefix every `nebula …` command with
  `docker compose exec -u nebula-admin executor` (admin guide
  [3.3](../admin/guide.md#33-in-containers)).
- UI paths are written as **Menu → Page → Button**; the URL path is given in
  brackets where it helps, for example *Inventory → Enroll hosts*
  (`/inventory/enroll`).
- `<rp-id>` is your Nebula hostname, for example `nebula.lab.example.org`.
- **Planned** marks something that is not in this release; the ADR or plan
  that covers it is named. Do not look for it in the UI yet.

## Using these pages as a knowledge base

The pages are written to be split by `##` heading. Every section names its
own prerequisites and links, so it still makes sense when it is the only
part a reader (or a help assistant) sees. Keep it that way when you edit:
one task per `##` section, no "as described above".
