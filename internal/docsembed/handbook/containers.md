# Containers

Docker and Compose on managed hosts: looking at containers, checking for
new images, updating Compose projects, and container updates with
rollback. Reference: admin guide
[9.3](../admin/guide.md#93-services-and-docker).

All Docker actions read through the `docker` group if the SSH user is in
it, otherwise through `sudo -n`. Both are root on the host.

## List the containers on a host

**Goal:** see every container with image, state, health, published ports
and Compose project.

**Prerequisites:** host enrolled; Docker on the host.

**Steps:**

1. *Operations → New operation* (`/operations/new`) → **List containers**
   (`docker.list`, LOW), select hosts, plan.
2. Or on the inventory chart (`/inventory/chart`): select hosts →
   **Refresh updates, containers, services**.

**Expected result:** the result lists the containers; the chart's host box
shows them, with links to *logs*, *inspect*, *restart* and *update
project*.

**Common errors:** "no Docker" on the host, or a permission error: Docker is
missing, or the SSH user is neither in the `docker` group nor allowed
`sudo -n`.

## Read a container's logs or details

**Goal:** troubleshoot one container without logging in to the host.

**Steps:**

1. *Operations → New operation* → **Container logs** (`docker.logs`) or
   **Container details** (`docker.inspect`), with the container name or ID.
   The chart's *logs* and *inspect* links prefill this form.
2. Plan.

**Expected result:** *logs* shows the state and the last 100 log lines.
*details* shows image and repository digest, state, health, restart policy,
mounts, published ports and networks.

**Note:** details never show the container's environment, command line or
labels, because they often hold secrets.

## Start, stop or restart a container

**Goal:** operate one container.

**Prerequisites:** your security key (MEDIUM).

**Steps:** *Operations → New operation* → **Start container**, **Stop
container** or **Restart container** (`docker.start`, `docker.stop`,
`docker.restart`) with the container name; approve.

**Expected result:** the result shows the state before and after. Nothing
is recreated, pulled or updated, and the action is never retried
automatically.

## Check which images have updates

**Goal:** know which running containers have a newer image for their tag.

**Steps:** *Operations → New operation* → **Check image updates**
(`docker.check_updates`, LOW), select hosts, plan.

**Expected result:** a list of images with an update available.

**How it works:** the host asks each registry for the current digest of the
tag (a manifest HEAD request, anonymous). Nothing is pulled, and Docker Hub
pull limits are not used.

**Common errors:** private registries that need credentials show as
"unknown". The host needs `curl` and HTTPS access to the registries.

## Update a Compose project

**Goal:** pull new images for one project and recreate its containers.

**Prerequisites:** *Check image updates* run first; your security key
(MEDIUM, a durable job).

**Steps:**

1. *Operations → New operation* → **Update Compose project**
   (`docker.compose_update`) with the project name, or *update project* on
   the chart.
2. Approve.

The job finds the project's directory and files from the container labels,
runs `docker compose pull`, then `docker compose up -d`, and compares the
containers before and after.

**Expected result:** OK when all containers run as before. FAILED when
fewer containers run, a command failed or a healthy container is no longer
healthy. WARNING when a container is unhealthy, published ports changed or
the number of containers changed.

**Note:** this path has no rollback. For updates you may want to undo, use
the next section.

## Update containers with a rollback option

**Goal:** update selected Compose services per environment, with the old
image kept for a rollback.

**Prerequisites:**

1. Built-ins trusted
   ([Getting started](getting-started.md#trust-the-built-in-actions-after-install-or-upgrade)).
2. The host has an environment (DEV, QA or PROD) and is enrolled.
3. *Prepare container updates* (`docker.update_prepare`, MEDIUM) ran once on
   the host.
4. A *Preview container updates* (`docker.update_preview`, LOW) ran at most
   one hour ago. To change a tag, put the target tags in the preview's
   `target_tags` parameter.

**Steps:**

1. On the inventory chart, follow the host's link to *Container and Compose
   updates and rollbacks* (`/inventory/containers`). The page links to the
   prepare or preview step if one is missing or old.
2. Tick the services to update. Services that share a namespace must be
   selected together. A major version change also needs "I confirm a major
   version change".
3. *Review the plan*: per service the images, digests, tags, containers to
   recreate, affected dependencies, stage and risk.
4. *Confirm and propose batch*, then approve on the batch page
   (`/batches/<id>`). Hardened mode: `nebula batch review DIGEST` and
   `nebula batch approve DIGEST`.
5. Open each stage (DEV, then QA, then PROD) when the previous one passed.

**Expected result:** the batch page shows every member's progress. The
first failed member stops everything not yet started.

**Common errors:**

- A service has no checkbox: the page says why (pinned by digest, built
  locally, private image, up to date, …).
- Standalone containers (not Compose) are not offered here yet.
- Only same-tag refreshes are offered while the server has no tag policy.

## Roll back a container update

**Goal:** go back to the images an update replaced.

**Prerequisites:** the update was recorded on
`/inventory/containers`; the rollback window is still open (old images are
kept on the host with the `nos-retained` marker); a fresh preview shows the
project as the update left it.

**Steps:** on `/inventory/containers`, under *Rollback*, pick the update,
review and propose; approve it like an update.

**Expected result:** the containers run the old images again.

**Note:** volume and database migrations are **not** undone. Back up data a
new version migrates. NOS never deletes retained images; remove them on the
host when you no longer need them.

## Store a standalone container's definition

**Goal:** record how a standalone (non-Compose) container is defined, as
input for later updates.

**Prerequisites:** admin login on the Nebula machine; a JSON definition
file.

**Steps:**

```
nebula container definition put web-01 grafana grafana.json
nebula container definition list web-01
nebula container definition remove web-01 grafana
```

The definition comes from a file or stdin (`-`), never from an argument.
`remove --version N` removes one older version; removing is refused inside
a rollback window.

**Expected result:** `list` shows version, author and time, never the
content.

**Note:** updating standalone containers from the UI is not offered yet
(see [Update containers with a rollback option](#update-containers-with-a-rollback-option)).
