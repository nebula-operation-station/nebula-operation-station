# Vulnerabilities

Nebula stores and shows vulnerability findings; an external agent,
**Hermes**, does the matching. Reference: admin guide
[10.4](../admin/guide.md#104-vulnerability-management-hermes) and
[ADR 0011](../adr/0011-vulnerability-management.md).

Nebula itself fetches no CVE feeds, matches no packages and runs no LLM.
Hermes runs on its own VM, reads an inventory export from Nebula and posts
findings back. Findings are **advisory only**: nothing in this chapter ever
proposes, schedules or approves a change. Every fix goes through the normal
operation flow ([Patching and services](patching-and-services.md)).

## What works in this release

| Part | Status |
| --- | --- |
| Agent API (inventory export, runs, findings, complete), findings store, *Vulnerabilities* pages, notifications, export | Available |
| Inventory export content | **Planned:** the export is still empty (snapshot ID `nos-empty-<unix time>`, no subjects), so Nebula rejects every finding with "subject not in the run's inventory snapshot". Runs complete, but nothing is stored or closed yet |
| Closing findings based on NOS's own package data | **Planned:** closures a run asks for are held for an admin instead |
| Maintainer decisions (accept risk, false positive, confirm or discard a held closure, reset a feed mark) | **Planned:** the forms are shown, but submitting fails with "vulnerability decisions need an executor-verified security key assertion, which this executor does not offer" |
| Priority with real exposure and host criticality | **Planned:** tier `vu-prio-v1` uses exposure "unknown" and criticality "unset" (counted as HIGH) |
| Fix suggestion cards from the ops agent (ADR 0016) | **Off by default:** the agent is disabled, and this release has no form to enable it, so a default install shows no cards. The section *Read a fix suggestion card* describes them |
| Device findings, Hermes narratives for attack paths | Not available; narratives are not planned |

## Set up the Hermes agent token

**Goal:** Hermes can read the inventory export and write findings, and
nothing else.

**Prerequisites:** root on the Nebula machine (to edit `server.json`); the
Hermes VM's address.

**Steps:**

1. Create the token:

   ```
   nebula-server -api-token hermes-vuln:vuln.inventory.read,vuln.findings.write
   ```

   It prints the token once and a JSON entry. (The usage text of
   `-api-token` lists only the read-only scopes; the two vulnerability
   scopes are accepted.)
2. Add the entry to `/etc/nebula/server.json` under
   `"api": {"enabled": true, "tokens": [ ... ]}` and add the Hermes VM's
   address:

   ```json
   {"name": "hermes-vuln", "sha256": "<printed hash>",
    "scopes": ["vuln.inventory.read", "vuln.findings.write"],
    "source_addresses": ["<address or prefix of the Hermes VM>"]}
   ```

3. `sudo systemctl restart nebula-server`.
4. Give the token to Hermes (its configuration is outside this repository).

**Expected result:** `nebula-server` starts; Hermes' requests to
`/api/v1/vuln/inventory` answer `200`.

**Common errors:**

- The server refuses to start: only **one** token may hold the
  vulnerability scopes, it may hold **no other** scope, and
  `source_addresses` (at most 16, no host bits in prefixes) is allowed only
  on that token.
- `401`: wrong token. `403`: wrong source address or missing scope. Each
  refusal is an `audit` line in `journalctl -u nebula-server`.
- `source_addresses` checks the TCP peer address. If Hermes goes through the
  reverse proxy, that address is the proxy's, which admits everyone who can
  reach the proxy. Let Hermes connect to `nebula-server` directly if the
  allowlist should mean something.

To revoke the token, remove the entry and restart `nebula-server`.

## Find the findings for a host, image or CVE

**Goal:** see what is open, where, and how urgent.

**Prerequisites:** logged in (the pages are open to every logged-in user).

**Steps:**

1. *Vulnerabilities* (`/vulnerabilities`): findings by CVE or by subject.
   Filter by tier, KEV, state, subject kind and stale.
2. Click a CVE (`/vulnerabilities/cve/<id>`) for all subjects it affects,
   or a subject (`/vulnerabilities/subject/<kind>/<id>`) for its findings.
3. Open a finding (`/vulnerabilities/f/<key>`) for its details, held
   closures and the Hermes assessment, labelled "Hermes assessment (LLM,
   unverified)".

**Expected result:** a list of at most 5,000 rows per page (a larger result
is marked truncated).

**Fix it:** use the finding's "Fix with" link. It opens the OS package
update or the container update prefilled and never submits anything. "update
available, fix not verified" means the candidate's source version is below
the fixed version. Kernel findings also say a reboot is required.

## Understand finding states and labels

**Goal:** read a finding's state correctly.

| You see | Meaning |
| --- | --- |
| `open` | Reported by a Hermes run (new or re-opened). The default filter |
| fixed (confirmed by NOS inventory) | Closed because NOS's own data shows the fix |
| fixed (subject removed) | The host or image is gone |
| fixed (confirmed by admin) | A maintainer confirmed a held closure |
| **closed by Hermes, not confirmed by NOS** | Hermes reported it fixed, but NOS could not confirm it from its own data. It has its own filter and is never shown as clean |
| `accepted_risk` | A maintainer accepted the risk with a reason; expires after 90 days by default, at most 365; re-opens on expiry, KEV listing or a version change |
| `false_positive` | A maintainer marked it with a category and reason; re-opens when the installed version changes |
| stale since … | No complete run covered the subject in 48 hours. Never shown as "0 findings" |
| not assessed | No complete run has covered the subject yet |
| feed `<source>` stale | A feed is past its maximum age; runs do not close findings resting on it |

**Held closures:** Nebula holds a closure for an admin instead of applying
it when NOS's own data contradicts it, the finding was KEV-listed or
critical in this episode, it rests on a feed on probation, or it would close
too many findings at once. Held findings stay `open`.

## Mark crown jewels and entry points

**Goal:** tell Nebula which systems matter most and which are entry
points (internet, NetBird), for prioritisation.

**Prerequisites:** admin.

**Steps:** open `/vuln/jewels`, pick a subject and a role, confirm or change
the suggested weight (1 to 10), and save. **Unmark** removes it.

**Expected result:** the page lists the marked crown jewels and entry
classes; every change is audited.

**Note:** suggested weights are only prefilled; nothing is applied without
your confirmation. Exposure and host criticality are not yet connected to
the priority tier (see *What works in this release*).

## Get notified about KEV and critical findings

**Goal:** a message when a finding becomes KEV-listed or critical, or Hermes
stops reporting.

**Prerequisites:** notifications configured in `server.json` (admin guide
[10.1](../admin/guide.md#101-notifications)); the vulnerability token set up.

**Steps:** nothing extra. Test the providers with
`nebula-server -config /etc/nebula/server.json -notify-test`.

**Expected result:** events `vuln.kev_new`, `vuln.critical_new`,
`vuln.hermes_stale` (no complete run for 48 hours), `vuln.feed_stale`,
`vuln.feed_regressed`; at most 10 messages per hour, the rest in an hourly
`vuln.digest`. Messages contain CVE ID, subject, tier and KEV flag, never
the LLM assessment.

## Export all findings

**Goal:** a CSV or JSON file of all findings.

**Prerequisites:** admin with an open privileged session.

**Steps:** open `/vulnerabilities/export?format=csv` (default) or
`/vulnerabilities/export?format=json`.

**Expected result:** a download with key, subject, state, versions, tier,
CVSS, KEV, dates and an advisory link. No assessment text, admin reasons,
host labels or addresses. More than 200,000 findings are refused, never
exported in part. Cells starting with `=`, `+`, `-`, `@`, a tab or a
carriage return get a leading `'`.

**Common errors:** the export is refused without a privileged session, or
when the audit entry cannot be written (`vuln.export_refused`).

## Check a container image with host Trivy

**Goal:** a quick image scan without Hermes.

**Prerequisites:** Trivy installed by you on the host.

**Steps:** run the read action `image.vulnerabilities` on the host.

**Expected result:** the org chart's image badge shows the result,
labelled "host Trivy, partial". When a fresh complete Hermes run covers the
image, the badge shows the Hermes status instead. The two are never merged.

## Read a fix suggestion card

**Goal:** decide what to do with a fix suggestion from the ops agent, and
submit a fix that you have checked yourself.

**Status:** no card can appear in this release. The card and the suggestion
form are built, but three things stop a card from appearing: the agent is
off by default, this release has no form to switch it on, and the server
does not yet connect the finding sources, so the agent never has a finding
to work on and no fix note can be made. Switching the settings on by other
means does not change that. A default install shows no card, and neither
does an install with the settings on (admin guide
[10.6](../admin/guide.md#106-ops-agent), "Status in this build"). Answers
to questions in the Ops tab are not produced yet.

**Prerequisites:** the ops agent is set up by an admin (admin guide
[10.6](../admin/guide.md#106-ops-agent)); you are an admin. Other users do
not see the Ops tab.

**Steps:**

1. Open the **Ops** tab of the assistant panel. A card is headed "Fix
   suggestion" with its number. With the agent off, the tab says "Agent
   switched off. No open suggestion."; with the agent on and no card yet, it
   says "No suggestion yet.". In this release that is the normal state, since
  no finding source is connected (see Status above). The question form is at the top of the tab;
   in this build its questions are stored but not answered (admin guide
   [10.6](../admin/guide.md#106-ops-agent)).
2. Read "What" first (the headings are shown in English). NOS renders it
   from its own stored facts: package and version, tier, KEV and exposure.
   It is not model text.
3. Read the card's label, which is shown in English and German: "Generated
   by an LLM – unverified. NOS checked only that each step is a catalog
   action on this host." The German text is "Von einem LLM erzeugt –
   ungeprüft. NOS hat nur geprüft, dass jeder Schritt eine Katalog-Aktion
   auf diesem Host ist." The text from the model is shown escaped. Treat it
   as a draft.
4. Read "How to fix". The steps are in order. Each step has one button.
5. Press a step's button. For every step except a container update, it
   **opens the normal form** with the action and the host filled in.
   Nothing is submitted by the button. A container update step is the
   exception in this build: its button opens a page that answers `404`.
   If you still want that update, use the container page by hand. An
   execution with the same action family on the same host is marked as
   suggested anyway, while a note for that host is stored.
6. Fill in every parameter yourself (the unit name, the container, the
   stage plan). The suggestion supplies no parameter and no secret.
7. Check the finding page and the section the card cites. They stay the
   authority.
8. Submit. Before you submit, the form shows the banner "Opened from an
   agent suggestion. This execution needs a security-key touch." (German:
   "Aus einem Agenten-Vorschlag geöffnet. Diese Ausführung braucht eine
   Security-Key-Berührung.") Touch your security key.

Mitigations (for example "restrict the port at the firewall") are text only.
They have no button and no form. If you act on one, do it outside the card,
with your own command, after you have checked it.

A card marked "outdated: findings changed" (the German label is in the
German copy of this page) was made for findings that have since changed. Do
not act on it; look at the current findings first.

**Dismissing a card** hides it and changes nothing else. It does **not**
remove the security-key rule for that host (below).

**The security-key rule.** Every execution that you open from a suggestion
needs a security-key touch, **also when the action is LOW**. While a stored
fix note exists for a host (at most 30 days, or 500 notes), a LOW action of
the same kind on that host that you start by hand needs the key too. In
this release no fix note and no card can come about yet, so no execution is
marked yet. The
operation page shows the risk the executor decides, which is at least MEDIUM
for a suggested execution, but no "From an agent suggestion" label; only the
form banner marks a card-opened form. Admin guide
[10.6](../admin/guide.md#106-ops-agent) explains the limit: a compromised
server can omit the marking.

**Residual risk** (ADR 0016, verbatim): an admin follows a plausible but
wrong suggestion, fills in the parameters and approves it with the key. The
card reduces reading, not responsibility; the finding page and the cited
section stay the authority.

**Expected result:** a submitted execution with its own approval and its own
audit entry. Before you submit, you saw the banner above, if you opened the
form from a card.
