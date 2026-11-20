# Decision paper: package inventory for the vulnerability export (ADR 0011)

Status: **open, maintainer decides.** Nothing in this paper is decided. Each
point gives the question, what ADR 0011, the spec and the code say today, the
options, a recommendation and the consequence for the code. The recommendations
are proposals for the maintainer; none of them changes an ADR or spec.

Ticket: iv01 (autopilot). Blocks: iv08 (the rest of the chain iv02–iv10 waits
for this paper; per the ticket, iv02–iv07 build what ADR and code already fix).

## Why this is open

ADR 0011 ([docs/adr/0011-vulnerability-management.md](../adr/0011-vulnerability-management.md))
defines the package inventory that Hermes matches against (D3, `vuln-inventory-v1`),
but it leaves four points open or silent: how long package reads are kept, how
old a read may be and still count as complete, what the classifier does when a
subject has no inventory, and how `image.packages` (optional in D3) gets its
freshness. Today `cmd/nebula-server/vuln.go` returns only the empty snapshot
`nos-empty-<hour>` (`vulnSnapshotPrefix`, `VulnSnapshot`), because the server
does not store package lists, so every export carries no inventory.

Reference points used below (all verified in this clone):

| Name | Where | Value / meaning |
| --- | --- | --- |
| `vulnstore.MaxInventoryAge` | `internal/vulnstore/vulnstore.go:59` | 24 h, maximum age of a snapshot ID |
| `vulnstore.StaleAfter` | `internal/vulnstore/vulnstore.go:83` | 48 h, run staleness (ADR D6, Q5) |
| `permit.PackageListInstalledMinInterval` | `internal/permit/lease.go:114` | 6 h, minimum interval per host |
| `VulnInventory` | `internal/web/api/vuln_export.go:50` | "A snapshot is immutable for its ID" |
| `vulnSnapshotPrefix`, `VulnSnapshot` | `cmd/nebula-server/vuln.go:148–150` | returns the empty `nos-empty-<hour>` snapshot |
| `leaseableAction` | `internal/executions/readgrants_propose.go:173` | which actions a proposed read lease may contain |
| `imageParam` | `internal/executions/actions/actions.go:172` | `image` parameter (`repo@sha256:digest`) of `image.packages` (line 500) |
| `RunDueReadGrants` | `internal/executions/leaserunner.go` | runs due, approved read leases |

---

## E1: Retention of package reads

**Question.** Which package reads (host `package.list_installed`, image
`image.packages`) does NOS keep, and for how long?

**What the sources say.**

- ADR 0011 D6, "Retention" (lines ~812–818): open, accepted and false-positive
  findings while the subject exists; `fixed` findings 365 days; run records
  90 days; assessment text of closed findings 90 days. Package reads are not
  named.
- ADR 0011 D5, "Closure classes" (line ~687 ff.): a closure is classified
  against NOS's current inventory; "installed" and the version come from "NOS's
  latest read that lists the component; if the latest read is partial (D3) and
  does not list it, from the last complete read". So NOS needs at least the
  latest read and the last complete read per subject.
- ADR 0011 D3 (`VulnInventory`, `vuln_export.go:50`): a snapshot is immutable
  for its ID, and `vulnstore.MaxInventoryAge` (24 h) bounds how long a snapshot
  ID stays valid. A snapshot therefore points at reads that must still exist for
  as long as the ID is valid.
- Spec `docs/spec/03-processes-and-data.md` (line 57) lists the vulnerability
  tables; it has no table for package reads yet.

**Options.**

1. Keep only the latest read per host.
2. Keep the latest read, the last complete read, and every read that a still
   valid snapshot points to; delete everything else.
3. Keep a fixed history (for example 90 days of reads).

**Recommendation: option 2.** It is the smallest set that D5 closure
classification and the D3 snapshot guarantee need. Option 1 breaks D5 when the
latest read is partial. Option 3 is a new retention number that no ADR decides;
if the maintainer wants history for audit, it should be a new decision (Q-style
entry in ADR 0011), not an implementation default. The rule in option 2 needs
no number of its own: it follows from D5 and `MaxInventoryAge`. The iv02/iv04
work reportedly already follows this rule (taken from the ticket; not verified
in this paper).

**Consequence for the code.** Pruning of package reads runs with the same
clock as `vulnstore` pruning. Rows that are neither latest, last complete nor
pinned by a valid snapshot are deleted. Tests must cover: a partial latest read
does not drop the last complete read; a snapshot ID keeps its read until
`MaxInventoryAge` has passed.

---

## E2: Maximum age of a read

**Question.** How old may a read be and still count as complete (and so cover a
subject in a run and keep a closure possible)?

**What the sources say.**

- ADR 0011 D3: `package.list_installed` runs at most every 6 h per host
  (`permit.PackageListInstalledMinInterval`). This bounds the frequency from
  below only.
- ADR 0011 D5 limits the age of the **snapshot** (`MaxInventoryAge`, 24 h) and
  the age of a run's **feed** data; it does not limit the age of a read.
  `vulnstore.MaxInventoryAge` (`internal/vulnstore/vulnstore.go:59`) is checked
  at run start against the snapshot ID, so it bounds snapshot age, not read age.
- ADR 0011 D6 "Staleness" limits the last complete **run** per subject
  (`vulnstore.StaleAfter`, 48 h, Q5). This is about the assessment, not the
  inventory.
- Result: without a rule, a host whose read lease has expired keeps its last
  complete read forever, and that read can still cover the host in a run and
  support a closure.

**Options.**

1. No limit on the age of a read.
2. 24 h (`MaxInventoryAge`): four missed 6-hour reads.
3. 48 h (`vulnstore.StaleAfter`): the run staleness threshold of D6.

**Recommendation: option 2 (24 h).** A read older than 24 h is exported as
**not complete** (the D3 partial-read path), so it does not cover that host in
a run. What a run then does with the host's findings is set by D5 for
incomplete or uncovered subjects. The sources cited here do not state that
outcome. D5 has no text on it. Two history notes in ADR 0011 touch the topic:
line 2115 says a failed, incomplete or invalid **agent** read fails the agent
run before matching, and line 662 is about incomplete **runs**. Neither says
what happens to closures of an incomplete subject in a Hermes run. The outcome
must be written into ADR 0011 before the code is built (see the list at the end). Note: `HoldClassifyFailed` is not the
reason for this case. In `internal/vulnstore/complete.go` it is set only when
the classifier returns an error (lines 646–647) or returns a class outside the
known set (lines 654–655).

Option 3 (48 h) would let a host be covered by a read up to two days old. The
24 h figure is proposed because it is four missed 6-hour reads, not because of
`MaxInventoryAge`: that constant limits snapshot age at run start, not read
age. A 24 h read inside a 24 h snapshot is already up to 48 h old when the run
uses it. Option 1 is the case the ADR text does not address; it is listed only
for completeness.

**Consequence for the code.** The export marks a subject without a fresh
complete read as incomplete (same effect as D3 partial read). The 24 h read age
needs its own named constant next to the code that enforces it. It must not
reuse `vulnstore.MaxInventoryAge`, whose meaning is snapshot age at run start.
The name and value are a maintainer decision (24 h proposed). Tests: a read
exactly at 24 h and one at 24 h + 1 s; a fresh read after a stale one restores
coverage.

---

## E3: Missing inventory in the classifier

**Question.** What does the classifier do with a subject that has no usable
inventory?

**What the sources say.**

- **Today's code (fail-closed).** `cmd/nebula-server/vuln.go:129-137`:
  `vulnClassifier.Classify` always returns `errVulnNotCheckable`, because NOS
  stores no package inventory. Every requested run closure therefore hits the
  classifier-error branch and is held as `HoldClassifyFailed`
  (`internal/vulnstore/complete.go:646-647`). Today no closure is closed as
  `hermes_unconfirmed`, for hosts or for images.
- ADR 0011 D5, closure-class table (line ~704–705): "Unconfirmed" covers "every
  other run closure: not checkable now (incl. kernel version unknown, image
  packages unknown, …)". Unconfirmed closures are applied as `fixed` with
  `closed_by = hermes_unconfirmed` and shown as "closed by Hermes, not confirmed
  by NOS" (D6), except that episode KEV or peak tier `critical` is always held
  (D7). So the ADR table, read literally, is looser than today's code for both
  host and image subjects with no inventory.
- ADR 0011 D3: completeness is defined only by the read itself (exit success,
  every line parsed, limit not reached). It does not say what happens when a
  subject has **no** read or no OS release.
- **Proposal, not in the ADR and not in any file in this clone.** The autopilot
  ticket for iv06 asks for host subjects without any stored read to be held
  instead of marked Unconfirmed. `docs/implementation/vulnerability-management.md`
  has no iv06 entry, and no code in `internal/` or `cmd/` implements a per-host
  rule (the classifier at `cmd/nebula-server/vuln.go:129-137` holds everything).
  This rule departs from the D5 Unconfirmed row.
- **Proposal, same source (ticket iv03).** Export a host without a known OS
  release (no `core.facts` result, or not Debian/Ubuntu) as **incomplete**. It
  is not in D3 or D5 and no file in this clone states it. It is a new rule.

**Options.** The "vs. today" column compares with the code as it stands
(`cmd/nebula-server/vuln.go:129-137`: every closure held). The "vs. D5" column
compares with the ADR table.

| Option | Host, no read | Image, no `image.packages` | vs. today (code) | vs. D5 table |
| --- | --- | --- | --- | --- |
| 1. ADR table as written | Unconfirmed (closed as `hermes_unconfirmed`) | Unconfirmed | **Loosens** for hosts and images | matches |
| 2. Hold host closures without a stored read; images Unconfirmed | Held | Unconfirmed | Hosts: unchanged. **Images: loosens** (held → `hermes_unconfirmed`) | Tightens hosts; images match |
| 3. Hold all closures without inventory | Held | Held | Unchanged for both (no loosening) | Tightens hosts and images |

Option 1 and option 2 both loosen today's behaviour for image subjects. Only
option 3 keeps today's fail-closed result for every subject until the code
stores package lists.

**Recommendation: option 2, with the image loosening accepted explicitly, and
the same export rule for the OS-release case in ticket iv03 (export as
incomplete).** Holding a host closure without any read stops a run from closing
findings by omission, which is the failure mode this ADR guards against. Image
subjects follow the D5 table because an image with no `image.packages` is a
known and common state (the action is optional, E4). This choice moves images
from held to closed-as-unconfirmed, which today's code does not do. If the
maintainer does not want that loosening before `image.packages` is stored,
choose option 3 for images and keep option 2 for hosts.

**Decision needed.** Pick one of the three options. For option 2 or 3, confirm
the image choice above. If option 1 or 2 is chosen, the ADR table (or the iv06
rule) must be written down first. Both host rules above are proposals and need
the maintainer's approval before any code follows them.

**Consequence for the code.** Nothing changes in the code yet; the classifier
keeps holding every closure (`cmd/nebula-server/vuln.go:129-137`) until a
decision is taken. Whatever is chosen, the ADR table needs an explicit row for
"host subject with no stored read" and a rule for the unknown OS release (see
the list at the end).

---

## E4: `image.packages` and freshness

**Question.** How does `image.packages` get fresh data, and does NOS run it on a
schedule?

**What the sources say.**

- ADR 0011 D3: `image.packages` is an **optional** LOW read action, run with
  the operator-installed Trivy under the P1-30 rules.
- `internal/executions/actions/actions.go:500`: `image.packages` takes
  `Params: imageParam`, i.e. the image digest is a required parameter.
- `internal/executions/readgrants_propose.go:173` (`leaseableAction`): a
  proposed read lease can contain only actions for which this predicate holds;
  an action with a required parameter is not a lease target. So a lease cannot
  carry the image digest and `image.packages` cannot run from a lease today.
- Host reads are different: `package.list_installed` is a lease action;
  `RunDueReadGrants` (`internal/executions/leaserunner.go`) runs due reads of
  an **approved** lease. The proposal and commit paths take a user
  (`ProposeReadGrant`, `internal/executions/readgrants_propose.go:259`;
  `CommitReadGrant`, line 475, which also takes an assertion). The files cited
  here show no automatic caller of these functions.
- ADR 0007 line 39 describes the **baseline for schedule grants**
  (`internal/permit/schedule.go`, `internal/schedgrant`): they currently require
  a privileged session to propose and browser-approve. ADR 0007 says nothing
  about read leases. Using the same manual approval for host read leases is
  this paper's proposal, not something the ADR states.

**Options for (a) image freshness.**

1. Add a parameterised image schedule now (in iv-chain, before iv10).
2. Put `image.packages` in its own follow-up chain after iv10, with its own
   decision on digest source and scheduling. Until then, image packages are not
   stored and image subjects stay Unconfirmed (E3).
3. Make the image digest a lease parameter (changes `leaseableAction`).

**Recommendation for (a): option 2.** Scheduling needs a decision on where the
digest comes from and who approves it, and the ticket chain does not have that.
Storing nothing for images until then is consistent with E3. Note that option 2
means image subjects are Unconfirmed (closed as `hermes_unconfirmed`) until then,
which loosens today's held state (E3, table). If that is not acceptable, E3
option 3 keeps images held. Option 3 here changes a security predicate
(`leaseableAction`) and needs its own review.

**Options for (b) host freshness.**

1. Create `package.list_installed` leases automatically for each host.
2. No automatic lease. The admin approves a read lease for the host; until then
   the host has no current read and E3 (hold) applies. The UI and export show
   the hint "no package inventory / inventory older than …" (from iv09).

**Recommendation for (b): option 2.** An automatic lease would be a new grant
created by software. Neither ADR 0007 nor ADR 0011 makes that decision (ADR 0007
line 39 is only the schedule-grant baseline, see the sources above), so the
manual approval path is kept until the maintainer decides otherwise. The hint
from iv09 makes the missing read visible instead of silent.

**Decision needed.** Confirm (a) option 2 and (b) option 2, or name a different
approver for host leases.

**Consequence for the code.** No code change in this paper. No new read grant
is created by the server; `leaseableAction` stays as it is.

---

## Needs ADR/spec text after the decision

These items are not changed here (`docs/adr/` and `docs/spec/` are protected).
Once the maintainer decides, the following text must be written by a maintainer:

1. **ADR 0011 D6 "Retention"**: add package reads (E1 option 2: latest, last
   complete, and reads pinned by a valid snapshot).
2. **ADR 0011 D3 or D5**: maximum age of a read for completeness (E2, 24 h
   proposed).
3. **ADR 0011 D5 closure-class table**: a row for "host subject with no stored
   read" (E3 option 2), and the D3 rule for an unknown OS release (iv03).
4. **ADR 0011 D3 `image.packages`**: freshness and scheduling (E4 a), and the
   statement that host reads are never created automatically (E4 b, a proposal
   of this paper; ADR 0007 line 39 does not cover read leases).
5. **`docs/spec/03-processes-and-data.md`** (vulnerability tables, line 57):
   name the package-read table, its retention rule and whether it has a
   column for the completeness flag.
6. **`docs/implementation/vulnerability-management.md`**: point the plan at
   this paper's answers once they are decided.

## Test

None. This is a documentation-only change; no Go code, shell script or YAML
file is touched.
