# Decision paper: package inventory for the vulnerability export (ADR 0011)

Status: **partly decided by the maintainer, 2026-11-20**; see "Decision
(2026-11-20)" and "Still open after the decision" below (previously: **open,
maintainer decides.** This paper decides nothing). The analysis sections E1–E4
are kept as written before the decision; where the decision differs from them,
the decision wins. Points that ADR 0011 already decides are not open and are
marked as decided (E4). Each point gives the question, what ADR 0011, the spec
and the code say today, the options, a recommendation and the consequence for
the code. The recommendations in E1–E4 were proposals for the maintainer and
changed no ADR or spec by themselves. The maintainer's decision is recorded in
ADR 0011 as the dated amendment "Amendment 2026-11-20: package inventory
retention and read interval" (previously: no ADR text for these points).

Ticket: iv01 (autopilot). Which tickets wait and which go ahead (previously:
iv08 and the E1–E3 parts of iv02–iv07 waited for the whole paper):

- **Goes ahead with the decision:** iv02 (E1: keep 2 reads per host), iv08
  (E2: count-based, no time limit; E3 host and OS-release rules), iv03 (E3:
  unknown OS release exported as incomplete), iv06 (E3: host without a stored
  read is held), iv09 (host tab), and the parts of iv02–iv07 that ADR 0011
  and the current code already fix.
- **Still waits for the maintainer:** the precedence of E1 over D5 and snapshot
  pinning (question Q1) and the E1/E2 reading (Q2), which iv02 and iv08 need
  before they delete or age out a read; the classifier rule for **image**
  subjects without `image.packages` (Q3, iv06): until it is answered, image
  closures stay held as in today's code.
- **Depends on E4:** image freshness (Q4) and the lease digest parameter (Q5)
  are still open. E4 (a) option 1 would put an image schedule before iv10,
  option 2 puts it after iv10. Until decided, iv10 must not assume image
  freshness.
- **iv12:** named by the maintainer in the E4 answer ("siehe iv12") for the
  retention of image inventories. Its ticket text is not in this clone; this
  paper knows only that reference.

The ticket text is not in this clone. This mapping comes from the references in
this paper; the maintainer should check it against the ticket.

## Decision (2026-11-20)

The maintainer (Axel) decided on 2026-11-20 at 22:12 (UTC+1) in chat. Where the
decision differs from a recommendation below, the decision wins. Original
wording (German), verbatim:

> - **E1:** Je Host immer **2 Inventar-Lesungen** aufheben (vorher/nachher);
>   ältere werden gelöscht.
> - **E2:** Eine Lesung gilt als **zu alt, sobald eine dritte vorhanden ist**
>   (zählbasiert, keine Zeitgrenze).
> - **E3:** Empfehlung angenommen (Host ohne Lesung → Schließung gehalten;
>   unbekanntes OS-Release → als unvollständig exportiert).
> - **E4:** Container-Images: je Image immer die **3 letzten Inventare** halten
>   (siehe iv12).
> - **Lese-Intervall:** Standard-Intervall der Host-Lese-Freigabe für
>   `package.list_installed` **6 Stunden**.

The quote above holds only the maintainer's words (previously it also held a
note from Claude, now under "Note (Claude)" below).

The same rules in English. The bold text translates the quote; the ticket
references, the comparison with the earlier recommendations and the pointers
to open questions are added by Claude and are not part of the decision:

1. **E1, retention of host reads.** NOS always keeps **2 package reads per
   host** (the one before and the one after); older reads are deleted. This
   replaces the recommended option 2 (latest, last complete and
   snapshot-pinned reads). Tickets: **iv02** (inventory store and pruning).
2. **E2, age of a read.** A read counts as **too old as soon as a third read
   exists** for the same host. The rule is count-based; there is **no time
   limit**. This replaces the proposed 24 h limit. Tickets: **iv08** (read
   age: count-based, no time constant), **iv09** (host tab).
3. **E3, missing inventory.** "Recommendation accepted", with the two rules
   the maintainer named: a closure for a **host without a stored read is
   held**; a host with an **unknown OS release is exported as incomplete**.
   Tickets: **iv08**, and the tickets that build these two rules (iv06
   classifier, iv03 hook; see E3 below). The image part of the recommendation
   is not named in the answer and is still open (Q3).
4. **E4, container images.** For each image NOS always keeps the **3 latest
   inventories**. Tickets: **iv12** (see the ticket list at the top). The rest
   of E4 is still open (Q4, Q5).
5. **Read interval.** The default interval of a host read lease for
   `package.list_installed` is **6 hours**. This answers E4 open point (2).
   Tickets: **iv08** (the read cadence that E2 relies on), **iv09** (host tab
   that shows the read age). The ticket that sets this default when a read
   lease is proposed is not named in this clone.

### Note (Claude)

Not part of the decision; Claude's notes and readings, for the maintainer to
confirm or correct.

- Given to the maintainer with the decision (originally in German: "Hinweis
  Claude an Axel"): under E2 a host that delivers no new reads keeps its last
  read indefinitely. Proposal, not decided: the UI shows the age of the read
  clearly (iv09), without changing the effect of the rule.
- The 6 h default equals the floor `permit.PackageListInstalledMinInterval`
  (`internal/permit/lease.go:114`), so a lease with the default runs at the
  highest frequency the permit allows.

### Still open after the decision (questions for the maintainer)

The ADR 0011 amendment lists the same points as open. Q1 and Q2 carry a
reading by Claude that iv02 and iv08 may follow only once the maintainer
confirms it.

- **Q1 (E1 against D5 and snapshot pinning).** E1 keeps exactly 2 reads. ADR
  0011 D5 (closure-class table, line ~704) takes "installed" from the last
  complete read when the latest read is partial, and a snapshot ID stays
  valid for `vulnstore.MaxInventoryAge` (24 h) and is immutable for its ID
  (`internal/web/api/vuln_export.go:52–54`). If both kept reads are partial,
  or a valid snapshot points at the read E1 would delete, the rules collide.
  **Reading (Claude):** the existing ADR text wins. The last complete read
  and every read a still valid snapshot points at are kept **in addition to**
  the 2 reads, until neither applies; such an extra read counts neither
  toward E1's 2 reads nor as E2's third read. Confirm or correct.
- **Q2 (E2 together with E1).** E1 never keeps more than 2 reads, so E2's
  "third read" exists only at the moment a new read is stored. Two readings:
  (i) the oldest of the three is too old and E1 deletes it, so a stored read
  is never too old and the latest read always counts; (ii) the "before" read
  counts as too old as soon as a newer read exists, so only the latest read
  ever counts and the "before" read is kept only for comparison.
  **Reading (Claude):** (i), because it is the literal wording. Confirm (i)
  or choose (ii). With (ii), D5's fallback to the last complete read (Q1)
  must still be settled.
- **Q3 (E3, image subjects).** The recommendation (option 2) asked the
  maintainer to confirm explicitly that image closures without
  `image.packages` are closed as `hermes_unconfirmed` (D5 table) instead of
  held as today (section E3, "Decision needed"). The answer names only the
  host and OS-release rules. Choose: option 2 (images `hermes_unconfirmed`)
  or option 3 (images held). Until then the code keeps holding them.
- **Q4 (E4 (a), image freshness).** Options 1–3 in E4 are not answered;
  the recommendation was option 2.
- **Q5 (E4 (1), lease digest parameter).** Whether `image.packages` may be
  leased with its image digest as a lease parameter is not answered;
  `leaseableAction` stays unchanged until then.

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
| `VulnInventory` | `internal/web/api/vuln_export.go:52–54` | "A snapshot is immutable for its ID" |
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
- The code's `VulnInventory` interface (`internal/web/api/vuln_export.go:52–54`)
  says a snapshot is immutable for its ID. That is a code comment, not ADR text.
  `vulnstore.MaxInventoryAge` (24 h) bounds how long a snapshot ID stays valid.
  A snapshot therefore points at reads that must still exist for as long as the
  ID is valid.
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
no number of its own: it follows from D5 and `MaxInventoryAge`. This retention rule is not decided yet, so iv02–iv07 must not implement it before the maintainer decides (they build only what ADR and code already fix, the "Goes ahead" bullet at lines 14–15).

**Consequence for the code.** Conditional on the choice. Only if option 2 is
chosen: pruning of package reads runs with the same clock as `vulnstore` pruning,
and rows that are neither latest, last complete nor pinned by a valid snapshot
are deleted. Tests must then cover: a partial latest read does not drop the last
complete read; a snapshot ID keeps its read until `MaxInventoryAge` has passed.
With option 1 or 3 the rule above does not apply and the tests change with it.

---

## E2: Maximum age of a read

**Question.** How old may a read be and still count as complete (and so cover a
subject in a run and keep a closure possible)?

**What the sources say.**

- ADR 0011 D3: `package.list_installed` runs at most every 6 h per host
  (`permit.PackageListInstalledMinInterval`). This bounds the frequency from
  below only.
- ADR 0011 D5 run protocol (lines 492–493) rejects a run whose inventory
  generation is more than 24 h older than the current one. The code's
  `vulnstore.MaxInventoryAge` (`internal/vulnstore/vulnstore.go:59`, 24 h) is the
  snapshot-age limit, so it bounds snapshot age, not read age. ADR 0011 D4 limits
  the age of **feed** snapshots (72 h for daily feeds, line 334). Neither limits
  the age of a read.
- ADR 0011 D6 "Staleness" limits the last complete **run** per subject
  (`vulnstore.StaleAfter`, 48 h, Q5). This is about the assessment, not the
  inventory.
- Result: without a rule, a host whose read lease has expired keeps its last
  complete read forever, and that read can still cover the host in a run and
  support a closure.

**Options.**

1. No limit on the age of a read.
2. 24 h (proposed value; the same number as `MaxInventoryAge`, but not derived
   from it).
3. 48 h (`vulnstore.StaleAfter`): the run staleness threshold of D6.

**Recommendation: option 2 (24 h).** A read older than 24 h is exported as
**not complete** (the D3 partial-read path), so it does not cover that host in
a run. What a run then does with the host's findings is set by D5 for
incomplete or uncovered subjects. The sources cited here do not state that
outcome. D5 has no text on it. ADR 0011 line 662 is about incomplete **runs** (an incomplete run only adds or
updates) and says nothing about an incomplete or old **read**; the feed-side
rules around line 2191 concern the primary-anchor list read, not package reads.
Neither says what happens to closures of an incomplete subject in a Hermes run. The outcome
must be written into ADR 0011 before the code is built (see the list at the end). Note: `HoldClassifyFailed` is not the
reason for this case. In `internal/vulnstore/complete.go` it is set only when
the classifier returns an error (lines 646–647) or returns a class outside the
known set (lines 654–655).

Option 3 (48 h) would let a host be covered by a read up to two days old. The
24 h figure is a judgement, not a value derived from a source. Neither
sourced value gives it: `MaxInventoryAge` limits snapshot age at run start, not
read age, and `PackageListInstalledMinInterval` (6 h) is a minimum interval, not
a cadence. It limits how often a read may run, not how often it runs. The real
cadence comes from the approved lease, so the 24 h limit must be checked against
the lease interval once the maintainer sets it (E4 b). The maintainer may choose
another value. A 24 h read inside a 24 h snapshot is already up to 48 h old when the run
uses it. Option 1 is the case the ADR text does not address; it is listed only
for completeness.

**Consequence for the code.** Conditional on the choice. With option 1 there is
no age check and nothing below applies. With option 2 or 3 the export marks a
subject without a fresh complete read as incomplete (same effect as a D3
partial read). The read age then needs its own named constant next to the code
that enforces it. It must not reuse `vulnstore.MaxInventoryAge`, whose meaning
is snapshot age at run start. The name and value are a maintainer decision; 24 h
is only the proposal. Tests, for the chosen value: a read exactly at the limit
and one a second past it; a fresh read after a stale one restores coverage.

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
- `internal/executions/readgrants_propose.go:173-179` (`leaseableAction`): a
  proposed read lease can contain only actions for which this predicate holds.
  It requires `len(a.Params) == 0` (line 178), so `image.packages` (it takes
  `imageParam`) is not a lease target today. This is a code predicate, not an
  ADR rule. ADR 0007 line 69 lets each lease action carry exact parameters: the
  Actions row binds "exact canonical parameters hash", and
  `permit.ReadGrantAction.ParametersHash` (`internal/permit/lease.go:147-152`)
  is that binding. The permit allowlist already lists `image.packages` with the
  digest pinned by the grant's parameters hash (`internal/permit/lease.go:99-103`).
  So under ADR 0007 a lease could carry one image digest. ADR 0011 D3 and line
  1175 decide that `image.packages` is in the read-only allowlist. They do not
  say whether a lease may carry its digest parameter, and the code blocks that
  today.
- Host reads: `package.list_installed` has no parameters and is in the code's
  read-only allowlist (`internal/permit/lease.go:98`), so `leaseableAction`
  (`internal/executions/readgrants_propose.go:173`) accepts it.
  `RunDueReadGrants` (`internal/executions/leaserunner.go`) runs due reads of
  an **approved** lease. The proposal and commit paths take a user
  (`ProposeReadGrant`, `internal/executions/readgrants_propose.go:259`;
  `CommitReadGrant`, line 475, which also takes an assertion). The files cited
  here show no automatic caller of these functions.
- **ADR 0007 decides the approval model for host read leases.** Its
  "One standing read-grant mechanism" (lines 48–60): in Standard mode one fresh
  user-verified assertion approves the complete grant digest (targets, actions,
  parameters, duration, budget); grant creation does not require a privileged
  session, which the ADR calls "an explicit change to the existing schedule
  proposal/commit precondition". Its identity table (line 68): renewal requires
  new approval; default 7 days, maximum 30. Lines 77–78: new enrollment, changed
  tag membership or a replacement key never joins a lease automatically.
  Lines 121–122: read runs need unlocked credentials but no privileged session
  and no per-run approval.
- Line 39 of ADR 0007 is the **pre-ADR baseline** for schedule grants (privileged
  session to propose and browser-approve). The read-lease decision replaces
  that baseline; it does not apply to read leases any more.
- **Decided by ADR 0011 D3 (not open).** ADR 0011 D3 (lines 198–199) adds
  `package.list_installed` to the read-lease allowlist with its own cost limit
  (at most every 6 h per host). The code does this: `internal/permit/lease.go:95–98`,
  with `PackageListInstalledMinInterval` at `lease.go:114`. What is still stale
  is the text: ADR 0007's initial allowlist (lines 83–84) does not name it, and
  the spec text (ADR 0011 line 1175: spec 07 and 10) is still to be written.
  That is a documentation follow-up (see the list at the end), not a decision.
- **Decided by ADR 0011 D3 and line 1175 (not open).** `image.packages` is in
  the read-only allowlist. The code agrees: `internal/permit/lease.go:99–103`
  lists it and cites ADR 0011 D3. Only its use in a lease with a digest
  parameter is open (decision (1) below).
- **Decided by ADR 0011 D3 and line 1175 (not open).** `image.packages` is in
  the read-only allowlist. The code agrees: `internal/permit/lease.go:99–103`
  lists it and cites ADR 0011 D3. Only its use in a lease with a digest
  parameter is open (decision (1) below).

**Options for (a) image freshness.**

1. Add a parameterised image schedule now (in iv-chain, before iv10).
2. Put `image.packages` in its own follow-up chain after iv10, with its own
   decision on digest source and scheduling. Until then, image packages are not
   stored and image subjects stay Unconfirmed (E3).
3. Allow one exact image digest per lease action: the digest is a lease
   parameter bound by `ParametersHash` (ADR 0007 line 69). Membership in the
   read-only allowlist is already decided (ADR 0011 line 1175), so this option
   only changes `leaseableAction` (`readgrants_propose.go:178`, which rejects
   any action with parameters).

**Recommendation for (a): option 2.** Scheduling needs a decision on where the
digest comes from and who approves it, and the ticket chain does not have that.
Storing nothing for images until then is consistent with E3. Note that option 2
means image subjects are Unconfirmed (closed as `hermes_unconfirmed`) until then,
which loosens today's held state (E3, table). If that is not acceptable, E3
option 3 keeps images held. Option 3 here changes a security predicate
(`leaseableAction`) and needs its own review.

**Options for (b) host freshness.**

1. Create `package.list_installed` leases automatically for each host. This
   conflicts with ADR 0007: each grant needs one fresh user-verified assertion
   (creation and renewal), so software cannot create it.
2. No automatic lease. The admin approves a read lease for the host under ADR
   0007's assertion rule; until then the host has no current read and E3
   (hold) applies. The UI and export show the hint "no package inventory /
   inventory older than …" (from iv09).

**Recommendation for (b): option 2.** This is the rule ADR 0007 already states;
no new approval decision is needed. The hint from iv09 makes the missing read
visible instead of silent. One detail stays open (decision (2) below): the
default interval of a host read lease, which sets the cadence that E2 depends on.

**Decision needed.** Confirm (a) option 2, or choose option 1 or 3. For (b), no
approver decision is needed. Open: (1) whether `image.packages` may be leased
with its digest as a lease parameter. Its read-only allowlist membership is
decided (ADR 0011 D3, line 1175). The open part is the parameter: `leaseableAction`
(`readgrants_propose.go:178`) rejects any action with parameters today, and
ADR 0007 line 69 allows a parameter hash; (2) the default interval of a host
read lease, which E2 needs. ADR 0007 line 72 requires a minimum interval in the
grant digest but sets no default. Whether
`package.list_installed` may sit in a read lease is decided (ADR 0011 D3) and
is not listed here.

**Consequence for the code.** None until the maintainer decides. If (a) option 3
is chosen, `leaseableAction` (`readgrants_propose.go:178`) changes and needs its
own security review; with options 1 or 2 it stays as it is. With (b) option 2
the server creates no read grant.

---

## Needs ADR/spec text after the decision

The decided points E1–E4 and the read interval are recorded in ADR 0011 as
"Amendment 2026-11-20: package inventory retention and read interval"; the
earlier ADR text (D3, D5, D6) is not rewritten (previously: "These items are
not changed here", with E1 option 2 and the 24 h limit as the text to write).
`docs/spec/` is protected and not changed here. Still to be written by a
maintainer:

1. **ADR 0011 D6 "Retention"** (done by the amendment, E1): 2 package reads
   per host, 3 inventories per image. Open: the precedence over D5 and
   snapshot pinning (Q1).
2. **ADR 0011 D3 or D5, age of a read** (done by the amendment, E2):
   count-based, no time limit. Open: the reading together with E1 (Q2).
3. **ADR 0011 D5 closure-class table** (done by the amendment, E3): host
   subject with no stored read is held; unknown OS release is exported as
   incomplete (iv03). Open: the image row (Q3).
4. **ADR 0011 D3 `image.packages`**: freshness and scheduling (Q4) and
   whether it may be leased with a digest (Q5) are still open.
5. **ADR 0007 initial allowlist or spec 07 and 10** (text only; no decision
   open): record `package.list_installed` (ADR 0011 D3 lines 198–199) and
   `image.packages` (ADR 0011 line 1175) as decided allowlist members. Host read leases need no new ADR text on approval: ADR 0007 already
   decides it.
6. **`docs/spec/03-processes-and-data.md`** (vulnerability tables, line 57):
   name the package-read table, its retention rule (E1: 2 reads per host;
   E4: 3 inventories per image) and whether it has a column for the
   completeness flag.
7. **`docs/implementation/vulnerability-management.md`**: point the plan at
   this paper's decision (2026-11-20) and its open questions Q1–Q5.

## Test

None. This is a documentation-only change; no Go code, shell script or YAML
file is touched.
