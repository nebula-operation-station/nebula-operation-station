// SPDX-License-Identifier: AGPL-3.0-or-later

package vulninventory

// The age of a package read (ADR 0011 D3/D5, amended 2026-11-20; decision E2
// in docs/implementation/vuln-inventory-decisions.md, decided by the
// maintainer on 2026-11-20). The rule is count-based and has NO time limit:
// a read counts as too old as soon as a third read of the same host exists,
// that is, once it has two newer reads of its host. A host that delivers no
// new reads keeps its last read indefinitely; its age is shown, not enforced
// (iv09).
//
// This file holds only the count rule. Whether the export and the classifier
// apply it to the reads they use depends on the open question Q2 of the
// decisions paper (the reading of E2 together with E1's two kept reads); until
// the maintainer confirms it, neither applies it. The export and the classifier
// do not check read times at all.

// readsNewerThanTooOld is the number of newer reads of the same host at which
// a read is too old: a third read exists (E2).
const readsNewerThanTooOld = 2

// tooOld reports whether a read with newer reads of its host (n) is too old
// under the count rule of E2. It never looks at the time of the read.
//
// TODO(Q2): no production caller yet. Wire it into the export and the
// classifier only after the maintainer answers Q2 of the decisions paper; the
// answer decides whether a stored read can be too old at all (reading (i) or
// (ii)).
func tooOld(n int) bool {
	return n >= readsNewerThanTooOld
}
