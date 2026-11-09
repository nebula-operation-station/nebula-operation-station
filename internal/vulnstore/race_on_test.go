// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build race

package vulnstore

// supersededHoldsAtScale: under the race detector SQLite runs about ten
// times slower, so the hold-drop test uses a tenth of MaxFindingsPerRun;
// that is still about ten apply transactions, and one transaction (or a
// bound by statements) still fails it. Without the race detector it runs
// at full scale.
const supersededHoldsAtScale = MaxFindingsPerRun / 10
