// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build race

package vulnstore

// supersededHoldsAtScale: under the race detector SQLite runs about ten
// times slower, so the hold-drop test uses a tenth of MaxFindingsPerRun;
// that is still about ten apply transactions, and one transaction (or a
// bound by statements) still fails it. Without the race detector it runs
// at full scale.
const supersededHoldsAtScale = MaxFindingsPerRun / 10

// contendingWriters: under the race detector the concurrent writers of
// server.db run at half the count (see race_off_test.go). Four writers
// contending with each other alone already exhaust the busy timeout of
// the slowest one there, whatever the apply transactions hold.
const contendingWriters = 2
