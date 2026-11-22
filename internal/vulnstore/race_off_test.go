// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !race

package vulnstore

// supersededHoldsAtScale: the hold-drop test runs at full scale without
// the race detector (see race_on_test.go).
const supersededHoldsAtScale = MaxFindingsPerRun

// contendingWriters: the concurrent writers of server.db run at four
// without the race detector (see race_on_test.go).
const contendingWriters = 4
