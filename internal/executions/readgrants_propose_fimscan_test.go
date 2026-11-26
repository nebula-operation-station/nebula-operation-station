// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
)

// TestFimScanIsLeaseableOnlyAsTheOneDurableException checks that fim.scan is
// the only durable action with parameters a lease can cover. Every other
// durable or parameterised action stays out.
func TestFimScanIsLeaseableOnlyAsTheOneDurableException(t *testing.T) {
	if !leaseableAction(permit.FimScanActionID) {
		t.Fatal("fim.scan is not leaseable")
	}
	for _, a := range actions.Builtin {
		if a.ID == permit.FimScanActionID || (!a.Durable && len(a.Params) == 0) {
			continue
		}
		if leaseableAction(a.ID) {
			t.Errorf("%s is leaseable (durable %v, %d parameters)", a.ID, a.Durable, len(a.Params))
		}
	}
	for _, id := range ReadGrantActionIDs() {
		if id == permit.FimScanActionID {
			t.Fatal("the page lists fim.scan without a mode choice")
		}
	}
}

// TestFimScanProposalNeedsAMode rejects a fim.scan proposal without a mode, or
// with another one, before anything is sent to the executor.
func TestFimScanProposalNeedsAMode(t *testing.T) {
	for _, tc := range []struct {
		mode string
		ok   bool
	}{
		{"", false},
		{"weekly", false},
		{"Full", false},
		{"incremental", true},
		{"full", true},
	} {
		err := checkReadGrantRequest(ReadGrantRequest{ScopeKind: ScopeAll, Actions: []string{permit.FimScanActionID},
			Days: ReadGrantShortDays, FimScanMode: tc.mode})
		var in *ReadGrantInputError
		if tc.ok && err != nil {
			t.Errorf("mode %q: %v", tc.mode, err)
		}
		if !tc.ok && (err == nil || !errors.As(err, &in)) {
			t.Errorf("mode %q: got %v, want an input error", tc.mode, err)
		}
	}
}

// TestFimScanProposalBindsTheHashOfItsMode checks that the document sent for
// a fim.scan proposal carries the hash of the chosen mode, and that the
// preview shows it.
func TestFimScanProposalBindsTheHashOfItsMode(t *testing.T) {
	for _, tc := range []struct {
		mode, hash string
	}{
		{"incremental", permit.FimScanIncrementalParametersHash},
		{"full", permit.FimScanFullParametersHash},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			f := newProposeFake()
			s, _ := proposeService(t, f, testInventory())
			now := time.Unix(1_800_000_000, 0)
			s.now = func() time.Time { return now }
			v, err := s.ProposeReadGrant(context.Background(), "alice", ReadGrantRequest{ScopeKind: ScopeTag, ScopeValue: "tier=front",
				Actions: []string{permit.FimScanActionID}, Days: ReadGrantShortDays, FimScanMode: tc.mode})
			if err != nil {
				t.Fatal(err)
			}
			if len(f.sent.Actions) != 1 || f.sent.Actions[0].ActionID != permit.FimScanActionID || f.sent.Actions[0].ParametersHash != tc.hash {
				t.Fatalf("sent %+v, want fim.scan bound to %s", f.sent.Actions, tc.hash)
			}
			if len(v.Actions) != 1 || v.Actions[0].ParametersHash != tc.hash {
				t.Fatalf("preview %+v, want fim.scan bound to %s", v.Actions, tc.hash)
			}
		})
	}
}
