// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"testing"
	"time"
)

func providerJoinRead(step string, vmid uint64) ProviderRead {
	r := providerRead(ProviderMethodGuests)
	r.JoinStep, r.VMID = step, vmid
	return r
}

// A guest join's identity reads and scheduled guest-list reads keep
// separate intervals: neither delays the other.
func TestProviderJoinReadsDoNotShareTheScheduledGuestsInterval(t *testing.T) {
	e, _ := newLeaseEnv(t, ModeStandard)
	approveReadGrant(t, e, readGrantRaw(t, providerDocAt(e.clk.Now(), rgID, 240)))
	if _, err := e.auth.AuthorizeProviderRead(providerRead(ProviderMethodGuests)); err != nil {
		t.Fatalf("scheduled read: %v", err)
	}
	for _, step := range []string{ProviderJoinStepBefore, ProviderJoinStepAfter} {
		if _, err := e.auth.AuthorizeProviderRead(providerJoinRead(step, 101)); err != nil {
			t.Fatalf("join %s right after a scheduled read: %v", step, err)
		}
	}
	// The scheduled read keeps its own interval, untouched by the join.
	_, err := e.auth.AuthorizeProviderRead(providerRead(ProviderMethodGuests))
	wantCode(t, err, CodeLeaseBudget)
	e.clk.Add(time.Minute)
	if _, err := e.auth.AuthorizeProviderRead(providerRead(ProviderMethodGuests)); err != nil {
		t.Fatalf("scheduled read after its interval: %v", err)
	}
	// And a join right after a scheduled read of another guest is not delayed.
	for _, step := range []string{ProviderJoinStepBefore, ProviderJoinStepAfter} {
		if _, err := e.auth.AuthorizeProviderRead(providerJoinRead(step, 102)); err != nil {
			t.Fatalf("join %s of another guest: %v", step, err)
		}
	}
}

// Each join request spends one unit of the remote's request budget, and a
// repeated join of the same guest waits for the grant's interval.
func TestProviderJoinReadsSpendOneUnitPerRequest(t *testing.T) {
	e, _ := newLeaseEnv(t, ModeStandard)
	approveReadGrant(t, e, readGrantRaw(t, providerDocAt(e.clk.Now(), rgID, 3)))
	for _, step := range []string{ProviderJoinStepBefore, ProviderJoinStepAfter} {
		if _, err := e.auth.AuthorizeProviderRead(providerJoinRead(step, 101)); err != nil {
			t.Fatalf("join %s: %v", step, err)
		}
	}
	// Budget is left (2 of 3), so this denial is the join step's interval.
	_, err := e.auth.AuthorizeProviderRead(providerJoinRead(ProviderJoinStepBefore, 101))
	wantCode(t, err, CodeLeaseBudget)
	if _, err := e.auth.AuthorizeProviderRead(providerRead(ProviderMethodNodes)); err != nil {
		t.Fatalf("third unit: %v", err)
	}
	// The two join requests spent two of the three units.
	_, err = e.auth.AuthorizeProviderRead(providerRead(ProviderMethodGuests))
	wantCode(t, err, CodeLeaseBudget)
	e.clk.Add(time.Minute)
	_, err = e.auth.AuthorizeProviderRead(providerJoinRead(ProviderJoinStepAfter, 102))
	wantCode(t, err, CodeLeaseBudget)
}

func TestProviderJoinReadNeedsGuestsMethodAndGuest(t *testing.T) {
	e, _ := newLeaseEnv(t, ModeStandard)
	approveReadGrant(t, e, readGrantRaw(t, providerDocAt(e.clk.Now(), rgID, 240, ProviderMethodNodes)))
	_, err := e.auth.AuthorizeProviderRead(providerJoinRead(ProviderJoinStepBefore, 101))
	wantCode(t, err, CodeLeaseNotCovered)
	for name, r := range map[string]ProviderRead{
		"no vmid":      providerJoinRead(ProviderJoinStepBefore, 0),
		"vmid below":   providerJoinRead(ProviderJoinStepBefore, 99),
		"unknown step": providerJoinRead("join_during", 101),
		"other method": func() ProviderRead {
			r := providerJoinRead(ProviderJoinStepAfter, 101)
			r.Method = ProviderMethodNodes
			return r
		}(),
		"per-guest method": func() ProviderRead {
			r := providerJoinRead(ProviderJoinStepAfter, 101)
			r.Method = ProviderMethodGuestAgent
			return r
		}(),
	} {
		_, err := e.auth.AuthorizeProviderRead(r)
		if err == nil {
			t.Fatalf("%s: authorized", name)
		}
		wantCode(t, err, CodeLeaseInvalid)
	}
}
