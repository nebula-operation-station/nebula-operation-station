// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnstore

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

func TestHumanStatesNeverChangedByRuns(t *testing.T) {
	e := newEnv(t)
	items := e.seed(t, "web01", 3)
	accepted, falsePos := items[0].Finding.Key, items[1].Finding.Key
	if err := e.st.SetAcceptedRisk(e.ctx, accepted, AcceptRisk{Approver: "admin", Reason: "isolated host", BasisVersion: "1.0-1"}); err != nil {
		t.Fatal(err)
	}
	if err := e.st.SetFalsePositive(e.ctx, falsePos, MarkFalsePositive{By: "admin", Category: CategoryBackportFixed, Reason: "patched", BasisVersion: "1.0-1"}); err != nil {
		t.Fatal(err)
	}

	// Omitted by a complete run.
	r1 := e.start(t)
	e.submit(t, r1, 0, []Subject{hostSubj("web01")})
	e.complete(t, r1)
	// Reported not_affected by a complete run.
	r2 := e.start(t)
	e.submit(t, r2, 0, []Subject{hostSubj("web01")},
		item(t, "web01", cve(0), withFix(vulnfinding.FixNotAffected, "")),
		item(t, "web01", cve(1), withFix(vulnfinding.FixNotAffected, "")))
	e.complete(t, r2)
	// Reported again with other values.
	r3 := e.start(t)
	e.submit(t, r3, 0, nil, item(t, "web01", cve(0), withCVSS(7.5)), item(t, "web01", cve(1), withKEV("2026-02-02")))
	e.complete(t, r3)

	a := e.get(t, accepted)
	if a.State != StateAcceptedRisk || a.Human == nil || a.Human.Reason != "isolated host" || a.Human.By != "admin" {
		t.Fatalf("accepted_risk changed: %+v", a)
	}
	if a.Record.Scores.CVSS.BaseScore != 7.5 {
		t.Fatal("values of a human-state finding not updated")
	}
	fp := e.get(t, falsePos)
	if fp.State != StateFalsePositive || fp.Human.Category != CategoryBackportFixed {
		t.Fatalf("false_positive changed: %+v", fp)
	}
	e.wantState(t, items[2].Finding.Key, StateFixed, ClosedByHermesUnconfirmed)
}

func TestHumanStateInputLimits(t *testing.T) {
	e := newEnv(t)
	items := e.seed(t, "web01", 2)
	k := items[0].Finding.Key
	now := e.clk.Now()
	bad := map[string]AcceptRisk{
		"no reason":      {Approver: "admin", BasisVersion: "1.0-1"},
		"reason > 1 KiB": {Approver: "admin", Reason: strings.Repeat("x", MaxHumanReason+1), BasisVersion: "1.0-1"},
		"invalid UTF-8":  {Approver: "admin", Reason: "a\xffb", BasisVersion: "1.0-1"},
		"no approver":    {Reason: "r", BasisVersion: "1.0-1"},
		"no basis":       {Approver: "admin", Reason: "r"},
		"expiry > 365 d": {Approver: "admin", Reason: "r", BasisVersion: "1.0-1", Expires: now.Add(MaxAcceptExpiry + time.Hour)},
		"expiry in past": {Approver: "admin", Reason: "r", BasisVersion: "1.0-1", Expires: now.Add(-time.Hour)},
	}
	for name, a := range bad {
		if err := e.st.SetAcceptedRisk(e.ctx, k, a); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s: %v, want ErrInvalidInput", name, err)
		}
	}
	if err := e.st.SetFalsePositive(e.ctx, k, MarkFalsePositive{By: "admin", Category: "guess", Reason: "r", BasisVersion: "1"}); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("unknown category: %v", err)
	}
	if err := e.st.SetAcceptedRisk(e.ctx, k, AcceptRisk{Approver: "admin", Reason: strings.Repeat("x", MaxHumanReason), BasisVersion: "1.0-1"}); err != nil {
		t.Fatalf("1 KiB reason refused: %v", err)
	}
	if f := e.get(t, k); !f.Human.Expires.Equal(now.Add(DefaultAcceptExpiry)) {
		t.Fatalf("default expiry = %v", f.Human.Expires)
	}
	// Only open findings take a human state.
	if err := e.st.SetFalsePositive(e.ctx, k, MarkFalsePositive{By: "admin", Category: CategoryOther, Reason: "r", BasisVersion: "1"}); !errors.Is(err, ErrWrongState) {
		t.Fatalf("human state over human state: %v", err)
	}
	r := e.start(t)
	e.submit(t, r, 0, []Subject{hostSubj("web01")}, items[0])
	e.complete(t, r)
	if err := e.st.SetAcceptedRisk(e.ctx, items[1].Finding.Key, AcceptRisk{Approver: "admin", Reason: "r", BasisVersion: "1"}); !errors.Is(err, ErrWrongState) {
		t.Fatalf("accept fixed finding: %v", err)
	}
}

func TestReviewHumanStatesReopens(t *testing.T) {
	e := newEnv(t)
	items := e.seed(t, "web01", 5)
	keys := make([]vulnfinding.Key, len(items))
	for i, it := range items {
		keys[i] = it.Finding.Key
	}
	accept := func(k vulnfinding.Key, exp time.Time) {
		if err := e.st.SetAcceptedRisk(e.ctx, k, AcceptRisk{Approver: "admin", Reason: "r", BasisVersion: "1.0-1", Expires: exp}); err != nil {
			t.Fatal(err)
		}
	}
	accept(keys[0], e.clk.Now().Add(24*time.Hour)) // will expire
	accept(keys[1], time.Time{})                   // becomes KEV-listed
	accept(keys[2], time.Time{})                   // basis changes
	if err := e.st.SetFalsePositive(e.ctx, keys[3], MarkFalsePositive{By: "admin", Category: CategoryOther, Reason: "r", BasisVersion: "1.0-1"}); err != nil {
		t.Fatal(err)
	}
	accept(keys[4], time.Time{}) // unchanged

	r := e.start(t)
	e.submit(t, r, 0, nil, item(t, "web01", cve(1), withKEV("2026-05-05")))
	e.complete(t, r)
	e.clk.Add(25 * time.Hour)

	basis := func(_ context.Context, f Finding) (string, bool, error) {
		switch f.Key {
		case keys[2]:
			return "1.0-2", true, nil
		case keys[3]:
			return "", false, nil // e.g. kernel version unknown
		}
		return "1.0-1", true, nil
	}
	got, err := e.st.ReviewHumanStates(e.ctx, basis)
	if err != nil {
		t.Fatal(err)
	}
	want := map[vulnfinding.Key]ReopenReason{keys[0]: ReopenExpired, keys[1]: ReopenKEV, keys[2]: ReopenBasisChanged, keys[3]: ReopenBasisUnknown}
	if len(got) != len(want) {
		t.Fatalf("reopened = %+v", got)
	}
	for _, g := range got {
		if want[g.Key] != g.Reason {
			t.Errorf("reopen %s: %s, want %s", g.Key, g.Reason, want[g.Key])
		}
		e.wantState(t, g.Key, StateOpen, "")
	}
	if f := e.get(t, keys[4]); f.State != StateAcceptedRisk {
		t.Fatal("unchanged accepted_risk re-opened")
	}
}

func TestAcceptedRiskOfKEVFindingNotReopenedForSameKEV(t *testing.T) {
	e := newEnv(t)
	items := e.seed(t, "web01", 1, withKEV("2026-01-01"))
	if err := e.st.SetAcceptedRisk(e.ctx, items[0].Finding.Key, AcceptRisk{Approver: "admin", Reason: "r", BasisVersion: "1.0-1"}); err != nil {
		t.Fatal(err)
	}
	got, err := e.st.ReviewHumanStates(e.ctx, func(context.Context, Finding) (string, bool, error) { return "1.0-1", true, nil })
	if err != nil || len(got) != 0 {
		t.Fatalf("reopened = %+v, %v", got, err)
	}
}
