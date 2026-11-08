// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

const recExec = "00000000-0000-4000-9000-0000000000a1"

func recRow(exec string) ContainerRecreation {
	return ContainerRecreation{
		ExecutionID: exec, BatchDigest: strings.Repeat("d", 64), MemberID: "m-01", Kind: "update",
		HostID: "web-1", HostKey: "SHA256:k", Form: "compose", Unit: "site",
		Binding:    []byte(`{"kind":"update"}`),
		Definition: []byte(`{"project":"site"}`),
		Images: []RecreationImage{{Service: "web", Repository: "docker.io/library/nginx", OldTag: "1.27", NewTag: "1.27",
			PriorImageID: "sha256:" + strings.Repeat("a", 64), RetainedTag: "nos-retained:" + exec + "-0",
			RetainedReference: "docker.io/library/nginx:1.27@sha256:" + strings.Repeat("b", 64)}},
	}
}

func TestContainerRecreationLifecycle(t *testing.T) {
	dir := privateDir(t)
	t1 := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
	db := openAtT(t, dir, t1)
	if err := db.CreateContainerRecreation(recRow(recExec)); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateContainerRecreation(recRow(recExec)); err == nil {
		t.Fatal("a second intent row for one execution was accepted")
	}
	intent, err := db.ContainerRecreationsInIntent()
	if err != nil || len(intent) != 1 || intent[0].State != RecreationIntent || !intent[0].WindowExpiresAt.IsZero() {
		t.Fatalf("intent rows %+v %v", intent, err)
	}
	// A rollback of a row in intent is refused.
	if err := db.MarkContainerRecreationRolledBack(recExec); !errors.Is(err, ErrRecreationState) {
		t.Fatalf("rollback of intent: %v", err)
	}
	c := RecreationCompletion{State: RecreationRecreated, Baseline: []byte(`[{"id":"x"}]`),
		Containers: []RecreationContainer{{Service: "web", Replica: "1", Name: "site-web-1", Status: ContainerRecreated}},
		Verdict:    RecreationVerdict{Judged: true, Passed: true}}
	if err := db.CompleteContainerRecreation(recExec, c, t1, 7*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	// Completed once: a second completion (a later reconcile pass, a
	// replayed result) changes nothing.
	c2 := c
	c2.State, c2.Baseline = RecreationPartial, []byte(`[{"id":"other"}]`)
	if err := db.CompleteContainerRecreation(recExec, c2, t1.Add(48*time.Hour), 7*24*time.Hour); !errors.Is(err, ErrRecreationState) {
		t.Fatalf("second completion: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db = openAtT(t, dir, t1.Add(time.Hour)) // restart
	got, err := db.GetContainerRecreation(recExec)
	if err != nil || got.State != RecreationRecreated || string(got.Baseline) != `[{"id":"x"}]` ||
		!got.WindowExpiresAt.Equal(t1.Add(7*24*time.Hour)) || !got.Verdict.Passed || len(got.Containers) != 1 ||
		len(got.Images) != 1 || got.Images[0].RetainedTag != "nos-retained:"+recExec+"-0" {
		t.Fatalf("row after restart %+v %v", got, err)
	}
	if err := db.MarkContainerRecreationRolledBack(recExec); err != nil {
		t.Fatal(err)
	}
	if err := db.MarkContainerRecreationRolledBack(recExec); !errors.Is(err, ErrRecreationState) {
		t.Fatalf("second rollback: %v", err)
	}
	if _, err := db.GetContainerRecreation("00000000-0000-4000-9000-0000000000ff"); !errors.Is(err, ErrNoRecreation) {
		t.Fatalf("unknown row: %v", err)
	}
}

func TestContainerRecreationStates(t *testing.T) {
	db := openAtT(t, privateDir(t), time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC))
	for i, state := range []string{RecreationNotRecreated, RecreationRecreated, RecreationPartial, RecreationUncertain} {
		exec := "00000000-0000-4000-9000-00000000010" + string(rune('0'+i))
		if err := db.CreateContainerRecreation(recRow(exec)); err != nil {
			t.Fatal(err)
		}
		if err := db.CompleteContainerRecreation(exec, RecreationCompletion{State: state}, time.Now(), time.Hour); err != nil {
			t.Fatalf("%s: %v", state, err)
		}
		err := db.MarkContainerRecreationRolledBack(exec)
		if allowed := state == RecreationRecreated || state == RecreationPartial; allowed != (err == nil) {
			t.Fatalf("%s: rolled back %v", state, err)
		}
	}
	for _, bad := range []string{RecreationIntent, RecreationRolledBack, "done", ""} {
		if err := db.CreateContainerRecreation(recRow("00000000-0000-4000-9000-000000000200")); err != nil && bad == RecreationIntent {
			t.Fatal(err)
		}
		if err := db.CompleteContainerRecreation("00000000-0000-4000-9000-000000000200", RecreationCompletion{State: bad}, time.Now(), time.Hour); err == nil {
			t.Fatalf("completion to %q accepted", bad)
		}
	}
	uncertain, err := db.HostHasUncertainRecreation("web-1")
	if err != nil || !uncertain {
		t.Fatalf("uncertain %v %v", uncertain, err)
	}
	if n, _ := db.HostHasUncertainRecreation("db-1"); n {
		t.Fatal("another host reported uncertain")
	}
	all, err := db.ListContainerRecreations("web-1")
	if err != nil || len(all) != 5 {
		t.Fatalf("list %d %v", len(all), err)
	}
}

// The reconcile pass reloads only intent rows whose run has finished, by
// key, in bounded pages: a row whose run never finishes (or never ran) is
// never loaded, and paging visits every finished row exactly once.
func TestFinishedRecreationIntentsArePagedAndSkipUnfinished(t *testing.T) {
	db := openAtT(t, privateDir(t), time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC))
	exec := func(i int) string { return fmt.Sprintf("00000000-0000-4000-9000-%012d", 300+i) }
	const finished = 7
	var want []string
	for i := 0; i < finished+3; i++ {
		id := exec(i)
		if err := db.CreateContainerRecreation(recRow(id)); err != nil {
			t.Fatal(err)
		}
		if i == finished+2 {
			continue // intent without a run
		}
		r := memberRun(id, fmt.Sprintf("m-%02d", i))
		if err := db.CreateRun(r); err != nil {
			t.Fatal(err)
		}
		switch {
		case i == finished:
			// dispatching forever
		case i == finished+1:
			if err := db.MarkRunRunning(id, r.HostID, "10.0.0.1:22"); err != nil {
				t.Fatal(err)
			}
		default:
			r.Class = "success"
			if err := db.FinishRun(r); err != nil {
				t.Fatal(err)
			}
			want = append(want, id)
		}
	}
	// A finished run whose row already left intent is not listed.
	done := exec(99)
	if err := db.CreateContainerRecreation(recRow(done)); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateRun(memberRun(done, "m-99")); err != nil {
		t.Fatal(err)
	}
	if err := db.FinishRun(Run{ExecutionID: done, HostID: "web-1", Class: "success"}); err != nil {
		t.Fatal(err)
	}
	if err := db.CompleteContainerRecreation(done, RecreationCompletion{State: RecreationUncertain}, time.Now(), time.Hour); err != nil {
		t.Fatal(err)
	}

	var got []string
	var after RecreationIntentKey
	pages := 0
	for {
		keys, err := db.FinishedRecreationIntents(after, 3)
		if err != nil {
			t.Fatal(err)
		}
		pages++
		if len(keys) > 3 {
			t.Fatalf("page of %d keys over the limit 3", len(keys))
		}
		for _, k := range keys {
			if k.HostID != "web-1" {
				t.Fatalf("key %+v", k)
			}
			got = append(got, k.ExecutionID)
		}
		if len(keys) < 3 {
			break
		}
		after = keys[len(keys)-1]
		if pages > 10 {
			t.Fatal("paging does not end")
		}
	}
	if !slices.Equal(got, want) || pages != 3 {
		t.Fatalf("%d pages, got %v, want %v", pages, got, want)
	}
	// A page size out of range is the maximum page.
	for _, limit := range []int{0, -1, maxIntentPage + 1} {
		keys, err := db.FinishedRecreationIntents(RecreationIntentKey{}, limit)
		if err != nil || len(keys) != finished {
			t.Fatalf("limit %d: %d keys %v", limit, len(keys), err)
		}
	}
}

func TestContainerRecreationRefusesMalformed(t *testing.T) {
	db := openT(t, privateDir(t))
	cases := map[string]func(*ContainerRecreation){
		"short execution": func(r *ContainerRecreation) { r.ExecutionID = "x" },
		"short digest":    func(r *ContainerRecreation) { r.BatchDigest = "d" },
		"no member":       func(r *ContainerRecreation) { r.MemberID = "" },
		"bad kind":        func(r *ContainerRecreation) { r.Kind = "restart" },
		"bad form":        func(r *ContainerRecreation) { r.Form = "swarm" },
		"binding not json": func(r *ContainerRecreation) {
			r.Binding = []byte("{")
		},
		"definition too large": func(r *ContainerRecreation) {
			r.Definition = []byte(`"` + strings.Repeat("a", maxRecreationJSON) + `"`)
		},
	}
	for name, mut := range cases {
		r := recRow(recExec)
		mut(&r)
		if err := db.CreateContainerRecreation(r); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := db.CreateContainerRecreation(recRow(recExec)); err != nil {
		t.Fatal(err)
	}
	big := RecreationCompletion{State: RecreationRecreated, Baseline: []byte(`"` + strings.Repeat("a", maxRecreationBaseline) + `"`)}
	if err := db.CompleteContainerRecreation(recExec, big, time.Now(), time.Hour); err == nil {
		t.Fatal("oversize baseline accepted")
	}
}

// A resolve changes only an uncertain row, only to not_recreated or
// partial, and keeps the baseline and the window expiry.
func TestResolveChangesOnlyUncertainRows(t *testing.T) {
	t1 := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
	db := openAtT(t, privateDir(t), t1)
	states := map[string]string{
		"00000000-0000-4000-9000-000000000301": RecreationUncertain,
		"00000000-0000-4000-9000-000000000302": RecreationRecreated,
		"00000000-0000-4000-9000-000000000303": RecreationPartial,
		"00000000-0000-4000-9000-000000000304": RecreationNotRecreated,
	}
	for exec, state := range states {
		if err := db.CreateContainerRecreation(recRow(exec)); err != nil {
			t.Fatal(err)
		}
		if err := db.CompleteContainerRecreation(exec, RecreationCompletion{State: state, Baseline: []byte(`[{"id":"x"}]`)}, t1, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	intent := "00000000-0000-4000-9000-000000000305"
	if err := db.CreateContainerRecreation(recRow(intent)); err != nil {
		t.Fatal(err)
	}
	cs := []RecreationContainer{{Service: "web", Name: "site-web-1", Status: ContainerRecreated, IDAfter: "n"}}
	v := RecreationVerdict{Findings: []string{"resolved"}}
	for exec, state := range states {
		err := db.ResolveContainerRecreation(exec, RecreationPartial, cs, v)
		if (state == RecreationUncertain) != (err == nil) {
			t.Fatalf("%s: resolve %v", state, err)
		}
	}
	if err := db.ResolveContainerRecreation(intent, RecreationNotRecreated, nil, v); !errors.Is(err, ErrRecreationState) {
		t.Fatalf("intent resolved: %v", err)
	}
	got, err := db.GetContainerRecreation("00000000-0000-4000-9000-000000000301")
	if err != nil || got.State != RecreationPartial || string(got.Baseline) != `[{"id":"x"}]` ||
		!got.WindowExpiresAt.Equal(t1.Add(time.Hour)) || len(got.Containers) != 1 || got.Verdict.Findings[0] != "resolved" {
		t.Fatalf("resolved row %+v %v", got, err)
	}
	// Never to recreated, intent or rolled_back.
	for _, bad := range []string{RecreationRecreated, RecreationIntent, RecreationRolledBack, RecreationUncertain, ""} {
		if err := db.ResolveContainerRecreation("00000000-0000-4000-9000-000000000301", bad, nil, v); err == nil {
			t.Fatalf("resolve to %q accepted", bad)
		}
	}
}

func TestRecoveryPlanNeedsExplicitNoDataDeclaration(t *testing.T) {
	t1 := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
	db := openAtT(t, privateDir(t), t1)
	for name, c := range map[string][2]string{
		"empty plan":            {RecoveryPlanReference, ""},
		"blank plan":            {RecoveryPlanReference, "   "},
		"no data with text":     {RecoveryNoData, "nightly backup"},
		"unknown kind":          {"stateless", ""},
		"control characters":    {RecoveryPlanReference, "backup\x1b[2J"},
		"oversize reference":    {RecoveryPlanReference, strings.Repeat("a", maxRecoveryReference+1)},
		"inferred from nothing": {"", ""},
	} {
		if _, err := db.SetContainerRecoveryPlan("web-1", "site", c[0], c[1], "alice"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := db.ContainerRecoveryPlan("web-1", "site"); !errors.Is(err, ErrNoRecoveryPlan) {
		t.Fatalf("plan recorded by a refused set: %v", err)
	}
	p1, err := db.SetContainerRecoveryPlan("web-1", "site", RecoveryNoData, "", "alice")
	if err != nil || p1.Version != 1 {
		t.Fatalf("%+v %v", p1, err)
	}
	got, err := db.ContainerRecoveryPlan("web-1", "site")
	if err != nil || got.Digest() != p1.Digest() || got.Kind != RecoveryNoData {
		t.Fatalf("%+v %v", got, err)
	}
	p2, err := db.SetContainerRecoveryPlan("web-1", "site", RecoveryPlanReference, "restic snapshot of /srv/site before update", "bob")
	if err != nil || p2.Version != 2 || p2.Digest() == p1.Digest() {
		t.Fatalf("changed plan %+v %v", p2, err)
	}
	if err := db.ClearContainerRecoveryPlan("web-1", "site"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ContainerRecoveryPlan("web-1", "site"); !errors.Is(err, ErrNoRecoveryPlan) {
		t.Fatalf("cleared plan still present: %v", err)
	}
	if err := db.ClearContainerRecoveryPlan("web-1", "site"); !errors.Is(err, ErrNoRecoveryPlan) {
		t.Fatalf("second clear: %v", err)
	}
}
