// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecollect

import (
	"fmt"
	"reflect"
	"testing"
	"time"
)

// keptSpoolName returns the spool name of remote's generation gen.
func keptSpoolName(remote string, gen uint64) string {
	return fmt.Sprintf("%s.gen-%020d.json", remote, gen)
}

// keptSpoolNames returns the names of remote's generations first..last, sorted.
func keptSpoolNames(remote string, first, last uint64) []string {
	var names []string
	for gen := first; gen <= last; gen++ {
		names = append(names, keptSpoolName(remote, gen))
	}
	return names
}

// keptGenerations returns the generations parsed from names, in order.
func keptGenerations(t *testing.T, names []string) []uint64 {
	t.Helper()
	gens := make([]uint64, 0, len(names))
	for _, name := range names {
		_, gen, err := parseSpoolName(name)
		if err != nil {
			t.Fatalf("parseSpoolName(%q): %v", name, err)
		}
		gens = append(gens, gen)
	}
	return gens
}

// TestKeptRetryDelaysFollowBackoffToCap checks the store back-off sequence:
// the first failure is retried at once, the second waits keptRetryBase, and
// each later one doubles the wait until keptRetryMax, which it never exceeds.
func TestKeptRetryDelaysFollowBackoffToCap(t *testing.T) {
	waits := []time.Duration{
		0,
		keptRetryBase,
		2 * keptRetryBase,
		4 * keptRetryBase,
		keptRetryMax,
		keptRetryMax,
	}
	if keptRetryBase <= 0 || keptRetryBase > keptRetryMax {
		t.Fatalf("keptRetryBase %v must be positive and not above keptRetryMax %v", keptRetryBase, keptRetryMax)
	}
	k := keptRemotes{}
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	for i, wait := range waits {
		k.storeFailed("pve-a", now)
		if got := k["pve-a"].notBefore; !got.Equal(now.Add(wait)) {
			t.Fatalf("failure %d: notBefore = %v, want %v (wait %v)", i+1, got, now.Add(wait), wait)
		}
		if wait > 0 && k.due("pve-a", now.Add(wait-time.Nanosecond)) {
			t.Fatalf("failure %d: due one nanosecond before the %v back-off ran out", i+1, wait)
		}
		if !k.due("pve-a", now.Add(wait)) {
			t.Fatalf("failure %d: not due at the end of the %v back-off", i+1, wait)
		}
		if k["pve-a"].delay > keptRetryMax {
			t.Fatalf("failure %d: delay %v exceeds keptRetryMax %v", i+1, k["pve-a"].delay, keptRetryMax)
		}
		now = now.Add(wait)
	}
}

// TestKeptRetryNotDueBeforeBackoffEnds checks due at the boundary of the
// back-off, with the wait taken from the state rather than from the clock.
func TestKeptRetryNotDueBeforeBackoffEnds(t *testing.T) {
	k := keptRemotes{}
	t0 := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	if !k.due("pve-a", t0) {
		t.Fatal("unknown remote is not due; it must be tried at once")
	}
	k.storeFailed("pve-a", t0)
	k.storeFailed("pve-a", t0)
	end := k["pve-a"].notBefore
	if !end.Equal(t0.Add(keptRetryBase)) {
		t.Fatalf("notBefore after two failures = %v, want %v", end, t0.Add(keptRetryBase))
	}
	if k.due("pve-a", end.Add(-time.Nanosecond)) {
		t.Fatal("due just before notBefore")
	}
	if !k.due("pve-a", end) {
		t.Fatal("not due at notBefore")
	}
}

// TestKeptRetrySucceededClearsBackoff checks that a success ends the failure
// episode, so the next failure starts the back-off from the beginning.
func TestKeptRetrySucceededClearsBackoff(t *testing.T) {
	k := keptRemotes{}
	t0 := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	for range 4 {
		k.storeFailed("pve-a", t0)
	}
	k.succeeded("pve-a")
	if _, ok := k["pve-a"]; ok {
		t.Fatal("succeeded kept the remote's state")
	}
	if !k.due("pve-a", t0) {
		t.Fatal("remote not due at once after succeeded")
	}
	k.storeFailed("pve-a", t0)
	if got := k["pve-a"].notBefore; !got.Equal(t0) {
		t.Fatalf("first failure after success: notBefore = %v, want %v (retry on the next pass)", got, t0)
	}
}

// TestKeptRetryReadFailureDoesNotExtendBackoff checks that failed reads leave
// the store back-off alone, both its end and the delay of the next failure.
func TestKeptRetryReadFailureDoesNotExtendBackoff(t *testing.T) {
	k := keptRemotes{}
	t0 := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	k.storeFailed("pve-a", t0)
	k.storeFailed("pve-a", t0)
	before := k["pve-a"]
	for range 3 {
		k.readFailed("pve-a")
	}
	after := k["pve-a"]
	if !after.notBefore.Equal(before.notBefore) || after.delay != before.delay {
		t.Fatalf("readFailed changed back-off: before %+v, after %+v", before, after)
	}
	if !k.due("pve-a", before.notBefore) {
		t.Fatal("readFailed moved the remote out of its due time")
	}

	k.storeFailed("pve-a", t0)
	if want := t0.Add(2 * keptRetryBase); !k["pve-a"].notBefore.Equal(want) {
		t.Fatalf("store failure after reads: notBefore = %v, want %v (the delay must keep doubling)", k["pve-a"].notBefore, want)
	}
}

// TestKeptRetryReadFailureOnlyTracksRemote checks that a failed read of an
// unknown remote records it without any back-off, so it stays due.
func TestKeptRetryReadFailureOnlyTracksRemote(t *testing.T) {
	k := keptRemotes{}
	k.readFailed("pve-a")
	if _, ok := k["pve-a"]; !ok {
		t.Fatal("readFailed did not record the remote")
	}
	if !k.due("pve-a", time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatal("readFailed alone made the remote not due")
	}
}

// TestKeptPlanHealthyRemotesStayOldestFirst checks the processing order of
// remotes without failures: each file in name order, oldest first.
func TestKeptPlanHealthyRemotesStayOldestFirst(t *testing.T) {
	k := keptRemotes{}
	names := append(keptSpoolNames("pve-a", 1, 3), keptSpoolNames("pve-b", 5, 6)...)
	order, excess := k.plan(names)
	if !reflect.DeepEqual(order, names) {
		t.Fatalf("order = %v, want %v", order, names)
	}
	if len(excess) != 0 {
		t.Fatalf("excess = %v for healthy remotes, want none", excess)
	}
}

// TestKeptPlanFailingRemoteNewestFirst checks that a remote with a failure on
// record is tried newest first, while its run stays contiguous and healthy
// remotes around it keep their order.
func TestKeptPlanFailingRemoteNewestFirst(t *testing.T) {
	k := keptRemotes{"pve-a": {}}
	names := append(keptSpoolNames("pve-a", 1, 3), keptSpoolNames("pve-b", 5, 6)...)
	names = append(names, keptSpoolNames("pve-c", 9, 9)...)
	order, excess := k.plan(names)
	want := []string{
		keptSpoolName("pve-a", 3), keptSpoolName("pve-a", 2), keptSpoolName("pve-a", 1),
		keptSpoolName("pve-b", 5), keptSpoolName("pve-b", 6),
		keptSpoolName("pve-c", 9),
	}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("order = %v, want %v", order, want)
	}
	if len(excess) != 0 {
		t.Fatalf("excess = %v for three files, want none", excess)
	}
}

// TestKeptPlanCapMarksOldestAsExcess checks the cap. At maxKeptPerRemote files
// nothing is in excess; with more, the oldest ones are, and they come last in
// the remote's run so the newer files are judged first.
func TestKeptPlanCapMarksOldestAsExcess(t *testing.T) {
	for _, extra := range []uint64{0, 1, 2} {
		n := uint64(maxKeptPerRemote) + extra
		k := keptRemotes{"pve-a": {}}
		names := keptSpoolNames("pve-a", 1, n)
		order, excess := k.plan(names)

		wantExcess := map[string]struct{}{}
		for _, name := range names[:extra] {
			wantExcess[name] = struct{}{}
		}
		if !reflect.DeepEqual(excess, wantExcess) {
			t.Fatalf("%d files: excess = %v, want %v", n, excess, wantExcess)
		}
		if len(order) != len(names) {
			t.Fatalf("%d files: order has %d names, want %d", n, len(order), len(names))
		}
		// Newest first: the run ends with the oldest, and the excess ones form
		// its tail.
		gens := keptGenerations(t, order)
		for i := 1; i < len(gens); i++ {
			if gens[i] >= gens[i-1] {
				t.Fatalf("%d files: order %v is not newest first", n, gens)
			}
		}
		tail := order[len(order)-int(extra):]
		for _, name := range tail {
			if _, ok := excess[name]; !ok && extra > 0 {
				t.Fatalf("%d files: %s ends the run but is not in excess", n, name)
			}
		}
	}
}

// TestKeptPlanCapHoldsOnlyWhenOverLimit checks at exactly the cap that a
// file is not marked excess, whichever generation it is.
func TestKeptPlanCapHoldsOnlyWhenOverLimit(t *testing.T) {
	k := keptRemotes{"pve-a": {}}
	names := keptSpoolNames("pve-a", 10, 9+uint64(maxKeptPerRemote))
	_, excess := k.plan(names)
	if len(excess) != 0 {
		t.Fatalf("exactly maxKeptPerRemote files: excess = %v, want none", excess)
	}
}

// TestKeptPlanForgetsRemotesWithoutListedFiles checks that a remote with no
// file left in the spool is dropped from the state, and that a remote which
// still has files keeps its state.
func TestKeptPlanForgetsRemotesWithoutListedFiles(t *testing.T) {
	k := keptRemotes{
		"pve-gone": {delay: keptRetryBase},
		"pve-a":    {delay: keptRetryBase},
	}
	k.plan(keptSpoolNames("pve-a", 1, 1))
	if _, ok := k["pve-gone"]; ok {
		t.Fatal("plan kept the state of a remote without listed files")
	}
	if _, ok := k["pve-a"]; !ok {
		t.Fatal("plan forgot the state of a remote that still has files")
	}
}

// TestKeptPlanCoversExactNamesOnly checks that plan keeps every listed name of
// a remote, and nothing of a remote that is not listed.
func TestKeptPlanCoversExactNamesOnly(t *testing.T) {
	k := keptRemotes{"pve-a": {}}
	names := keptSpoolNames("pve-a", 1, 2)
	order, _ := k.plan(names)
	if len(order) != len(names) {
		t.Fatalf("order = %v, want exactly the %d listed names", order, len(names))
	}
	for _, name := range order {
		if spoolRemote(name) != "pve-a" {
			t.Fatalf("order contains %s, which is not pve-a", name)
		}
	}
}

// TestKeptJudgedValidIsMonotonic checks that judgedValid only raises the
// newest judged generation, so an older verdict never lowers it.
func TestKeptJudgedValidIsMonotonic(t *testing.T) {
	k := keptRemotes{}
	k.judgedValid("pve-a", 5)
	k.judgedValid("pve-a", 5)
	k.judgedValid("pve-a", 4)
	if got := k["pve-a"].valid; got != 5 {
		t.Fatalf("valid after 5, 5, 4 = %d, want 5", got)
	}
	k.judgedValid("pve-a", 7)
	if got := k["pve-a"].valid; got != 7 {
		t.Fatalf("valid after 7 = %d, want 7", got)
	}
}

// TestKeptRejectedClearsOnlyTheJudgedGeneration checks rejected for an equal,
// older and newer generation, and for a remote without state.
func TestKeptRejectedClearsOnlyTheJudgedGeneration(t *testing.T) {
	tests := []struct {
		name      string
		rejectGen uint64
		wantValid uint64
	}{
		{name: "same generation clears the judgement", rejectGen: 5, wantValid: 0},
		{name: "older generation leaves it", rejectGen: 4, wantValid: 5},
		{name: "newer generation leaves it", rejectGen: 6, wantValid: 5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := keptRemotes{"pve-a": {valid: 5}}
			k.rejected("pve-a", tt.rejectGen)
			if got := k["pve-a"].valid; got != tt.wantValid {
				t.Fatalf("valid = %d, want %d", got, tt.wantValid)
			}
		})
	}

	k := keptRemotes{}
	k.rejected("pve-a", 5)
	if _, ok := k["pve-a"]; ok {
		t.Fatal("rejected created state for a remote without state")
	}
}

// TestKeptCoveredNeedsNewerValidFile checks covered for older, equal and newer
// generations, and that a judgement of one remote covers nothing of another.
func TestKeptCoveredNeedsNewerValidFile(t *testing.T) {
	k := keptRemotes{"pve-a": {valid: 5}}
	tests := []struct {
		name   string
		remote string
		gen    uint64
		want   bool
	}{
		{name: "older than the valid file", remote: "pve-a", gen: 4, want: true},
		{name: "the valid file itself", remote: "pve-a", gen: 5, want: false},
		{name: "newer than the valid file", remote: "pve-a", gen: 6, want: false},
		{name: "foreign remote, older generation", remote: "pve-b", gen: 4, want: false},
		{name: "foreign remote, same generation", remote: "pve-b", gen: 5, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := k.covered(tt.remote, tt.gen); got != tt.want {
				t.Fatalf("covered(%s, %d) = %v, want %v", tt.remote, tt.gen, got, tt.want)
			}
		})
	}
}

// TestKeptCoveredNothingWithoutJudgement checks that no generation counts as
// covered while no file of the remote has been judged valid.
func TestKeptCoveredNothingWithoutJudgement(t *testing.T) {
	k := keptRemotes{"pve-a": {}}
	for _, gen := range []uint64{0, 1, 1 << 40} {
		if k.covered("pve-a", gen) {
			t.Fatalf("covered(pve-a, %d) = true without a judged file", gen)
		}
	}
}

// TestKeptJudgementLeavesSpoolForgotten checks that a file judged valid which
// left the spool no longer covers older files after the next plan, and that
// the same happens when a later look rejects it.
func TestKeptJudgementLeavesSpoolForgotten(t *testing.T) {
	k := keptRemotes{"pve-a": {}}
	k.judgedValid("pve-a", 5)
	k.plan(keptSpoolNames("pve-a", 1, 4))
	if k.covered("pve-a", 4) {
		t.Fatal("judged file 5 left the spool but still covers generation 4")
	}
	if got := k["pve-a"].valid; got != 0 {
		t.Fatalf("valid after the judged file left = %d, want 0", got)
	}
}

// TestKeptJudgementStaysWhileListed checks that a judged file still in the
// spool keeps covering older generations through plan.
func TestKeptJudgementStaysWhileListed(t *testing.T) {
	k := keptRemotes{"pve-a": {}}
	k.judgedValid("pve-a", 5)
	k.plan(keptSpoolNames("pve-a", 3, 5))
	if !k.covered("pve-a", 3) {
		t.Fatal("judged file 5 is still listed but no longer covers generation 3")
	}
}

// TestKeptJudgementOfOtherRemoteStaysWithItsRemote checks that planning
// another remote leaves a listed judgement of this remote in place.
func TestKeptJudgementOfOtherRemoteStaysWithItsRemote(t *testing.T) {
	k := keptRemotes{"pve-a": {}, "pve-b": {}}
	k.judgedValid("pve-a", 5)
	names := append(keptSpoolNames("pve-a", 3, 5), keptSpoolNames("pve-b", 1, 2)...)
	k.plan(names)
	if !k.covered("pve-a", 4) {
		t.Fatal("planning pve-b dropped the judgement of listed pve-a")
	}
}

// TestSpoolRemoteNames checks the remote of each name form: valid names give
// their remote, malformed names give "". The forms follow spool_test.go.
func TestSpoolRemoteNames(t *testing.T) {
	maxRemote := "a" + keptRepeat('b', 63)
	tests := []struct {
		name string
		want string
	}{
		{name: "remote-a.gen-00000000000000000001.json", want: "remote-a"},
		{name: "pve-1.gen-00000000000000000000.json", want: "pve-1"},
		{name: keptSpoolName(maxRemote, 1), want: maxRemote},
		{name: "remote-a.gen-18446744073709551615.json", want: "remote-a"},
		{name: "remote-a.gen-99999999999999999999.json", want: ""},
		{name: "remote-a.gen-1.json", want: ""},
		{name: "remote-a.gen-000000000000000000001.json", want: ""},
		{name: "remote-a.gen-00000000000000000001.jsonx", want: ""},
		{name: "remote-a.tmp-123", want: ""},
		{name: "REMOTE-a.gen-00000000000000000001.json", want: ""},
		{name: "-remote.gen-00000000000000000001.json", want: ""},
		{name: "remote-a.gen-0000000000000000000a.json", want: ""},
		{name: "remote-a.gen-00000000000000000001.json.tmp-1", want: ""},
		{name: "dir/remote-a.gen-00000000000000000001.json", want: ""},
		{name: keptSpoolName(keptRepeat('b', 65), 1), want: ""},
		{name: "", want: ""},
	}
	for _, tt := range tests {
		if got := spoolRemote(tt.name); got != tt.want {
			t.Errorf("spoolRemote(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
}

// keptRepeat returns a string of n copies of b.
func keptRepeat(b byte, n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return string(out)
}
