// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Tests for the PVE guest/host link cells, review round 1 of PR #346:
// suggestions have their own bounded budget and cannot expire the rest of
// the detail page, at most 100 guests get suggestions, a candidate-only
// conflict needs the confirmation, a host linked elsewhere gets no button,
// hostile conflict and match text is escaped, and the unlink reason limit
// counts characters (runes) and still respects the store's byte limit.

package ui_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/ipam"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// fakeSuggestStore is the real store with the suggestions and
// GuestConflicts replaced. The page computes suggestions with one
// SuggestHostsBatch call; suggest answers for the whole batch (an error
// fails the batch) or, when it succeeds, gives every guest the same
// candidates. calls counts the batch calls, guests the guests asked for,
// single the per-guest SuggestHosts calls.
type fakeSuggestStore struct {
	*pveinventory.Store
	suggest   func(ctx context.Context) ([]pveinventory.Candidate, error)
	conflicts func(ctx context.Context) ([]string, error)
	calls     atomic.Int64
	guests    atomic.Int64
	single    atomic.Int64
}

func (f *fakeSuggestStore) SuggestHosts(ctx context.Context, _ string, _, _ uint64) ([]pveinventory.Candidate, error) {
	f.single.Add(1)
	return f.suggest(ctx)
}

func (f *fakeSuggestStore) SuggestHostsBatch(ctx context.Context, _ string, guests []pveinventory.GuestRef) (map[pveinventory.GuestRef][]pveinventory.Candidate, error) {
	f.calls.Add(1)
	f.guests.Add(int64(len(guests)))
	cands, err := f.suggest(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[pveinventory.GuestRef][]pveinventory.Candidate, len(guests))
	for _, g := range guests {
		out[g] = cands
	}
	return out, nil
}

func (f *fakeSuggestStore) GuestConflicts(ctx context.Context, remoteID string, vmid, gen uint64) ([]string, error) {
	if f.conflicts == nil {
		return f.Store.GuestConflicts(ctx, remoteID, vmid, gen)
	}
	return f.conflicts(ctx)
}

func newFakeSuggestEnv(t *testing.T, f *fakeSuggestStore) *linkEnv {
	t.Helper()
	return newLinkEnvWith(t, func(s *pveinventory.Store) ui.PVEStore {
		f.Store = s
		return f
	})
}

// manyGuests returns n agent guests with VMIDs from 101.
func manyGuests(n int) []pvecontract.GuestObservation {
	gs := make([]pvecontract.GuestObservation, 0, n)
	for i := range n {
		vmid := uint64(101 + i)
		gs = append(gs, agentGuest(vmid, 1, fmt.Sprintf("vm-%d", vmid),
			fmt.Sprintf("aa:bb:cc:00:%02x:%02x", i/256, i%256), fmt.Sprintf("10.78.%d.%d", i/200, 1+i%200)))
	}
	return gs
}

const (
	capNote     = "Suggestions are computed for the first 100 unlinked guests only."
	skippedNote = "Suggestions skipped: the time budget of this page was used up."
)

// TestPVESlowSuggestionsKeepDatasetTable checks with 100 unlinked guests
// and a store whose suggestions never finish that the page still renders
// the dataset table, that the suggestion budget is spent once (not 100
// times), and that the guests show the skipped note.
func TestPVESlowSuggestionsKeepDatasetTable(t *testing.T) {
	f := &fakeSuggestStore{suggest: func(ctx context.Context) ([]pveinventory.Candidate, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	e := newFakeSuggestEnv(t, f)
	e.guests(1, manyGuests(100)...)

	start := time.Now()
	body := e.page()
	if d := time.Since(start); d > 4*time.Second {
		t.Errorf("page took %v; the suggestion budget is not bounded", d)
	}
	if !strings.Contains(body, "<th>Dataset</th>") || strings.Contains(body, "No dataset status stored.") {
		t.Errorf("dataset table missing after slow suggestions")
	}
	if n := f.calls.Load(); n != 1 {
		t.Errorf("SuggestHostsBatch calls = %d, want 1 (later guests skipped once the budget is used up)", n)
	}
	if n := f.single.Load(); n != 0 {
		t.Errorf("per-guest SuggestHosts calls = %d, want 0", n)
	}
	if n := strings.Count(body, skippedNote); n != 100 {
		t.Errorf("skipped notes = %d, want 100", n)
	}
	if strings.Contains(body, "Suggestions unavailable.") {
		t.Errorf("a used-up budget is shown as a store error")
	}
}

// TestPVESuggestionsCappedAt100Guests checks that suggestions are computed
// for 100 unlinked guests and the 101st shows the cap note.
func TestPVESuggestionsCappedAt100Guests(t *testing.T) {
	f := &fakeSuggestStore{suggest: func(context.Context) ([]pveinventory.Candidate, error) { return nil, nil }}
	e := newFakeSuggestEnv(t, f)
	e.guests(1, manyGuests(101)...)

	body := e.page()
	if n := f.calls.Load(); n != 1 {
		t.Errorf("SuggestHostsBatch calls = %d, want 1 for the page", n)
	}
	if n := f.guests.Load(); n != 100 {
		t.Errorf("guests in the suggestion batch = %d, want 100", n)
	}
	if n := f.single.Load(); n != 0 {
		t.Errorf("per-guest SuggestHosts calls = %d, want 0", n)
	}
	if n := strings.Count(body, capNote); n != 1 {
		t.Errorf("cap notes = %d, want 1", n)
	}
	if !strings.Contains(body, "<th>Dataset</th>") {
		t.Errorf("dataset table missing")
	}
}

// TestPVESuggestionStoreErrorShownAsUnavailable checks that a store error
// (not the budget) shows "Suggestions unavailable." for that guest only.
func TestPVESuggestionStoreErrorShownAsUnavailable(t *testing.T) {
	f := &fakeSuggestStore{suggest: func(context.Context) ([]pveinventory.Candidate, error) {
		return nil, errors.New("disk on fire")
	}}
	e := newFakeSuggestEnv(t, f)
	e.guests(1, manyGuests(2)...)
	body := e.page()
	if n := strings.Count(body, "Suggestions unavailable."); n != 2 {
		t.Errorf("unavailable notes = %d, want 2", n)
	}
	if strings.Contains(body, skippedNote) {
		t.Errorf("a store error is shown as a used-up budget")
	}
}

// TestPVECandidateOnlyConflictNeedsConfirmation covers a conflict flagged
// on the candidate only (one MAC on IPAM assets of two hosts) while the
// guest itself has no conflict: the page asks for the confirmation and the
// POST refuses the link without it.
func TestPVECandidateOnlyConflictNeedsConfirmation(t *testing.T) {
	e := newLinkEnv(t)
	e.guests(1, agentGuest(101, 1, "vm-a", "aa:bb:cc:dd:ee:01", "10.77.10.101"))
	e.host("h1", "Host one", "10.77.20.1")
	e.host("h2", "Host two", "10.77.20.2")
	for i, host := range []string{"h1", "h2"} {
		if err := e.ipam.SaveAsset(context.Background(), ipam.Asset{
			ID: fmt.Sprintf("asset-%d", i), Name: host, Kind: ipam.KindServer, MAC: "aa:bb:cc:dd:ee:01",
			Addresses: []netip.Addr{netip.MustParseAddr(fmt.Sprintf("10.77.20.%d", i+1))}, HostID: host,
		}); err != nil {
			t.Fatalf("SaveAsset: %v", err)
		}
	}
	conflicts, err := e.pve.GuestConflicts(context.Background(), linkRemote, 101, 1)
	if err != nil || len(conflicts) != 0 {
		t.Fatalf("guest conflicts = %v, %v; the test needs a candidate-only conflict", conflicts, err)
	}

	body := e.page()
	for _, want := range []string{`name="host" value="h1"`, `name="host" value="h2"`, `name="confirm_conflict"`, ">conflict<"} {
		if !strings.Contains(body, want) {
			t.Errorf("candidate-only conflict view misses %q", want)
		}
	}
	if code, body, _ := e.link("101", "1", "h1"); code != http.StatusConflict {
		t.Errorf("link without confirmation = %d, want 409\n%s", code, body)
	}
	if _, err := e.pve.GetLink(context.Background(), linkRemote, 101, 1); !errors.Is(err, pveinventory.ErrLinkNotFound) {
		t.Fatalf("unconfirmed candidate conflict linked: %v", err)
	}
	if code, body, _ := e.link("101", "1", "h1", "confirm_conflict", "1"); code != http.StatusSeeOther {
		t.Fatalf("confirmed link = %d\n%s", code, body)
	}
}

// TestPVECandidateLinkedElsewhereHasNoButton checks that a candidate host
// already linked to another guest is named, without a link button.
func TestPVECandidateLinkedElsewhereHasNoButton(t *testing.T) {
	e := newLinkEnv(t)
	e.guests(1, agentGuest(101, 1, "vm-a", "aa:bb:cc:dd:ee:01", "10.77.10.101"),
		agentGuest(102, 1, "vm-b", "aa:bb:cc:dd:ee:02", "10.77.10.102"))
	e.host("web1", "Web one", "10.77.10.101")
	if code, body, _ := e.link("102", "1", "web1"); code != http.StatusSeeOther {
		t.Fatalf("link = %d\n%s", code, body)
	}
	body := e.page()
	if !strings.Contains(body, "Already linked to remote-a VMID 102 (incarnation 1)") {
		t.Errorf("candidate linked elsewhere is not named")
	}
	if strings.Contains(body, `name="host" value="web1"`) {
		t.Errorf("candidate linked elsewhere still has a link button")
	}
}

// TestPVEHostileConflictAndMatchTextEscaped checks that conflict and match
// detail strings are rendered as text.
func TestPVEHostileConflictAndMatchTextEscaped(t *testing.T) {
	const hostileDetail = `<script>alert("detail")</script>`
	const hostileConflict = `<img src=x onerror=alert(3)>`
	f := &fakeSuggestStore{
		suggest: func(context.Context) ([]pveinventory.Candidate, error) {
			return []pveinventory.Candidate{{HostID: "web1", Match: pveinventory.MatchIP, Detail: hostileDetail}}, nil
		},
		conflicts: func(context.Context) ([]string, error) { return []string{hostileConflict}, nil },
	}
	e := newFakeSuggestEnv(t, f)
	e.guests(1, agentGuest(101, 1, "vm-a", "aa:bb:cc:dd:ee:01", "10.77.10.101"))
	e.host("web1", "Web one", "10.77.10.101")
	body := e.page()
	for _, bad := range []string{hostileDetail, hostileConflict} {
		if strings.Contains(body, bad) {
			t.Errorf("hostile text rendered raw: %q", bad)
		}
	}
	for _, want := range []string{"&lt;script&gt;alert(&#34;detail&#34;)&lt;/script&gt;", "&lt;img src=x onerror=alert(3)&gt;"} {
		if !strings.Contains(body, want) {
			t.Errorf("escaped text %q missing", want)
		}
	}
}

// TestPVEUnlinkReasonCountsBytes checks the reason limit: it is the
// store's byte limit, so 100 umlauts (200 bytes) fit and 101 umlauts
// (202 bytes, only 101 characters) are rejected with a message that names
// bytes, before anything reaches the store.
func TestPVEUnlinkReasonCountsBytes(t *testing.T) {
	e := newLinkEnv(t)
	e.guests(1, agentGuest(101, 1, "vm-a", "aa:bb:cc:dd:ee:01", "10.77.10.101"))
	e.host("web1", "Web one", "10.77.10.101")
	if code, body, _ := e.link("101", "1", "web1"); code != http.StatusSeeOther {
		t.Fatalf("link = %d\n%s", code, body)
	}
	for _, tc := range []struct {
		name   string
		reason string
	}{
		{"201 ASCII characters", strings.Repeat("a", 201)},
		{"101 umlauts, 202 bytes", strings.Repeat("ü", 101)},
		{"199 ASCII and one umlaut, 201 bytes", strings.Repeat("a", 199) + "ä"},
		{"umlaut with control character", "Grund ö\x07"},
	} {
		code, body, _ := e.unlink("101", "1", tc.reason)
		if code != http.StatusBadRequest {
			t.Errorf("%s: unlink = %d, want 400\n%s", tc.name, code, body)
			continue
		}
		if !strings.Contains(body, "1 to 200 bytes") || strings.Contains(body, "200 characters") {
			t.Errorf("%s: message %q does not explain the limit", tc.name, body)
		}
	}
	if strings.Contains(e.logs.String(), "unlink PVE guest") {
		t.Errorf("a rejected reason reached the store:\n%s", e.logs.String())
	}
	reason := strings.Repeat("ä", 100) // 100 characters, 200 bytes
	if code, body, _ := e.unlink("101", "1", reason); code != http.StatusSeeOther {
		t.Fatalf("unlink with 100 umlauts = %d, want 303\n%s", code, body)
	}
	hist, err := e.pve.LinkHistory(context.Background(), linkRemote, 101, 1)
	if err != nil || len(hist) != 1 || hist[0].UnlinkReason != reason {
		t.Fatalf("history = %+v, %v", hist, err)
	}
}

// TestPVEUnlinkReasonASCIIAtLimit checks that 200 ASCII characters are
// accepted.
func TestPVEUnlinkReasonASCIIAtLimit(t *testing.T) {
	e := newLinkEnv(t)
	e.guests(1, agentGuest(101, 1, "vm-a", "aa:bb:cc:dd:ee:01", "10.77.10.101"))
	e.host("web1", "Web one", "10.77.10.101")
	if code, body, _ := e.link("101", "1", "web1"); code != http.StatusSeeOther {
		t.Fatalf("link = %d\n%s", code, body)
	}
	if code, body, _ := e.unlink("101", "1", strings.Repeat("a", 200)); code != http.StatusSeeOther {
		t.Fatalf("unlink with 200 characters = %d, want 303\n%s", code, body)
	}
}
