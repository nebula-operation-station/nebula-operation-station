// SPDX-License-Identifier: AGPL-3.0-or-later

package notifylog

import (
	"context"
	"errors"
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
)

// fakeClock is the injected time source for the store and for Prune.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func newTestStore(t *testing.T) (*Store, *fakeClock) {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "nos.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	clk := &fakeClock{t: time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)}
	s, err := New(db, clk.now)
	if err != nil {
		t.Fatal(err)
	}
	return s, clk
}

// testExecID is a lowercase UUIDv4, the execution ID form the executions
// package generates.
const testExecID = "3f2b8c1e-9a4d-4e7f-8c2a-1b2c3d4e5f60"

func sampleRecord() Record {
	return Record{
		Kind:        KindLeaseRunFailed,
		Host:        "web-1",
		State:       StateFailed,
		Reason:      ReasonTimeout,
		ExecutionID: testExecID,
		Link:        "/executions/" + testExecID,
		Outcome:     OutcomeSent,
		Providers:   2,
	}
}

func mustAppend(t *testing.T, s *Store, r Record) int64 {
	t.Helper()
	seq, err := s.Append(context.Background(), r)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	return seq
}

func TestLimitConstantsMatchSpec(t *testing.T) {
	if Retention != 30*24*time.Hour {
		t.Fatalf("Retention = %v, want 30 days", Retention)
	}
	if MaxEntries != 5000 {
		t.Fatalf("MaxEntries = %d, want 5000", MaxEntries)
	}
	if MaxPage != 100 {
		t.Fatalf("MaxPage = %d, want 100", MaxPage)
	}
}

func TestNewRejectsNilDatabase(t *testing.T) {
	if _, err := New(nil, time.Now); err == nil {
		t.Fatal("New(nil) returned no error")
	}
}

func TestAppendAssignsIncreasingSequence(t *testing.T) {
	s, _ := newTestStore(t)
	a := mustAppend(t, s, sampleRecord())
	b := mustAppend(t, s, sampleRecord())
	if a <= 0 || b <= a {
		t.Fatalf("sequence not increasing: %d then %d", a, b)
	}
}

func TestAppendRejectsUnknownOutcome(t *testing.T) {
	s, _ := newTestStore(t)
	r := sampleRecord()
	r.Outcome = "maybe"
	if _, err := s.Append(context.Background(), r); err == nil {
		t.Fatal("unknown outcome was accepted")
	}
}

// TestAppendRejectsKindAndStateThatAreNotCodes: Kind and State are closed
// sets like Reason. Free text, URLs and tokens are refused, so they never
// reach the log through these fields either.
func TestAppendRejectsKindAndStateThatAreNotCodes(t *testing.T) {
	const token = "123456:SECRET-TOKEN-XYZ"
	bad := []string{
		"",
		"executions",
		"Lease.Expiring",
		"lease.expiring ",
		"lease.expiring\n",
		"https://api.telegram.org/bot" + token + "/sendMessage",
		"lease.expiring?token=" + token,
		"lease.expiring#access_token=" + token,
		"dial tcp: connection refused",
		"bot " + token,
	}
	s, _ := newTestStore(t)
	ctx := context.Background()
	for _, v := range bad {
		r := sampleRecord()
		r.Kind = KindCode(v)
		if _, err := s.Append(ctx, r); err == nil {
			t.Errorf("Append accepted kind %q", v)
		}
		r = sampleRecord()
		r.State = StateCode(v)
		if _, err := s.Append(ctx, r); err == nil {
			t.Errorf("Append accepted state %q", v)
		}
	}
	page, err := s.List(ctx, 0, MaxPage)
	if err != nil || len(page) != 0 {
		t.Fatalf("refused records left %d rows (err %v); want none", len(page), err)
	}
}

// TestClosedFieldsNeverStoreProviderText runs one provider error text through
// every field. The closed fields, Host and ExecutionID must refuse it, and the
// link must drop it.
func TestClosedFieldsNeverStoreProviderText(t *testing.T) {
	const token = "123456:SECRET-TOKEN-XYZ"
	providerText := []string{
		"https://api.telegram.org/bot" + token + "/sendMessage?chat_id=42",
		"Post \"https://api.telegram.org/bot" + token + "/sendMessage\": dial tcp: refused",
		token,
		"timeout?token=" + token,
		"timeout#access_token=" + token,
	}
	for _, v := range providerText {
		s, _ := newTestStore(t)
		ctx := context.Background()
		for _, set := range []struct {
			name  string
			apply func(*Record)
		}{
			{"kind", func(r *Record) { r.Kind = KindCode(v) }},
			{"state", func(r *Record) { r.State = StateCode(v) }},
			{"reason", func(r *Record) { r.Reason = ReasonCode(v) }},
			{"outcome", func(r *Record) { r.Outcome = Outcome(v) }},
			{"host", func(r *Record) { r.Host = v }},
			{"execution_id", func(r *Record) { r.ExecutionID = v }},
		} {
			r := sampleRecord()
			set.apply(&r)
			if _, err := s.Append(ctx, r); err == nil {
				t.Fatalf("%s: Append accepted provider text %q", set.name, v)
			}
		}
		r := sampleRecord()
		r.Link = v
		mustAppend(t, s, r)

		page, err := s.List(ctx, 0, MaxPage)
		if err != nil || len(page) != 1 {
			t.Fatalf("List: %d rows, err %v; want the link-only record", len(page), err)
		}
		if page[0].Link != "" || !page[0].Changed.Has(FieldLink) {
			t.Fatalf("provider text %q reached the link: %+v", v, page[0])
		}
	}
}

func TestKindAndStateCodesAreTheDocumentedSet(t *testing.T) {
	gotKinds := []KindCode{KindVulnKEVNew, KindVulnCriticalNew, KindVulnHermesStale,
		KindVulnFeedStale, KindVulnFeedRegressed, KindVulnFeedMarkReset,
		KindIntegrityNOSMismatch, KindIntegrityHostChange, KindIntegrityScanIncomplete,
		KindIntegrityBaselineTamper, KindLeaseExpiring, KindLeaseRunFailed, KindDigest,
		KindOpsSuggestionNew, KindOpsSettingsChanged}
	wantKinds := []KindCode{"vuln.kev_new", "vuln.critical_new", "vuln.hermes_stale",
		"vuln.feed_stale", "vuln.feed_regressed", "vuln.feed_mark_reset",
		"integrity.nos_mismatch", "integrity.host_change", "integrity.scan_incomplete",
		"integrity.baseline_tamper", "lease.expiring", "lease.run_failed", "digest",
		"opsagent.suggestion_new", "opsagent.settings_changed"}
	if !reflect.DeepEqual(gotKinds, wantKinds) {
		t.Fatalf("kind codes = %q, want %q", gotKinds, wantKinds)
	}
	gotStates := []StateCode{StateNew, StateEscalated, StateExpiring, StateFailed,
		StateStale, StateRegressed, StateMismatch, StateIncomplete, StateTamper,
		StateChanged, StateReset, StateSummary}
	wantStates := []StateCode{"new", "escalated", "expiring", "failed", "stale",
		"regressed", "mismatch", "incomplete", "tamper", "changed", "reset", "summary"}
	if !reflect.DeepEqual(gotStates, wantStates) {
		t.Fatalf("state codes = %q, want %q", gotStates, wantStates)
	}
}

// TestReasonRejectsFreeTextAndURLs: Reason is a closed code set. Anything
// else is a caller bug and is refused, so no provider text can reach the log.
func TestReasonRejectsFreeTextAndURLs(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	for _, bad := range []ReasonCode{
		"ssh timeout",
		"https://api.telegram.org/bot123456:SECRET/sendMessage",
		"timeout?token=abc",
		"timeout#access_token=abc",
		"Timeout",
	} {
		r := sampleRecord()
		r.Reason = bad
		if _, err := s.Append(ctx, r); err == nil {
			t.Fatalf("Append accepted reason %q", bad)
		}
	}
	page, err := s.List(ctx, 0, MaxPage)
	if err != nil || len(page) != 0 {
		t.Fatalf("rejected reasons left %d rows (err %v); want none", len(page), err)
	}
}

// TestProviderErrorWithTelegramURLNeverReachesLog: a *url.Error carries the
// full target URL, and a Telegram URL carries the bot token. The caller maps
// the error with ReasonForError, and no stored text may contain the token.
func TestProviderErrorWithTelegramURLNeverReachesLog(t *testing.T) {
	const token = "123456:SECRET-TOKEN-XYZ"
	s, _ := newTestStore(t)
	ctx := context.Background()
	providerErr := &url.Error{
		Op:  "Post",
		URL: "https://api.telegram.org/bot" + token + "/sendMessage?chat_id=42",
		Err: errors.New("dial tcp: connection refused"),
	}
	if !strings.Contains(providerErr.Error(), token) {
		t.Fatal("test setup: provider error does not carry the token")
	}

	r := sampleRecord()
	r.Outcome = OutcomeFailed
	r.Reason = ReasonForError(providerErr)
	if r.Reason != ReasonProviderUnreachable {
		t.Fatalf("ReasonForError = %q, want %q", r.Reason, ReasonProviderUnreachable)
	}
	mustAppend(t, s, r)

	rows, err := s.db.QueryContext(ctx, `SELECT kind, host, state, reason, execution_id, link, outcome FROM notify_log`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var kind, host, state, reason, execID, link, outcome string
		if err := rows.Scan(&kind, &host, &state, &reason, &execID, &link, &outcome); err != nil {
			t.Fatal(err)
		}
		n++
		for _, v := range []string{kind, host, state, reason, execID, link, outcome} {
			for _, leak := range []string{token, "SECRET", "api.telegram.org", "bot", "sendMessage", "chat_id", "://"} {
				if strings.Contains(v, leak) {
					t.Fatalf("stored text %q contains %q", v, leak)
				}
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("%d rows, want 1", n)
	}
}

func TestReasonForErrorMapsErrorsToCodes(t *testing.T) {
	timeout := &url.Error{Op: "Get", URL: "https://example.invalid/", Err: context.DeadlineExceeded}
	for _, tc := range []struct {
		name string
		err  error
		want ReasonCode
	}{
		{"nil error has no reason", nil, ReasonNone},
		{"deadline is a timeout", context.DeadlineExceeded, ReasonTimeout},
		{"url error timeout is a timeout", timeout, ReasonTimeout},
		{"url error is provider unreachable", &url.Error{Op: "Get", URL: "https://x.invalid/", Err: errors.New("refused")}, ReasonProviderUnreachable},
		{"other error is internal", errors.New("boom"), ReasonInternal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ReasonForError(tc.err); got != tc.want {
				t.Fatalf("ReasonForError = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestReasonCodesAreTheDocumentedSet(t *testing.T) {
	got := []ReasonCode{ReasonNone, ReasonRateLimited, ReasonMuted, ReasonProviderUnreachable,
		ReasonProviderRejected, ReasonTimeout, ReasonInternal}
	want := []ReasonCode{"", "rate_limited", "muted", "provider_unreachable",
		"provider_rejected", "timeout", "internal"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("reason codes = %q, want %q", got, want)
	}
}

// TestSchemaRejectsNonCodes: the database enforces the closed sets too. Each
// insert below is valid except for the one field under test.
func TestSchemaRejectsNonCodes(t *testing.T) {
	s, _ := newTestStore(t)
	for name, values := range map[string][]string{
		"reason": {"'https://api.telegram.org/bot1:x/sendMessage'", "'Timeout'"},
		"kind":   {"'https://api.telegram.org/bot1:x/sendMessage'", "'unknown.kind'", "'digest '"},
		"state":  {"'FAILED'", "'bot1:x'"},
	} {
		for _, v := range values {
			var kind, state, reason = "'lease.expiring'", "'expiring'", "''"
			switch name {
			case "reason":
				reason = v
			case "kind":
				kind = v
			case "state":
				state = v
			}
			_, err := s.db.Exec(`INSERT INTO notify_log (at, kind, host, state, reason, execution_id, link, outcome, providers, changed)
				VALUES (1, ` + kind + `, 'h', ` + state + `, ` + reason + `, '', '', 'failed', 0, 0)`)
			if err == nil {
				t.Errorf("the database accepted %s %s", name, v)
			}
		}
	}
}

func TestListIsNewestFirstAndPagesWithoutGapsOrRepeats(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	const total = 250
	for i := 0; i < total; i++ {
		mustAppend(t, s, sampleRecord())
	}

	var seen []int64
	var after int64
	for {
		page, err := s.List(ctx, after, MaxPage)
		if err != nil {
			t.Fatalf("List(%d): %v", after, err)
		}
		if len(page) == 0 {
			break
		}
		if len(page) > MaxPage {
			t.Fatalf("page has %d entries, max %d", len(page), MaxPage)
		}
		for _, e := range page {
			seen = append(seen, e.Seq)
		}
		after = page[len(page)-1].Seq
	}

	if len(seen) != total {
		t.Fatalf("paged %d entries, want %d", len(seen), total)
	}
	for i := 1; i < len(seen); i++ {
		if seen[i] >= seen[i-1] {
			t.Fatalf("entry %d (seq %d) is not older than entry %d (seq %d)", i, seen[i], i-1, seen[i-1])
		}
	}
}

func TestListStableWhenNewEntriesArrive(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		mustAppend(t, s, sampleRecord())
	}
	first, err := s.List(ctx, 0, 2)
	if err != nil || len(first) != 2 {
		t.Fatalf("first page: %v, %d entries", err, len(first))
	}
	mustAppend(t, s, sampleRecord())
	next, err := s.List(ctx, first[len(first)-1].Seq, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(next) != 1 || next[0].Seq != 1 {
		t.Fatalf("second page after new append = %+v, want only seq 1", next)
	}
}

func TestListRejectsNonPositiveLimitAndClampsLarge(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	if _, err := s.List(ctx, 0, 0); err == nil {
		t.Fatal("limit 0 accepted")
	}
	if _, err := s.List(ctx, 0, -5); err == nil {
		t.Fatal("negative limit accepted")
	}
	for i := 0; i < MaxPage+5; i++ {
		mustAppend(t, s, sampleRecord())
	}
	page, err := s.List(ctx, 0, MaxPage*10)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != MaxPage {
		t.Fatalf("large limit returned %d entries, want %d", len(page), MaxPage)
	}
}

func TestListRoundTripsFields(t *testing.T) {
	s, clk := newTestStore(t)
	mustAppend(t, s, sampleRecord())
	page, err := s.List(context.Background(), 0, 1)
	if err != nil || len(page) != 1 {
		t.Fatalf("List: %v, %d entries", err, len(page))
	}
	got := page[0]
	if !got.At.Equal(clk.t) {
		t.Fatalf("At = %v, want injected %v", got.At, clk.t)
	}
	want := sampleRecord()
	if got.Kind != want.Kind || got.Host != want.Host || got.State != want.State ||
		got.Reason != want.Reason || got.ExecutionID != want.ExecutionID ||
		got.Link != want.Link || got.Outcome != want.Outcome || got.Providers != want.Providers {
		t.Fatalf("round trip = %+v, want fields of %+v", got, want)
	}
	if got.Changed != 0 {
		t.Fatalf("Changed = %b for clean input, want 0", got.Changed)
	}
}

func TestPruneRemovesEntriesOlderThanRetention(t *testing.T) {
	s, clk := newTestStore(t)
	ctx := context.Background()

	old := clk.t.Add(-Retention - time.Second)
	kept := clk.t.Add(-Retention + time.Second)
	clk.t = old
	mustAppend(t, s, sampleRecord())
	clk.t = kept
	mustAppend(t, s, sampleRecord())
	clk.t = clk.t.Add(Retention)
	mustAppend(t, s, sampleRecord())

	removed, err := s.Prune(ctx)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if removed != 1 {
		t.Fatalf("Prune removed %d, want 1 (the entry older than Retention)", removed)
	}
	page, err := s.List(ctx, 0, MaxPage)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 2 {
		t.Fatalf("%d entries left, want 2", len(page))
	}
}

// TestPruneKeepsEntryWrittenExactlyRetentionAgo pins the boundary: an entry
// written exactly Retention ago is kept, and one second later it is removed.
func TestPruneKeepsEntryWrittenExactlyRetentionAgo(t *testing.T) {
	s, clk := newTestStore(t)
	ctx := context.Background()
	mustAppend(t, s, sampleRecord()) // written at clk.t

	clk.t = clk.t.Add(Retention)
	removed, err := s.Prune(ctx)
	if err != nil || removed != 0 {
		t.Fatalf("Prune at exactly Retention = %d, %v; want 0, nil (entry is kept)", removed, err)
	}

	clk.t = clk.t.Add(time.Second)
	removed, err = s.Prune(ctx)
	if err != nil || removed != 1 {
		t.Fatalf("Prune one second later = %d, %v; want 1, nil", removed, err)
	}
}

// TestPruneUsesInjectedClock: Prune has no time argument. It ages entries on
// the Store's clock, the same clock Append stamps entries with.
func TestPruneUsesInjectedClock(t *testing.T) {
	s, clk := newTestStore(t)
	ctx := context.Background()
	mustAppend(t, s, sampleRecord())

	clk.t = clk.t.Add(Retention + time.Hour)
	mustAppend(t, s, sampleRecord()) // stamped with the same clock, so it is recent

	removed, err := s.Prune(ctx)
	if err != nil || removed != 1 {
		t.Fatalf("Prune = %d, %v; want 1, nil (only the old entry)", removed, err)
	}
	page, err := s.List(ctx, 0, MaxPage)
	if err != nil || len(page) != 1 || !page[0].At.Equal(clk.t) {
		t.Fatalf("left %+v (err %v); want the entry stamped at the injected time %v", page, err, clk.t)
	}
}

// fillRaw inserts n rows in one transaction, bypassing Append's trim, so a
// test can build a table over MaxEntries and then exercise the cap itself.
func fillRaw(t *testing.T, s *Store, n int) {
	t.Helper()
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for i := 0; i < n; i++ {
		if _, err := tx.Exec(`INSERT INTO notify_log
			(at, kind, host, state, reason, execution_id, link, outcome, providers, changed)
			VALUES (?, ?, 'web-1', ?, '', 'ex-1', '/executions/ex-1', 'sent', 2, 0)`,
			time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC).Unix(), string(KindLeaseRunFailed), string(StateFailed)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestPruneRemovesOldestBeyondMaxEntries(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	const extra = 7
	fillRaw(t, s, MaxEntries+extra)

	removed, err := s.Prune(ctx)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if removed != extra {
		t.Fatalf("Prune removed %d, want %d", removed, extra)
	}
	// The newest MaxEntries survive: the oldest kept seq is extra+1.
	var oldest int64
	var after int64
	count := 0
	for {
		page, err := s.List(ctx, after, MaxPage)
		if err != nil {
			t.Fatal(err)
		}
		if len(page) == 0 {
			break
		}
		count += len(page)
		oldest = page[len(page)-1].Seq
		after = oldest
	}
	if count != MaxEntries {
		t.Fatalf("%d entries left, want %d", count, MaxEntries)
	}
	if oldest != extra+1 {
		t.Fatalf("oldest kept seq = %d, want %d", oldest, extra+1)
	}
}

func TestPruneIsNoOpWithinLimits(t *testing.T) {
	s, _ := newTestStore(t)
	mustAppend(t, s, sampleRecord())
	removed, err := s.Prune(context.Background())
	if err != nil || removed != 0 {
		t.Fatalf("Prune = %d, %v; want 0, nil", removed, err)
	}
}

// TestHostileHostAndExecutionIDAreRefused: control, bidi, zero-width, invalid
// UTF-8 and provider text in Host or ExecutionID is not a label or an ID, so
// the record is refused and nothing is stored.
func TestHostileHostAndExecutionIDAreRefused(t *testing.T) {
	hostile := []string{
		"web\x00-1\x1b[31m",
		"web" + string(rune(0x202E)) + "evil",
		"web" + string(rune(0x200B)) + "1",
		"ex\ncution",
		"ex\xff bad utf8",
	}
	s, _ := newTestStore(t)
	ctx := context.Background()
	for _, v := range hostile {
		r := sampleRecord()
		r.Host = v
		if _, err := s.Append(ctx, r); !errors.Is(err, ErrRefused) {
			t.Errorf("Host %q: Append err = %v, want ErrRefused", v, err)
		}
		r = sampleRecord()
		r.ExecutionID = v
		if _, err := s.Append(ctx, r); !errors.Is(err, ErrRefused) {
			t.Errorf("ExecutionID %q: Append err = %v, want ErrRefused", v, err)
		}
	}
	page, err := s.List(ctx, 0, MaxPage)
	if err != nil || len(page) != 0 {
		t.Fatalf("refused records left %d rows (err %v); want none", len(page), err)
	}
}

// TestRealHostIDsAreAccepted: a host is stored only as an inventory host ID
// (lowercase letters, digits, '.', '_' or '-', starting with a letter or
// digit, at most 63 bytes), and an execution ID only as a lowercase UUIDv4.
// Both are stored exactly as given, with no field marked changed. A machine-id
// style host (32 hex digits) and a host whose name merely contains "tk" are
// real inventory IDs and are accepted.
func TestRealHostIDsAreAccepted(t *testing.T) {
	hosts := []string{
		"web-1", "nas.lab_01", "a", "9", "pve-node-02.lab", strings.Repeat("h", 63),
		"5b9ae4c1d0f3e2a7b8c6d5e4f3a2b1c0",                   // machine-id style, 32 hex
		"5b9ae4c1d0f3e2a7b8c6d5e4f3a2b1",                     // 30 hex
		"5b9ae4c1d0f3e2a7b8c6d5e4f3a2b1c0" + "abcdefabcdefa", // 45 hex
		strings.Repeat("0", 63),                              // 63 hex digits, the length limit
		"tk-web",                                             // contains "tk", not a token
		"tk_x7aq9mzp2lwr8vn4bkc6shd3fgj1",                    // inventory-shaped, lowercase
	}
	execIDs := []string{testExecID, "00000000-0000-4000-8000-000000000000", "ffffffff-ffff-4fff-bfff-ffffffffffff"}
	s, _ := newTestStore(t)
	ctx := context.Background()
	for _, h := range hosts {
		for _, e := range execIDs {
			r := sampleRecord()
			r.Host = h
			r.ExecutionID = e
			mustAppend(t, s, r)
		}
	}
	page, err := s.List(ctx, 0, MaxPage)
	if err != nil || len(page) != len(hosts)*len(execIDs) {
		t.Fatalf("List: %d rows, err %v; want %d", len(page), err, len(hosts)*len(execIDs))
	}
	for _, e := range page {
		if e.Changed != 0 {
			t.Errorf("accepted host %q / execution %q marked changed %b", e.Host, e.ExecutionID, e.Changed)
		}
	}
}

// TestHostAndExecutionIDShape: values outside the real ID schemas are refused.
// Empty is allowed for both (no host or no execution), as before.
func TestHostAndExecutionIDShape(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	mustAppend(t, s, sampleRecord())
	badHosts := []string{
		"-web", ".web", "_web", "web 1", "web/1", "web:1", "web?x", "web#x",
		"web\x00", "web\n1", "ä", "\xff", "Web-1", "WEB", "web.1\t",
		"Lab Server", // a display name, not an inventory ID
		strings.Repeat("h", 64),
		"https://api.telegram.org/bot123456:SECRET/sendMessage",
		"123456:SECRET",
	}
	badExecIDs := []string{
		"ex-1", "web-1", "",
		"3F2B8C1E-9A4D-4E7F-8C2A-1B2C3D4E5F60", // not a lowercase UUIDv4
		"3f2b8c1e-9a4d-1e7f-8c2a-1b2c3d4e5f60", // version 1
		"3f2b8c1e-9a4d-4e7f-7c2a-1b2c3d4e5f60", // wrong variant
		"3f2b8c1e9a4d4e7f8c2a1b2c3d4e5f60",     // no hyphens
		testExecID + " ",
		testExecID + "\n",
	}
	for _, v := range badHosts {
		r := sampleRecord()
		r.Host = v
		if _, err := s.Append(ctx, r); !errors.Is(err, ErrRefused) {
			t.Errorf("Host %q accepted or wrong error: %v", v, err)
		}
	}
	for _, v := range badExecIDs {
		r := sampleRecord()
		r.ExecutionID = v
		if v == "" {
			// Empty means no execution: accepted, as before.
			if _, err := s.Append(ctx, r); err != nil {
				t.Errorf("empty ExecutionID refused: %v", err)
			}
			continue
		}
		if _, err := s.Append(ctx, r); !errors.Is(err, ErrRefused) {
			t.Errorf("ExecutionID %q accepted or wrong error: %v", v, err)
		}
	}
	page, err := s.List(ctx, 0, MaxPage)
	if err != nil || len(page) != 2 {
		t.Fatalf("refused values left rows: %d, err %v; want only the valid sample and the empty ID", len(page), err)
	}
}

// TestSecretValuesAreRefusedWithoutEcho: a value that is not a valid ID is
// refused and the error names only the field, never the value. Each secret is
// refused in ExecutionID (not a UUIDv4). In Host it is refused when it breaks
// the inventory pattern (uppercase, a symbol, a space, over 63 bytes); the
// Host rule is the shape, not a secret detector, so a secret-looking value
// that has the inventory shape is a valid ID (see
// TestHostIDIsExactlyInventoryPattern).
func TestSecretValuesAreRefusedWithoutEcho(t *testing.T) {
	secrets := []string{
		"tk_Xy7aQ9mZp2LwR8vN4bKc6sHd3fGj1",                                 // ntfy access token, mixed case
		"tk_x7aq9mzp2lwr8vn4bkc6shd3fgj1",                                  // ntfy access token, lowercase
		"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", // 64 hex HMAC key
		"5b9ae4c1d0f3e2a7b8c6d5e4f3a2b1c0",                                 // 32 hex HMAC key
		"A9Lq3-xT7_mZ2vK8pR0sW4eY6uI1oP5aS9dF3gH7jKl",                      // base64url, mixed case
		"AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw",                               // Telegram token, no numeric prefix
		"https://api.telegram.org/bot123456:SECRET/sendMessage",            // target URL with a token
	}
	s, _ := newTestStore(t)
	ctx := context.Background()
	for _, v := range secrets {
		r := sampleRecord()
		r.ExecutionID = v
		_, err := s.Append(ctx, r)
		if !errors.Is(err, ErrRefused) {
			t.Errorf("execution_id secret accepted or wrong error: %v", err)
		} else if msg := err.Error(); !strings.Contains(msg, "execution_id") || strings.Contains(msg, v) {
			t.Errorf("execution_id refusal %q must name the field and not echo the value", msg)
		}
	}
	// Host: only the values that break the inventory pattern are refused.
	for _, v := range []string{secrets[0], secrets[2], secrets[4], secrets[5], secrets[6]} {
		r := sampleRecord()
		r.Host = v
		_, err := s.Append(ctx, r)
		if !errors.Is(err, ErrRefused) {
			t.Errorf("host secret %q accepted or wrong error: %v", v, err)
		} else if msg := err.Error(); !strings.Contains(msg, "host") || strings.Contains(msg, v) {
			t.Errorf("host refusal %q must name the field and not echo the value", msg)
		}
	}
	page, err := s.List(ctx, 0, MaxPage)
	if err != nil || len(page) != 0 {
		t.Fatalf("secret values left %d rows (err %v); want none", len(page), err)
	}
}

// TestHostIDIsExactlyInventoryPattern pins Host to the inventory pattern in
// both directions: a value Append refuses is one canonical.ValidHostID rejects,
// and a value it accepts is one the inventory accepts. Boundaries (63 and 64
// bytes, 31/32/33 hex digits, "tk" prefixes, a leading or trailing separator)
// are included, so an extra secret filter or a looser check fails here.
func TestHostIDIsExactlyInventoryPattern(t *testing.T) {
	cases := []string{
		"", "a", "9", "web-1", "tk-web", "tk_web", "tk_x7aq9mzp2lwr8vn4bkc6shd3fgj1",
		strings.Repeat("h", 63), strings.Repeat("h", 64),
		strings.Repeat("0", 31), strings.Repeat("0", 32), strings.Repeat("f", 33),
		"5b9ae4c1d0f3e2a7b8c6d5e4f3a2b1c0", // machine-id
		"-web", "web-", ".web", "web.", "_web", "Web", "web 1", "web/1",
		"A9Lq3-xT7_mZ2vK8pR0sW4eY6uI1oP5aS9dF3gH7jKl",
	}
	s, _ := newTestStore(t)
	ctx := context.Background()
	for _, h := range cases {
		r := sampleRecord()
		r.Host = h
		_, err := s.Append(ctx, r)
		accepted := err == nil
		if want := h == "" || canonical.ValidHostID(h); accepted != want {
			t.Errorf("Host %q: accepted = %v (err %v), inventory pattern says %v", h, accepted, err, want)
		}
		if err != nil && !errors.Is(err, ErrRefused) {
			t.Errorf("Host %q: error %v does not wrap ErrRefused", h, err)
		}
	}
}

// TestEmptyHostIsStored: a record with no host (for example a digest event
// that belongs to no single host) is stored with an empty Host, and it is not
// marked changed. Refusing it would drop the event.
func TestEmptyHostIsStored(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	r := sampleRecord()
	r.Host = ""
	mustAppend(t, s, r)
	page, err := s.List(ctx, 0, MaxPage)
	if err != nil || len(page) != 1 {
		t.Fatalf("List: %d rows, err %v; want 1", len(page), err)
	}
	if page[0].Host != "" || page[0].Changed != 0 {
		t.Errorf("empty host stored as %q with changed %b; want \"\" and no change", page[0].Host, page[0].Changed)
	}
}

// TestRefusalErrorsNameTheFieldNeverTheValue: a refused field is reported by
// name only. The input is a Telegram bot URL with a token, so any echo of the
// value would leak it into the error text and into logs that wrap it.
func TestRefusalErrorsNameTheFieldNeverTheValue(t *testing.T) {
	const token = "123456:SECRET-TOKEN-XYZ"
	botURL := "https://api.telegram.org/bot" + token + "/sendMessage?chat_id=42"
	s, _ := newTestStore(t)
	ctx := context.Background()
	for _, tc := range []struct {
		field string
		apply func(*Record)
	}{
		{"kind", func(r *Record) { r.Kind = KindCode(botURL) }},
		{"state", func(r *Record) { r.State = StateCode(botURL) }},
		{"reason", func(r *Record) { r.Reason = ReasonCode(botURL) }},
		{"outcome", func(r *Record) { r.Outcome = Outcome(botURL) }},
		{"host", func(r *Record) { r.Host = botURL }},
		{"execution_id", func(r *Record) { r.ExecutionID = botURL }},
	} {
		r := sampleRecord()
		tc.apply(&r)
		_, err := s.Append(ctx, r)
		if err == nil {
			t.Fatalf("%s: Append accepted a bot URL", tc.field)
		}
		if !errors.Is(err, ErrRefused) {
			t.Errorf("%s: error %v does not wrap ErrRefused", tc.field, err)
		}
		msg := err.Error()
		if !strings.Contains(msg, tc.field) {
			t.Errorf("%s: error %q does not name the field", tc.field, msg)
		}
		for _, leak := range []string{token, "123456", "api.telegram.org", "bot", "sendMessage", "chat_id"} {
			if strings.Contains(msg, leak) {
				t.Errorf("%s: error %q echoes input fragment %q", tc.field, msg, leak)
			}
		}
	}
}

// TestAppendEnforcesMaxEntriesWithoutPrune: a flood of held events must not
// grow the table past MaxEntries between prune runs. Append trims the oldest
// rows in the same transaction as the insert.
func TestAppendEnforcesMaxEntriesWithoutPrune(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	const extra = 7
	fillRaw(t, s, MaxEntries)
	for i := 0; i < extra; i++ {
		mustAppend(t, s, sampleRecord())
	}
	var n, oldest int64
	if err := s.db.QueryRow(`SELECT COUNT(*), MIN(seq) FROM notify_log`).Scan(&n, &oldest); err != nil {
		t.Fatal(err)
	}
	if n != MaxEntries {
		t.Fatalf("%d rows after flood, want %d", n, MaxEntries)
	}
	if oldest != extra+1 {
		t.Fatalf("oldest seq = %d, want %d", oldest, extra+1)
	}
	if removed, err := s.Prune(ctx); err != nil || removed != 0 {
		t.Fatalf("Prune after Append trim = %d, %v; want 0, nil", removed, err)
	}
}

// TestOverlongHostOrExecutionIDIsRefused: a host or execution ID over the
// schema length is not a shorter ID, so it is refused, not cut. A cut value
// could match a different real ID.
func TestOverlongHostOrExecutionIDIsRefused(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	r := sampleRecord()
	r.ExecutionID = testExecID + strings.Repeat("a", MaxExecutionID)
	if _, err := s.Append(ctx, r); !errors.Is(err, ErrRefused) {
		t.Errorf("overlong ExecutionID: err = %v, want ErrRefused", err)
	}
	r = sampleRecord()
	r.Host = strings.Repeat("h", MaxHost+10)
	if _, err := s.Append(ctx, r); !errors.Is(err, ErrRefused) {
		t.Errorf("overlong Host: err = %v, want ErrRefused", err)
	}
}

// TestNOSLinkRules checks isNOSLink one rule at a time: each bad value breaks
// exactly one rule, so removing any single check makes a case fail.
func TestNOSLinkRules(t *testing.T) {
	good := []string{"/", "/executions/ex-1", "/a:b/c", "/x.y~z_-"}
	bad := map[string]string{
		"empty":                 "",
		"no leading slash":      "executions/ex-1",
		"https url":             "https://ntfy.example.invalid/topic",
		"scheme-relative":       "//evil.example/x",
		"javascript":            "javascript:alert(1)",
		"backslash after slash": "/\\evil.example/x",
		"backslash in path":     "/x\\y",
		"slash in path":         "/x//y",
		"tab after slash":       "/\tevil.example/x",
		"newline after slash":   "/\n/evil.example/x",
		"space":                 "/a b",
		"query with token":      "/x?token=a",
		"bare query mark":       "/x?",
		"fragment with token":   "/x#access_token=a",
		"bare fragment mark":    "/x#",
		"absolute url in path":  "/x://evil.example",
		"non-ASCII":             "/ä",
		"nul byte":              "/x\x00y",
		"del byte":              "/x\x7fy",
	}
	for _, v := range good {
		if !isNOSLink(v) {
			t.Errorf("isNOSLink(%q) = false, want true", v)
		}
	}
	for name, v := range bad {
		if isNOSLink(v) {
			t.Errorf("%s: isNOSLink(%q) = true, want false", name, v)
		}
	}
}

func TestLinkMustBeNOSPathOtherwiseDropped(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	for _, bad := range []string{
		"https://ntfy.example.invalid/topic?token=abc",
		"//evil.example/x",
		"/\\evil.example/x",
		"/x#access_token=a",
		"/x?token=a",
		"javascript:alert(1)",
	} {
		r := sampleRecord()
		r.Link = bad
		mustAppend(t, s, r)
	}
	good := sampleRecord()
	mustAppend(t, s, good)

	page, err := s.List(ctx, 0, MaxPage)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 7 {
		t.Fatalf("%d entries, want 7 (a bad link never drops the message)", len(page))
	}
	if page[0].Link != good.Link || page[0].Changed.Has(FieldLink) {
		t.Fatalf("good link altered: %+v", page[0])
	}
	for _, e := range page[1:] {
		if e.Link != "" || !e.Changed.Has(FieldLink) {
			t.Fatalf("bad link stored as %q with Changed=%b", e.Link, e.Changed)
		}
	}
}

// TestEmptyLinkIsNoLinkNotAChangedLink: an event without a link (a held or
// summary event) has no link to drop, so Changed must not report one.
func TestEmptyLinkIsNoLinkNotAChangedLink(t *testing.T) {
	s, _ := newTestStore(t)
	r := sampleRecord()
	r.Link = ""
	mustAppend(t, s, r)

	page, err := s.List(context.Background(), 0, 1)
	if err != nil || len(page) != 1 {
		t.Fatalf("List: %d rows, err %v", len(page), err)
	}
	if page[0].Link != "" || page[0].Changed.Has(FieldLink) || page[0].Changed != 0 {
		t.Fatalf("empty link: Link %q, Changed %b; want no link and no change", page[0].Link, page[0].Changed)
	}
}

// TestLinkOverMaxIsDroppedNotTruncated: a cut path could point at another or
// a nonexistent UI route, so an over-long link is dropped like any invalid
// link. A link of exactly MaxLink bytes is kept.
func TestLinkOverMaxIsDroppedNotTruncated(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	atLimit := "/" + strings.Repeat("a", MaxLink-1)
	overLimit := "/" + strings.Repeat("a", MaxLink)

	r := sampleRecord()
	r.Link = atLimit
	mustAppend(t, s, r)
	r.Link = overLimit
	mustAppend(t, s, r)

	page, err := s.List(ctx, 0, MaxPage)
	if err != nil || len(page) != 2 {
		t.Fatalf("List: %d rows, err %v", len(page), err)
	}
	if page[0].Link != "" || !page[0].Changed.Has(FieldLink) {
		t.Fatalf("over-limit link not dropped: Link %q (len %d), Changed=%b", page[0].Link, len(page[0].Link), page[0].Changed)
	}
	if page[1].Link != atLimit || page[1].Changed.Has(FieldLink) {
		t.Fatalf("link of MaxLink bytes altered: Link len %d, Changed=%b", len(page[1].Link), page[1].Changed)
	}
}

// TestProvidersAreClampedAndNeverLoseEntry: a count outside 0..MaxProviders is
// clamped, so the row is still written. Without the clamp the CHECK constraint
// would refuse it and the entry would be lost.
func TestProvidersAreClampedAndNeverLoseEntry(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	for _, n := range []int{-5, -1, 0, MaxProviders, MaxProviders + 1, 1000} {
		r := sampleRecord()
		r.Providers = n
		if _, err := s.Append(ctx, r); err != nil {
			t.Fatalf("Append with Providers %d: %v; the entry must not be lost", n, err)
		}
	}
	page, err := s.List(ctx, 0, MaxPage)
	if err != nil || len(page) != 6 {
		t.Fatalf("List: %d rows, err %v; want 6", len(page), err)
	}
	// Newest first: 1000, 17, 16, 0, -1, -5, clamped to 16, 16, 16, 0, 0, 0.
	want := []int{MaxProviders, MaxProviders, MaxProviders, 0, 0, 0}
	for i, e := range page {
		if e.Providers != want[i] {
			t.Fatalf("entry %d: Providers = %d, want %d", i, e.Providers, want[i])
		}
	}
}

func TestSchemaHasNoTokenOrTargetURLColumn(t *testing.T) {
	s, _ := newTestStore(t)
	rows, err := s.db.Query(`SELECT name FROM pragma_table_info('notify_log') ORDER BY cid`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		cols = append(cols, n)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	want := []string{"seq", "at", "kind", "host", "state", "reason", "execution_id", "link", "outcome", "providers", "changed"}
	if !reflect.DeepEqual(cols, want) {
		t.Fatalf("columns = %v, want exactly %v", cols, want)
	}
	for _, c := range cols {
		for _, bad := range []string{"token", "secret", "url", "target", "body", "text", "payload", "log"} {
			if strings.Contains(c, bad) {
				t.Fatalf("column %q looks like it stores %s", c, bad)
			}
		}
	}
}

// TestSchemaEnforcesEveryCheck inserts one valid row, then changes one column
// at a time. Each invalid value must be refused by the table, and the limit
// values themselves must be accepted, so each CHECK is exercised at its edge.
func TestSchemaEnforcesEveryCheck(t *testing.T) {
	s, _ := newTestStore(t)
	base := map[string]string{
		"at": "1", "kind": "'lease.expiring'", "host": "'h'", "state": "'expiring'",
		"reason": "''", "execution_id": "''", "link": "''", "outcome": "'failed'",
		"providers": "0", "changed": "0",
	}
	insert := func(over map[string]string) error {
		vals := make(map[string]string, len(base))
		for k, v := range base {
			vals[k] = v
		}
		for k, v := range over {
			vals[k] = v
		}
		cols := []string{"at", "kind", "host", "state", "reason", "execution_id", "link", "outcome", "providers", "changed"}
		list := make([]string, len(cols))
		for i, c := range cols {
			list[i] = vals[c]
		}
		_, err := s.db.Exec(`INSERT INTO notify_log (at, kind, host, state, reason, execution_id, link, outcome, providers, changed)
			VALUES (` + strings.Join(list, ", ") + `)`)
		return err
	}
	quote := func(s string) string { return "'" + s + "'" }

	// Edges that must be accepted.
	accept := map[string]map[string]string{
		"host at 64 bytes":        {"host": quote(strings.Repeat("h", MaxHost))},
		"execution_id at 128":     {"execution_id": quote(strings.Repeat("e", MaxExecutionID))},
		"link at 256 bytes":       {"link": quote("/" + strings.Repeat("l", MaxLink-1))},
		"providers 16":            {"providers": "16"},
		"changed 7":               {"changed": "7"},
		"reason empty":            {"reason": "''"},
		"outcome held_rate_limit": {"outcome": "'held_rate_limit'"},
		"kind digest":             {"kind": "'digest'"},
		"state summary":           {"state": "'summary'"},
	}
	for name, over := range accept {
		if err := insert(over); err != nil {
			t.Errorf("%s: database refused a valid row: %v", name, err)
		}
	}

	// Edges that must be refused: one per CHECK clause and bound.
	refuse := map[string]map[string]string{
		"kind not a code":          {"kind": "'unknown.kind'"},
		"kind URL":                 {"kind": quote("https://api.telegram.org/bot1:x/sendMessage")},
		"state not a code":         {"state": "'FAILED'"},
		"state URL":                {"state": quote("bot1:x")},
		"reason not a code":        {"reason": "'Timeout'"},
		"reason URL":               {"reason": quote("https://api.telegram.org/bot1:x/sendMessage")},
		"outcome not a code":       {"outcome": "'maybe'"},
		"outcome empty":            {"outcome": "''"},
		"outcome NULL":             {"outcome": "NULL"},
		"providers -1":             {"providers": "-1"},
		"providers 17":             {"providers": "17"},
		"changed 8":                {"changed": "8"},
		"changed -1":               {"changed": "-1"},
		"host 65 bytes":            {"host": quote(strings.Repeat("h", MaxHost+1))},
		"host 33 runes (66 bytes)": {"host": quote(strings.Repeat("ä", 33))},
		"execution_id 129 bytes":   {"execution_id": quote(strings.Repeat("e", MaxExecutionID+1))},
		"link 257 bytes":           {"link": quote("/" + strings.Repeat("l", MaxLink))},
		"host NULL":                {"host": "NULL"},
		"link NULL":                {"link": "NULL"},
	}
	for name, over := range refuse {
		if err := insert(over); err == nil {
			t.Errorf("%s: the database accepted the row", name)
		}
	}
}
