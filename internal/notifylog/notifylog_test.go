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
	"unicode"
	"unicode/utf8"

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

func sampleRecord() Record {
	return Record{
		Kind:        "execution",
		Host:        "web-1",
		State:       "FAILED",
		Reason:      ReasonTimeout,
		ExecutionID: "ex-1",
		Link:        "/executions/ex-1",
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

func TestSchemaRejectsURLReason(t *testing.T) {
	s, _ := newTestStore(t)
	_, err := s.db.Exec(`INSERT INTO notify_log (at, kind, host, state, reason, execution_id, link, outcome, providers, changed)
		VALUES (1, 'execution', 'h', 'FAILED', 'https://api.telegram.org/bot1:x/sendMessage', '', '', 'failed', 0, 0)`)
	if err == nil {
		t.Fatal("the database accepted a URL as reason")
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

func TestPruneRemovesOldestBeyondMaxEntries(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	const extra = 7
	for i := 0; i < MaxEntries+extra; i++ {
		mustAppend(t, s, sampleRecord())
	}

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

func TestHostileTextIsCleanedAndStored(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	r := sampleRecord()
	r.Host = "web\x00-1\x1b[31m" + string(rune(0x202E)) + "evil" + string(rune(0x200B)) + string(rune(0xFEFF))
	r.Kind = "exe\ncution \xff bad utf8"
	r.State = "FAILED" + string(rune(0x2066)) + "x" + string(rune(0x2069))
	seq := mustAppend(t, s, r)

	page, err := s.List(ctx, 0, 1)
	if err != nil || len(page) != 1 || page[0].Seq != seq {
		t.Fatalf("List: %v, %+v", err, page)
	}
	got := page[0]
	for _, v := range []string{got.Host, got.Kind, got.State} {
		if !utf8.ValidString(v) {
			t.Fatalf("stored text is not valid UTF-8: %q", v)
		}
		for _, c := range v {
			if c == '\n' || c == '\r' || c == '\t' {
				t.Fatalf("stored text keeps a line break or tab: %q", v)
			}
			if !unicode.IsPrint(c) || unicode.Is(unicode.Cf, c) || unicode.Is(unicode.Bidi_Control, c) {
				t.Fatalf("stored text keeps control, bidi or zero-width rune %U in %q", c, v)
			}
		}
	}
	if !strings.Contains(got.Kind, "exe cution") {
		t.Fatalf("line breaks were not turned into spaces: %q", got.Kind)
	}
	if got.Changed != 0 {
		t.Fatalf("Changed = %b; cleaning alone must not mark a field as shortened", got.Changed)
	}
}

func TestOverlongFieldIsShortenedAndMarkedNotRejected(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	r := sampleRecord()
	r.ExecutionID = strings.Repeat("a", MaxExecutionID+100)
	r.Host = strings.Repeat("ä", MaxHost) // 2 bytes per rune: twice the byte limit
	mustAppend(t, s, r)

	page, err := s.List(ctx, 0, 1)
	if err != nil || len(page) != 1 {
		t.Fatalf("List: %v", err)
	}
	got := page[0]
	if len(got.ExecutionID) != MaxExecutionID {
		t.Fatalf("ExecutionID has %d bytes, want %d", len(got.ExecutionID), MaxExecutionID)
	}
	if len(got.Host) > MaxHost || !utf8.ValidString(got.Host) {
		t.Fatalf("Host %q exceeds %d bytes or is not valid UTF-8", got.Host, MaxHost)
	}
	if !got.Changed.Has(FieldExecutionID) || !got.Changed.Has(FieldHost) {
		t.Fatalf("Changed = %b, want execution id and host marked", got.Changed)
	}
	if got.Changed.Has(FieldState) || got.Changed.Has(FieldKind) {
		t.Fatalf("Changed = %b marks fields that were not shortened", got.Changed)
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

func TestCleanKeepsPrintableAndBoundsRunes(t *testing.T) {
	got, cut := clean("a\u0007b"+string(rune(0xAD))+"c", 10)
	if got != "a�b�c" || cut {
		t.Fatalf("clean = %q, %v; want control and soft-hyphen replaced, not cut", got, cut)
	}
	got, cut = clean("äöü", 3)
	if got != "ä" || !cut {
		t.Fatalf("clean at byte limit 3 = %q, %v; want %q, true", got, cut, "ä")
	}
}
