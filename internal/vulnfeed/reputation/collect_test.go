// SPDX-License-Identifier: AGPL-3.0-or-later

package reputation

import (
	"bytes"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// readFixture returns a file from testdata/ (synthetic, documentation
// ranges only).
func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

// collectRecords runs ForEachRecord over data and returns the records.
func collectRecords(data []byte, comment byte) ([]string, error) {
	var recs []string
	err := ForEachRecord(bytes.NewReader(data), comment, func(rec string) error {
		recs = append(recs, rec)
		return nil
	})
	return recs, err
}

// TestNewCollectorAcceptsOnlyRegisteredFeeds checks the fixed NOS-side feed
// ID list (ADR 0012 D6): no caller can invent a feed ID.
func TestNewCollectorAcceptsOnlyRegisteredFeeds(t *testing.T) {
	for _, id := range []FeedID{"", "Feodo", "feodo ", "unknown-feed", "abuseipdb"} {
		if _, err := NewCollector(id); !errors.Is(err, ErrUnknownFeed) {
			t.Errorf("NewCollector(%q) error = %v, want ErrUnknownFeed", id, err)
		}
	}
	for _, id := range Feeds() {
		if _, err := NewCollector(id); err != nil {
			t.Errorf("NewCollector(%q): %v", id, err)
		}
	}
}

// TestFeedCategoriesAreFixed pins the category of each feed to the kind
// given in ADR 0012 D6. A feed cannot choose its own category.
func TestFeedCategoriesAreFixed(t *testing.T) {
	want := map[FeedID]Category{
		FeedFeodo:         CategoryBotnetC2,
		FeedSSLBL:         CategoryBotnetC2,
		FeedSpamhausDROP:  CategoryHijackedNetblock,
		FeedSpamhausEDROP: CategoryHijackedNetblock,
		FeedFireHOLLevel1: CategoryAggregate,
	}
	if got := Feeds(); len(got) != len(want) {
		t.Fatalf("Feeds() has %d entries, want %d", len(got), len(want))
	}
	for id, cat := range want {
		got, ok := id.Category()
		if !ok || got != cat {
			t.Errorf("%s.Category() = %q, %v; want %q", id, got, ok, cat)
		}
	}
	if _, ok := FeedID("nope").Category(); ok {
		t.Error("unknown feed has a category")
	}
}

// TestForEachRecordSkipsCommentsAndBlanks checks that comment and blank
// lines are skipped and that CRLF endings are accepted.
func TestForEachRecordSkipsCommentsAndBlanks(t *testing.T) {
	recs, err := collectRecords(readFixture(t, "generic_list.txt"), '#')
	if err != nil {
		t.Fatalf("ForEachRecord: %v", err)
	}
	want := []string{"192.0.2.10", "192.0.2.0/24", "198.51.100.0/24", "2001:db8::/32", "2001:db8:1::5"}
	if strings.Join(recs, "|") != strings.Join(want, "|") {
		t.Errorf("records = %q, want %q", recs, want)
	}

	crlf, err := collectRecords([]byte("; c\r\n192.0.2.1\r\n\r\n198.51.100.1\r\n"), ';')
	if err != nil {
		t.Fatalf("ForEachRecord CRLF: %v", err)
	}
	if strings.Join(crlf, "|") != "192.0.2.1|198.51.100.1" {
		t.Errorf("CRLF records = %q", crlf)
	}
}

// TestForEachRecordSizeLimit tests the feed size limit at the limit and one
// byte past it. The limit applies to the bytes read from the feed.
func TestForEachRecordSizeLimit(t *testing.T) {
	line := "#" + strings.Repeat("x", 99) + "\n" // 101 bytes
	atLimit := []byte(strings.Repeat(line, MaxFeedBytes/len(line)))
	atLimit = append(atLimit, bytes.Repeat([]byte{'\n'}, MaxFeedBytes-len(atLimit))...)
	if len(atLimit) != MaxFeedBytes {
		t.Fatalf("test input is %d bytes, want %d", len(atLimit), MaxFeedBytes)
	}
	if _, err := collectRecords(atLimit, '#'); err != nil {
		t.Errorf("feed at the size limit: %v", err)
	}
	over := append(atLimit, '\n')
	if _, err := collectRecords(over, '#'); !errors.Is(err, ErrFeedTooLarge) {
		t.Errorf("feed one byte past the size limit: error %v, want ErrFeedTooLarge", err)
	}
}

// TestForEachRecordLineLimit tests the record length limit at the limit and
// one byte past it, for entry lines and for comment lines alike.
func TestForEachRecordLineLimit(t *testing.T) {
	for _, prefix := range []string{"#", ""} {
		atLimit := []byte(prefix + strings.Repeat("a", MaxLineBytes-len(prefix)) + "\n")
		if _, err := collectRecords(atLimit, '#'); err != nil {
			t.Errorf("line of %d bytes (prefix %q): %v", MaxLineBytes, prefix, err)
		}
		over := []byte(prefix + strings.Repeat("a", MaxLineBytes+1-len(prefix)) + "\n")
		if _, err := collectRecords(over, '#'); !errors.Is(err, ErrLineTooLong) {
			t.Errorf("line of %d bytes (prefix %q): error %v, want ErrLineTooLong", MaxLineBytes+1, prefix, err)
		}
	}
}

// TestForEachRecordRejectsInvalidUTF8 checks that feed bytes must be UTF-8
// before any record reaches a caller (AGENTS.md rule 6).
func TestForEachRecordRejectsInvalidUTF8(t *testing.T) {
	_, err := collectRecords([]byte("192.0.2.1\n# \xff\xfe\n"), '#')
	if !errors.Is(err, ErrMalformedEntry) {
		t.Errorf("invalid UTF-8: error %v, want ErrMalformedEntry", err)
	}
}

// TestCollectorNormalisesAndDeduplicates checks the normal form of a feed:
// entries are unique, sorted and carry the feed's fixed category; repeats
// are counted, not stored twice.
func TestCollectorNormalisesAndDeduplicates(t *testing.T) {
	c, err := NewCollector(FeedFeodo)
	if err != nil {
		t.Fatal(err)
	}
	recs, err := collectRecords(readFixture(t, "generic_duplicates.txt"), '#')
	if err != nil {
		t.Fatalf("ForEachRecord: %v", err)
	}
	for _, r := range recs {
		if err := c.Add(r); err != nil {
			t.Fatalf("Add(%q): %v", r, err)
		}
	}
	snap, err := c.Finish(time.Time{}, false)
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	if snap.Feed != FeedFeodo || snap.Category != CategoryBotnetC2 {
		t.Errorf("snapshot feed/category = %s/%s", snap.Feed, snap.Category)
	}
	want := []Entry{
		{Prefix: netip.MustParsePrefix("192.0.2.0/24"), Category: CategoryBotnetC2},
		{Prefix: netip.MustParsePrefix("192.0.2.1/32"), Category: CategoryBotnetC2},
		{Prefix: netip.MustParsePrefix("2001:db8::/32"), Category: CategoryBotnetC2},
	}
	if len(snap.Entries) != len(want) {
		t.Fatalf("entries = %v, want %v", snap.Entries, want)
	}
	for i := range want {
		if snap.Entries[i] != want[i] {
			t.Errorf("entry %d = %v, want %v", i, snap.Entries[i], want[i])
		}
	}
	if snap.Duplicates != 2 {
		t.Errorf("Duplicates = %d, want 2", snap.Duplicates)
	}
}

// TestCollectorInvalidRecordFailsFeed checks fail-closed behaviour: one
// malformed record makes the whole feed unusable, it is not skipped.
func TestCollectorInvalidRecordFailsFeed(t *testing.T) {
	c, err := NewCollector(FeedFireHOLLevel1)
	if err != nil {
		t.Fatal(err)
	}
	recs, err := collectRecords(readFixture(t, "generic_invalid.txt"), '#')
	if err != nil {
		t.Fatalf("ForEachRecord: %v", err)
	}
	var addErr error
	for _, r := range recs {
		if addErr = c.Add(r); addErr != nil {
			break
		}
	}
	if !errors.Is(addErr, ErrMalformedEntry) {
		t.Errorf("invalid record: error %v, want ErrMalformedEntry", addErr)
	}
}

// TestCollectorEntryLimit tests the per-feed entry cap at the limit and one
// entry past it.
func TestCollectorEntryLimit(t *testing.T) {
	c, err := NewCollector(FeedSpamhausDROP)
	if err != nil {
		t.Fatal(err)
	}
	base := netip.MustParseAddr("10.0.0.0") // only the prefixes matter here
	addr := base
	for i := 0; i < MaxEntriesPerFeed; i++ {
		if err := c.Add(addr.String() + "/32"); err != nil {
			t.Fatalf("entry %d of %d: %v", i+1, MaxEntriesPerFeed, err)
		}
		addr = addr.Next()
	}
	if err := c.Add(addr.String() + "/32"); !errors.Is(err, ErrEntryLimit) {
		t.Errorf("entry %d: error %v, want ErrEntryLimit", MaxEntriesPerFeed+1, err)
	}
	// The limit failed the feed, so even a repeat of a stored entry is refused.
	if err := c.Add(base.String() + "/32"); !errors.Is(err, ErrCollectorFailed) {
		t.Errorf("repeat after the entry limit: error %v, want ErrCollectorFailed", err)
	}
	if _, err := c.Finish(time.Time{}, false); !errors.Is(err, ErrCollectorFailed) {
		t.Errorf("Finish after the entry limit: error %v, want ErrCollectorFailed", err)
	}
}

// TestCollectorEntryLimitAcceptsRepeatsWithinLimit checks that repeats of
// stored entries do not count against the cap while the feed is still
// under it.
func TestCollectorEntryLimitAcceptsRepeatsWithinLimit(t *testing.T) {
	c, err := NewCollector(FeedSpamhausDROP)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := c.Add("10.0.0.1/32"); err != nil {
			t.Fatalf("repeat %d: %v", i+1, err)
		}
	}
	snap, err := c.Finish(time.Time{}, false)
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	if snap.Duplicates != 2 || len(snap.Entries) != 1 {
		t.Errorf("Duplicates = %d, Entries = %d; want 2 and 1", snap.Duplicates, len(snap.Entries))
	}
}

// TestCollectorFailureIsSticky checks fail-closed behaviour at the collector
// itself, not only in the caller: after one failed Add, every later Add and
// Finish is refused, so a partial snapshot can never be produced.
func TestCollectorFailureIsSticky(t *testing.T) {
	cases := []struct {
		name  string
		entry string
		cause error
	}{
		{"malformed entry", "not-an-address", ErrMalformedEntry},
		{"default route", "0.0.0.0/0", ErrMalformedEntry},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewCollector(FeedFeodo)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.Add("192.0.2.1"); err != nil {
				t.Fatalf("valid Add before the failure: %v", err)
			}
			if err := c.Add(tc.entry); !errors.Is(err, tc.cause) {
				t.Fatalf("Add(%q): error %v, want %v", tc.entry, err, tc.cause)
			}
			if err := c.Add("198.51.100.1"); !errors.Is(err, ErrCollectorFailed) {
				t.Errorf("Add after the failure: error %v, want ErrCollectorFailed", err)
			}
			snap, err := c.Finish(time.Time{}, false)
			if !errors.Is(err, ErrCollectorFailed) {
				t.Errorf("Finish after the failure: error %v, want ErrCollectorFailed", err)
			}
			if len(snap.Entries) != 0 {
				t.Errorf("Finish after the failure returned %d entries", len(snap.Entries))
			}
		})
	}
}

// TestCollectorFinishErrorKeepsCause checks that the refusal from Finish and
// the refusal from Add both carry ErrCollectorFailed, and that the original
// cause is still visible to errors.Is.
func TestCollectorFinishErrorKeepsCause(t *testing.T) {
	c, err := NewCollector(FeedFeodo)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Add("bogus"); !errors.Is(err, ErrMalformedEntry) {
		t.Fatalf("Add(bogus): error %v, want ErrMalformedEntry", err)
	}
	if _, err := c.Finish(time.Time{}, false); !errors.Is(err, ErrCollectorFailed) || !errors.Is(err, ErrMalformedEntry) {
		t.Errorf("Finish: error %v, want ErrCollectorFailed wrapping ErrMalformedEntry", err)
	}
}

// TestFinishContentDate checks the content date rules: a date that is
// absent, zero, unusable or out of range makes the snapshot undated. The
// collector never substitutes a retrieval time.
func TestFinishContentDate(t *testing.T) {
	valid := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name  string
		date  time.Time
		ok    bool
		dated bool
	}{
		{"valid date", valid, true, true},
		{"flag says no date", valid, false, false},
		{"zero time", time.Time{}, true, false},
		{"year before range", time.Date(1969, 12, 31, 0, 0, 0, 0, time.UTC), true, false},
		{"year after range", time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC), true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := NewCollector(FeedSSLBL)
			if err != nil {
				t.Fatal(err)
			}
			snap, err := c.Finish(tc.date, tc.ok)
			if err != nil {
				t.Fatalf("Finish: %v", err)
			}
			if snap.Dated != tc.dated {
				t.Fatalf("Dated = %v, want %v", snap.Dated, tc.dated)
			}
			if tc.dated && !snap.ContentDate.Equal(tc.date) {
				t.Errorf("ContentDate = %v, want %v", snap.ContentDate, tc.date)
			}
			if !tc.dated && !snap.ContentDate.IsZero() {
				t.Errorf("undated snapshot has ContentDate %v", snap.ContentDate)
			}
		})
	}
}
