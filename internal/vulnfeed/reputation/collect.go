// SPDX-License-Identifier: AGPL-3.0-or-later

package reputation

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// Limit errors. Callers branch on them with errors.Is. They never repeat
// feed text.
var (
	// ErrUnknownFeed: the feed ID is not in the fixed NOS-side list.
	ErrUnknownFeed = errors.New("reputation: unknown feed id")
	// ErrFeedTooLarge: the feed exceeds MaxFeedBytes; the whole feed is refused.
	ErrFeedTooLarge = errors.New("reputation: feed exceeds the size limit")
	// ErrLineTooLong: a line exceeds MaxLineBytes; the whole feed is refused.
	ErrLineTooLong = errors.New("reputation: feed line exceeds the length limit")
	// ErrEntryLimit: the feed yields more than MaxEntriesPerFeed entries.
	ErrEntryLimit = errors.New("reputation: feed exceeds the entry limit")
)

// Snapshot is the normalised result of one feed (ADR 0012 D6). Feed and
// Category are fixed by the feed ID.
type Snapshot struct {
	// Feed is the feed ID.
	Feed FeedID
	// Category is the fixed category of the feed.
	Category Category
	// Dated reports whether the feed carried a usable content date.
	Dated bool
	// ContentDate is the date the feed states for its content; zero when
	// Dated is false. It is never the retrieval time.
	ContentDate time.Time
	// Entries are the distinct entries, sorted by address then length.
	Entries []Entry
	// Duplicates counts the repeated entries that were dropped.
	Duplicates int
}

// ForEachRecord splits feed bytes into lines and calls fn for each record.
// Blank lines and lines whose first non-blank byte is comment are skipped;
// a trailing CR is part of the terminator. Records are passed with their
// surrounding blanks trimmed.
//
// The input is read up to MaxFeedBytes; a longer feed returns ErrFeedTooLarge
// before any record is passed. A line longer than MaxLineBytes returns
// ErrLineTooLong, including a comment line. Input that is not valid UTF-8
// returns ErrMalformedEntry. An error returned by fn stops the walk and is
// returned unchanged.
func ForEachRecord(r io.Reader, comment byte, fn func(rec string) error) error {
	data, err := io.ReadAll(io.LimitReader(r, MaxFeedBytes+1))
	if err != nil {
		return fmt.Errorf("reputation: read feed: %w", err)
	}
	if len(data) > MaxFeedBytes {
		return ErrFeedTooLarge
	}
	if !utf8.Valid(data) {
		return malformed("feed is not valid UTF-8")
	}
	for len(data) > 0 {
		var line []byte
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			line, data = data[:i], data[i+1:]
		} else {
			line, data = data, nil
		}
		line = bytes.TrimSuffix(line, []byte("\r"))
		if len(line) > MaxLineBytes {
			return ErrLineTooLong
		}
		rec := strings.Trim(string(line), " \t")
		if rec == "" || rec[0] == comment {
			continue
		}
		if err := fn(rec); err != nil {
			return err
		}
	}
	return nil
}

// Collector gathers the entries of one feed. It enforces MaxEntriesPerFeed
// and removes duplicates. A malformed entry fails the feed (fail closed):
// the caller must discard the collector.
type Collector struct {
	feed FeedID
	cat  Category
	seen map[netip.Prefix]struct{}
	dups int
}

// NewCollector starts a collector for a registered feed.
func NewCollector(feed FeedID) (*Collector, error) {
	cat, ok := feed.Category()
	if !ok {
		return nil, ErrUnknownFeed
	}
	return &Collector{feed: feed, cat: cat, seen: map[netip.Prefix]struct{}{}}, nil
}

// Add normalises one entry text and stores it. A repeat of a stored entry is
// counted and kept once. A new entry beyond MaxEntriesPerFeed returns
// ErrEntryLimit. A malformed entry returns an error wrapping
// ErrMalformedEntry.
func (c *Collector) Add(text string) error {
	p, err := ParseEntry(text)
	if err != nil {
		return err
	}
	if _, dup := c.seen[p]; dup {
		c.dups++
		return nil
	}
	if len(c.seen) >= MaxEntriesPerFeed {
		return ErrEntryLimit
	}
	c.seen[p] = struct{}{}
	return nil
}

// Finish returns the snapshot. date is used only when dated is true and it is
// a year in the accepted range; otherwise the snapshot is undated. Finish
// never reads a clock.
func (c *Collector) Finish(date time.Time, dated bool) Snapshot {
	entries := make([]Entry, 0, len(c.seen))
	for p := range c.seen {
		entries = append(entries, Entry{Prefix: p, Category: c.cat})
	}
	slices.SortFunc(entries, func(a, b Entry) int {
		if x := a.Prefix.Addr().Compare(b.Prefix.Addr()); x != 0 {
			return x
		}
		return cmp.Compare(a.Prefix.Bits(), b.Prefix.Bits())
	})
	snap := Snapshot{Feed: c.feed, Category: c.cat, Entries: entries, Duplicates: c.dups}
	if dated && validContentDate(date) {
		snap.Dated = true
		snap.ContentDate = date
	}
	return snap
}

// validContentDate reports whether a date is in the accepted year range.
func validContentDate(d time.Time) bool {
	y := d.Year()
	return !d.IsZero() && y >= minContentYear && y <= maxContentYear
}
