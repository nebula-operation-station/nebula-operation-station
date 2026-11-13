// SPDX-License-Identifier: AGPL-3.0-or-later

package reputation

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// seedFixtures adds every file under testdata/ to the fuzz corpus as raw bytes.
func seedFixtures(f *testing.F) {
	for _, b := range fixtureBytes(f) {
		f.Add(b)
	}
}

// seedFixtureLines adds every line of every fixture under testdata/ to the
// corpus, for targets that take one entry text.
func seedFixtureLines(f *testing.F) {
	for _, b := range fixtureBytes(f) {
		for _, line := range strings.Split(string(b), "\n") {
			f.Add(line)
		}
	}
}

// fixtureBytes reads every file under testdata/.
func fixtureBytes(f *testing.F) [][]byte {
	entries, err := os.ReadDir("testdata")
	if err != nil {
		f.Fatalf("read testdata: %v", err)
	}
	var out [][]byte
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join("testdata", e.Name()))
		if err != nil {
			f.Fatalf("read seed %s: %v", e.Name(), err)
		}
		out = append(out, b)
	}
	return out
}

// FuzzParseEntry checks that no input panics and that every accepted entry
// is a normal prefix within the text limit.
func FuzzParseEntry(f *testing.F) {
	for _, s := range []string{"192.0.2.0/24", "192.0.2.7", "2001:db8::/32", "2001:db8::1", "0.0.0.0/0", "::ffff:192.0.2.1/120"} {
		f.Add(s)
	}
	seedFixtureLines(f)
	f.Fuzz(func(t *testing.T, s string) {
		p, err := ParseEntry(s)
		if err != nil {
			if !errors.Is(err, ErrMalformedEntry) {
				t.Fatalf("ParseEntry(%q) error %v, want ErrMalformedEntry", s, err)
			}
			return
		}
		// Same trim as ParseEntry: only space and tab are blanks here.
		if len(strings.Trim(s, " \t")) > maxEntryTextBytes {
			t.Fatalf("ParseEntry(%q) accepted text longer than the limit", s)
		}
		if !p.IsValid() || p.Masked() != p || p.Addr().Is4In6() || p.Bits() == 0 {
			t.Fatalf("ParseEntry(%q) = %s, not a normal non-default prefix", s, p)
		}
	})
}

// FuzzForEachRecord checks that no input panics, that the size limit holds
// and that every record handed to a caller is within the line limit.
func FuzzForEachRecord(f *testing.F) {
	f.Add([]byte("# c\n192.0.2.1\r\n\n2001:db8::/32\n"))
	seedFixtures(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		err := ForEachRecord(bytes.NewReader(data), '#', func(rec string) error {
			if len(rec) > MaxLineBytes {
				t.Fatalf("record of %d bytes passed the line limit", len(rec))
			}
			return nil
		})
		if err != nil && !errors.Is(err, ErrMalformedEntry) && !errors.Is(err, ErrLineTooLong) && !errors.Is(err, ErrFeedTooLarge) {
			t.Fatalf("ForEachRecord error %v is not a documented error", err)
		}
	})
}
