// SPDX-License-Identifier: AGPL-3.0-or-later

package fimbaseline

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/fimscan"
)

// FuzzDiff parses two fim-scan-v1 documents, builds a baseline from the
// first and diffs the second against it.
func FuzzDiff(f *testing.F) {
	var seeds [][]byte
	for _, pattern := range []string{"../fimscan/testdata/*.json", "../fimscan/testdata/partial/*.json"} {
		files, err := filepath.Glob(pattern)
		if err != nil || len(files) == 0 {
			f.Fatalf("no seeds for %s: %v", pattern, err)
		}
		for _, name := range files {
			b, err := os.ReadFile(name)
			if err != nil {
				f.Fatal(err)
			}
			seeds = append(seeds, b)
		}
	}
	valid := string(seeds[0])
	// A changed hash, a removed record and a setuid bit as extra seeds.
	seeds = append(seeds,
		[]byte(strings.Replace(valid, "1111111111111111111111111111111111111111111111111111111111111111", "3333333333333333333333333333333333333333333333333333333333333333", 1)),
		[]byte(strings.Replace(valid, `"mode": 420`, `"mode": 2468`, 1)),
	)
	for _, a := range seeds {
		for _, b := range seeds {
			f.Add(a, b)
		}
	}
	opts := fimscanOpts()
	f.Fuzz(func(t *testing.T, docA, docB []byte) {
		resA, errA := fimscan.Parse(context.Background(), bytes.NewReader(docA), opts)
		resB, errB := fimscan.Parse(context.Background(), bytes.NewReader(docB), opts)
		if errA != nil || errB != nil {
			return
		}
		base, err := NewBaseline(resA)
		if err != nil {
			if !errors.Is(err, ErrPartialScan) && !errors.Is(err, ErrUnhashedFile) {
				t.Fatalf("NewBaseline: unexpected error class: %v", err)
			}
			return
		}
		if again := mustBaseline(t, resA); again.Digest() != base.Digest() {
			t.Fatal("digest not stable")
		}
		// A baseline compared with its own run has no deviation.
		for _, o := range []Options{{}, usable()} {
			if rep := mustDiff(t, base, resA, o); len(rep.Deviations) != 0 {
				t.Fatalf("self diff: %d deviations", len(rep.Deviations))
			}
		}
		rep := mustDiff(t, base, resB, usable())
		checkReport(t, base, resB, rep)
		if rep2 := mustDiff(t, base, resB, usable()); !reflect.DeepEqual(rep, rep2) {
			t.Fatal("diff not deterministic")
		}
		for _, d := range mustDiff(t, base, resB, Options{}).Deviations {
			if d.Class != ClassCritical {
				t.Fatal("deviation not critical without a derived SSH set")
			}
		}
	})
}

func checkReport(t *testing.T, base *Baseline, scan *fimscan.Result, rep *Report) {
	t.Helper()
	if rep.Complete != scan.Complete() {
		t.Fatal("completeness not carried over")
	}
	if len(rep.Deviations) > base.Len()+len(scan.Records)+1 || len(rep.Deviations) > MaxDeviations {
		t.Fatalf("%d deviations exceed the bound", len(rep.Deviations))
	}
	for i, d := range rep.Deviations {
		if i > 0 && bytes.Compare(rep.Deviations[i-1].Path, d.Path) >= 0 {
			t.Fatal("deviations not strictly sorted")
		}
		if d.Class != ClassNormal && d.Class != ClassCritical {
			t.Fatalf("bad class %v", d.Class)
		}
		if (d.Class == ClassCritical) != (d.Rules != 0) {
			t.Fatalf("class %v with rules %b", d.Class, d.Rules)
		}
		switch d.Kind {
		case KindAdded:
			if d.Old != nil || d.New == nil {
				t.Fatal("added without new record")
			}
		case KindRemoved:
			if !rep.Complete {
				t.Fatal("removal from a partial scan")
			}
			if d.Old == nil || d.New != nil || d.Changes != 0 {
				t.Fatal("bad removal")
			}
		case KindChanged:
			if d.Changes == 0 {
				t.Fatal("change without changed fields")
			}
		default:
			t.Fatalf("bad kind %v", d.Kind)
		}
	}
}
