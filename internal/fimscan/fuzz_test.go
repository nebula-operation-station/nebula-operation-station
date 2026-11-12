// SPDX-License-Identifier: AGPL-3.0-or-later

package fimscan

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func readVectors(t testing.TB, pattern string) map[string][]byte {
	t.Helper()
	files, err := filepath.Glob(pattern)
	if err != nil || len(files) == 0 {
		t.Fatalf("no test vectors for %s: %v", pattern, err)
	}
	out := map[string][]byte{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		out[filepath.Base(f)] = b
	}
	return out
}

func TestRejectVectors(t *testing.T) {
	for name, doc := range readVectors(t, "testdata/reject/*.json") {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(context.Background(), bytes.NewReader(doc), testOpts()); !errors.Is(err, ErrInvalidResult) {
				t.Fatalf("err = %v, want ErrInvalidResult", err)
			}
		})
	}
}

func TestPartialVectors(t *testing.T) {
	for name, doc := range readVectors(t, "testdata/partial/*.json") {
		t.Run(name, func(t *testing.T) {
			res, err := Parse(context.Background(), bytes.NewReader(doc), testOpts())
			if err != nil {
				t.Fatal(err)
			}
			if res.Complete() {
				t.Fatal("partial vector parsed as complete")
			}
			checkInvariants(t, res, defaultLimits)
		})
	}
}

// checkInvariants holds for every result the parser returns, whatever the
// input.
func checkInvariants(t *testing.T, res *Result, lim limits) {
	t.Helper()
	opts := testOpts()
	if len(res.Records) > lim.records || len(res.Mounts) > lim.mounts || len(res.SSHConfig) > lim.sshFiles {
		t.Fatalf("limit exceeded: %d records, %d mounts, %d ssh files", len(res.Records), len(res.Mounts), len(res.SSHConfig))
	}
	dropped := 0
	for _, n := range res.Dropped {
		dropped += n
	}
	if res.Complete() && (dropped > 0 || res.SSHConfigState != SSHConfigValid) {
		t.Fatalf("complete with %d drops, ssh state %v", dropped, res.SSHConfigState)
	}
	if res.SSHConfigState != SSHConfigValid && res.SSHConfig != nil {
		t.Fatal("SSH configuration content returned for a non-valid array")
	}
	if len(res.Roots) != len(opts.Profile.Roots) {
		t.Fatalf("%d root states for %d roots", len(res.Roots), len(opts.Profile.Roots))
	}
	seen := map[string]bool{}
	for _, r := range res.Records {
		if validatePath(r.Path) != nil {
			t.Fatalf("invalid path accepted: %q", r.Path)
		}
		ok := false
		for _, root := range opts.Profile.Roots {
			ok = ok || matchRoot(root.Pattern, r.Path)
		}
		if !ok {
			t.Fatalf("path outside the profile accepted: %q", r.Path)
		}
		if seen[string(r.Path)] {
			t.Fatalf("duplicate path accepted: %q", r.Path)
		}
		seen[string(r.Path)] = true
		if r.Type < TypeFile || r.Type > TypeOther || r.Mode > MaxMode || r.Size < 0 ||
			r.Mtime < MinTime || r.Mtime > MaxTime || r.Ctime < MinTime || r.Ctime > MaxTime {
			t.Fatalf("out of range record accepted: %+v", r)
		}
		if (r.Type == TypeSymlink) != (r.Link != nil) || (r.Link != nil && validateLink(r.Link) != nil) {
			t.Fatalf("bad link accepted: %+v", r)
		}
		if r.Hash.Kind != HashNone && r.Type != TypeFile {
			t.Fatalf("hash on non-file accepted: %+v", r)
		}
		if r.Hash.Kind == HashPlain && !PlainHashAllowed(r.Path) {
			t.Fatalf("plain hash for keyed path %q", r.Path)
		}
		if r.Hash.Kind != HashNone && r.Hash.Secret != SecretPath(r.Path) {
			t.Fatalf("secret flag wrong for %q", r.Path)
		}
	}
	for _, m := range res.Mounts {
		if validatePath(m.Path) != nil || !isIDString(m.FSType) || len(m.FSType) > MaxFSTypeBytes {
			t.Fatalf("bad mount accepted: %+v", m)
		}
	}
	total := 0
	for _, f := range res.SSHConfig {
		total += len(f.Content)
	}
	if total > lim.sshBytes {
		t.Fatalf("ssh config of %d bytes accepted", total)
	}
}

func FuzzParse(f *testing.F) {
	for _, pattern := range []string{"testdata/*.json", "testdata/reject/*.json", "testdata/partial/*.json"} {
		for _, doc := range readVectors(f, pattern) {
			f.Add(doc)
		}
	}
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"records": [[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]}`))
	// Small limits make the cut paths reachable for the fuzzer.
	small := defaultLimits
	small.records = 4
	small.docBytes = 2048
	small.recordBytes = 512
	small.mounts = 1
	small.sshFiles = 1
	small.sshBytes = 16
	small.sshEntry = 256
	f.Fuzz(func(t *testing.T, doc []byte) {
		for _, lim := range []limits{defaultLimits, small} {
			res, err := parse(context.Background(), bytes.NewReader(doc), testOpts(), lim)
			if err != nil {
				if res != nil {
					t.Fatal("result returned with error")
				}
				if !errors.Is(err, ErrInvalidResult) {
					t.Fatalf("unexpected error class: %v", err)
				}
				continue
			}
			checkInvariants(t, res, lim)
		}
	})
}
