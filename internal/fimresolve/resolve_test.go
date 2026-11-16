// SPDX-License-Identifier: AGPL-3.0-or-later

package fimresolve

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/fimscan"
)

// fixture is a record set keyed by absolute path, as a scan would report it.
type fixture map[string]fimscan.Record

// lookup adapts the fixture to the Resolve lookup signature.
func (f fixture) lookup(p []byte) (fimscan.Record, bool) {
	r, ok := f[string(p)]
	return r, ok
}

func dirRec(p string) fimscan.Record {
	return fimscan.Record{Path: []byte(p), Type: fimscan.TypeDir}
}

func fileRec(p string) fimscan.Record {
	return fimscan.Record{Path: []byte(p), Type: fimscan.TypeFile}
}

func linkRec(p, target string) fimscan.Record {
	return fimscan.Record{Path: []byte(p), Type: fimscan.TypeSymlink, Link: []byte(target)}
}

// baseSet holds the directories and files the table cases share.
func baseSet() fixture {
	return fixture{
		"/":              dirRec("/"),
		"/etc":           dirRec("/etc"),
		"/etc/ssh":       dirRec("/etc/ssh"),
		"/etc/passwd":    fileRec("/etc/passwd"),
		"/srv":           dirRec("/srv"),
		"/srv/a":         dirRec("/srv/a"),
		"/srv/a/b":       dirRec("/srv/a/b"),
		"/srv/a/x":       fileRec("/srv/a/x"),
		"/var":           dirRec("/var"),
		"/var/q":         fileRec("/var/q"),
		"/etc/other":     dirRec("/etc/other"),
		"/etc/other/y":   fileRec("/etc/other/y"),
		"/etc/ssh/l":     linkRec("/etc/ssh/l", "/srv/a/b"),
		"/etc/ssh/r":     linkRec("/etc/ssh/r", "../other"),
		"/etc/ssh/abs":   linkRec("/etc/ssh/abs", "/var"),
		"/etc/ssh/dev":   {Path: []byte("/etc/ssh/dev"), Type: fimscan.TypeOther},
		"/etc/ssh/lf":    linkRec("/etc/ssh/lf", "/etc/passwd"),
		"/etc/ssh/lfd":   linkRec("/etc/ssh/lfd", "/etc/passwd/"),
		"/etc/ssh/ld":    linkRec("/etc/ssh/ld", "/etc/"),
		"/etc/ssh/empty": linkRec("/etc/ssh/empty", ""),
		"/etc/ssh/self":  linkRec("/etc/ssh/self", "/etc/ssh/self"),
		"/etc/ssh/ping":  linkRec("/etc/ssh/ping", "/etc/ssh/pong"),
		"/etc/ssh/pong":  linkRec("/etc/ssh/pong", "/etc/ssh/ping"),
		"/etc/ssh/out":   linkRec("/etc/ssh/out", "/outside/dir"),
	}
}

// chain returns a record set with links c0..c(n-1), where c(i) points to
// c(i+1) and the last link points to /etc. Resolving /c0 follows n links.
func chain(n int) fixture {
	f := baseSet()
	for i := 0; i < n; i++ {
		p := fmt.Sprintf("/c%d", i)
		target := fmt.Sprintf("/c%d", i+1)
		if i == n-1 {
			target = "/etc"
		}
		f[p] = linkRec(p, target)
	}
	return f
}

func TestResolveTable(t *testing.T) {
	long := "/" + strings.Repeat("a", 4000)
	longSet := baseSet()
	longSet[long] = dirRec(long)
	longSet[long+"/"+strings.Repeat("b", 94)] = fileRec(long + "/" + strings.Repeat("b", 94))
	longSet[long+"/"+strings.Repeat("b", 95)] = fileRec(long + "/" + strings.Repeat("b", 95))
	longSet["/lnk"] = linkRec("/lnk", long)
	longSet["/lnk2"] = linkRec("/lnk2", long+"/"+strings.Repeat("b", 95))

	tests := []struct {
		name    string
		set     fixture
		path    string
		want    string
		wantErr error
	}{
		{"adr example dotdot after link", baseSet(), "/etc/ssh/l/../x", "/srv/a/x", nil},
		{"relative target continues from link directory", baseSet(), "/etc/ssh/r/y", "/etc/other/y", nil},
		{"absolute target restarts at root", baseSet(), "/etc/ssh/abs/q", "/var/q", nil},
		{"dot is dropped", baseSet(), "/etc/./ssh", "/etc/ssh", nil},
		{"double slash collapses", baseSet(), "//etc//ssh", "/etc/ssh", nil},
		{"trailing slash on directory", baseSet(), "/etc/ssh/", "/etc/ssh", nil},
		{"root stays root", baseSet(), "/", "/", nil},
		{"dotdot at root stays at root", baseSet(), "/../../etc", "/etc", nil},
		{"dotdot removes a plain component", baseSet(), "/etc/ssh/..", "/etc", nil},
		{"final symlink is followed", baseSet(), "/etc/ssh/lf", "/etc/passwd", nil},
		{"symlink to directory with trailing slash", baseSet(), "/etc/ssh/ld", "/etc", nil},
		{"trailing slash after symlink to directory", baseSet(), "/etc/ssh/ld/", "/etc", nil},
		{"self loop", baseSet(), "/etc/ssh/self/x", "", ErrSymlinkLimit},
		{"two link loop", baseSet(), "/etc/ssh/ping", "", ErrSymlinkLimit},
		{"empty symlink target", baseSet(), "/etc/ssh/empty", "", ErrEmptyLink},
		{"trailing slash after file", baseSet(), "/etc/passwd/", "", ErrNotDir},
		{"file in the middle", baseSet(), "/etc/passwd/x", "", ErrNotDir},
		{"dotdot after file", baseSet(), "/etc/passwd/..", "", ErrNotDir},
		{"trailing slash after symlink to file", baseSet(), "/etc/ssh/lfd", "", ErrNotDir},
		{"symlink to file followed by slash", baseSet(), "/etc/ssh/lf/", "", ErrNotDir},
		{"other type in the middle", baseSet(), "/etc/ssh/dev/x", "", ErrNotDir},
		{"missing record", baseSet(), "/etc/missing", "", ErrNotFound},
		{"missing intermediate record", baseSet(), "/nope/x", "", ErrNotFound},
		{"target outside scanned set", baseSet(), "/etc/ssh/out/x", "", ErrNotFound},
		{"relative input", baseSet(), "etc/ssh", "", ErrNotAbsolute},
		{"empty input", baseSet(), "", "", ErrNotAbsolute},
		{"input over MaxPathBytes", baseSet(), "/" + strings.Repeat("a", fimscan.MaxPathBytes), "", ErrTooLong},
		{"result of exactly MaxPathBytes", longSet, "/lnk/" + strings.Repeat("b", 94), long + "/" + strings.Repeat("b", 94), nil},
		{"growth beyond MaxPathBytes", longSet, "/lnk/" + strings.Repeat("b", 95), "", ErrTooLong},
		{"target grows beyond MaxPathBytes", longSet, "/lnk2", "", ErrTooLong},
		{"dotdot after long target", longSet, "/lnk/../etc", "/etc", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Resolve(tt.set.lookup, []byte(tt.path))
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Resolve(%q) error = %v, want %v", tt.path, err, tt.wantErr)
				}
				if got != nil {
					t.Fatalf("Resolve(%q) returned %q with an error", tt.path, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Resolve(%q) error = %v", tt.path, err)
			}
			if string(got) != tt.want {
				t.Fatalf("Resolve(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestResolveLinkLimit(t *testing.T) {
	tests := []struct {
		name    string
		links   int
		wantErr error
	}{
		{"40 links allowed", MaxSymlinkFollows, nil},
		{"41 links rejected", MaxSymlinkFollows + 1, ErrSymlinkLimit},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Resolve(chain(tt.links).lookup, []byte("/c0"))
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil || string(got) != "/etc" {
				t.Fatalf("Resolve = %q, %v; want /etc", got, err)
			}
		})
	}
}

// TestResolveLengthLimitsAlone pins each ADR 0015 D9 length rule with a case
// in which only that rule is violated. Each case would resolve successfully
// (to the path named in want) if that rule were removed, so each one fails
// when its own check is deleted.
func TestResolveLengthLimitsAlone(t *testing.T) {
	// Every "/." pair is a component that is dropped, so the target is long
	// but resolution needs only a few real components.
	shortResultTarget := "/etc" + strings.Repeat("/.", (fimscan.MaxPathBytes-len("/etc"))/2)
	if len(shortResultTarget) != fimscan.MaxPathBytes {
		t.Fatalf("fixture target is %d bytes, want %d", len(shortResultTarget), fimscan.MaxPathBytes)
	}
	set := baseSet()
	set["/etc/x"] = fileRec("/etc/x")
	set["/etc/ssh/big"] = linkRec("/etc/ssh/big", shortResultTarget)
	// The input prefix "/" plus "./" pairs; "//" collapses to one slash.
	input4096 := "/" + strings.Repeat("./", 2042) + "/etc/passwd"
	input4097 := "/" + strings.Repeat("./", 2042) + "//etc/passwd"
	if len(input4096) != fimscan.MaxPathBytes || len(input4097) != fimscan.MaxPathBytes+1 {
		t.Fatalf("fixture inputs are %d and %d bytes", len(input4096), len(input4097))
	}

	tests := []struct {
		name    string
		path    string
		want    string
		wantErr error
	}{
		{
			// The remaining path "/x" after the link pushes the path still to
			// be resolved (target included) to 4,098 bytes, but the result is
			// /etc/x, which is short.
			name:    "remaining path with target over MaxPathBytes, short result",
			path:    "/etc/ssh/big/x",
			wantErr: ErrTooLong,
		},
		{
			name: "input of exactly MaxPathBytes is accepted",
			path: input4096,
			want: "/etc/passwd",
		},
		{
			// Only the input check refuses this: every component after the
			// dropped "." components fits, and the result is short.
			name:    "input of MaxPathBytes plus one is refused",
			path:    input4097,
			wantErr: ErrTooLong,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Resolve(set.lookup, []byte(tt.path))
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Resolve error = %v, want %v", err, tt.wantErr)
				}
				if got != nil {
					t.Fatalf("Resolve returned %q with an error", got)
				}
				return
			}
			if err != nil || string(got) != tt.want {
				t.Fatalf("Resolve = %q, %v; want %q", got, err, tt.want)
			}
		})
	}
}

// TestResolveTargetOverMaxPathBytesAlone checks a link whose own target is
// 4,097 bytes long. The rule is ADR 0015 D9 "target included": the path
// still to be resolved may not exceed 4,096 bytes.
func TestResolveTargetOverMaxPathBytesAlone(t *testing.T) {
	target := "/etc" + strings.Repeat("/.", (fimscan.MaxPathBytes+1-len("/etc"))/2) + "/"
	set := baseSet()
	set["/etc/ssh/huge"] = linkRec("/etc/ssh/huge", target)
	if _, err := Resolve(set.lookup, []byte("/etc/ssh/huge")); !errors.Is(err, ErrTooLong) {
		t.Fatalf("Resolve error = %v, want ErrTooLong", err)
	}
}

// TestResolveWorkAndAllocationsBounded runs the worst case the limits allow:
// a 4,002-byte path of 2,000 real directory components and a final link that
// points back at that same path. Every pass looks up all 2,000 components,
// so 41 passes make about 82,000 lookups before the 41st symlink is refused.
// Child paths reuse one buffer, so allocations stay near the number of
// symlinks instead of growing with the number of lookups.
func TestResolveWorkAndAllocationsBounded(t *testing.T) {
	const depth = 2000
	dirs := strings.Repeat("/d", depth)
	link := []byte(dirs + "/L")
	if len(link) > fimscan.MaxPathBytes {
		t.Fatalf("fixture path is %d bytes", len(link))
	}
	lookups := 0
	lookup := func(p []byte) (fimscan.Record, bool) {
		lookups++
		if bytes.HasSuffix(p, []byte("/L")) {
			return fimscan.Record{Path: p, Type: fimscan.TypeSymlink, Link: link}, true
		}
		return fimscan.Record{Path: p, Type: fimscan.TypeDir}, true
	}
	var err error
	allocs := testing.AllocsPerRun(5, func() {
		lookups = 0
		_, err = Resolve(lookup, link)
	})
	if !errors.Is(err, ErrSymlinkLimit) {
		t.Fatalf("Resolve error = %v, want ErrSymlinkLimit", err)
	}
	if lookups < MaxSymlinkFollows*depth {
		t.Fatalf("fixture did only %d lookups, want at least %d", lookups, MaxSymlinkFollows*depth)
	}
	if allocs > 200 {
		t.Fatalf("Resolve made %.0f allocations per call, want at most 200", allocs)
	}
}

func TestMaxSymlinkFollowsIsForty(t *testing.T) {
	if MaxSymlinkFollows != 40 {
		t.Fatalf("MaxSymlinkFollows = %d, want 40 (ADR 0015 D9)", MaxSymlinkFollows)
	}
}

func TestResolveNilLookupIsError(t *testing.T) {
	if _, err := Resolve(nil, []byte("/etc")); !errors.Is(err, ErrNilLookup) {
		t.Fatalf("error = %v, want ErrNilLookup", err)
	}
}

func TestResolveDoesNotModifyInput(t *testing.T) {
	in := []byte("/etc/ssh/l/../x")
	orig := string(in)
	if _, err := Resolve(baseSet().lookup, in); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if string(in) != orig {
		t.Fatalf("input changed from %q to %q", orig, in)
	}
}
