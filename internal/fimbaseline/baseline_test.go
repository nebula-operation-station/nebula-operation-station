// SPDX-License-Identifier: AGPL-3.0-or-later

package fimbaseline

import (
	"bytes"
	"errors"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/fimscan"
)

func TestBaselineFromValidVector(t *testing.T) {
	res := parseFile(t, "../fimscan/testdata/valid.json")
	b := mustBaseline(t, res)
	if b.Len() != len(res.Records) || b.ProfileID() != testProfile {
		t.Fatalf("len %d profile %q", b.Len(), b.ProfileID())
	}
	es := b.Entries()
	for i := 1; i < len(es); i++ {
		if bytes.Compare(es[i-1].Path, es[i].Path) >= 0 {
			t.Fatal("entries not sorted")
		}
	}
}

func TestBaselineRejects(t *testing.T) {
	long := "/etc/" + strings.Repeat("a", MaxPathBytes)
	deep := "/etc" + strings.Repeat("/a", MaxPathDepth)
	unhashed := file("/etc/x", 1)
	unhashed.Hash = fimscan.Hash{}
	hashedDir := dir("/etc/d")
	hashedDir.Hash.Kind = fimscan.HashKeyed
	noLink := symlink("/etc/l", "x")
	noLink.Link = nil
	tests := []struct {
		name string
		res  *fimscan.Result
		want error
	}{
		{"nil", nil, ErrInvalidInput},
		{"partial", partial(file("/etc/a", 1)), ErrPartialScan},
		{"no profile", &fimscan.Result{SSHConfigState: fimscan.SSHConfigValid}, ErrInvalidInput},
		{"unhashed file", result(unhashed), ErrUnhashedFile},
		{"duplicate", result(file("/etc/a", 1), file("/etc/a", 2)), ErrInvalidInput},
		{"path too long", result(file(long, 1)), ErrLimit},
		{"path too deep", result(file(deep, 1)), ErrLimit},
		{"relative path", result(file("etc/a", 1)), ErrInvalidInput},
		{"dotdot", result(file("/etc/../a", 1)), ErrInvalidInput},
		{"trailing slash", result(file("/etc/a/", 1)), ErrInvalidInput},
		{"NUL", result(file("/etc/a\x00", 1)), ErrInvalidInput},
		{"hash on dir", result(hashedDir), ErrInvalidInput},
		{"symlink without target", result(noLink), ErrInvalidInput},
		{"link too long", result(symlink("/etc/l", strings.Repeat("x", MaxLinkBytes+1))), ErrLimit},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewBaseline(tc.res); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestBaselineEntryLimit(t *testing.T) {
	res := result()
	res.Records = make([]fimscan.Record, MaxEntries+1)
	if _, err := NewBaseline(res); !errors.Is(err, ErrLimit) {
		t.Fatalf("err = %v, want ErrLimit", err)
	}
	res.Mounts = make([]fimscan.Mount, MaxMounts+1)
	res.Records = nil
	if _, err := NewBaseline(res); !errors.Is(err, ErrLimit) {
		t.Fatalf("mounts: err = %v, want ErrLimit", err)
	}
}

func TestBaselineDigestStableAndOrderIndependent(t *testing.T) {
	recs := []fimscan.Record{
		dir("/etc"), file("/etc/passwd", 1), file("/etc/hosts", 2),
		symlink("/etc/localtime", "/usr/share/zoneinfo/UTC"), file("/usr/bin/ls", 3),
	}
	base := mustBaseline(t, result(recs...))
	// Golden value: a change of the canonical form must be deliberate.
	const golden = "ec5810427306344b7e2144408253b47c291d9ac552763f8671e465a33b248bab"
	if got := base.Digest().String(); got != golden {
		t.Fatalf("digest %s, want %s", got, golden)
	}
	rng := rand.New(rand.NewPCG(1, 2))
	for range 20 {
		sh := append([]fimscan.Record(nil), recs...)
		rng.Shuffle(len(sh), func(i, j int) { sh[i], sh[j] = sh[j], sh[i] })
		if d := mustBaseline(t, result(sh...)).Digest(); d != base.Digest() {
			t.Fatal("digest depends on record order")
		}
	}
}

func TestBaselineDigestCoversEveryField(t *testing.T) {
	ref := file("/etc/a", 1)
	base := mustBaseline(t, result(ref)).Digest()
	mods := map[string]func(r *fimscan.Record){
		"path":   func(r *fimscan.Record) { r.Path = []byte("/etc/b") },
		"size":   func(r *fimscan.Record) { r.Size++ },
		"mode":   func(r *fimscan.Record) { r.Mode = 0o600 },
		"uid":    func(r *fimscan.Record) { r.UID = 1 },
		"gid":    func(r *fimscan.Record) { r.GID = 1 },
		"inode":  func(r *fimscan.Record) { r.Inode++ },
		"mtime":  func(r *fimscan.Record) { r.Mtime++ },
		"ctime":  func(r *fimscan.Record) { r.Ctime++ },
		"sum":    func(r *fimscan.Record) { r.Hash.Sum[0] ^= 1 },
		"kind":   func(r *fimscan.Record) { r.Hash.Kind = fimscan.HashPlain },
		"secret": func(r *fimscan.Record) { r.Hash.Secret = true },
	}
	for name, mod := range mods {
		t.Run(name, func(t *testing.T) {
			r := cloneRecord(ref)
			mod(&r)
			if mustBaseline(t, result(r)).Digest() == base {
				t.Fatal("digest does not cover field")
			}
		})
	}
	t.Run("link", func(t *testing.T) {
		a := mustBaseline(t, result(symlink("/etc/l", "a"))).Digest()
		if mustBaseline(t, result(symlink("/etc/l", "b"))).Digest() == a {
			t.Fatal("digest does not cover link")
		}
	})
	t.Run("mount", func(t *testing.T) {
		r := result(ref)
		r.Mounts = []fimscan.Mount{{Path: []byte("/boot/efi"), FSType: "vfat"}}
		if mustBaseline(t, r).Digest() == base {
			t.Fatal("digest does not cover mounts")
		}
	})
	t.Run("profile", func(t *testing.T) {
		r := result(ref)
		r.ProfileID = "fim-other-v1"
		if mustBaseline(t, r).Digest() == base {
			t.Fatal("digest does not cover profile")
		}
	})
	t.Run("length prefix", func(t *testing.T) {
		// Two paths whose concatenation is equal must not collide.
		a := mustBaseline(t, result(file("/etc/ab", 1), file("/etc/c", 1))).Digest()
		b := mustBaseline(t, result(file("/etc/a", 1), file("/etc/bc", 1))).Digest()
		if a == b {
			t.Fatal("digest collision across entry boundaries")
		}
	})
}

func TestBaselineIsDeepCopy(t *testing.T) {
	res := result(file("/etc/a", 1))
	b := mustBaseline(t, res)
	d := b.Digest()
	res.Records[0].Path[1] = 'x'
	es := b.Entries()
	es[0].Path[1] = 'y'
	if string(b.Entries()[0].Path) != "/etc/a" || b.Digest() != d {
		t.Fatal("baseline aliases caller memory")
	}
}
