// SPDX-License-Identifier: AGPL-3.0-or-later

package fimbaseline

import (
	"bytes"
	"context"
	"crypto/sha256"
	"os"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/fimscan"
)

const testProfile = "fim-test-v1"

// file returns a hashed regular file record.
func file(p string, content byte) fimscan.Record {
	return fimscan.Record{
		Path: []byte(p), Type: fimscan.TypeFile, Size: 10, Mode: 0o644,
		Inode: 100, Mtime: 1000, Ctime: 1000,
		Hash: fimscan.Hash{Kind: fimscan.HashKeyed, Sum: sha256.Sum256([]byte{content})},
	}
}

func dir(p string) fimscan.Record {
	return fimscan.Record{Path: []byte(p), Type: fimscan.TypeDir, Size: 4096, Mode: 0o755, Inode: 2, Mtime: 1000, Ctime: 1000}
}

func symlink(p, target string) fimscan.Record {
	return fimscan.Record{Path: []byte(p), Type: fimscan.TypeSymlink, Size: int64(len(target)), Mode: 0o777, Inode: 3, Mtime: 1000, Ctime: 1000, Link: []byte(target)}
}

// result wraps records in a complete scan result.
func result(recs ...fimscan.Record) *fimscan.Result {
	return &fimscan.Result{
		ProfileID: testProfile, Mode: fimscan.ModeFull, Records: recs,
		SSHConfigState: fimscan.SSHConfigValid,
	}
}

func partial(recs ...fimscan.Record) *fimscan.Result {
	r := result(recs...)
	r.Partial = []fimscan.Reason{fimscan.ReasonRootSkipped}
	return r
}

func mustBaseline(t testing.TB, res *fimscan.Result) *Baseline {
	t.Helper()
	b, err := NewBaseline(res)
	if err != nil {
		t.Fatalf("NewBaseline: %v", err)
	}
	return b
}

// fimscanOpts mirrors the options of the fimscan package tests, so that its
// test vectors parse here as well.
func fimscanOpts() fimscan.Options {
	return fimscan.Options{
		Profile: fimscan.Profile{ID: testProfile, Roots: []fimscan.Root{
			{Pattern: "/etc"},
			{Pattern: "/usr/bin"},
			{Pattern: "/boot"},
			{Pattern: "/boot/efi", Optional: true},
			{Pattern: "/home/*/.ssh/authorized_keys*", Optional: true},
			{Pattern: "/opt", Optional: true},
		}},
		Mode:    fimscan.ModeFull,
		HostKey: bytes.Repeat([]byte{0x5a}, fimscan.HostKeySize),
	}
}

func parseFile(t testing.TB, name string) *fimscan.Result {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	res, err := fimscan.Parse(context.Background(), bytes.NewReader(b), fimscanOpts())
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return res
}
