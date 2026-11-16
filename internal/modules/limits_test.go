// SPDX-License-Identifier: AGPL-3.0-or-later

package modules

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/modulelock"
)

// noise returns n pseudo-random bytes; they do not compress.
func noise(n int, seed int64) []byte {
	b := make([]byte, n)
	rand.New(rand.NewSource(seed)).Read(b)
	return b
}

// gzTar writes entries as a .tar.gz.
func gzTar(t testing.TB, es []entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, e := range es {
		if err := tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(e.body); err != nil {
			t.Fatal(err)
		}
	}
	_ = tw.Close()
	_ = zw.Close()
	return buf.Bytes()
}

// emptyMember is a gzip member with no payload: 20 bytes.
const emptyMember = 20

// stored returns a gzip member holding k zero bytes in one stored block
// (25+k bytes for k > 0). Concatenated members are a valid gzip stream; the
// tar reader stops at its end marker and never reads the padding.
func stored(t testing.TB, k int) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.NoCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zw.Write(make([]byte, k)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// archiveOfSize returns entries as an archive of exactly size bytes: the
// tar.gz of es, then a padding member. The last entry is shortened until
// the padding can make up the exact size (sizes 21 to 25 bytes short are
// not reachable with a member).
func archiveOfSize(t testing.TB, size int, es []entry) []byte {
	t.Helper()
	last := len(es) - 1
	for i := 0; i < 50; i++ {
		a := gzTar(t, es)
		pad := size - len(a)
		switch {
		case pad == emptyMember:
			return append(a, stored(t, 0)...)
		case pad >= emptyMember+6:
			m := stored(t, pad-25)
			if len(a)+len(m) != size {
				t.Fatalf("padding gives %d bytes, want %d", len(a)+len(m), size)
			}
			return append(a, m...)
		}
		// Too close to size: shorten the last entry by enough to leave room.
		cut := 26 - pad
		if pad < 0 {
			cut = -pad + 26
		}
		b := es[last].body
		if cut >= len(b) {
			t.Fatalf("entries do not fit %d bytes", size)
		}
		es[last].body = b[:len(b)-cut]
	}
	t.Fatalf("no archive of %d bytes", size)
	return nil
}

// filesOf returns one regular file per size, with noise as content.
func filesOf(sizes ...int) []entry {
	es := make([]entry, 0, len(sizes))
	for i, n := range sizes {
		es = append(es, entry{name: fmt.Sprintf("f%02d.bin", i), body: noise(n, int64(i+1))})
	}
	return es
}

// Edges of the archive limits: a size equal to a limit is accepted, one
// byte more is refused with the reason the limit names.

func TestUnpackArchiveSizeEdges(t *testing.T) {
	ctx := context.Background()
	s := store(t, &fakeExec{})
	sizes := []int{modulelock.MaxScript, modulelock.MaxScript, modulelock.MaxScript, modulelock.MaxScript - 4096}
	exact := archiveOfSize(t, MaxArchive, filesOf(sizes...))
	files, err := unpack(exact)
	if err != nil || len(files) != 4 {
		t.Fatalf("archive of exactly MaxArchive: %d files, %v", len(files), err)
	}
	over := archiveOfSize(t, MaxArchive+1, filesOf(sizes...))
	var ie *ImportError
	if _, err := s.Import(ctx, "axel", over); !errors.As(err, &ie) || ie.Reason != "the archive must be 1 byte to 1024 KiB" {
		t.Fatalf("MaxArchive+1: %v", err)
	}
}

func TestUnpackEntryCountEdges(t *testing.T) {
	for _, tc := range []struct {
		n    int
		want string
	}{{MaxEntries, ""}, {MaxEntries + 1, fmt.Sprintf("at most %d entries", MaxEntries)}} {
		sizes := make([]int, tc.n)
		for i := range sizes {
			sizes[i] = 8
		}
		files, err := unpack(gzTar(t, filesOf(sizes...)))
		if tc.want == "" {
			if err != nil || len(files) != tc.n {
				t.Errorf("%d entries: %d files, %v", tc.n, len(files), err)
			}
			continue
		}
		var ie *ImportError
		if !errors.As(err, &ie) || ie.Reason != tc.want {
			t.Errorf("%d entries: %v", tc.n, err)
		}
	}
}

func TestUnpackUnpackedSizeEdges(t *testing.T) {
	// Zeros compress well, so 4 MiB of content fits into MaxArchive. Sixteen
	// full files make exactly MaxUnpacked; one byte more in a seventeenth
	// file exceeds it.
	full := make([]entry, 0, MaxUnpacked/modulelock.MaxScript+1)
	for i := 0; i < MaxUnpacked/modulelock.MaxScript; i++ {
		full = append(full, entry{name: fmt.Sprintf("z%02d.bin", i), body: make([]byte, modulelock.MaxScript)})
	}
	if _, err := unpack(gzTar(t, full)); err != nil {
		t.Errorf("exactly MaxUnpacked: %v", err)
	}
	over := append(full, entry{name: "z99.bin", body: []byte{0}})
	var ie *ImportError
	if _, err := unpack(gzTar(t, over)); !errors.As(err, &ie) || ie.Reason != "the archive unpacks to more than 4 MiB" {
		t.Errorf("MaxUnpacked+1: %v", err)
	}
}

// verify branches that the executor's answer can reach.

func TestVerifyRejectsDifferentAnswers(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		mut  func(*fakeExec)
		want string
	}{
		"action count differs":   {func(f *fakeExec) { f.dropAction = true }, "does not match"},
		"lock sha256 differs":    {func(f *fakeExec) { f.badLockSum = true }, "does not match"},
		"module version differs": {func(f *fakeExec) { f.otherVersion = true }, "differ"},
	} {
		t.Run(name, func(t *testing.T) {
			f := &fakeExec{}
			s := store(t, f)
			if _, err := s.Import(ctx, "axel", demo(t, "1.0.0", true)); err != nil {
				t.Fatal(err)
			}
			tc.mut(f)
			v, err := s.Verify(ctx, "demo", "1.0.0")
			if err != nil {
				t.Fatal(err)
			}
			if v.State != StateUnverified || !bytes.Contains([]byte(v.Detail), []byte(tc.want)) {
				t.Fatalf("state %q detail %q", v.State, v.Detail)
			}
			if got, _ := s.Get(ctx, "demo", "1.0.0"); got.State != StateUnverified {
				t.Fatalf("stored state %q", got.State)
			}
		})
	}
}
