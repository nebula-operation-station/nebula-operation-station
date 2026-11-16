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
	"strings"
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

// exactStream returns a .tar.gz whose tar stream is exactly size bytes, with
// headers, padding and the end marker counted. size must be a multiple of
// 512. It holds full MaxScript files and then one file that takes the rest.
// Zeros compress well, so the archive stays within MaxArchive.
func exactStream(t testing.TB, size int) []byte {
	t.Helper()
	const block = 512
	if size%block != 0 || size < 2*block {
		t.Fatalf("exactStream: %d is not a stream size", size)
	}
	rem := size - 2*block // the end marker
	var es []entry
	for rem-(block+modulelock.MaxScript) >= block {
		es = append(es, entry{name: fmt.Sprintf("z%02d.bin", len(es)), body: make([]byte, modulelock.MaxScript)})
		rem -= block + modulelock.MaxScript
	}
	// The last file takes the rest; its content is a whole number of blocks,
	// so it needs no padding.
	es = append(es, entry{name: "last.bin", body: make([]byte, rem-block)})
	return gzTar(t, es)
}

// The tar stream is capped at MaxUnpacked+1 bytes, headers included. Tar
// streams are whole blocks, so the largest stream that can be accepted is
// MaxUnpacked, and the smallest refused one is MaxUnpacked+512. Content is
// what is left after the headers and the end marker.
func TestUnpackUnpackedSizeEdges(t *testing.T) {
	files, err := unpack(exactStream(t, MaxUnpacked))
	if err != nil {
		t.Fatalf("stream of exactly MaxUnpacked: %v", err)
	}
	content := 0
	for _, b := range files {
		content += len(b)
	}
	if want := MaxUnpacked - (len(files)+2)*512; content != want {
		t.Errorf("content of a MaxUnpacked stream: %d bytes, want %d", content, want)
	}
	var ie *ImportError
	if _, err := unpack(exactStream(t, MaxUnpacked+512)); !errors.As(err, &ie) || ie.Reason != "the archive is damaged or too large" {
		t.Errorf("stream one block past MaxUnpacked: %v", err)
	}
}

// longNamed returns n entries of body bytes each whose names need a PAX
// header of about nameLen bytes.
func longNamed(n, body, nameLen int) []entry {
	es := make([]entry, 0, n)
	for i := 0; i < n; i++ {
		name := strings.Repeat("p", nameLen-6) + fmt.Sprintf("/%03d", i)
		es = append(es, entry{name: name, body: make([]byte, body)})
	}
	return es
}

func TestUnpackAcceptsPAXHeadersWithinStreamBound(t *testing.T) {
	// 64 entries of 60 KiB each need a PAX header of about 300 bytes. The
	// headers, one block each for the PAX record and the file header, count
	// toward the stream bound: 3.75 MiB of content plus about 96 KiB of
	// headers stays within MaxUnpacked.
	files, err := unpack(gzTar(t, longNamed(MaxEntries, 60<<10, 300)))
	if err != nil || len(files) != MaxEntries {
		t.Errorf("64 PAX entries within the stream bound: %d files, %v", len(files), err)
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
