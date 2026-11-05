// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecollect

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
)

func testWant(written, expires int64) pvecontract.LiveWant {
	return pvecontract.LiveWant{
		Version:     pvecontract.LiveWantVersion,
		WrittenUnix: written,
		ExpiresUnix: expires,
		Targets: []pvecontract.LiveTarget{
			{Remote: "remote-a", Kind: pvecontract.LiveKindNode, Node: "pve1"},
			{Remote: "remote-a", Kind: pvecontract.LiveKindQEMU, Node: "pve1", VMID: 101},
		},
	}
}

func testSamples(remote string) pvecontract.LiveSamples {
	return pvecontract.LiveSamples{
		Version:     pvecontract.LiveSamplesVersion,
		Remote:      remote,
		WrittenUnix: 1000,
		Samples: []pvecontract.LiveSample{
			{Kind: pvecontract.LiveKindNode, Node: "pve1", VMID: 0, CPU: 0.5,
				MemUsed: 100, MemTotal: 200, DiskUsed: 1000, DiskTotal: 2000,
				NetIn: 10, NetOut: 20, ObservedUnix: 1000},
		},
	}
}

func newTestHandoff(t *testing.T) *LiveHandoff {
	t.Helper()
	root := t.TempDir()
	expectTempDirOwnership(t, root)
	h, err := NewLiveHandoff(root)
	if err != nil {
		t.Fatalf("NewLiveHandoff: %v", err)
	}
	t.Cleanup(func() { h.Close() })
	return h
}

func TestLiveHandoffRoundTrip(t *testing.T) {
	h := newTestHandoff(t)
	h.now = func() time.Time { return time.Unix(1020, 0) }
	ctx := context.Background()

	if err := h.WriteLiveWant(ctx, testWant(1000, 1030)); err != nil {
		t.Fatalf("WriteLiveWant: %v", err)
	}
	got, err := h.ReadLiveWant(ctx)
	if err != nil {
		t.Fatalf("ReadLiveWant: %v", err)
	}
	if len(got.Targets) != 2 || got.ExpiresUnix != 1030 {
		t.Fatalf("want-list round trip = %+v", got)
	}

	if err := h.WriteLiveSamples(ctx, testSamples("remote-a")); err != nil {
		t.Fatalf("WriteLiveSamples: %v", err)
	}
	gotS, err := h.ReadLiveSamples(ctx, "remote-a")
	if err != nil {
		t.Fatalf("ReadLiveSamples: %v", err)
	}
	if len(gotS.Samples) != 1 || gotS.Samples[0].CPU != 0.5 {
		t.Fatalf("samples round trip = %+v", gotS)
	}

	if err := h.RemoveLiveSamples(ctx, "remote-a"); err != nil {
		t.Fatalf("RemoveLiveSamples: %v", err)
	}
	if _, err := h.ReadLiveSamples(ctx, "remote-a"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ReadLiveSamples after remove = %v, want ENOENT", err)
	}
}

func TestLiveHandoffWantMissingIsNoTargets(t *testing.T) {
	h := newTestHandoff(t)
	got, err := h.ReadLiveWant(context.Background())
	if err != nil {
		t.Fatalf("ReadLiveWant on empty dir: %v", err)
	}
	if len(got.Targets) != 0 {
		t.Fatalf("missing want-list returned targets: %+v", got)
	}
}

func TestLiveHandoffWantExpiredIsNoTargets(t *testing.T) {
	h := newTestHandoff(t)
	h.now = func() time.Time { return time.Unix(1030, 0) } // at the expiry
	ctx := context.Background()
	if err := h.WriteLiveWant(ctx, testWant(1000, 1030)); err != nil {
		t.Fatalf("WriteLiveWant: %v", err)
	}
	got, err := h.ReadLiveWant(ctx)
	if err != nil {
		t.Fatalf("ReadLiveWant: %v", err)
	}
	if len(got.Targets) != 0 {
		t.Fatalf("expired want-list returned targets: %+v", got)
	}
}

func TestLiveHandoffWantSymlinkRefused(t *testing.T) {
	h := newTestHandoff(t)
	ctx := context.Background()
	target := filepath.Join(t.TempDir(), "target.json")
	if err := os.WriteFile(target, []byte(`{}`), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(h.RequestsDir(), "live.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := h.ReadLiveWant(ctx); !errors.Is(err, ErrSymlink) {
		t.Fatalf("ReadLiveWant = %v, want ErrSymlink", err)
	}
	if err := h.WriteLiveWant(ctx, testWant(1000, 1030)); !errors.Is(err, ErrSymlink) {
		t.Fatalf("WriteLiveWant = %v, want ErrSymlink", err)
	}
}

func TestLiveHandoffSamplesSymlinkRefused(t *testing.T) {
	h := newTestHandoff(t)
	ctx := context.Background()
	target := filepath.Join(t.TempDir(), "target.json")
	if err := os.WriteFile(target, []byte(`{}`), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(h.LiveDir(), "remote-a.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := h.ReadLiveSamples(ctx, "remote-a"); !errors.Is(err, ErrSymlink) {
		t.Fatalf("ReadLiveSamples = %v, want ErrSymlink", err)
	}
	if err := h.RemoveLiveSamples(ctx, "remote-a"); !errors.Is(err, ErrSymlink) {
		t.Fatalf("RemoveLiveSamples = %v, want ErrSymlink", err)
	}
}

func TestLiveHandoffSymlinkedDirRefused(t *testing.T) {
	parent := t.TempDir()
	real := filepath.Join(parent, "real")
	if err := os.Mkdir(real, 0o750); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewLiveHandoff(link); !errors.Is(err, ErrSymlink) {
		t.Fatalf("NewLiveHandoff = %v, want ErrSymlink", err)
	}
}

func TestLiveHandoffWantOversizeRefused(t *testing.T) {
	h := newTestHandoff(t)
	ctx := context.Background()
	raw := make([]byte, pvecontract.MaxLiveWantBytes+1)
	if err := os.WriteFile(filepath.Join(h.RequestsDir(), "live.json"), raw, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := h.ReadLiveWant(ctx); !errors.Is(err, ErrOversize) {
		t.Fatalf("ReadLiveWant = %v, want ErrOversize", err)
	}
}

func TestLiveHandoffSamplesOversizeRefused(t *testing.T) {
	h := newTestHandoff(t)
	ctx := context.Background()
	raw := make([]byte, pvecontract.MaxLiveSamplesBytes+1)
	if err := os.WriteFile(filepath.Join(h.LiveDir(), "remote-a.json"), raw, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := h.ReadLiveSamples(ctx, "remote-a"); !errors.Is(err, ErrOversize) {
		t.Fatalf("ReadLiveSamples = %v, want ErrOversize", err)
	}
}

func TestLiveHandoffSamplesWrongRemoteRefused(t *testing.T) {
	h := newTestHandoff(t)
	ctx := context.Background()
	// A file named remote-b.json whose content declares remote-a must be refused.
	raw, err := pvecontract.MarshalLiveSamples(testSamples("remote-a"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.LiveDir(), "remote-b.json"), raw, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := h.ReadLiveSamples(ctx, "remote-b"); err == nil {
		t.Fatal("ReadLiveSamples accepted a remote/file-name mismatch")
	}
}

func TestLiveHandoffAtomicReplace(t *testing.T) {
	h := newTestHandoff(t)
	h.now = func() time.Time { return time.Unix(1020, 0) }
	ctx := context.Background()
	if err := h.WriteLiveWant(ctx, testWant(1000, 1030)); err != nil {
		t.Fatalf("WriteLiveWant 1: %v", err)
	}
	second := testWant(1000, 1030)
	second.Targets = append(second.Targets, pvecontract.LiveTarget{Remote: "remote-b", Kind: pvecontract.LiveKindLXC, Node: "pve2", VMID: 100})
	if err := h.WriteLiveWant(ctx, second); err != nil {
		t.Fatalf("WriteLiveWant 2: %v", err)
	}
	got, err := h.ReadLiveWant(ctx)
	if err != nil {
		t.Fatalf("ReadLiveWant: %v", err)
	}
	if len(got.Targets) != 3 {
		t.Fatalf("after replace, targets = %d, want 3", len(got.Targets))
	}
	entries, err := os.ReadDir(h.RequestsDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Fatalf("leftover temp file %s", e.Name())
		}
	}
}

func TestLiveHandoffDirModes(t *testing.T) {
	h := newTestHandoff(t)
	check := func(path string, wantPerm os.FileMode) {
		t.Helper()
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("Stat %s: %v", path, err)
		}
		if fi.Mode().Perm() != wantPerm {
			t.Fatalf("perm of %s = %o, want %o", path, fi.Mode().Perm(), wantPerm)
		}
		if fi.Mode()&os.ModeSetgid == 0 {
			t.Fatalf("%s is not setgid", path)
		}
	}
	check(h.RequestsDir(), 0o770)
	check(h.LiveDir(), 0o750)
}

func TestOpenLiveHandoffRequiresExisting(t *testing.T) {
	if _, err := OpenLiveHandoff(t.TempDir()); err == nil {
		t.Fatal("OpenLiveHandoff succeeded on an empty root")
	}
}

func TestLiveHandoffWantFutureDatedIsNoTargets(t *testing.T) {
	h := newTestHandoff(t)
	h.now = func() time.Time { return time.Unix(1000, 0) }
	ctx := context.Background()
	future := int64(1000 + 1_000_000)
	if err := h.WriteLiveWant(ctx, testWant(future, future+pvecontract.LiveWantMaxExpiry)); err != nil {
		t.Fatalf("WriteLiveWant: %v", err)
	}
	got, err := h.ReadLiveWant(ctx)
	if err != nil {
		t.Fatalf("ReadLiveWant: %v", err)
	}
	if len(got.Targets) != 0 {
		t.Fatalf("future-dated want-list returned targets: %+v", got)
	}
	// Within the clock skew the same shape is accepted.
	near := int64(1000 + pvecontract.LiveClockSkew)
	if err := h.WriteLiveWant(ctx, testWant(near, 1000+pvecontract.LiveWantMaxExpiry)); err != nil {
		t.Fatalf("WriteLiveWant: %v", err)
	}
	if got, err := h.ReadLiveWant(ctx); err != nil || len(got.Targets) != 2 {
		t.Fatalf("ReadLiveWant within skew = %+v, %v; want 2 targets", got, err)
	}
}

func TestLiveHandoffWantInvalidIsNoTargets(t *testing.T) {
	h := newTestHandoff(t)
	h.now = func() time.Time { return time.Unix(1020, 0) }
	raw := []byte(`{"version":2,"written_unix":1000,"expires_unix":1030,"targets":[{"remote":"remote-a","kind":"node","node":"pve1","vmid":0}]}`)
	if err := os.WriteFile(filepath.Join(h.RequestsDir(), "live.json"), raw, 0o640); err != nil {
		t.Fatal(err)
	}
	got, err := h.ReadLiveWant(context.Background())
	if err != nil {
		t.Fatalf("ReadLiveWant: %v", err)
	}
	if len(got.Targets) != 0 {
		t.Fatalf("invalid want-list returned targets: %+v", got)
	}
}

func TestLiveHandoffSamplesFutureDatedRefused(t *testing.T) {
	h := newTestHandoff(t)
	ctx := context.Background()
	s := testSamples("remote-a")
	s.WrittenUnix = 1000 + 1_000_000
	if err := h.WriteLiveSamples(ctx, s); err != nil {
		t.Fatalf("WriteLiveSamples: %v", err)
	}
	h.now = func() time.Time { return time.Unix(1000, 0) }
	if _, err := h.ReadLiveSamples(ctx, "remote-a"); !errors.Is(err, pvecontract.ErrInvalid) {
		t.Fatalf("ReadLiveSamples = %v, want ErrInvalid for a future-dated document", err)
	}
	s = testSamples("remote-a")
	s.Samples[0].ObservedUnix = 1000 + pvecontract.LiveClockSkew + 1
	if err := h.WriteLiveSamples(ctx, s); err != nil {
		t.Fatalf("WriteLiveSamples: %v", err)
	}
	if _, err := h.ReadLiveSamples(ctx, "remote-a"); !errors.Is(err, pvecontract.ErrInvalid) {
		t.Fatalf("ReadLiveSamples = %v, want ErrInvalid for a future observation", err)
	}
}

func TestLiveHandoffWriteReplacesOversizeFile(t *testing.T) {
	h := newTestHandoff(t)
	h.now = func() time.Time { return time.Unix(1020, 0) }
	ctx := context.Background()
	junk := make([]byte, pvecontract.MaxLiveSamplesBytes+1)
	if err := os.WriteFile(filepath.Join(h.RequestsDir(), "live.json"), junk, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.LiveDir(), "remote-a.json"), junk, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := h.WriteLiveWant(ctx, testWant(1000, 1030)); err != nil {
		t.Fatalf("WriteLiveWant over an oversize file: %v", err)
	}
	if got, err := h.ReadLiveWant(ctx); err != nil || len(got.Targets) != 2 {
		t.Fatalf("ReadLiveWant = %+v, %v", got, err)
	}
	if err := h.WriteLiveSamples(ctx, testSamples("remote-a")); err != nil {
		t.Fatalf("WriteLiveSamples over an oversize file: %v", err)
	}
	if _, err := h.ReadLiveSamples(ctx, "remote-a"); err != nil {
		t.Fatalf("ReadLiveSamples: %v", err)
	}
}

func TestLiveHandoffSamplesWriteSymlinkRefused(t *testing.T) {
	h := newTestHandoff(t)
	target := filepath.Join(t.TempDir(), "target.json")
	if err := os.WriteFile(target, []byte(`{}`), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(h.LiveDir(), "remote-a.json")); err != nil {
		t.Fatal(err)
	}
	if err := h.WriteLiveSamples(context.Background(), testSamples("remote-a")); !errors.Is(err, ErrSymlink) {
		t.Fatalf("WriteLiveSamples = %v, want ErrSymlink", err)
	}
}
