// SPDX-License-Identifier: AGPL-3.0-or-later

package modules

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/modulelock"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
)

const fixtures = "../../test/security/testdata/module/"

func fx(t *testing.T, n string) []byte {
	t.Helper()
	b, err := os.ReadFile(fixtures + n)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type entry struct {
	name string
	body []byte
	typ  byte
}

func tgz(t *testing.T, es ...entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, e := range es {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		if err := tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.body)), Typeflag: typ, Linkname: "x"}); err != nil {
			t.Fatal(err)
		}
		_, _ = tw.Write(e.body)
	}
	_ = tw.Close()
	_ = zw.Close()
	return buf.Bytes()
}

func demo(t *testing.T, version string, sig bool) []byte {
	es := []entry{{"module.lock.json", fx(t, "lock-"+version+".json"), 0}, {"./actions/hello.sh", fx(t, "hello.sh"), 0},
		{"actions/restart.sh", fx(t, "restart.sh"), 0}, {"module.yaml", []byte("ignored"), 0}}
	if sig {
		es = append(es, entry{"module.lock.json.sig", fx(t, "lock-"+version+".a.sig"), 0})
	}
	return tgz(t, es...)
}

// fakeExec answers RegisterModule like the executor would.
type fakeExec struct {
	err      error
	wrongSum bool
	calls    int
}

func (f *fakeExec) RegisterModule(_ context.Context, in *pb.RegisterModuleRequest, _ ...grpc.CallOption) (*pb.RegisterModuleResponse, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	v := Version{Scripts: in.GetScripts()}
	l, sum, _ := modulelock.Parse(in.GetLockJson())
	v.Lock = l
	r := &pb.RegisterModuleResponse{Name: l.Name, Version: l.Version, LockSha256: sum, SignerFingerprint: "SHA256:x", SignerName: "Test"}
	for _, a := range v.Actions() {
		s := a.SHA256()
		if f.wrongSum {
			s = strings.Repeat("0", 64)
		}
		r.Actions = append(r.Actions, &pb.ModuleAction{ActionId: a.ID, ModuleVersion: a.Version, ArtifactSha256: s})
	}
	return r, nil
}

func store(t *testing.T, f *fakeExec) *Store {
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if f == nil {
		return New(db, nil)
	}
	return New(db, f)
}

func TestImport(t *testing.T) {
	f := &fakeExec{}
	s := store(t, f)
	ctx := context.Background()
	v, err := s.Import(ctx, "axel", demo(t, "1.0.0", true))
	if err != nil || v.State != StateVerified || v.Signer != "Test (SHA256:x)" || len(v.Actions()) != 2 {
		t.Fatalf("%+v %v", v, err)
	}
	if _, err := s.Import(ctx, "axel", demo(t, "1.0.0", true)); err == nil || !strings.Contains(err.Error(), "imported already") {
		t.Fatal(err)
	}
	// Unsigned: unverified, the executor is not asked.
	n := f.calls
	v, err = s.Import(ctx, "axel", demo(t, "1.1.0", false))
	if err != nil || v.State != StateUnverified || !strings.Contains(v.Detail, "not signed") || f.calls != n {
		t.Fatalf("%+v %v", v, err)
	}
	latest, _ := s.Get(ctx, "demo", "")
	if latest.Lock.Version != "1.1.0" {
		t.Fatal(latest.Lock.Version)
	}
	if a, ok := latest.Action("demo.hello"); !ok || a.Version != "1.1.0" || !strings.Contains(string(a.Script), "signed module") {
		t.Fatal("action not found")
	}
	if all, _ := s.Latest(ctx); len(all) != 1 {
		t.Fatal(len(all))
	}
	// Stored versions never change.
	if _, err := s.db.Exec(`UPDATE module_versions SET scripts = '{}'`); err == nil {
		t.Fatal("scripts changed")
	}
	if _, err := s.db.Exec(`DELETE FROM module_versions`); err == nil {
		t.Fatal("versions deleted")
	}
	if _, err := s.Get(ctx, "nope", ""); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}

func TestImportVerdicts(t *testing.T) {
	ctx := context.Background()
	f := &fakeExec{err: status.Error(codes.PermissionDenied, "signer_untrusted: SHA256:x is not a trusted signer")}
	s := store(t, f)
	v, err := s.Import(ctx, "axel", demo(t, "1.0.0", true))
	if err != nil || v.State != StateUnverified || !strings.Contains(v.Detail, "signer_untrusted") {
		t.Fatalf("%+v %v", v, err)
	}
	f.err = nil
	if v, err = s.Verify(ctx, "demo", "1.0.0"); err != nil || v.State != StateVerified {
		t.Fatalf("%+v %v", v, err)
	}
	if got, _ := s.Get(ctx, "demo", "1.0.0"); got.State != StateVerified {
		t.Fatal("verdict not stored")
	}
	f.wrongSum = true
	if v, _ = s.Verify(ctx, "demo", "1.0.0"); v.State != StateUnverified || !strings.Contains(v.Detail, "differ") {
		t.Fatalf("%+v", v)
	}
	f.wrongSum, f.err = false, status.Error(codes.InvalidArgument, "modulelock: invalid lock")
	if _, err := store(t, f).Import(ctx, "axel", demo(t, "1.0.0", true)); err == nil {
		t.Fatal("refused module imported")
	}
	if v, err := store(t, nil).Import(ctx, "axel", demo(t, "1.0.0", true)); err != nil || !strings.Contains(v.Detail, "not connected") {
		t.Fatalf("%+v %v", v, err)
	}
}

func TestImportRefusesBadArchives(t *testing.T) {
	ctx := context.Background()
	s := store(t, &fakeExec{})
	lock := fx(t, "lock-1.0.0.json")
	for name, arch := range map[string][]byte{
		"not gzip":     []byte("PK\x03\x04"),
		"no lock":      tgz(t, entry{"actions/hello.sh", fx(t, "hello.sh"), 0}),
		"symlink":      tgz(t, entry{"module.lock.json", lock, 0}, entry{"actions/hello.sh", nil, tar.TypeSymlink}),
		"traversal":    tgz(t, entry{"../module.lock.json", lock, 0}),
		"absolute":     tgz(t, entry{"/module.lock.json", lock, 0}),
		"dup":          tgz(t, entry{"module.lock.json", lock, 0}, entry{"./module.lock.json", lock, 0}),
		"missing":      tgz(t, entry{"module.lock.json", lock, 0}, entry{"actions/hello.sh", fx(t, "hello.sh"), 0}),
		"other script": tgz(t, entry{"module.lock.json", lock, 0}, entry{"actions/hello.sh", []byte("rm -rf /\n"), 0}, entry{"actions/restart.sh", fx(t, "restart.sh"), 0}),
		"huge":         tgz(t, entry{"big", bytes.Repeat([]byte("a"), 300<<10), 0}),
		"extra file": tgz(t, entry{"module.lock.json", lock, 0}, entry{"actions/hello.sh", fx(t, "hello.sh"), 0}, entry{"actions/restart.sh", fx(t, "restart.sh"), 0},
			entry{"notes.txt", []byte("x"), 0}),
	} {
		var ie *ImportError
		if _, err := s.Import(ctx, "axel", arch); !errors.As(err, &ie) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
