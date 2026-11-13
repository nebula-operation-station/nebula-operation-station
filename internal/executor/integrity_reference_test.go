// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/integrity"
	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
)

// refEnv is a release directory (the stand-in for /usr/share/nebula/
// release), a durable root state trusting k, and an executor database.
type refEnv struct {
	k     *bundleSK
	state release.RootState
	dir   string
	dbDir string
	db    *executordb.DB
}

func newRefEnv(t *testing.T) *refEnv {
	t.Helper()
	k := newBundleSK(t)
	st, err := release.Bootstrap(k.anchors())
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	e := &refEnv{k: k, state: st, dir: filepath.Join(base, "release"), dbDir: filepath.Join(base, "db")}
	if err := os.Mkdir(e.dbDir, 0o700); err != nil {
		t.Fatal(err)
	}
	e.db = openTestDB(t, e.dbDir)
	return e
}

// signedFiles returns a list for version (tag varies its content, so the
// same version yields another manifest), a manifest covering it and k's
// signature.
func signedFiles(t *testing.T, k *bundleSK, version, tag string) (man, sig, list []byte) {
	t.Helper()
	bin := []byte("server binary " + tag)
	l := release.InstalledFiles{ReleaseVersion: version, Flavours: []release.Flavour{{Name: "deb:amd64",
		Files: []release.InstalledFile{{Path: "/usr/bin/nebula-server", Type: release.FileRegular,
			Size: int64(len(bin)), SHA256: bundleSum(bin), Mode: 0o755, Owner: release.GeneratedOwner}}}}}
	list, err := l.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	bundle, mod := []byte("builtins"), []byte("module tar")
	man = bundleCanon(t, map[string]any{"format": release.ManifestFormat, "release_version": version,
		"artifacts": []any{
			map[string]any{"name": release.BundleArtifact, "size": len(bundle), "sha256": bundleSum(bundle)},
			map[string]any{"name": release.InstalledFilesArtifact, "size": len(list), "sha256": bundleSum(list)},
		},
		"modules": []any{map[string]any{"name": "docker", "version": "1.2.0", "size": len(mod), "sha256": bundleSum(mod)}}})
	return man, k.sign(man), list
}

func (e *refEnv) write(t *testing.T, man, sig, list []byte) {
	t.Helper()
	if err := os.MkdirAll(e.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for n, b := range map[string][]byte{release.ManifestFile: man, release.SignatureFile: sig, release.InstalledFilesArtifact: list} {
		if err := os.WriteFile(filepath.Join(e.dir, n), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func (e *refEnv) release(t *testing.T, version, tag string) (man, sig, list []byte) {
	t.Helper()
	man, sig, list = signedFiles(t, e.k, version, tag)
	e.write(t, man, sig, list)
	return man, sig, list
}

func (e *refEnv) admit(t *testing.T, running string) ReferenceAdmission {
	t.Helper()
	a, err := AdmitInstalledFiles(e.db, e.state, running, e.dir)
	if err != nil {
		t.Fatalf("AdmitInstalledFiles: %v", err)
	}
	return a
}

func TestAdmitInstalledFilesStoresVerifiedCopy(t *testing.T) {
	e := newRefEnv(t)
	man, sig, list := e.release(t, "1.4.0", "a")
	a := e.admit(t, "1.4.0")
	if a.Outcome != ReferenceAdmitted || !a.Available || a.Err != nil {
		t.Fatalf("admission = %+v", a)
	}
	if a.ReleaseVersion != "1.4.0" || a.ManifestSHA256 != bundleSum(man) {
		t.Fatalf("admission = %+v", a)
	}
	stored, err := e.db.ActiveIntegrityReference()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored.Manifest, man) || !bytes.Equal(stored.Signature, sig) || !bytes.Equal(stored.List, list) {
		t.Fatal("stored copy differs from the verified files")
	}
	if stored.SignedBy != "root-1" || stored.ListSHA256 != bundleSum(list) {
		t.Fatalf("stored = %+v", stored)
	}
	ref, err := LoadAdmittedReference(e.db, e.state, "1.4.0")
	if err != nil {
		t.Fatal(err)
	}
	if ref.ManifestDigest() != bundleSum(man) || ref.ListDigest() != bundleSum(list) {
		t.Fatal("loaded reference does not match the admitted one")
	}
	// A second start with the same files changes nothing.
	if a := e.admit(t, "1.4.0"); a.Outcome != ReferenceUnchanged || !a.Available {
		t.Fatalf("second admission = %+v", a)
	}
}

func TestAdmitInstalledFilesRejections(t *testing.T) {
	other := newBundleSK(t)
	cases := []struct {
		name    string
		running string
		files   func(t *testing.T, e *refEnv)
		want    ReferenceRejection
		wantErr error
	}{
		{"wrong signature", "1.4.0", func(t *testing.T, e *refEnv) {
			man, _, list := signedFiles(t, e.k, "1.4.0", "a")
			e.write(t, man, other.sign(man), list)
		}, RejectSignature, release.ErrUntrusted},
		{"corrupt signature", "1.4.0", func(t *testing.T, e *refEnv) {
			man, sig, list := signedFiles(t, e.k, "1.4.0", "a")
			sig = bytes.Replace(sig, []byte("\n-----END"), []byte("AAAA\n-----END"), 1)
			e.write(t, man, sig, list)
		}, RejectFormat, release.ErrFormat},
		{"manifest changed after signing", "1.4.0", func(t *testing.T, e *refEnv) {
			man, sig, list := signedFiles(t, e.k, "1.4.0", "a")
			man2, _, _ := signedFiles(t, e.k, "1.4.0", "b")
			_ = man
			e.write(t, man2, sig, list)
		}, RejectSignature, release.ErrSignature},
		{"wrong list hash", "1.4.0", func(t *testing.T, e *refEnv) {
			man, sig, _ := signedFiles(t, e.k, "1.4.0", "a")
			_, _, list2 := signedFiles(t, e.k, "1.4.0", "b") // same size, other bytes
			e.write(t, man, sig, list2)
		}, RejectHash, release.ErrInstalledFiles},
		{"wrong version", "1.4.1", func(t *testing.T, e *refEnv) {
			e.release(t, "1.4.0", "a")
		}, RejectVersion, integrity.ErrVersion},
		{"oversize list", "1.4.0", func(t *testing.T, e *refEnv) {
			man, sig, _ := signedFiles(t, e.k, "1.4.0", "a")
			e.write(t, man, sig, make([]byte, release.MaxInstalledFilesDocument+1))
		}, RejectOversize, ErrReferenceFileTooLarge},
		{"oversize manifest", "1.4.0", func(t *testing.T, e *refEnv) {
			_, sig, list := signedFiles(t, e.k, "1.4.0", "a")
			e.write(t, make([]byte, release.MaxManifest+1), sig, list)
		}, RejectOversize, ErrReferenceFileTooLarge},
		{"oversize signature", "1.4.0", func(t *testing.T, e *refEnv) {
			man, _, list := signedFiles(t, e.k, "1.4.0", "a")
			e.write(t, man, make([]byte, release.MaxSignature+1), list)
		}, RejectOversize, ErrReferenceFileTooLarge},
		{"symlinked list", "1.4.0", func(t *testing.T, e *refEnv) {
			man, sig, list := signedFiles(t, e.k, "1.4.0", "a")
			e.write(t, man, sig, list)
			p := filepath.Join(e.dir, release.InstalledFilesArtifact)
			if err := os.Rename(p, p+".real"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(release.InstalledFilesArtifact+".real", p); err != nil {
				t.Fatal(err)
			}
		}, RejectRead, nil},
		{"missing signature", "1.4.0", func(t *testing.T, e *refEnv) {
			man, sig, list := signedFiles(t, e.k, "1.4.0", "a")
			e.write(t, man, sig, list)
			if err := os.Remove(filepath.Join(e.dir, release.SignatureFile)); err != nil {
				t.Fatal(err)
			}
		}, RejectRead, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newRefEnv(t)
			tc.files(t, e)
			a := e.admit(t, tc.running)
			if a.Outcome != ReferenceRejected || a.Rejection != tc.want {
				t.Fatalf("admission = %+v, want rejected %s", a, tc.want)
			}
			if tc.wantErr != nil && !errors.Is(a.Err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", a.Err, tc.wantErr)
			}
			if a.Available {
				t.Fatal("rejected admission reports an available reference")
			}
			if _, err := e.db.ActiveIntegrityReference(); !errors.Is(err, executordb.ErrNoIntegrityReference) {
				t.Fatalf("rejected files were stored: %v", err)
			}
		})
	}
}

func TestAdmitInstalledFilesRejectsLowerVersion(t *testing.T) {
	e := newRefEnv(t)
	man, _, _ := e.release(t, "1.5.0", "a")
	e.admit(t, "1.5.0")
	// The release directory is rolled back to a validly signed older
	// release and the older binary runs.
	e.release(t, "1.4.0", "a")
	a := e.admit(t, "1.4.0")
	if a.Outcome != ReferenceRejected || a.Rejection != RejectRollback || !errors.Is(a.Err, executordb.ErrReferenceRollback) {
		t.Fatalf("admission = %+v, want rollback rejection", a)
	}
	if a.Available {
		t.Fatal("rollback leaves a reference for the running version")
	}
	stored, err := e.db.ActiveIntegrityReference()
	if err != nil || stored.ManifestSHA256 != bundleSum(man) {
		t.Fatalf("active reference changed by a rollback: %v", err)
	}
}

func TestAdmitInstalledFilesRejectsSecondManifestForVersion(t *testing.T) {
	e := newRefEnv(t)
	man, _, _ := e.release(t, "1.4.0", "a")
	e.admit(t, "1.4.0")
	e.release(t, "1.4.0", "b")
	a := e.admit(t, "1.4.0")
	if a.Outcome != ReferenceRejected || a.Rejection != RejectConflict || !errors.Is(a.Err, executordb.ErrReferenceConflict) {
		t.Fatalf("admission = %+v, want conflict rejection", a)
	}
	// The earlier admitted reference stays the one checks use.
	if !a.Available || a.ManifestSHA256 != bundleSum(man) {
		t.Fatalf("admission = %+v, want the earlier reference available", a)
	}
}

func TestAdmitInstalledFilesUpgradeSupersedes(t *testing.T) {
	e := newRefEnv(t)
	e.release(t, "1.4.0", "a")
	e.admit(t, "1.4.0")
	man, _, _ := e.release(t, "1.5.0", "a")
	a := e.admit(t, "1.5.0")
	if a.Outcome != ReferenceAdmitted || !a.Available || a.ManifestSHA256 != bundleSum(man) {
		t.Fatalf("admission = %+v", a)
	}
}

func TestAdmitInstalledFilesWithoutFiles(t *testing.T) {
	e := newRefEnv(t)
	// No directory at all, then a directory without the list.
	for _, prep := range []func(){func() {}, func() {
		if err := os.MkdirAll(e.dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}} {
		prep()
		a := e.admit(t, "1.4.0")
		if a.Outcome != ReferenceNoFiles || a.Available {
			t.Fatalf("admission = %+v, want no-files without reference", a)
		}
	}
	if _, err := LoadAdmittedReference(e.db, e.state, "1.4.0"); !errors.Is(err, executordb.ErrNoIntegrityReference) {
		t.Fatalf("load: err = %v", err)
	}
}

func TestAdmitInstalledFilesDevelopmentBuild(t *testing.T) {
	e := newRefEnv(t)
	e.release(t, "1.4.0", "a")
	a := e.admit(t, "dev")
	if a.Outcome != ReferenceNotCheckable || a.Available {
		t.Fatalf("admission = %+v", a)
	}
	if _, err := e.db.ActiveIntegrityReference(); !errors.Is(err, executordb.ErrNoIntegrityReference) {
		t.Fatal("a development build admitted a reference")
	}
}

func TestAdmittedReferenceSurvivesRestartWithoutUsrShare(t *testing.T) {
	e := newRefEnv(t)
	man, _, list := e.release(t, "1.4.0", "a")
	e.admit(t, "1.4.0")
	if err := e.db.Close(); err != nil {
		t.Fatal(err)
	}
	// The copy under /usr/share disappears; the executor restarts.
	if err := os.RemoveAll(e.dir); err != nil {
		t.Fatal(err)
	}
	db, err := executordb.Open(e.dbDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	e.db = db
	a := e.admit(t, "1.4.0")
	if a.Outcome != ReferenceNoFiles || !a.Available || a.ManifestSHA256 != bundleSum(man) {
		t.Fatalf("admission after restart = %+v", a)
	}
	ref, err := LoadAdmittedReference(db, e.state, "1.4.0")
	if err != nil || ref.ListDigest() != bundleSum(list) {
		t.Fatalf("load after restart: %v", err)
	}
}

func TestLaterChecksIgnoreUsrShareCopy(t *testing.T) {
	e := newRefEnv(t)
	_, _, list := e.release(t, "1.4.0", "a")
	e.admit(t, "1.4.0")
	// Someone replaces the files under /usr/share with another validly
	// signed list for the same version, or with garbage.
	e.release(t, "1.4.0", "b")
	ref, err := LoadAdmittedReference(e.db, e.state, "1.4.0")
	if err != nil || ref.ListDigest() != bundleSum(list) {
		t.Fatalf("load used the /usr/share copy: %v", err)
	}
	e.write(t, []byte("x"), []byte("y"), []byte("z"))
	if ref, err := LoadAdmittedReference(e.db, e.state, "1.4.0"); err != nil || ref.ListDigest() != bundleSum(list) {
		t.Fatalf("load used the /usr/share copy: %v", err)
	}
}

func TestLoadAdmittedReferenceReverifies(t *testing.T) {
	e := newRefEnv(t)
	e.release(t, "1.4.0", "a")
	e.admit(t, "1.4.0")
	// Another root state (the stored signer is not trusted) and another
	// running version both refuse the stored copy.
	other, err := release.Bootstrap(newBundleSK(t).anchors())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAdmittedReference(e.db, other, "1.4.0"); !errors.Is(err, release.ErrUntrusted) {
		t.Fatalf("other root state: err = %v", err)
	}
	if _, err := LoadAdmittedReference(e.db, e.state, "1.5.0"); !errors.Is(err, integrity.ErrVersion) {
		t.Fatalf("other version: err = %v", err)
	}
}

// recordingHandler keeps every log record.
type recordingHandler struct {
	mu   sync.Mutex
	recs []slog.Record
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.recs = append(h.recs, r.Clone())
	return nil
}
func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler      { return h }

// kinds returns "kind" (or the message when absent) of every record,
// with the reason/outcome attribute appended.
func (h *recordingHandler) kinds() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []string
	for _, r := range h.recs {
		kind, extra := r.Message, ""
		r.Attrs(func(a slog.Attr) bool {
			switch a.Key {
			case "kind":
				kind = a.Value.String()
			case "reason":
				extra = ":" + a.Value.String()
			}
			return true
		})
		out = append(out, kind+extra)
	}
	return out
}

// startService wires built-in trust the way the executor does at start.
func startService(t *testing.T, e *refEnv, running string) (*Service, *recordingHandler) {
	t.Helper()
	storeDir := filepath.Join(filepath.Dir(e.dir), "trust")
	now := func() time.Time { return time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC) }
	bt, err := NewDirBuiltinTrust(storeDir, e.dir, e.k.anchors(), now, e.db)
	if err != nil {
		t.Fatal(err)
	}
	h := &recordingHandler{}
	s := &Service{db: e.db, log: slog.New(h), runningVersion: running}
	s.SetBuiltinTrust(bt)
	return s, h
}

func TestExecutorStartAdmitsReference(t *testing.T) {
	e := newRefEnv(t)
	man, _, _ := e.release(t, "1.4.0", "a")
	s, h := startService(t, e, "1.4.0")
	st := s.IntegrityReferenceStatus()
	if st.Outcome != ReferenceAdmitted || !st.Available {
		t.Fatalf("status = %+v", st)
	}
	ref, err := s.AdmittedIntegrityReference(context.Background())
	if err != nil || ref.ManifestDigest() != bundleSum(man) {
		t.Fatalf("AdmittedIntegrityReference: %v", err)
	}
	if !containsKind(h.kinds(), "integrity_reference_admitted") {
		t.Fatalf("no admission audit record: %v", h.kinds())
	}
}

func TestExecutorStartAuditsRollbackAndKeepsRunning(t *testing.T) {
	e := newRefEnv(t)
	e.release(t, "1.5.0", "a")
	startService(t, e, "1.5.0")
	e.release(t, "1.4.0", "a")
	s, h := startService(t, e, "1.4.0")
	st := s.IntegrityReferenceStatus()
	if st.Outcome != ReferenceRejected || st.Rejection != RejectRollback || st.Available {
		t.Fatalf("status = %+v", st)
	}
	kinds := h.kinds()
	if !containsKind(kinds, "integrity_reference_rejected:rollback") || !containsKind(kinds, "integrity_reference_unavailable") {
		t.Fatalf("audit records = %v", kinds)
	}
	if _, err := s.AdmittedIntegrityReference(context.Background()); !errors.Is(err, integrity.ErrVersion) {
		t.Fatalf("AdmittedIntegrityReference: err = %v, want the stored 1.5.0 refused for 1.4.0", err)
	}
}

func TestExecutorStartWithoutFilesReportsNoReference(t *testing.T) {
	e := newRefEnv(t)
	if err := os.MkdirAll(e.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	s, h := startService(t, e, "1.4.0")
	st := s.IntegrityReferenceStatus()
	if st.Outcome != ReferenceNoFiles || st.Available {
		t.Fatalf("status = %+v", st)
	}
	if !containsKind(h.kinds(), "integrity_reference_unavailable") {
		t.Fatalf("no 'no admitted reference' record: %v", h.kinds())
	}
	if _, err := s.AdmittedIntegrityReference(context.Background()); !errors.Is(err, executordb.ErrNoIntegrityReference) {
		t.Fatalf("err = %v", err)
	}
}

func TestServiceWithoutWiringHasNoReference(t *testing.T) {
	s := &Service{}
	if st := s.IntegrityReferenceStatus(); st.Outcome != ReferenceNotRun || st.Available {
		t.Fatalf("status = %+v", st)
	}
	if _, err := s.AdmittedIntegrityReference(context.Background()); !errors.Is(err, integrity.ErrNoReference) {
		t.Fatalf("err = %v", err)
	}
}

func containsKind(kinds []string, want string) bool {
	for _, k := range kinds {
		if k == want || strings.HasPrefix(k, want+":") && !strings.Contains(want, ":") {
			return true
		}
	}
	return false
}
