// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/keyring"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnreg"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

// This file tests the start-time load of the signed image catalog from the
// release bundle (ADR 0008 PV-03c, D2 (a)) and its fail-closed behaviour.
// Every test uses temporary bundle, data and trust directories; nothing
// under /usr/share is read.

const (
	// catalogStateFile is the executor's durable catalog rollback state
	// (executor pveCatalogStateFile).
	catalogStateFile = "pve-catalog.json"
	catImgUbuntu     = "ubuntu-24.04-amd64"
	catImgDebian     = "debian-12-amd64"
	catImgLocal      = "local-alpine-3.20-amd64"
)

func catalogImage(id, osName, rel, sha string) map[string]any {
	return map[string]any{"id": id, "os": osName, "release": rel, "arch": "amd64",
		"url": "https://images.example.org/" + id + ".qcow2", "sha256": sha, "disk_format": "qcow2"}
}

// signedCatalog returns a canonical catalog with sequence seq holding the
// Ubuntu and Debian images, and k's signature over it.
func signedCatalog(t *testing.T, k *testRoot, seq int64) ([]byte, []byte) {
	t.Helper()
	ub := catalogImage(catImgUbuntu, "ubuntu", "24.04", strings.Repeat("ab", 32))
	de := catalogImage(catImgDebian, "debian", "12", strings.Repeat("cd", 32))
	raw := canon(t, map[string]any{"format": release.CatalogFormat, "sequence": seq, "images": []any{de, ub}})
	return raw, k.sign(raw)
}

func writeCatalogPair(t *testing.T, dir string, raw, sig []byte) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for n, b := range map[string][]byte{release.CatalogFile: raw, release.CatalogSignatureFile: sig} {
		_ = os.Remove(filepath.Join(dir, n))
		if b == nil {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, n), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// catalogStart is one executor start against a data directory.
type catalogStart struct {
	svc    *executor.Service
	loaded bool
	audit  string
}

// startExecutor builds the executor service the way run() does on dataDir
// (executor.db, permit authority, served-service wiring, built-in trust
// with k's anchors in <dataDir>/trust), then runs the start-time catalog
// load from bundleDir. The database is closed when the test ends or when
// the next start of the same test closes it with stop.
func startExecutor(t *testing.T, k *testRoot, dataDir, bundleDir string) (*catalogStart, func()) {
	t.Helper()
	db, err := executordb.Open(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	stopped := false
	stop := func() {
		if !stopped {
			stopped = true
			_ = db.Close()
		}
	}
	t.Cleanup(stop)
	verifier, err := webauthnverify.New(webauthnverify.Config{RPID: "catalog.test", Origins: []string{"https://catalog.test"}, Counters: db}, nil)
	if err != nil {
		t.Fatal(err)
	}
	power := &executor.PveGuestPowerBindings{}
	risk, err := executor.NewExecutorRiskPolicy(db, power)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := permit.New(permit.Options{Mode: permit.ModeStandard, Verifier: verifier, Store: db, RiskPolicy: risk, Schedules: db})
	if err != nil {
		t.Fatal(err)
	}
	reg, err := webauthnreg.New(webauthnreg.Config{RPID: "catalog.test", Origins: []string{"https://catalog.test"}}, verifier, db)
	if err != nil {
		t.Fatal(err)
	}
	keysDir := filepath.Join(dataDir, "keys")
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	svc := executor.NewService(auth, keyring.New(keysDir), db, reg, log)
	eventKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wireServedService(svc, power, eventKey, dataDir, keysDir)
	now := func() time.Time { return time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC) }
	storeDir := builtinTrustStoreDir(dataDir, "")
	if err := wireBuiltinTrust(svc, storeDir, bundleDir, k.anchors(), now, db); err != nil {
		t.Fatal(err)
	}
	loaded := loadBundleImageCatalog(svc, storeDir, bundleDir, now, log)
	return &catalogStart{svc: svc, loaded: loaded, audit: buf.String()}, stop
}

func (s *catalogStart) list(t *testing.T) *pb.ListPVEImagesResponse {
	t.Helper()
	out, err := call(t, wireServerUID, pb.ExecutorService_ListPVEImages_FullMethodName, &pb.ListPVEImagesRequest{}, s.svc.ListPVEImages)
	if err != nil {
		t.Fatalf("list images: %v", err)
	}
	return out
}

func (s *catalogStart) signedIDs(t *testing.T) []string {
	t.Helper()
	var ids []string
	for _, img := range s.list(t).GetImages() {
		if img.GetTrust() == string(executor.ImageTrustSigned) {
			ids = append(ids, img.GetImage().GetId())
		}
	}
	return ids
}

// propose asks for pve.image.prepare of id as the server, through the
// executor's real role table.
func (s *catalogStart) propose(t *testing.T, id string) error {
	t.Helper()
	_, err := call(t, wireServerUID, pb.ExecutorService_ProposePVEImagePrepare_FullMethodName,
		&pb.ProposePVEImagePrepareRequest{Spec: &pb.PVEImagePrepareSpec{RemoteId: "pve-a", Node: "pve1", Storage: "local-lvm",
			ImageId: id, ImportStorage: "local", Vmid: 9000}}, s.svc.ProposePVEImagePrepare)
	return err
}

// requireUnknown asserts the proposal is refused as ErrPveImageUnknown
// (codes.NotFound with the fixed catalog text).
func requireUnknown(t *testing.T, s *catalogStart, id string) {
	t.Helper()
	err := s.propose(t, id)
	if status.Code(err) != codes.NotFound || !strings.Contains(status.Convert(err).Message(), "not in the catalog") {
		t.Fatalf("prepare %s: %v, want NotFound (ErrPveImageUnknown)", id, err)
	}
}

// requirePastCatalog asserts the proposal resolved id in the catalog: it
// is refused later (this test executor has no unlocked vault and no
// remote), never as an unknown image.
func requirePastCatalog(t *testing.T, s *catalogStart, id string) {
	t.Helper()
	err := s.propose(t, id)
	// The vault check follows the catalog lookup (PveImages.mutation runs
	// before PveMutations.checkDeps), so reaching it means id resolved.
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(status.Convert(err).Message(), "unlocked vault") {
		t.Fatalf("prepare %s: %v, want the image resolved and the locked vault refused next", id, err)
	}
}

func auditKinds(t *testing.T, log string) []string {
	t.Helper()
	var kinds []string
	for line := range strings.SplitSeq(strings.TrimSpace(log), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		if rec["msg"] == "audit" {
			if k, ok := rec["kind"].(string); ok && strings.HasPrefix(k, "pve_image_catalog") {
				kinds = append(kinds, k+":"+str(rec["reason"]))
			}
		}
	}
	return kinds
}

func str(v any) string { s, _ := v.(string); return s }

func readState(t *testing.T, dataDir string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dataDir, catalogStateFile))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The start loads the signed catalog from the bundle directory with the
// active roots of the trust store and persists its sequence; after a
// restart with a lower sequence in the bundle the executor refuses it
// (rollback), still starts, serves no signed image and keeps the state.
func TestStartLoadsSignedImageCatalogAndRefusesRollbackAfterRestart(t *testing.T) {
	k := newTestRoot(t)
	dataDir := privateTempDir(t)
	bundleDir := filepath.Join(t.TempDir(), "release")
	raw2, sig2 := signedCatalog(t, k, 2)
	writeCatalogPair(t, bundleDir, raw2, sig2)

	first, stop := startExecutor(t, k, dataDir, bundleDir)
	if !first.loaded {
		t.Fatalf("signed catalog not loaded; audit:\n%s", first.audit)
	}
	l := first.list(t)
	if l.GetCatalogSequence() != 2 || l.GetCatalogDigest() != sum(raw2) {
		t.Fatalf("catalog sequence %d digest %s, want 2 %s", l.GetCatalogSequence(), l.GetCatalogDigest(), sum(raw2))
	}
	if got := first.signedIDs(t); !slices.Equal(got, []string{catImgDebian, catImgUbuntu}) {
		t.Fatalf("signed images %v", got)
	}
	if got := auditKinds(t, first.audit); !slices.Equal(got, []string{"pve_image_catalog_loaded:"}) {
		t.Fatalf("audit %v, want one pve_image_catalog_loaded", got)
	}
	requirePastCatalog(t, first, catImgUbuntu)
	state := readState(t, dataDir)
	if state == nil || !bytes.Contains(state, []byte(sum(raw2))) {
		t.Fatalf("catalog state %q, want sequence 2 and its digest", state)
	}

	// Restart with the same catalog: loads again, state unchanged.
	stop()
	again, stop := startExecutor(t, k, dataDir, bundleDir)
	if !again.loaded || again.list(t).GetCatalogSequence() != 2 {
		t.Fatalf("same catalog after restart not loaded; audit:\n%s", again.audit)
	}
	if !bytes.Equal(readState(t, dataDir), state) {
		t.Fatal("catalog state changed by reloading the same catalog")
	}

	// Release "downgrade": sequence 1 in the bundle, then restart.
	stop()
	raw1, sig1 := signedCatalog(t, k, 1)
	writeCatalogPair(t, bundleDir, raw1, sig1)
	rolled, _ := startExecutor(t, k, dataDir, bundleDir)
	if rolled.loaded {
		t.Fatal("older catalog loaded after restart")
	}
	if got := auditKinds(t, rolled.audit); !slices.Equal(got, []string{"pve_image_catalog_refused:rollback"}) {
		t.Fatalf("audit %v, want pve_image_catalog_refused rollback", got)
	}
	if l := rolled.list(t); l.GetCatalogSequence() != 0 || l.GetCatalogDigest() != "" || len(rolled.signedIDs(t)) != 0 {
		t.Fatalf("signed catalog after rollback: sequence %d digest %q images %v", l.GetCatalogSequence(), l.GetCatalogDigest(), rolled.signedIDs(t))
	}
	requireUnknown(t, rolled, catImgUbuntu)
	requireUnknown(t, rolled, catImgDebian)
	if !bytes.Equal(readState(t, dataDir), state) {
		t.Fatal("catalog state changed by a refused rollback")
	}
}

// Fail closed at start (D2 (a)): a missing file, an incomplete pair, a
// symlinked file, a signature that does not verify against the trust
// store's roots, malformed bytes and a rollback each start the executor
// with no signed catalog, store no catalog state and refuse every signed
// image with ErrPveImageUnknown. A local entry persisted earlier (D3 (a))
// stays preparable: the test asserts this on purpose.
func TestStartWithoutVerifiedImageCatalogFailsClosed(t *testing.T) {
	k := newTestRoot(t)
	other := newTestRoot(t)
	cases := []struct {
		name string
		// prior runs on the first start, before the local entry is added
		// (used to set a rollback floor); nil means a first start with no
		// catalog.
		prior func(t *testing.T, dir string)
		setup func(t *testing.T, dir string)
		audit string
		// keepsState: the state of the earlier accepted catalog must stay
		// byte-for-byte; otherwise no state file may exist.
		keepsState bool
	}{
		{"missing bundle directory", nil, func(t *testing.T, dir string) {}, "pve_image_catalog_absent:", false},
		{"missing catalog files", nil, func(t *testing.T, dir string) {
			writeBundle(t, k, dir)
		}, "pve_image_catalog_absent:", false},
		{"missing signature", nil, func(t *testing.T, dir string) {
			raw, _ := signedCatalog(t, k, 3)
			writeCatalogPair(t, dir, raw, nil)
		}, "pve_image_catalog_refused:incomplete", false},
		{"missing catalog", nil, func(t *testing.T, dir string) {
			_, sig := signedCatalog(t, k, 3)
			writeCatalogPair(t, dir, nil, sig)
		}, "pve_image_catalog_refused:incomplete", false},
		{"signed by an untrusted key", nil, func(t *testing.T, dir string) {
			raw, _ := signedCatalog(t, k, 3)
			writeCatalogPair(t, dir, raw, other.sign(raw))
		}, "pve_image_catalog_refused:signature", false},
		{"signature over other bytes", nil, func(t *testing.T, dir string) {
			raw, _ := signedCatalog(t, k, 3)
			raw4, _ := signedCatalog(t, k, 4)
			writeCatalogPair(t, dir, raw, k.sign(raw4))
		}, "pve_image_catalog_refused:signature", false},
		{"garbage signature", nil, func(t *testing.T, dir string) {
			raw, _ := signedCatalog(t, k, 3)
			writeCatalogPair(t, dir, raw, []byte("not a signature"))
		}, "pve_image_catalog_refused:format", false},
		{"symlinked catalog", nil, func(t *testing.T, dir string) {
			raw, sig := signedCatalog(t, k, 3)
			elsewhere := filepath.Join(t.TempDir(), "catalog.json")
			if err := os.WriteFile(elsewhere, raw, 0o644); err != nil {
				t.Fatal(err)
			}
			writeCatalogPair(t, dir, nil, sig)
			if err := os.Symlink(elsewhere, filepath.Join(dir, release.CatalogFile)); err != nil {
				t.Fatal(err)
			}
		}, "pve_image_catalog_refused:unreadable", false},
		{"catalog is a directory", nil, func(t *testing.T, dir string) {
			_, sig := signedCatalog(t, k, 3)
			writeCatalogPair(t, dir, nil, sig)
			mkdir(t, filepath.Join(dir, release.CatalogFile))
		}, "pve_image_catalog_refused:unreadable", false},
		{"rollback", func(t *testing.T, dir string) {
			raw, sig := signedCatalog(t, k, 5)
			writeCatalogPair(t, dir, raw, sig)
		}, func(t *testing.T, dir string) {
			raw, sig := signedCatalog(t, k, 4)
			writeCatalogPair(t, dir, raw, sig)
		}, "pve_image_catalog_refused:rollback", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := privateTempDir(t)
			bundleDir := filepath.Join(t.TempDir(), "release")
			if tc.prior != nil {
				tc.prior(t, bundleDir)
			}
			// First start: an admin adds a local entry over the admin
			// socket, which persists it (D3 (a)).
			first, stop := startExecutor(t, k, dataDir, bundleDir)
			if tc.prior != nil && !first.loaded {
				t.Fatalf("prior catalog not loaded; audit:\n%s", first.audit)
			}
			local := &pb.PVECatalogImage{Id: catImgLocal, Os: "alpine", Release: "3.20", Arch: "amd64",
				Url: "https://images.example.org/alpine.qcow2", Sha256: strings.Repeat("ef", 32), DiskFormat: "qcow2"}
			if _, err := call(t, wireAdminUID, pb.ExecutorService_AddPVELocalImage_FullMethodName,
				&pb.AddPVELocalImageRequest{Image: local}, first.svc.AddPVELocalImage); err != nil {
				t.Fatalf("add local entry: %v", err)
			}
			state := readState(t, dataDir)
			stop()
			_ = os.RemoveAll(bundleDir)
			tc.setup(t, bundleDir)

			s, _ := startExecutor(t, k, dataDir, bundleDir)
			if s.loaded {
				t.Fatal("a signed catalog was loaded")
			}
			if got := auditKinds(t, s.audit); !slices.Equal(got, []string{tc.audit}) {
				t.Fatalf("audit %v, want [%s]", got, tc.audit)
			}
			l := s.list(t)
			if l.GetCatalogSequence() != 0 || l.GetCatalogDigest() != "" || len(s.signedIDs(t)) != 0 {
				t.Fatalf("signed catalog served: sequence %d digest %q images %v", l.GetCatalogSequence(), l.GetCatalogDigest(), s.signedIDs(t))
			}
			got := readState(t, dataDir)
			if tc.keepsState {
				if got == nil || !bytes.Equal(got, state) {
					t.Fatalf("catalog state %q, want unchanged %q", got, state)
				}
			} else if got != nil {
				t.Fatalf("catalog state written without a verified catalog: %q", got)
			}
			for _, id := range []string{catImgUbuntu, catImgDebian} {
				requireUnknown(t, s, id)
			}
			// The local entry is served independently of the signed part
			// (pve_images.go Lookup): listed as Local and resolved by the
			// preparation, not refused as unknown.
			var listed bool
			for _, img := range l.GetImages() {
				if img.GetImage().GetId() == catImgLocal && img.GetTrust() == string(executor.ImageTrustLocal) {
					listed = true
				}
			}
			if !listed {
				t.Fatalf("local entry not served: %v", l.GetImages())
			}
			requirePastCatalog(t, s, catImgLocal)
		})
	}
}

// Without a usable trust store no catalog is admitted, not even against
// the compiled anchors, and nothing is persisted.
func TestStartImageCatalogNeedsTrustStoreRoots(t *testing.T) {
	k := newTestRoot(t)
	dataDir := privateTempDir(t)
	bundleDir := filepath.Join(t.TempDir(), "release")
	raw, sig := signedCatalog(t, k, 1)
	writeCatalogPair(t, bundleDir, raw, sig)
	s, _ := startExecutor(t, k, dataDir, bundleDir)
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	if loadBundleImageCatalog(s.svc, filepath.Join(dataDir, "no-such-store"), bundleDir, time.Now, log) {
		t.Fatal("catalog loaded without a trust store")
	}
	if got := auditKinds(t, buf.String()); !slices.Equal(got, []string{"pve_image_catalog_refused:roots"}) {
		t.Fatalf("audit %v", got)
	}
}

// run() performs the catalog load at start, after built-in trust set up
// the store whose roots it uses.
func TestRunLoadsImageCatalogAfterBuiltinTrust(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	trustAt := strings.Index(s, "setupBuiltinTrust(svc,")
	loadAt := strings.Index(s, "loadBundleImageCatalog(svc, builtinTrustStoreDir(*dataDir, *trustDir), *bundleDir,")
	serveAt := strings.Index(s, "srv.Serve(lis)")
	if trustAt < 0 || loadAt < 0 || serveAt < 0 || !(trustAt < loadAt && loadAt < serveAt) {
		t.Fatalf("run() must load the image catalog after setupBuiltinTrust and before serving (%d, %d, %d)", trustAt, loadAt, serveAt)
	}
}
