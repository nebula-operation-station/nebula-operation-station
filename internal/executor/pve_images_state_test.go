// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
)

// newCatalogAt returns a catalog whose durable state is the file at path,
// as the executor builds it on every start.
func newCatalogAt(path string) *PveImageCatalog {
	return &PveImageCatalog{State: &FilePveCatalogState{Path: path}}
}

func TestImageCatalogRollbackRefusedAfterRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pve-catalog.json")
	sk := newReleaseSK(t)
	roots := []release.Root{sk.root()}
	v1 := catalogDoc(t, 1, ubuntuEntry(imgUbuntuSHA))
	v2 := catalogDoc(t, 2, ubuntuEntry(strings.Repeat("99", 32)))
	if err := newCatalogAt(path).LoadSigned(roots, v1, sk.sign(t, v1)); err != nil {
		t.Fatal(err)
	}
	before := newCatalogAt(path)
	if err := before.LoadSigned(roots, v2, sk.sign(t, v2)); err != nil {
		t.Fatal(err)
	}

	// Restart: a fresh catalog in memory, the same state file.
	after := newCatalogAt(path)
	if err := after.LoadSigned(roots, v1, sk.sign(t, v1)); !errors.Is(err, ErrPveCatalogRollback) {
		t.Fatalf("older catalog after restart: %v", err)
	}
	if _, ok := after.Lookup(imgUbuntuID); ok {
		t.Fatal("refused catalog entry is visible")
	}
	// The catalog that was current before the restart loads again.
	if err := after.LoadSigned(roots, v2, sk.sign(t, v2)); err != nil {
		t.Fatalf("current catalog after restart: %v", err)
	}
	if img, _ := after.Lookup(imgUbuntuID); img.SHA256 != strings.Repeat("99", 32) || img.CatalogSequence != 2 {
		t.Fatalf("entry after restart = %+v", img)
	}
}

func TestImageCatalogSameSequenceOtherBytesRefusedAfterRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pve-catalog.json")
	sk := newReleaseSK(t)
	roots := []release.Root{sk.root()}
	v2 := catalogDoc(t, 2, ubuntuEntry(imgUbuntuSHA))
	if err := newCatalogAt(path).LoadSigned(roots, v2, sk.sign(t, v2)); err != nil {
		t.Fatal(err)
	}
	after := newCatalogAt(path)
	v2b := catalogDoc(t, 2, ubuntuEntry(imgLocalSHA))
	if err := after.LoadSigned(roots, v2b, sk.sign(t, v2b)); !errors.Is(err, ErrPveCatalogRollback) {
		t.Fatalf("same sequence, other bytes after restart: %v", err)
	}
	if _, ok := after.Lookup(imgUbuntuID); ok {
		t.Fatal("conflicting catalog entry is visible")
	}
	st, ok, err := (&FilePveCatalogState{Path: path}).PveCatalogState()
	if err != nil || !ok || st.Sequence != 2 {
		t.Fatalf("state after refusal = %+v %v %v", st, ok, err)
	}
}

func TestImageCatalogNewerAcceptedAndPersisted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pve-catalog.json")
	sk := newReleaseSK(t)
	roots := []release.Root{sk.root()}
	c := newCatalogAt(path)
	v1 := catalogDoc(t, 1, ubuntuEntry(imgUbuntuSHA))
	if err := c.LoadSigned(roots, v1, sk.sign(t, v1)); err != nil {
		t.Fatal(err)
	}
	v5 := catalogDoc(t, 5, ubuntuEntry(strings.Repeat("99", 32)))
	if err := c.LoadSigned(roots, v5, sk.sign(t, v5)); err != nil {
		t.Fatalf("newer catalog: %v", err)
	}
	img, _ := c.Lookup(imgUbuntuID)
	st, ok, err := (&FilePveCatalogState{Path: path}).PveCatalogState()
	if err != nil || !ok || st.Sequence != 5 || st.Digest != img.CatalogDigest || !validHexDigest(st.Digest) {
		t.Fatalf("persisted state = %+v %v %v (catalog digest %s)", st, ok, err, img.CatalogDigest)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("state file mode = %v %v", fi.Mode(), err)
	}
	// No temporary files are left next to the state.
	ents, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(ents) != 1 {
		t.Fatalf("state directory = %v %v", ents, err)
	}
}

func TestImageCatalogCorruptStateFailsClosed(t *testing.T) {
	sk := newReleaseSK(t)
	roots := []release.Root{sk.root()}
	raw := catalogDoc(t, 3, ubuntuEntry(imgUbuntuSHA))
	sig := sk.sign(t, raw)
	digest := strings.Repeat("ab", 32)
	for name, content := range map[string]string{
		"garbage":         "{not json",
		"empty":           "",
		"unknown field":   `{"sequence":1,"digest":"` + digest + `","evil":1}`,
		"trailing data":   `{"sequence":1,"digest":"` + digest + `"}{}`,
		"zero sequence":   `{"sequence":0,"digest":"` + digest + `"}`,
		"negative":        `{"sequence":-1,"digest":"` + digest + `"}`,
		"too large":       `{"sequence":9007199254740992,"digest":"` + digest + `"}`,
		"bad digest":      `{"sequence":1,"digest":"` + strings.Repeat("AB", 32) + `"}`,
		"short digest":    `{"sequence":1,"digest":"abcd"}`,
		"missing digest":  `{"sequence":1}`,
		"null":            `null`,
		"oversize":        `{"sequence":1,"digest":"` + digest + `"}` + strings.Repeat(" ", maxPveCatalogState),
		"array not state": `[]`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "pve-catalog.json")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			c := newCatalogAt(path)
			if err := c.LoadSigned(roots, raw, sig); !errors.Is(err, ErrPveCatalogState) {
				t.Fatalf("corrupt state: %v", err)
			}
			if _, ok := c.Lookup(imgUbuntuID); ok {
				t.Fatal("catalog loaded over a corrupt state")
			}
			if got, err := os.ReadFile(path); err != nil || string(got) != content {
				t.Fatal("corrupt state was overwritten")
			}
		})
	}
}

func TestImageCatalogWithoutStateStoreFailsClosed(t *testing.T) {
	sk := newReleaseSK(t)
	raw := catalogDoc(t, 1, ubuntuEntry(imgUbuntuSHA))
	c := &PveImageCatalog{}
	if err := c.LoadSigned([]release.Root{sk.root()}, raw, sk.sign(t, raw)); !errors.Is(err, ErrPveCatalogState) {
		t.Fatalf("no state store: %v", err)
	}
	if _, ok := c.Lookup(imgUbuntuID); ok {
		t.Fatal("catalog loaded without durable state")
	}
}

// failingCatalogState is a state store whose write fails.
type failingCatalogState struct{ FilePveCatalogState }

func (s *failingCatalogState) PutPveCatalogState(PveCatalogState) error {
	return errors.New("disk full")
}

func TestImageCatalogStateWriteFailureKeepsOldCatalog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pve-catalog.json")
	sk := newReleaseSK(t)
	roots := []release.Root{sk.root()}
	v1 := catalogDoc(t, 1, ubuntuEntry(imgUbuntuSHA))
	c := newCatalogAt(path)
	if err := c.LoadSigned(roots, v1, sk.sign(t, v1)); err != nil {
		t.Fatal(err)
	}
	c.State = &failingCatalogState{FilePveCatalogState{Path: path}}
	v2 := catalogDoc(t, 2, ubuntuEntry(strings.Repeat("99", 32)))
	if err := c.LoadSigned(roots, v2, sk.sign(t, v2)); !errors.Is(err, ErrPveCatalogState) {
		t.Fatalf("unpersisted newer catalog: %v", err)
	}
	if img, _ := c.Lookup(imgUbuntuID); img.SHA256 != imgUbuntuSHA || img.CatalogSequence != 1 {
		t.Fatalf("catalog switched without durable state: %+v", img)
	}
	// Reloading the persisted catalog needs no write and still works.
	if err := c.LoadSigned(roots, v1, sk.sign(t, v1)); err != nil {
		t.Fatalf("reload of the persisted catalog: %v", err)
	}
}

// failingPutTemplates is a template store whose write fails.
type failingPutTemplates struct{ *FilePveTemplateStore }

func (s failingPutTemplates) PutPveTemplate(PveTemplateRecord) error { return errors.New("disk full") }

func TestImagePrepareUnrecordedTemplateIsAudited(t *testing.T) {
	e := newImagesEnv(t)
	e.imgs.Templates = failingPutTemplates{e.store}
	req := e.approveImage(prepareReq(imgUbuntuID, 9000))
	if _, err := e.imgs.Prepare(context.Background(), req); !errors.Is(err, ErrPveTemplateStore) {
		t.Fatalf("prepare with a failing record store: %v", err)
	}
	if n := len(e.client.dispatched()); n != 3 {
		t.Fatalf("steps = %d, want the template built in PVE", n)
	}
	logs := e.logs.String()
	for _, want := range []string{"kind=pve_template_unrecorded", "remote=" + mutRemote, "node=pve1", "storage=local-lvm",
		"image=" + imgUbuntuID, "vmid=9000", "execution="} {
		if !strings.Contains(logs, want) {
			t.Fatalf("audit line lacks %q:\n%s", want, logs)
		}
	}
	if strings.Contains(logs, "disk full") {
		t.Fatal("raw store error in the audit line")
	}
}

func TestImagePrepareUnreadableTemplateIsAudited(t *testing.T) {
	e := newImagesEnv(t)
	e.client.setTemplateDigest("not-a-digest")
	req := e.approveImage(prepareReq(imgUbuntuID, 9000))
	if _, err := e.imgs.Prepare(context.Background(), req); !errors.Is(err, ErrPveTemplateChanged) {
		t.Fatalf("prepare with an unreadable template: %v", err)
	}
	if !strings.Contains(e.logs.String(), "kind=pve_template_unrecorded") {
		t.Fatalf("template without record not audited:\n%s", e.logs.String())
	}
	if _, ok, _ := e.store.PveTemplate(req.PveTemplateKey); ok {
		t.Fatal("unreadable template recorded")
	}
}
