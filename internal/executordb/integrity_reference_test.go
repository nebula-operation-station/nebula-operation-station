// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
)

func refSum(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// testRef builds a reference whose digests match its bytes. The bytes are
// opaque to the store (the executor verified them); tag makes them unique.
func testRef(version, tag string) IntegrityReference {
	m := []byte(`{"manifest":"` + version + `","tag":"` + tag + `"}`)
	l := []byte(`{"list":"` + version + `","tag":"` + tag + `"}`)
	return IntegrityReference{
		ReleaseVersion: version,
		Manifest:       m,
		Signature:      []byte("-----BEGIN SSH SIGNATURE-----\n" + tag + "\n-----END SSH SIGNATURE-----\n"),
		List:           l,
		ManifestSHA256: refSum(m),
		ListSHA256:     refSum(l),
		SignedBy:       "root-1",
	}
}

func TestAdmitIntegrityReferenceStoresExactBytes(t *testing.T) {
	db := openAtT(t, privateDir(t), t0)
	if _, err := db.ActiveIntegrityReference(); !errors.Is(err, ErrNoIntegrityReference) {
		t.Fatalf("empty store: err = %v, want ErrNoIntegrityReference", err)
	}
	r := testRef("1.4.0", "a")
	added, err := db.AdmitIntegrityReference(r)
	if err != nil || !added {
		t.Fatalf("admit = %v, %v; want true, nil", added, err)
	}
	got, err := db.ActiveIntegrityReference()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Manifest, r.Manifest) || !bytes.Equal(got.Signature, r.Signature) || !bytes.Equal(got.List, r.List) {
		t.Fatal("stored bytes differ from admitted bytes")
	}
	if got.ReleaseVersion != "1.4.0" || got.ManifestSHA256 != r.ManifestSHA256 || got.ListSHA256 != r.ListSHA256 ||
		got.SignedBy != "root-1" || !got.Active || !got.AdmittedAt.Equal(t0) {
		t.Fatalf("stored record = %+v", got)
	}
}

func TestAdmitIntegrityReferenceSameManifestIsIdempotent(t *testing.T) {
	db := openAtT(t, privateDir(t), t0)
	r := testRef("1.4.0", "a")
	if _, err := db.AdmitIntegrityReference(r); err != nil {
		t.Fatal(err)
	}
	added, err := db.AdmitIntegrityReference(r)
	if err != nil || added {
		t.Fatalf("re-admit = %v, %v; want false, nil", added, err)
	}
	if n := countRefs(t, db); n != 1 {
		t.Fatalf("rows = %d, want 1", n)
	}
}

func TestAdmitIntegrityReferenceHigherVersionKeepsHistory(t *testing.T) {
	db := openAtT(t, privateDir(t), t0)
	for _, v := range []string{"1.4.0-rc.1", "1.4.0", "1.4.1", "1.10.0"} {
		if added, err := db.AdmitIntegrityReference(testRef(v, "a")); err != nil || !added {
			t.Fatalf("admit %s = %v, %v", v, added, err)
		}
	}
	got, err := db.ActiveIntegrityReference()
	if err != nil {
		t.Fatal(err)
	}
	if got.ReleaseVersion != "1.10.0" {
		t.Fatalf("active = %s, want 1.10.0", got.ReleaseVersion)
	}
	if n := countRefs(t, db); n != 4 {
		t.Fatalf("rows = %d, want 4 (predecessors kept)", n)
	}
	var active int
	if err := db.sql.QueryRow(`SELECT count(*) FROM integrity_references WHERE active = 1`).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 1 {
		t.Fatalf("active rows = %d, want exactly 1", active)
	}
}

func TestAdmitIntegrityReferenceRejectsLowerVersion(t *testing.T) {
	db := openAtT(t, privateDir(t), t0)
	if _, err := db.AdmitIntegrityReference(testRef("1.4.1", "a")); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"1.4.0", "1.4.1-rc.1", "0.99.99", "1.3.10"} {
		if _, err := db.AdmitIntegrityReference(testRef(v, "a")); !errors.Is(err, ErrReferenceRollback) {
			t.Fatalf("admit %s: err = %v, want ErrReferenceRollback", v, err)
		}
	}
	got, _ := db.ActiveIntegrityReference()
	if got.ReleaseVersion != "1.4.1" {
		t.Fatalf("active changed to %s after rejected rollback", got.ReleaseVersion)
	}
}

func TestAdmitIntegrityReferenceRejectsSameVersionOtherManifest(t *testing.T) {
	db := openAtT(t, privateDir(t), t0)
	if _, err := db.AdmitIntegrityReference(testRef("1.4.0", "a")); err != nil {
		t.Fatal(err)
	}
	// Another manifest for the same release version, and one whose
	// version differs only in build metadata (same SemVer precedence).
	for _, r := range []IntegrityReference{testRef("1.4.0", "b"), testRef("1.4.0+build.2", "a")} {
		if _, err := db.AdmitIntegrityReference(r); !errors.Is(err, ErrReferenceConflict) {
			t.Fatalf("admit %s: err = %v, want ErrReferenceConflict", r.ReleaseVersion, err)
		}
	}
	got, _ := db.ActiveIntegrityReference()
	if got.ManifestSHA256 != testRef("1.4.0", "a").ManifestSHA256 {
		t.Fatal("active reference replaced by a conflicting manifest")
	}
}

func TestAdmitIntegrityReferenceValidatesRecord(t *testing.T) {
	db := openAtT(t, privateDir(t), t0)
	mut := func(f func(*IntegrityReference)) IntegrityReference {
		r := testRef("1.4.0", "a")
		f(&r)
		return r
	}
	cases := map[string]IntegrityReference{
		"bad version":     mut(func(r *IntegrityReference) { r.ReleaseVersion = "v1.4" }),
		"manifest digest": mut(func(r *IntegrityReference) { r.ManifestSHA256 = strings.Repeat("0", 64) }),
		"list digest":     mut(func(r *IntegrityReference) { r.ListSHA256 = strings.Repeat("0", 64) }),
		"empty manifest":  mut(func(r *IntegrityReference) { r.Manifest = nil; r.ManifestSHA256 = refSum(nil) }),
		"empty signature": mut(func(r *IntegrityReference) { r.Signature = nil }),
		"empty list":      mut(func(r *IntegrityReference) { r.List = nil; r.ListSHA256 = refSum(nil) }),
		"oversize manifest": mut(func(r *IntegrityReference) {
			r.Manifest = make([]byte, release.MaxManifest+1)
			r.ManifestSHA256 = refSum(r.Manifest)
		}),
		"oversize sig": mut(func(r *IntegrityReference) { r.Signature = make([]byte, release.MaxSignature+1) }),
		"oversize list": mut(func(r *IntegrityReference) {
			r.List = make([]byte, release.MaxInstalledFilesDocument+1)
			r.ListSHA256 = refSum(r.List)
		}),
		"signer control": mut(func(r *IntegrityReference) { r.SignedBy = "root\n1" }),
		"signer empty":   mut(func(r *IntegrityReference) { r.SignedBy = "" }),
	}
	for name, r := range cases {
		if _, err := db.AdmitIntegrityReference(r); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
	if n := countRefs(t, db); n != 0 {
		t.Fatalf("rows = %d after invalid records", n)
	}
}

func TestIntegrityReferenceSurvivesReopen(t *testing.T) {
	dir := privateDir(t)
	db := openAtT(t, dir, t0)
	r := testRef("1.4.0", "a")
	if _, err := db.AdmitIntegrityReference(r); err != nil {
		t.Fatal(err)
	}
	db.Close()
	db = openAtT(t, dir, t0.Add(time.Hour))
	got, err := db.ActiveIntegrityReference()
	if err != nil {
		t.Fatal(err)
	}
	if got.ManifestSHA256 != r.ManifestSHA256 || !bytes.Equal(got.List, r.List) {
		t.Fatal("reference lost or changed across reopen")
	}
	// The rollback rule holds across restarts.
	if _, err := db.AdmitIntegrityReference(testRef("1.3.0", "a")); !errors.Is(err, ErrReferenceRollback) {
		t.Fatalf("rollback after reopen: err = %v", err)
	}
}

func TestIntegrityReferenceRowsAreImmutable(t *testing.T) {
	db := openAtT(t, privateDir(t), t0)
	if _, err := db.AdmitIntegrityReference(testRef("1.4.0", "a")); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AdmitIntegrityReference(testRef("1.5.0", "a")); err != nil {
		t.Fatal(err)
	}
	for name, stmt := range map[string]string{
		"delete":          `DELETE FROM integrity_references`,
		"change bytes":    `UPDATE integrity_references SET list = x'00' WHERE active = 1`,
		"change version":  `UPDATE integrity_references SET release_version = '9.9.9' WHERE active = 0`,
		"reactivate":      `UPDATE integrity_references SET active = 1, superseded_at = NULL WHERE active = 0`,
		"second active":   `INSERT INTO integrity_references (release_version, manifest, signature, list, manifest_sha256, list_sha256, signed_by, admitted_at, active) SELECT '2.0.0', manifest, signature, list, manifest_sha256, list_sha256, signed_by, admitted_at, 1 FROM integrity_references WHERE active = 1`,
		"insert inactive": `INSERT INTO integrity_references (release_version, manifest, signature, list, manifest_sha256, list_sha256, signed_by, admitted_at, active) SELECT '2.0.0', manifest, signature, list, 'zz', list_sha256, signed_by, admitted_at, 0 FROM integrity_references WHERE active = 1`,
	} {
		if _, err := db.sql.Exec(stmt); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if n := countRefs(t, db); n != 2 {
		t.Fatalf("rows = %d, want 2", n)
	}
}

func TestCompareReleaseVersion(t *testing.T) {
	ordered := []string{"0.9.0", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
		"1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1", "1.2.0", "1.10.0", "2.0.0"}
	for i := range ordered {
		for j := range ordered {
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if got := compareReleaseVersion(ordered[i], ordered[j]); got != want {
				t.Errorf("compare(%s, %s) = %d, want %d", ordered[i], ordered[j], got, want)
			}
		}
	}
	if compareReleaseVersion("1.0.0+a", "1.0.0+b") != 0 {
		t.Error("build metadata must not affect precedence")
	}
}

func countRefs(t *testing.T, db *DB) int {
	t.Helper()
	var n int
	if err := db.sql.QueryRow(`SELECT count(*) FROM integrity_references`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
