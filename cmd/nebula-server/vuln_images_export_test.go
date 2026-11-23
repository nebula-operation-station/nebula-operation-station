// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulninventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
)

// exportImageRepo is the repository of the export test image. The export must
// never carry it.
const exportImageRepo = "registry.example/app/web"

// putExportImage stores an image read of host (execution n) of the test image
// digest, with the OS family and release osFamily and osName and the packages.
func putExportImage(t *testing.T, e *srcEnv, host string, n int, digest string, osFamily, osName string, pkgs []vulninventory.ImagePackage) {
	t.Helper()
	st, err := vulninventory.NewWithNow(e.db, e.clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	storeRun(t, e.db, n, imageActionID, `{"image":"`+exportImageRepo+`@`+digest+`"}`, host, "finished", "success", e.clk.Now().Add(-time.Minute), []byte("{}"))
	r := vulninventory.ImageRead{Repository: exportImageRepo, Digest: digest, HostID: host, ExecutionID: execN(n),
		ReadAt: e.clk.Now().Add(-time.Minute), Complete: true, OSFamily: osFamily, OSName: osName, Packages: pkgs}
	if _, err := st.PutImage(context.Background(), r); err != nil {
		t.Fatalf("put image read %d: %v", n, err)
	}
}

// debianImagePackages is a Debian image's package list: one OS package and
// one Python package, which the export must not carry.
func debianImagePackages() []vulninventory.ImagePackage {
	return []vulninventory.ImagePackage{
		{Ecosystem: "debian", Name: "libc6", Version: "2.36-9", Source: "glibc", SourceVersion: "2.36-9"},
		{Ecosystem: "pypi", Name: "requests", Version: "2.31.0"},
	}
}

// TestSnapshotExportsHostAndImageSubjects checks that the export carries the
// host subject of a host and then the image subject of its image read, in that
// order, and that the image subject names the digest and the host only.
func TestSnapshotExportsHostAndImageSubjects(t *testing.T) {
	e := newSrcEnv(t)
	e.addHost(t, srcHost)
	e.addRead(t, srcRead(srcHost, "exec-1", e.clk.Now().Add(-time.Minute), true, "openssl"))
	putExportImage(t, e, srcHost, 2, imgDigest, "debian", "12.5", debianImagePackages())

	snap, err := e.inv.VulnSnapshot(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Subjects) != 2 {
		t.Fatalf("exported %d subjects, want 2 (host, image)", len(snap.Subjects))
	}
	h, img := snap.Subjects[0], snap.Subjects[1]
	if h.Kind != vulnfinding.SubjectHost || h.Ref.ID != srcHost {
		t.Fatalf("first subject %+v, want the host subject of %s", h.Ref, srcHost)
	}
	if img.Kind != vulnfinding.SubjectImage || img.Ref.ID != srcHost || img.Ref.ImageDigest != imgDigest {
		t.Fatalf("second subject ref %+v, want the image subject of %s at the digest", img.Ref, srcHost)
	}
	if img.Ecosystem != "debian:bookworm" || !img.Complete {
		t.Fatalf("image ecosystem %q complete %v, want debian:bookworm complete", img.Ecosystem, img.Complete)
	}
	if len(img.Components) != 1 || img.Components[0].Source != "glibc" {
		t.Fatalf("image components %+v, want the one OS source glibc", img.Components)
	}
}

// TestImageEcosystemNamesOSReleases checks the ecosystem an image read is
// exported under: Debian by its major version (a codename from the fixed
// table), Alpine by major.minor, Ubuntu as before. Anything else is refused.
func TestImageEcosystemNamesOSReleases(t *testing.T) {
	tests := []struct {
		name, family, release, want string
	}{
		{"debian 12.5 is bookworm", "debian", "12.5", "debian:bookworm"},
		{"debian 12 is bookworm", "debian", "12", "debian:bookworm"},
		{"debian 11.9 is bullseye", "debian", "11.9", "debian:bullseye"},
		{"debian 13.1 is trixie", "debian", "13.1", "debian:trixie"},
		{"alpine 3.19.1 is alpine:3.19", "alpine", "3.19.1", "alpine:3.19"},
		{"alpine 3.19 is alpine:3.19", "alpine", "3.19", "alpine:3.19"},
		{"ubuntu 24.04 as before", "ubuntu", "24.04", "ubuntu:24.04"},
		{"debian 99 has no codename", "debian", "99.1", ""},
		{"debian 10 has no codename here", "debian", "10.2", ""},
		{"alpine edge is not a release", "alpine", "edge", ""},
		{"alpine without minor", "alpine", "3", ""},
		{"unknown family", "rhel", "9.3", ""},
		{"empty release", "debian", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := imageEcosystem(tt.family, tt.release)
			if tt.want == "" {
				if err == nil || got != "" {
					t.Fatalf("imageEcosystem(%q, %q) = %q, %v; want errNoImageEcosystem", tt.family, tt.release, got, err)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("imageEcosystem(%q, %q) = %q, %v; want %q", tt.family, tt.release, got, err, tt.want)
			}
		})
	}
}

// TestImageSubjectsSkipUnnamedReleases checks that an image whose release has
// no ecosystem is not exported as a subject, while the host subject is.
func TestImageSubjectsSkipUnnamedReleases(t *testing.T) {
	e := newSrcEnv(t)
	e.addHost(t, srcHost)
	e.addRead(t, srcRead(srcHost, "exec-1", e.clk.Now().Add(-time.Minute), true, "openssl"))
	putExportImage(t, e, srcHost, 2, imgDigest, "debian", "99", debianImagePackages())

	snap, err := e.inv.VulnSnapshot(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Subjects) != 1 || snap.Subjects[0].Kind != vulnfinding.SubjectHost {
		t.Fatalf("subjects %+v, want only the host subject", snap.Subjects)
	}
}

// TestImageSubjectAlpineComponentsAreOSPackages checks that an Alpine image
// exports its apk packages as components and no language packages.
func TestImageSubjectAlpineComponentsAreOSPackages(t *testing.T) {
	e := newSrcEnv(t)
	e.addHost(t, srcHost)
	pkgs := []vulninventory.ImagePackage{
		{Ecosystem: "alpine", Name: "musl", Version: "1.2.4-r2", Source: "musl", SourceVersion: "1.2.4-r2"},
		{Ecosystem: "gobinary", Name: "xnet", Version: "v0.33.0"},
	}
	putExportImage(t, e, srcHost, 2, imgDigest, "alpine", "3.19.1", pkgs)

	snap, err := e.inv.VulnSnapshot(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Subjects) != 1 {
		t.Fatalf("subjects %+v, want the image subject only", snap.Subjects)
	}
	img := snap.Subjects[0]
	if img.Ecosystem != "alpine:3.19" || len(img.Components) != 1 || img.Components[0].Source != "musl" {
		t.Fatalf("image subject %+v, want alpine:3.19 with the musl component only", img)
	}
}

// TestImageExportCarriesNoRepository checks that the exported JSON of a
// snapshot with an image subject does not name the image repository.
func TestImageExportCarriesNoRepository(t *testing.T) {
	e := newSrcEnv(t)
	e.addHost(t, srcHost)
	putExportImage(t, e, srcHost, 2, imgDigest, "debian", "12.5", debianImagePackages())

	snap, err := e.inv.VulnSnapshot(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Subjects) != 1 {
		t.Fatalf("subjects %+v, want the image subject", snap.Subjects)
	}
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{exportImageRepo, "app/web", "registry.example"} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("exported JSON contains %q", leak)
		}
	}
}

// TestImageOfUnlistedHostIsNotExported checks that an image read of a host
// that is not in the inventory does not appear in the export.
func TestImageOfUnlistedHostIsNotExported(t *testing.T) {
	e := newSrcEnv(t)
	e.addHost(t, srcHost)
	putExportImage(t, e, "ghost", 2, imgDigest, "debian", "12.5", debianImagePackages())

	snap, err := e.inv.VulnSnapshot(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range snap.Subjects {
		if s.Kind == vulnfinding.SubjectImage {
			t.Fatalf("exported image subject %+v of a host outside the inventory", s.Ref)
		}
	}
}

// TestSnapshotIDKeepsImagesAfterNewRead checks that a snapshot ID serves the
// same content after a newer image read: the snapshot pins the images it was
// built with. The check decodes the ID with a fresh export, so no cached copy
// answers it.
func TestSnapshotIDKeepsImagesAfterNewRead(t *testing.T) {
	e := newSrcEnv(t)
	e.addHost(t, srcHost)
	putExportImage(t, e, srcHost, 2, imgDigest, "debian", "12.5", debianImagePackages())

	ctx := context.Background()
	first, err := e.inv.VulnSnapshot(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	// A newer read of the same image with another package.
	newer := []vulninventory.ImagePackage{
		{Ecosystem: "debian", Name: "openssl", Version: "3.0.15-1", Source: "openssl", SourceVersion: "3.0.15-1"},
	}
	putExportImage(t, e, srcHost, 3, imgDigest, "debian", "12.5", newer)
	if _, err := e.inv.VulnSnapshot(ctx, ""); err != nil {
		t.Fatal(err)
	}

	st, err := vulninventory.NewWithNow(e.db, e.clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	fresh := newVulnInventoryOn(st, e.db, e.hosts, e.clk.Now)
	again, err := fresh.VulnSnapshot(ctx, first.ID)
	if err != nil {
		t.Fatalf("snapshot %s: %v", first.ID, err)
	}
	if !reflect.DeepEqual(first.Subjects, again.Subjects) {
		t.Fatalf("snapshot %s changed after a new image read:\nfirst %+v\nagain %+v", first.ID, first.Subjects, again.Subjects)
	}
}

// TestImageSubjectClassifiesUnconfirmed checks that a finding on an image
// subject is never closed by inventory: Classify returns ClassUnconfirmed,
// without an error, for the image subject of a Debian package finding.
func TestImageSubjectClassifiesUnconfirmed(t *testing.T) {
	e := clsEnv(t)
	image := vulnstore.Subject{Kind: vulnfinding.SubjectImage, ID: clsHost, ImageDigest: imgDigest}
	comp := vulnfinding.Component{SourcePackage: "openssl", SourceVersion: clsOld}
	f := vulnstore.Finding{Subject: image, EpisodeFixedVersion: clsNew,
		Record: vulnfinding.Record{MatchBasis: vulnfinding.MatchDistroTracker, Ecosystem: "debian:bookworm", Component: comp}}
	c, err := e.svc.classifier.Classify(context.Background(), f)
	if err != nil || c != vulnstore.ClassUnconfirmed {
		t.Fatalf("Classify(image subject) = %d, %v; want ClassUnconfirmed without error", c, err)
	}
}

// TestSnapshotLogsOmittedImageCount checks that a snapshot which leaves image
// reads out logs how many, as a number and without any image name.
func TestSnapshotLogsOmittedImageCount(t *testing.T) {
	e := newSrcEnv(t)
	e.addHost(t, srcHost)
	st, err := vulninventory.NewWithNow(e.db, e.clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	// One read through the store, then copies of its row under other digests
	// and executions: one transaction instead of one per read. One digest more
	// than the cap is stored, so the last one is left out.
	seed := vulninventory.ImageRead{Repository: exportImageRepo, Digest: imgDigest, HostID: srcHost, ExecutionID: execN(1000),
		ReadAt: e.clk.Now().Add(-time.Minute), Complete: true, OSFamily: "debian", OSName: "12.5"}
	if _, err := st.PutImage(context.Background(), seed); err != nil {
		t.Fatalf("put seed image: %v", err)
	}
	tx, err := e.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := range vulninventory.MaxSnapshotImages {
		if _, err := tx.Exec(`INSERT INTO vuln_image_reads (repository, digest, host_id, execution_id, read_at,
			complete, reason, os_family, os_name, packages, body)
			SELECT repository, ?, host_id, ?, read_at, complete, reason, os_family, os_name, packages, body
			FROM vuln_image_reads WHERE host_id = ? AND digest = ?`,
			fmt.Sprintf("sha256:%064x", i+1), execN(1001+i), srcHost, imgDigest); err != nil {
			_ = tx.Rollback()
			t.Fatalf("copy image read %d: %v", i, err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	if _, err := e.inv.VulnSnapshot(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "omitted_images=1") {
		t.Fatalf("log %q does not count the omitted image", out)
	}
	if strings.Contains(out, exportImageRepo) || strings.Contains(out, "sha256:") {
		t.Fatalf("log %q names an image", out)
	}
}
