// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulninventory"
)

// imgHex is a platform digest used by the image tests.
var imgHex = strings.Repeat("b", 64)

// imgRef is the digest-pinned reference image.packages runs for.
var imgRef = "registry.example/app/web@sha256:" + imgHex

// imgDigest is imgHex as the digest the stores key on.
var imgDigest = "sha256:" + imgHex

// imgClock is the read time of the test reads and the clock of the service;
// it is in the past for the store's skew rule.
var imgClock = time.Unix(1_700_000_000, 0).UTC()

// fakeInspects serves stored docker.inspect results by host, applying the
// since bound as the database does.
type fakeInspects struct {
	rows map[string][]imageInspectRow
}

func (f fakeInspects) InspectResults(_ context.Context, host string, since time.Time, _ int) ([]imageInspectRow, error) {
	var out []imageInspectRow
	for _, r := range f.rows[host] {
		if !r.FinishedAt.Before(since) {
			out = append(out, r)
		}
	}
	return out, nil
}

// inspected is a stored docker.inspect result finished at imgClock.
func inspected(result []byte) imageInspectRow {
	return imageInspectRow{Result: result, FinishedAt: imgClock}
}

// inspectDoc is a stored docker.inspect result of a container whose image has
// the repository digests repoDigests and, when platform is set, the platform
// digest platform (the frame and inner document of dockerhost.ParseInspect).
func inspectDoc(repoDigests []string, platform string) []byte {
	enc := base64.StdEncoding.EncodeToString
	inner := `{"id":"` + strings.Repeat("a", 64) + `","name":"/web","image":"img","image_id":"sha256:` +
		strings.Repeat("c", 64) + `","created":"2026-01-02T03:04:05Z","state":{"Status":"running","StartedAt":"2026-01-01T00:00:00Z"}}`
	descriptor := ""
	if platform != "" {
		descriptor = `,"descriptor":{"digest":"sha256:` + platform + `","mediaType":"application/vnd.oci.image.manifest.v1+json"}`
	}
	quoted := make([]string, 0, len(repoDigests))
	for _, d := range repoDigests {
		quoted = append(quoted, `"`+d+`"`)
	}
	image := `{"id":"sha256:` + strings.Repeat("c", 64) + `","created":"2026-01-01T00:00:00Z",` +
		`"os":"linux","architecture":"amd64","repo_digests":[` + strings.Join(quoted, ",") + `]` + descriptor + `}`
	return []byte(`{"format":"docker-inspect-v1","phase":"done","container":"c1","inspect":"` +
		enc([]byte(inner)) + `","image":"` + enc([]byte(image)) + `"}`)
}

// inspectResult is a stored docker.inspect result whose image has the repo
// digest registry.example/app/web@sha256:hex.
func inspectResult(hex string) []byte {
	return inspectDoc([]string{"registry.example/app/web@sha256:" + hex}, "")
}

// imageResult is a successful image.packages result for imgRef with one
// Debian package list (libc6 from glibc) and the given OS family and release.
func imageResult(family, release, pkgEcosystem string) []byte {
	report := `{"SchemaVersion":2,"ArtifactName":"registry.example/app/web@sha256:` + imgHex + `",` +
		`"Metadata":{"OS":{"Family":"` + family + `","Name":"` + release + `"},` +
		`"RepoDigests":["registry.example/app/web@sha256:` + imgHex + `"]},` +
		`"Results":[{"Class":"os-pkgs","Type":"` + pkgEcosystem + `","Packages":[` +
		`{"Name":"libc6","Version":"2.36","Release":"9","SrcName":"glibc","SrcVersion":"2.36","SrcRelease":"9"}]}]}`
	return []byte(`{"format":"image-packages-v1","phase":"done","image":"` + imgRef +
		`","status":"ok","present":true,"rc":0,"output":"ok","report":` + report + `}`)
}

// resultFor is imageResult for the reference ref (the same package list, its
// image field and report naming ref).
func resultFor(ref string) []byte {
	return []byte(strings.ReplaceAll(string(imageResult("debian", "12.8", "debian")), imgRef, ref))
}

// imageServer returns the image service on a fresh server.db, with the given
// stored inspect results, and its store.
func imageServer(t *testing.T, rows map[string][]imageInspectRow) (*vulnImageService, *vulninventory.Store) {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatalf("open server db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	svc, err := newVulnImageService(db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	svc.inspects = fakeInspects{rows: rows}
	svc.now = func() time.Time { return imgClock }
	st, err := vulninventory.New(db)
	if err != nil {
		t.Fatal(err)
	}
	return svc, st
}

// storedReads returns the kept reads of host for the test image.
func storedReads(t *testing.T, st *vulninventory.Store, host string) []vulninventory.ImageRead {
	t.Helper()
	reads, err := st.ImageReads(context.Background(), host, imgDigest)
	if err != nil {
		t.Fatal(err)
	}
	return reads
}

// TestImageReadStoredWhenInspectNamesDigest checks that a successful
// image.packages result is stored when the host's stored docker.inspect names
// its repository and digest.
func TestImageReadStoredWhenInspectNamesDigest(t *testing.T) {
	svc, st := imageServer(t, map[string][]imageInspectRow{"host-1": {inspected(inspectResult(imgHex))}})
	svc.ObserveImage(context.Background(), "host-1", "exec-1", imgRef, imgRef, imgClock, imageResult("debian", "12.8", "debian"))
	reads := storedReads(t, st, "host-1")
	if len(reads) != 1 {
		t.Fatalf("stored %d reads, want 1", len(reads))
	}
	if r := reads[0]; r.Digest != imgDigest || r.Repository != "registry.example/app/web" || !r.Complete ||
		len(r.Packages) != 1 || r.Packages[0].Source != "glibc" {
		t.Fatalf("stored read %+v, want a complete read with libc6 from glibc", r)
	}
}

// TestImageReadStoredOnPlatformDigestMatch checks the platform digest path:
// the inspect result names the image's platform digest, and the read's
// repository is one of the image's repository digests.
func TestImageReadStoredOnPlatformDigestMatch(t *testing.T) {
	index := strings.Repeat("c", 64)
	svc, st := imageServer(t, map[string][]imageInspectRow{
		"host-1": {inspected(inspectDoc([]string{"registry.example/app/web@sha256:" + index}, imgHex))},
	})
	svc.ObserveImage(context.Background(), "host-1", "exec-1", imgRef, imgRef, imgClock, imageResult("debian", "12.8", "debian"))
	if reads := storedReads(t, st, "host-1"); len(reads) != 1 {
		t.Fatalf("stored %d reads on the platform digest match, want 1", len(reads))
	}
}

// TestImageReadRefusedForDifferentRepository checks that the repository of
// the read must be one the inspect result names for the digest: a read of
// another name at the same digest is refused, on both the repository digest
// path and the platform digest path.
func TestImageReadRefusedForDifferentRepository(t *testing.T) {
	index := strings.Repeat("c", 64)
	cases := map[string][]imageInspectRow{
		"repository digest names another repo": {inspected(inspectResult(imgHex))},
		"platform digest, repo not in repo digests": {inspected(inspectDoc(
			[]string{"registry.example/app/web@sha256:" + index}, imgHex))},
	}
	other := "other.example/web@sha256:" + imgHex
	for name, rows := range cases {
		t.Run(name, func(t *testing.T) {
			svc, st := imageServer(t, map[string][]imageInspectRow{"host-1": rows})
			svc.ObserveImage(context.Background(), "host-1", "exec-1", other, other, imgClock, resultFor(other))
			if reads, err := st.ImageReads(context.Background(), "host-1", imgDigest); err != nil || len(reads) != 0 {
				t.Fatalf("stored %d reads (err %v) of a repository the inspect does not name, want 0", len(reads), err)
			}
		})
	}
}

// TestImageReadRefusedWithoutInspectNamingDigest checks the source rule: a
// digest the host's stored results do not name is refused and nothing is
// stored, including when the inspect result names another digest, and when
// there is no inspect result at all.
func TestImageReadRefusedWithoutInspectNamingDigest(t *testing.T) {
	cases := map[string]map[string][]imageInspectRow{
		"no inspect result":          {},
		"inspect names other digest": {"host-1": {inspected(inspectResult(strings.Repeat("c", 64)))}},
		"inspect of another host":    {"host-2": {inspected(inspectResult(imgHex))}},
	}
	for name, rows := range cases {
		t.Run(name, func(t *testing.T) {
			svc, st := imageServer(t, rows)
			svc.ObserveImage(context.Background(), "host-1", "exec-1", imgRef, imgRef, imgClock, imageResult("debian", "12.8", "debian"))
			if reads := storedReads(t, st, "host-1"); len(reads) != 0 {
				t.Fatalf("stored %d reads for a digest the host does not name, want 0", len(reads))
			}
		})
	}
}

// TestImageReadUsesEveryContainerOfHost checks that the digest source covers
// all containers of the host: a digest named by an older inspect of another
// container is accepted, while a newer inspect of a different container does
// not hide it.
func TestImageReadUsesEveryContainerOfHost(t *testing.T) {
	newer := imageResult("debian", "12.8", "debian")
	svc, st := imageServer(t, map[string][]imageInspectRow{"host-1": {
		{Result: inspectResult(strings.Repeat("c", 64)), FinishedAt: imgClock},
		{Result: inspectResult(imgHex), FinishedAt: imgClock.Add(-time.Hour)},
	}})
	svc.ObserveImage(context.Background(), "host-1", "exec-1", imgRef, imgRef, imgClock, newer)
	if reads := storedReads(t, st, "host-1"); len(reads) != 1 {
		t.Fatalf("stored %d reads, want 1: the digest of the older container inspect", len(reads))
	}
}

// TestImageReadRefusedForStaleInspect checks the age rule: an inspect result
// older than ImageInspectMaxAge does not name its image, and one just inside
// the bound does.
func TestImageReadRefusedForStaleInspect(t *testing.T) {
	cases := []struct {
		name     string
		finished time.Time
		stored   bool
	}{
		{"inspect older than the bound", imgClock.Add(-ImageInspectMaxAge - time.Minute), false},
		{"inspect just inside the bound", imgClock.Add(-ImageInspectMaxAge + time.Minute), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, st := imageServer(t, map[string][]imageInspectRow{"host-1": {
				{Result: inspectResult(imgHex), FinishedAt: tc.finished},
			}})
			svc.ObserveImage(context.Background(), "host-1", "exec-1", imgRef, imgRef, imgClock, imageResult("debian", "12.8", "debian"))
			if got := len(storedReads(t, st, "host-1")) == 1; got != tc.stored {
				t.Fatalf("stored = %v, want %v", got, tc.stored)
			}
		})
	}
}

// TestImageReadRefusedWhenNotGranted checks that the read must be the one the
// read grant pinned: an image reference other than the granted one is refused
// even when the host's inspect names it.
func TestImageReadRefusedWhenNotGranted(t *testing.T) {
	svc, st := imageServer(t, map[string][]imageInspectRow{"host-1": {inspected(inspectResult(imgHex))}})
	granted := "registry.example/app/web@sha256:" + strings.Repeat("d", 64)
	svc.ObserveImage(context.Background(), "host-1", "exec-1", granted, imgRef, imgClock, imageResult("debian", "12.8", "debian"))
	if reads := storedReads(t, st, "host-1"); len(reads) != 0 {
		t.Fatalf("stored %d reads of a reference the grant did not pin, want 0", len(reads))
	}
}

// TestFourthImageReadPushesOutOldest checks decision E4 through the service:
// after four successful reads of one image on one host, the oldest is gone.
func TestFourthImageReadPushesOutOldest(t *testing.T) {
	svc, st := imageServer(t, map[string][]imageInspectRow{"host-1": {inspected(inspectResult(imgHex))}})
	for i := range 4 {
		at := imgClock.Add(time.Duration(i) * time.Minute)
		svc.ObserveImage(context.Background(), "host-1", "exec-"+string(rune('1'+i)), imgRef, imgRef, at, imageResult("debian", "12.8", "debian"))
	}
	reads := storedReads(t, st, "host-1")
	if len(reads) != vulninventory.ImageReadsKept {
		t.Fatalf("kept %d reads, want %d", len(reads), vulninventory.ImageReadsKept)
	}
	for _, r := range reads {
		if r.ReadAt.Equal(imgClock) {
			t.Fatal("the oldest read survived a fourth read")
		}
	}
}

// TestImageReadsOfOneImageUnderSeveralNamesKeepThree checks that one image
// reached under several repository names shares one budget of three reads per
// host.
func TestImageReadsOfOneImageUnderSeveralNamesKeepThree(t *testing.T) {
	svc, st := imageServer(t, map[string][]imageInspectRow{"host-1": {inspected(inspectDoc([]string{
		"registry.example/app/web@sha256:" + imgHex,
		"web@sha256:" + imgHex,
		"web:1@sha256:" + imgHex,
	}, ""))}})
	names := []string{"registry.example/app/web", "web", "web:1", "registry.example/app/web"}
	for i, name := range names {
		ref := name + "@sha256:" + imgHex
		at := imgClock.Add(time.Duration(i) * time.Minute)
		svc.ObserveImage(context.Background(), "host-1", "exec-"+string(rune('1'+i)), ref, ref, at, resultFor(ref))
	}
	if reads := storedReads(t, st, "host-1"); len(reads) != vulninventory.ImageReadsKept {
		t.Fatalf("kept %d reads of one image under several names, want %d", len(reads), vulninventory.ImageReadsKept)
	}
}

// TestImageRetentionIsPerHost checks that the reads of one host do not push
// out the reads of another host of the same image. host-2's reads are the
// oldest, so a budget shared by hosts would drop them all.
func TestImageRetentionIsPerHost(t *testing.T) {
	svc, st := imageServer(t, map[string][]imageInspectRow{
		"host-1": {inspected(inspectResult(imgHex))},
		"host-2": {inspected(inspectResult(imgHex))},
	})
	for i := range 3 {
		at := imgClock.Add(time.Duration(i-10) * time.Minute)
		svc.ObserveImage(context.Background(), "host-2", "exec-h2-"+string(rune('1'+i)), imgRef, imgRef, at, imageResult("debian", "12.8", "debian"))
	}
	for i := range 4 {
		at := imgClock.Add(time.Duration(i) * time.Minute)
		svc.ObserveImage(context.Background(), "host-1", "exec-h1-"+string(rune('1'+i)), imgRef, imgRef, at, imageResult("debian", "12.8", "debian"))
	}
	for _, host := range []string{"host-1", "host-2"} {
		if reads := storedReads(t, st, host); len(reads) != vulninventory.ImageReadsKept {
			t.Fatalf("%s kept %d reads, want %d", host, len(reads), vulninventory.ImageReadsKept)
		}
	}
}

// TestUnknownImageReadIsNotStored checks that a result with no package
// listing (Trivy absent) is not stored, so it cannot push out a kept read.
func TestUnknownImageReadIsNotStored(t *testing.T) {
	svc, st := imageServer(t, map[string][]imageInspectRow{"host-1": {inspected(inspectResult(imgHex))}})
	absent := []byte(`{"format":"image-packages-v1","phase":"done","image":"` + imgRef + `","status":"absent","present":false}`)
	svc.ObserveImage(context.Background(), "host-1", "exec-1", imgRef, imgRef, imgClock, absent)
	if reads := storedReads(t, st, "host-1"); len(reads) != 0 {
		t.Fatalf("stored %d reads of an unknown result, want 0", len(reads))
	}
}

// TestSplitImageRef checks that only a repository@sha256 reference is split.
func TestSplitImageRef(t *testing.T) {
	cases := []struct {
		ref, repo, digest string
		ok                bool
	}{
		{"registry.example/app/web@sha256:" + imgHex, "registry.example/app/web", "sha256:" + imgHex, true},
		{"web:latest", "", "", false},
		{"@sha256:" + imgHex, "", "", false},
		{"web@sha256:ABC", "", "", false},
		{"web@sha512:" + imgHex, "", "", false},
	}
	for _, c := range cases {
		repo, digest, ok := splitImageRef(c.ref)
		if repo != c.repo || digest != c.digest || ok != c.ok {
			t.Errorf("splitImageRef(%q) = %q, %q, %v; want %q, %q, %v", c.ref, repo, digest, ok, c.repo, c.digest, c.ok)
		}
	}
}

// TestImageSubjectsExportNewestReadPerDigest checks that the export carries
// one image subject per host and digest, from the newest read, with the
// digest as the image reference and only the OS packages as components.
func TestImageSubjectsExportNewestReadPerDigest(t *testing.T) {
	older := vulninventory.ImageRead{ID: 1, Repository: "r", Digest: "sha256:" + imgHex, HostID: "host-1",
		ReadAt: imgClock, Complete: false, OSFamily: "ubuntu", OSName: "24.04",
		Packages: []vulninventory.ImagePackage{{Ecosystem: "ubuntu", Name: "bash", Version: "5.2"}}}
	newer := older
	newer.ID, newer.ReadAt, newer.Complete = 2, imgClock.Add(time.Hour), true
	newer.Packages = []vulninventory.ImagePackage{
		{Ecosystem: "ubuntu", Name: "zlib1g", Version: "1:1.2.13", Source: "zlib", SourceVersion: "1:1.2.13"},
		{Ecosystem: "ubuntu", Name: "bash", Version: "5.2"},
		{Ecosystem: "gobinary", Name: "golang.org/x/net", Version: "v0.33.0"},
	}
	subs := imageSubjects([]vulninventory.ImageRead{older, newer})
	if len(subs) != 1 {
		t.Fatalf("exported %d subjects, want 1", len(subs))
	}
	s := subs[0]
	if s.Kind != vulnfinding.SubjectImage || s.Ref.ID != "host-1" || s.Ref.ImageDigest != "sha256:"+imgHex {
		t.Fatalf("subject %+v, want an image subject of host-1 at the digest", s)
	}
	if s.Ecosystem != "ubuntu:24.04" || !s.Complete {
		t.Fatalf("ecosystem %q complete %v, want ubuntu:24.04 complete", s.Ecosystem, s.Complete)
	}
	if len(s.Components) != 2 || s.Components[0].Source != "bash" || s.Components[1].Source != "zlib" {
		t.Fatalf("components %+v, want bash and zlib, without the gobinary package", s.Components)
	}
}

// TestImageSubjectsSkipUnnamedEcosystem checks that an image whose OS release
// cannot be named the way the export names ecosystems is not exported (a
// Debian release is reported by version, not codename).
func TestImageSubjectsSkipUnnamedEcosystem(t *testing.T) {
	debian := vulninventory.ImageRead{ID: 1, Digest: "sha256:" + imgHex, HostID: "host-1", ReadAt: imgClock,
		Complete: true, OSFamily: "debian", OSName: "12.8",
		Packages: []vulninventory.ImagePackage{{Ecosystem: "debian", Name: "bash", Version: "5.2"}}}
	if subs := imageSubjects([]vulninventory.ImageRead{debian}); len(subs) != 0 {
		t.Fatalf("exported %d subjects for an unnamed ecosystem, want 0", len(subs))
	}
}
