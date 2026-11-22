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

// imgClock is the read time of the test reads; it is in the past for the
// store's skew rule.
var imgClock = time.Unix(1_700_000_000, 0).UTC()

// fakeLastResults serves stored results by action and host.
type fakeLastResults struct {
	results map[string][]byte
}

func (f fakeLastResults) LastResult(_ context.Context, actionID, host string) ([]byte, time.Time, bool, error) {
	raw, ok := f.results[actionID+"/"+host]
	return raw, imgClock, ok, nil
}

// inspectResult is a stored docker.inspect result whose image has the repo
// digest repo@sha256:hex (the frame and inner document of dockerhost.ParseInspect).
func inspectResult(hex string) []byte {
	enc := base64.StdEncoding.EncodeToString
	inner := `{"id":"` + strings.Repeat("a", 64) + `","name":"/web","image":"img","image_id":"sha256:` +
		strings.Repeat("c", 64) + `","created":"2026-01-02T03:04:05Z","state":{"Status":"running","StartedAt":"2026-01-01T00:00:00Z"}}`
	image := `{"id":"sha256:` + strings.Repeat("c", 64) + `","created":"2026-01-01T00:00:00Z",` +
		`"os":"linux","architecture":"amd64","repo_digests":["registry.example/app/web@sha256:` + hex + `"]}`
	return []byte(`{"format":"docker-inspect-v1","phase":"done","container":"c1","inspect":"` +
		enc([]byte(inner)) + `","image":"` + enc([]byte(image)) + `"}`)
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

// imageServer returns the image service on a fresh server.db, with the given
// stored results.
func imageServer(t *testing.T, results map[string][]byte) (*vulnImageService, *vulninventory.Store) {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatalf("open server db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	svc, err := newVulnImageService(db, fakeLastResults{results: results}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	st, err := vulninventory.New(db)
	if err != nil {
		t.Fatal(err)
	}
	return svc, st
}

// TestImageReadStoredWhenInspectNamesDigest checks that a successful
// image.packages result is stored when the host's stored docker.inspect names
// its digest.
func TestImageReadStoredWhenInspectNamesDigest(t *testing.T) {
	svc, st := imageServer(t, map[string][]byte{
		"docker.inspect/host-1": inspectResult(imgHex),
	})
	svc.ObserveImage(context.Background(), "host-1", "exec-1", imgRef, imgClock, imageResult("debian", "12.8", "debian"))
	reads, err := st.ImageReads(context.Background(), "registry.example/app/web")
	if err != nil {
		t.Fatal(err)
	}
	if len(reads) != 1 {
		t.Fatalf("stored %d reads, want 1", len(reads))
	}
	if r := reads[0]; r.Digest != "sha256:"+imgHex || !r.Complete || len(r.Packages) != 1 || r.Packages[0].Source != "glibc" {
		t.Fatalf("stored read %+v, want a complete read with libc6 from glibc", r)
	}
}

// TestImageReadRefusedWithoutInspectNamingDigest checks the source rule: a
// digest the host's stored results do not name is refused and nothing is
// stored, including when the inspect result names another digest, and when
// there is no inspect result at all.
func TestImageReadRefusedWithoutInspectNamingDigest(t *testing.T) {
	cases := map[string]map[string][]byte{
		"no inspect result":          {},
		"inspect names other digest": {"docker.inspect/host-1": inspectResult(strings.Repeat("c", 64))},
		"inspect of another host":    {"docker.inspect/host-2": inspectResult(imgHex)},
	}
	for name, results := range cases {
		t.Run(name, func(t *testing.T) {
			svc, st := imageServer(t, results)
			svc.ObserveImage(context.Background(), "host-1", "exec-1", imgRef, imgClock, imageResult("debian", "12.8", "debian"))
			reads, err := st.ImageReads(context.Background(), "registry.example/app/web")
			if err != nil {
				t.Fatal(err)
			}
			if len(reads) != 0 {
				t.Fatalf("stored %d reads for a digest the host does not name, want 0", len(reads))
			}
		})
	}
}

// TestFourthImageReadPushesOutOldest checks decision E4 through the service:
// after four successful reads of one image, the oldest is gone.
func TestFourthImageReadPushesOutOldest(t *testing.T) {
	svc, st := imageServer(t, map[string][]byte{"docker.inspect/host-1": inspectResult(imgHex)})
	for i := range 4 {
		at := imgClock.Add(time.Duration(i) * time.Minute)
		svc.ObserveImage(context.Background(), "host-1", "exec-"+string(rune('1'+i)), imgRef, at, imageResult("debian", "12.8", "debian"))
	}
	reads, err := st.ImageReads(context.Background(), "registry.example/app/web")
	if err != nil {
		t.Fatal(err)
	}
	if len(reads) != vulninventory.ImageReadsKept {
		t.Fatalf("kept %d reads, want %d", len(reads), vulninventory.ImageReadsKept)
	}
	for _, r := range reads {
		if r.ReadAt.Equal(imgClock) {
			t.Fatal("the oldest read survived a fourth read")
		}
	}
}

// TestUnknownImageReadIsNotStored checks that a result with no package
// listing (Trivy absent) is not stored, so it cannot push out a kept read.
func TestUnknownImageReadIsNotStored(t *testing.T) {
	svc, st := imageServer(t, map[string][]byte{"docker.inspect/host-1": inspectResult(imgHex)})
	absent := []byte(`{"format":"image-packages-v1","phase":"done","image":"` + imgRef + `","status":"absent","present":false}`)
	svc.ObserveImage(context.Background(), "host-1", "exec-1", imgRef, imgClock, absent)
	reads, err := st.ImageReads(context.Background(), "registry.example/app/web")
	if err != nil {
		t.Fatal(err)
	}
	if len(reads) != 0 {
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
