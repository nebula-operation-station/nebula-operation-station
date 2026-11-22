// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
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

// imgClock is the finish time of the test runs and the clock of the service;
// it is in the past for the store's skew rule.
var imgClock = time.Unix(1_700_000_000, 0).UTC()

// execN is the execution ID of test run n: 36 characters, as the executions
// table requires.
func execN(n int) string { return fmt.Sprintf("%036d", n) }

// execer is the part of *sql.DB and *sql.Tx the test helpers write with.
type execer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

// storeRun stores one execution n of action, with the parameters params (a
// JSON object), and one host row of host in state and class, finished at at
// with result. It writes the rows through server.db's own schema.
func storeRun(t *testing.T, db execer, n int, action, params, host, state, class string, at time.Time, result []byte) {
	t.Helper()
	id := execN(n)
	if _, err := db.Exec(`INSERT INTO executions (id, digest, action_id, module_version, artifact_sha256, risk,
		requirement, state, durable, timeout_s, created_by, created_at, finished_at, params)
		VALUES (?, '', ?, '1.0.0', ?, 'LOW', 'test', 'finished', 0, 60, 'test', ?, ?, ?)`,
		id, action, strings.Repeat("0", 64), at.Unix(), at.Unix(), params); err != nil {
		t.Fatalf("store execution %d: %v", n, err)
	}
	if _, err := db.Exec(`INSERT INTO execution_hosts (execution_id, host_id, fingerprint, credential_ref, endpoints,
		state, class, result, started_at, finished_at) VALUES (?, ?, 'fp', 'cred', '[]', ?, ?, ?, ?, ?)`,
		id, host, state, class, result, at.Unix()-1, at.Unix()); err != nil {
		t.Fatalf("store host row of execution %d: %v", n, err)
	}
}

// inspectRun stores a successful docker.inspect run n on host, finished at at.
func inspectRun(t *testing.T, db execer, n int, host string, at time.Time, result []byte) {
	t.Helper()
	storeRun(t, db, n, inspectActionID, "{}", host, "finished", "success", at, result)
}

// grantRun stores a successful image.packages run n on host whose grant pins
// ref, finished at at.
func grantRun(t *testing.T, db *sql.DB, n int, host, ref string, at time.Time, result []byte) {
	t.Helper()
	storeRun(t, db, n, imageActionID, `{"image":"`+ref+`"}`, host, "finished", "success", at, result)
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

// imageServer returns the image service on a fresh server.db, its store and
// the db. Runs are stored with storeRun; the service's clock is imgClock.
func imageServer(t *testing.T) (*vulnImageService, *vulninventory.Store, *sql.DB) {
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
	svc.now = func() time.Time { return imgClock }
	st, err := vulninventory.New(db)
	if err != nil {
		t.Fatal(err)
	}
	return svc, st, db
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
// its repository and digest, and that the read carries the run's finish time.
func TestImageReadStoredWhenInspectNamesDigest(t *testing.T) {
	svc, st, db := imageServer(t)
	inspectRun(t, db, 1, "host-1", imgClock, inspectResult(imgHex))
	grantRun(t, db, 2, "host-1", imgRef, imgClock, nil)
	svc.ObserveImage(context.Background(), "host-1", execN(2), imageResult("debian", "12.8", "debian"))
	reads := storedReads(t, st, "host-1")
	if len(reads) != 1 {
		t.Fatalf("stored %d reads, want 1", len(reads))
	}
	if r := reads[0]; r.Digest != imgDigest || r.Repository != "registry.example/app/web" || !r.Complete ||
		len(r.Packages) != 1 || r.Packages[0].Source != "glibc" || !r.ReadAt.Equal(imgClock) || r.ExecutionID != execN(2) {
		t.Fatalf("stored read %+v, want a complete read of run 2 at its finish time with libc6 from glibc", r)
	}
}

// TestImageReadStoredOnPlatformDigestMatch checks the platform digest path:
// the inspect result names the image's platform digest, and the read's
// repository is one of the image's repository digests.
func TestImageReadStoredOnPlatformDigestMatch(t *testing.T) {
	svc, st, db := imageServer(t)
	index := strings.Repeat("c", 64)
	inspectRun(t, db, 1, "host-1", imgClock,
		inspectDoc([]string{"registry.example/app/web@sha256:" + index}, imgHex))
	grantRun(t, db, 2, "host-1", imgRef, imgClock, nil)
	svc.ObserveImage(context.Background(), "host-1", execN(2), imageResult("debian", "12.8", "debian"))
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
	cases := map[string][]byte{
		"repository digest names another repo": inspectResult(imgHex),
		"platform digest, repo not in repo digests": inspectDoc(
			[]string{"registry.example/app/web@sha256:" + index}, imgHex),
	}
	other := "other.example/web@sha256:" + imgHex
	for name, inspect := range cases {
		t.Run(name, func(t *testing.T) {
			svc, st, db := imageServer(t)
			inspectRun(t, db, 1, "host-1", imgClock, inspect)
			grantRun(t, db, 2, "host-1", other, imgClock, nil)
			svc.ObserveImage(context.Background(), "host-1", execN(2), resultFor(other))
			if reads := storedReads(t, st, "host-1"); len(reads) != 0 {
				t.Fatalf("stored %d reads of a repository the inspect does not name, want 0", len(reads))
			}
		})
	}
}

// TestImageReadRefusedWithoutInspectNamingDigest checks the source rule: a
// digest the host's stored results do not name is refused and nothing is
// stored, including when the inspect result names another digest, when the
// inspect is of another host, and when there is no inspect result at all.
func TestImageReadRefusedWithoutInspectNamingDigest(t *testing.T) {
	cases := map[string]func(*testing.T, *sql.DB){
		"no inspect result": func(*testing.T, *sql.DB) {},
		"inspect names other digest": func(t *testing.T, db *sql.DB) {
			inspectRun(t, db, 1, "host-1", imgClock, inspectResult(strings.Repeat("c", 64)))
		},
		"inspect of another host": func(t *testing.T, db *sql.DB) {
			inspectRun(t, db, 1, "host-2", imgClock, inspectResult(imgHex))
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			svc, st, db := imageServer(t)
			setup(t, db)
			grantRun(t, db, 2, "host-1", imgRef, imgClock, nil)
			svc.ObserveImage(context.Background(), "host-1", execN(2), imageResult("debian", "12.8", "debian"))
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
	svc, st, db := imageServer(t)
	inspectRun(t, db, 1, "host-1", imgClock, inspectResult(strings.Repeat("c", 64)))
	inspectRun(t, db, 2, "host-1", imgClock.Add(-time.Hour), inspectResult(imgHex))
	grantRun(t, db, 3, "host-1", imgRef, imgClock, nil)
	svc.ObserveImage(context.Background(), "host-1", execN(3), imageResult("debian", "12.8", "debian"))
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
			svc, st, db := imageServer(t)
			inspectRun(t, db, 1, "host-1", tc.finished, inspectResult(imgHex))
			grantRun(t, db, 2, "host-1", imgRef, imgClock, nil)
			svc.ObserveImage(context.Background(), "host-1", execN(2), imageResult("debian", "12.8", "debian"))
			if got := len(storedReads(t, st, "host-1")) == 1; got != tc.stored {
				t.Fatalf("stored = %v, want %v", got, tc.stored)
			}
		})
	}
}

// TestImageReadRefusedWithoutGrant checks that a read needs an existing read
// grant: a successful image.packages run of this host whose stored parameter
// names the image. Every other execution is refused and nothing is stored,
// even though the host's inspect names the digest.
func TestImageReadRefusedWithoutGrant(t *testing.T) {
	other := "registry.example/app/web@sha256:" + strings.Repeat("d", 64)
	cases := map[string]func(*testing.T, *sql.DB){
		"no execution": func(*testing.T, *sql.DB) {},
		"other action": func(t *testing.T, db *sql.DB) {
			storeRun(t, db, 2, inspectActionID, `{"image":"`+imgRef+`"}`, "host-1", "finished", "success", imgClock, nil)
		},
		"run of another host": func(t *testing.T, db *sql.DB) {
			grantRun(t, db, 2, "host-2", imgRef, imgClock, nil)
		},
		"host run failed": func(t *testing.T, db *sql.DB) {
			storeRun(t, db, 2, imageActionID, `{"image":"`+imgRef+`"}`, "host-1", "finished", "failed", imgClock, nil)
		},
		"host run not finished": func(t *testing.T, db *sql.DB) {
			storeRun(t, db, 2, imageActionID, `{"image":"`+imgRef+`"}`, "host-1", "running", "", imgClock, nil)
		},
		"lease or schedule run without image parameter": func(t *testing.T, db *sql.DB) {
			storeRun(t, db, 2, imageActionID, "{}", "host-1", "finished", "success", imgClock, nil)
		},
		"extra parameter": func(t *testing.T, db *sql.DB) {
			storeRun(t, db, 2, imageActionID, `{"image":"`+imgRef+`","x":"y"}`, "host-1", "finished", "success", imgClock, nil)
		},
		"grant pins another image": func(t *testing.T, db *sql.DB) {
			grantRun(t, db, 2, "host-1", other, imgClock, nil)
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			svc, st, db := imageServer(t)
			inspectRun(t, db, 1, "host-1", imgClock, inspectResult(imgHex))
			setup(t, db)
			svc.ObserveImage(context.Background(), "host-1", execN(2), imageResult("debian", "12.8", "debian"))
			if reads := storedReads(t, st, "host-1"); len(reads) != 0 {
				t.Fatalf("stored %d reads without a grant, want 0", len(reads))
			}
		})
	}
}

// TestImageReadRefusedForResultOfAnotherImage checks that the result must
// describe the granted image: a result for another image is unknown and is not
// stored, even under a grant and an inspect that name the granted digest.
func TestImageReadRefusedForResultOfAnotherImage(t *testing.T) {
	svc, st, db := imageServer(t)
	inspectRun(t, db, 1, "host-1", imgClock, inspectResult(imgHex))
	grantRun(t, db, 2, "host-1", imgRef, imgClock, nil)
	other := "registry.example/app/web@sha256:" + strings.Repeat("e", 64)
	svc.ObserveImage(context.Background(), "host-1", execN(2), resultFor(other))
	if reads := storedReads(t, st, "host-1"); len(reads) != 0 {
		t.Fatalf("stored %d reads of a result for another image, want 0", len(reads))
	}
}

// TestFourthImageReadPushesOutOldest checks decision E4 through the service:
// after four successful reads of one image on one host, the oldest is gone.
func TestFourthImageReadPushesOutOldest(t *testing.T) {
	svc, st, db := imageServer(t)
	inspectRun(t, db, 1, "host-1", imgClock, inspectResult(imgHex))
	for i := range 4 {
		at := imgClock.Add(time.Duration(i) * time.Minute)
		grantRun(t, db, 10+i, "host-1", imgRef, at, nil)
		svc.ObserveImage(context.Background(), "host-1", execN(10+i), imageResult("debian", "12.8", "debian"))
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

// TestImageReadLogsDiscardedByRetention checks that a late read which
// retention deletes at once is not logged as stored: it is logged as
// discarded_by_retention, and the kept reads are unchanged.
func TestImageReadLogsDiscardedByRetention(t *testing.T) {
	svc, st, db := imageServer(t)
	var logs bytes.Buffer
	svc.log = slog.New(slog.NewTextHandler(&logs, nil))
	inspectRun(t, db, 1, "host-1", imgClock, inspectResult(imgHex))
	for i := range vulninventory.ImageReadsKept {
		at := imgClock.Add(time.Duration(i+1) * time.Hour)
		grantRun(t, db, 10+i, "host-1", imgRef, at, nil)
		svc.ObserveImage(context.Background(), "host-1", execN(10+i), imageResult("debian", "12.8", "debian"))
	}
	grantRun(t, db, 20, "host-1", imgRef, imgClock.Add(-time.Hour), nil)
	svc.ObserveImage(context.Background(), "host-1", execN(20), imageResult("debian", "12.8", "debian"))
	if !strings.Contains(logs.String(), "discarded_by_retention") {
		t.Fatalf("late read not logged as discarded_by_retention: %s", logs.String())
	}
	if n := strings.Count(logs.String(), "vuln_image_read_stored"); n != vulninventory.ImageReadsKept {
		t.Fatalf("%d reads logged as stored, want %d (the late read is not one)", n, vulninventory.ImageReadsKept)
	}
	if reads := storedReads(t, st, "host-1"); len(reads) != vulninventory.ImageReadsKept {
		t.Fatalf("kept %d reads, want %d", len(reads), vulninventory.ImageReadsKept)
	}
}

// TestImageReadsOfOneImageUnderSeveralNamesKeepThree checks that one image
// reached under several repository names shares one budget of three reads per
// host.
func TestImageReadsOfOneImageUnderSeveralNamesKeepThree(t *testing.T) {
	svc, st, db := imageServer(t)
	inspectRun(t, db, 1, "host-1", imgClock, inspectDoc([]string{
		"registry.example/app/web@sha256:" + imgHex,
		"web@sha256:" + imgHex,
		"web:1@sha256:" + imgHex,
	}, ""))
	names := []string{"registry.example/app/web", "web", "web:1", "registry.example/app/web"}
	for i, name := range names {
		ref := name + "@sha256:" + imgHex
		at := imgClock.Add(time.Duration(i) * time.Minute)
		grantRun(t, db, 10+i, "host-1", ref, at, nil)
		svc.ObserveImage(context.Background(), "host-1", execN(10+i), resultFor(ref))
	}
	if reads := storedReads(t, st, "host-1"); len(reads) != vulninventory.ImageReadsKept {
		t.Fatalf("kept %d reads of one image under several names, want %d", len(reads), vulninventory.ImageReadsKept)
	}
}

// TestImageRetentionIsPerHost checks that the reads of one host do not push
// out the reads of another host of the same image. host-2's reads are the
// oldest, so a budget shared by hosts would drop them all.
func TestImageRetentionIsPerHost(t *testing.T) {
	svc, st, db := imageServer(t)
	inspectRun(t, db, 1, "host-1", imgClock, inspectResult(imgHex))
	inspectRun(t, db, 2, "host-2", imgClock, inspectResult(imgHex))
	for i := range 3 {
		at := imgClock.Add(time.Duration(i-10) * time.Minute)
		grantRun(t, db, 10+i, "host-2", imgRef, at, nil)
		svc.ObserveImage(context.Background(), "host-2", execN(10+i), imageResult("debian", "12.8", "debian"))
	}
	for i := range 4 {
		at := imgClock.Add(time.Duration(i) * time.Minute)
		grantRun(t, db, 20+i, "host-1", imgRef, at, nil)
		svc.ObserveImage(context.Background(), "host-1", execN(20+i), imageResult("debian", "12.8", "debian"))
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
	svc, st, db := imageServer(t)
	inspectRun(t, db, 1, "host-1", imgClock, inspectResult(imgHex))
	grantRun(t, db, 2, "host-1", imgRef, imgClock, nil)
	absent := []byte(`{"format":"image-packages-v1","phase":"done","image":"` + imgRef + `","status":"absent","present":false}`)
	svc.ObserveImage(context.Background(), "host-1", execN(2), absent)
	if reads := storedReads(t, st, "host-1"); len(reads) != 0 {
		t.Fatalf("stored %d reads of an unknown result, want 0", len(reads))
	}
}

// TestInspectResultsIsTheStoredDigestSource checks the production digest
// source against server.db: only successful docker.inspect runs of the host,
// finished at or after since, are passed on, newest first, at most limit of
// them, and a row larger than maxInspectResultBytes is never passed on.
func TestInspectResultsIsTheStoredDigestSource(t *testing.T) {
	svc, _, db := imageServer(t)
	since := imgClock.Add(-time.Hour)
	inspectRun(t, db, 1, "host-1", imgClock.Add(-2*time.Minute), []byte("older"))
	inspectRun(t, db, 2, "host-1", imgClock.Add(-time.Minute), []byte("newer"))
	inspectRun(t, db, 3, "host-1", imgClock, []byte("newest"))
	inspectRun(t, db, 4, "host-1", imgClock.Add(time.Minute), bytes.Repeat([]byte("x"), maxInspectResultBytes+1))
	inspectRun(t, db, 5, "host-2", imgClock, []byte("other host"))
	inspectRun(t, db, 6, "host-1", since.Add(-time.Second), []byte("before since"))
	storeRun(t, db, 7, imageActionID, "{}", "host-1", "finished", "success", imgClock, []byte("other action"))
	storeRun(t, db, 8, inspectActionID, "{}", "host-1", "finished", "failed", imgClock, []byte("failed"))
	storeRun(t, db, 9, inspectActionID, "{}", "host-1", "running", "", imgClock, []byte("running"))

	collect := func(limit int) []string {
		var got []string
		err := svc.inspects.InspectResults(context.Background(), "host-1", since, limit, func(r imageInspectRow) bool {
			got = append(got, string(r.Result))
			return false
		})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if got := collect(10); strings.Join(got, ",") != "newest,newer,older" {
		t.Fatalf("passed on %v, want newest first: newest,newer,older", got)
	}
	if got := collect(2); strings.Join(got, ",") != "newest,newer" {
		t.Fatalf("limit 2 passed on %v, want the two newest", got)
	}
	var first []string
	err := svc.inspects.InspectResults(context.Background(), "host-1", since, 10, func(r imageInspectRow) bool {
		first = append(first, string(r.Result))
		return true
	})
	if err != nil || len(first) != 1 || first[0] != "newest" {
		t.Fatalf("stop after the first row passed on %v (err %v), want only newest", first, err)
	}
}

// TestImageReadNamedOnlyByBoundedInspect checks that the lookup of the digest
// source stops at its row limit: a matching inspect older than the newest
// maxInspectRows of the host does not name the digest.
func TestImageReadNamedOnlyByBoundedInspect(t *testing.T) {
	svc, st, db := imageServer(t)
	// One transaction: a commit per row would fsync maxInspectRows times.
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	inspectRun(t, tx, 1, "host-1", imgClock.Add(-time.Hour), inspectResult(imgHex))
	for i := range maxInspectRows {
		inspectRun(t, tx, 10+i, "host-1", imgClock.Add(time.Duration(i)*time.Second), inspectResult(strings.Repeat("c", 64)))
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	grantRun(t, db, 2, "host-1", imgRef, imgClock, nil)
	svc.ObserveImage(context.Background(), "host-1", execN(2), imageResult("debian", "12.8", "debian"))
	if reads := storedReads(t, st, "host-1"); len(reads) != 0 {
		t.Fatalf("stored %d reads named by an inspect beyond the row bound, want 0", len(reads))
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
