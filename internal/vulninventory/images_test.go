// SPDX-License-Identifier: AGPL-3.0-or-later

package vulninventory

import (
	"context"
	"errors"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

const imgRepo = "registry.example/app/web"

// imgDigest returns a sha256 digest made of the hex digit d.
func imgDigest(d string) string { return "sha256:" + strings.Repeat(d, 64) }

// testImageRead is a valid complete image read of repo on host-1 at base+at
// seconds, of the digest imgDigest("a").
func testImageRead(repo string, at int64) ImageRead {
	return ImageRead{
		Repository:  repo,
		Digest:      imgDigest("a"),
		HostID:      "host-1",
		ExecutionID: "exec-" + strconv.FormatInt(at, 10),
		ReadAt:      base.Add(time.Duration(at) * time.Second),
		Complete:    true,
		OSFamily:    "debian",
		OSName:      "12.5",
		Packages: []ImagePackage{
			{Ecosystem: "debian", Name: "libc6", Version: "2.36-9", Source: "glibc", SourceVersion: "2.36-9"},
		},
	}
}

// testImageReadOn is testImageRead for host.
func testImageReadOn(host, repo string, at int64) ImageRead {
	r := testImageRead(repo, at)
	r.HostID = host
	return r
}

// TestImageStoreKeepsThreeReadsPerHostAndDigest checks decision E4 with the
// image as the key: the fourth read of one image on one host pushes out the
// oldest, even when the reads name the image under several repositories, and
// another digest on the same host is not touched.
func TestImageStoreKeepsThreeReadsPerHostAndDigest(t *testing.T) {
	s, db := openStore(t)
	ctx := context.Background()
	other := testImageReadOn("host-1", "api", 1)
	other.Digest = imgDigest("b")
	if _, err := s.PutImage(ctx, other); err != nil {
		t.Fatalf("put other digest: %v", err)
	}
	names := []string{imgRepo, "web", "web:1", imgRepo}
	for i, at := range []int64{10, 11, 12, 13} {
		if _, err := s.PutImage(ctx, testImageReadOn("host-1", names[i], at)); err != nil {
			t.Fatalf("put read %d: %v", at, err)
		}
	}
	reads, err := s.ImageReads(ctx, "host-1", imgDigest("a"))
	if err != nil {
		t.Fatalf("image reads: %v", err)
	}
	if len(reads) != ImageReadsKept {
		t.Fatalf("kept %d reads, want %d", len(reads), ImageReadsKept)
	}
	for i, want := range []int64{13, 12, 11} {
		if got := reads[i].ReadAt.Unix() - base.Unix(); got != want {
			t.Errorf("read %d at %d, want %d (newest first)", i, got, want)
		}
	}
	var rows int
	if err := db.QueryRow(`SELECT count(*) FROM vuln_image_reads WHERE host_id = ? AND digest = ?`,
		"host-1", imgDigest("a")).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != ImageReadsKept {
		t.Fatalf("table holds %d rows for the image, want %d", rows, ImageReadsKept)
	}
	if otherReads, err := s.ImageReads(ctx, "host-1", imgDigest("b")); err != nil || len(otherReads) != 1 {
		t.Fatalf("other digest: %d reads, err %v; want 1", len(otherReads), err)
	}
}

// TestImageStoreRetentionIsPerHost checks that one host's reads do not push
// out another host's reads of the same image: each host keeps its own three.
// host-2's reads are the oldest, so a shared budget would drop them all.
func TestImageStoreRetentionIsPerHost(t *testing.T) {
	s, _ := openStore(t)
	ctx := context.Background()
	for _, at := range []int64{1, 2, 3} {
		if _, err := s.PutImage(ctx, testImageReadOn("host-2", imgRepo, at)); err != nil {
			t.Fatal(err)
		}
	}
	for _, at := range []int64{10, 11, 12, 13} {
		if _, err := s.PutImage(ctx, testImageReadOn("host-1", imgRepo, at)); err != nil {
			t.Fatal(err)
		}
	}
	for _, host := range []string{"host-1", "host-2"} {
		reads, err := s.ImageReads(ctx, host, imgDigest("a"))
		if err != nil {
			t.Fatal(err)
		}
		if len(reads) != ImageReadsKept {
			t.Fatalf("%s kept %d reads, want %d", host, len(reads), ImageReadsKept)
		}
		for _, r := range reads {
			if r.HostID != host {
				t.Fatalf("%s read holds host %q", host, r.HostID)
			}
		}
	}
}

// TestImageStoreRetentionFollowsReadTime checks that the kept reads are the
// newest by read time, not the last inserted: a late-arriving older read is
// removed at once when three newer reads are kept.
func TestImageStoreRetentionFollowsReadTime(t *testing.T) {
	s, _ := openStore(t)
	ctx := context.Background()
	for _, at := range []int64{30, 40, 50} {
		if _, err := s.PutImage(ctx, testImageRead(imgRepo, at)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.PutImage(ctx, testImageRead(imgRepo, 5)); err != nil {
		t.Fatal(err)
	}
	reads, err := s.ImageReads(ctx, "host-1", imgDigest("a"))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range reads {
		if r.ReadAt.Unix() == base.Unix()+5 {
			t.Fatalf("the oldest read was kept over three newer ones")
		}
	}
	if len(reads) != ImageReadsKept {
		t.Fatalf("kept %d reads, want %d", len(reads), ImageReadsKept)
	}
}

// TestImageStoreRoundTripsPackages checks that the packages come back as
// written, in canonical order, with their source packages.
func TestImageStoreRoundTripsPackages(t *testing.T) {
	s, _ := openStore(t)
	ctx := context.Background()
	in := testImageRead(imgRepo, 1)
	in.Packages = []ImagePackage{
		{Ecosystem: "debian", Name: "zlib1g", Version: "1:1.2.13", Source: "zlib", SourceVersion: "1:1.2.13"},
		{Ecosystem: "debian", Name: "bash", Version: "5.2-1"},
	}
	if _, err := s.PutImage(ctx, in); err != nil {
		t.Fatal(err)
	}
	reads, err := s.ImageReads(ctx, "host-1", imgDigest("a"))
	if err != nil || len(reads) != 1 {
		t.Fatalf("image reads: %d, err %v", len(reads), err)
	}
	got := reads[0]
	if got.Digest != in.Digest || got.HostID != in.HostID || !got.Complete || got.OSName != "12.5" {
		t.Fatalf("header mismatch: %+v", got)
	}
	if len(got.Packages) != 2 || got.Packages[0].Name != "bash" || got.Packages[1].Source != "zlib" {
		t.Fatalf("packages %+v, want bash then zlib", got.Packages)
	}
}

// TestImageStoreRefusesInvalidReadsWithoutWriting checks the rejections: a
// bad digest, repository or package field, too many packages, and a read
// time in the future. A refused read writes nothing and deletes nothing.
func TestImageStoreRefusesInvalidReadsWithoutWriting(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*ImageRead)
		want   error
	}{
		{"digest without prefix", func(r *ImageRead) { r.Digest = strings.Repeat("a", 64) }, ErrInvalidRead},
		{"digest uppercase", func(r *ImageRead) { r.Digest = "sha256:" + strings.Repeat("A", 64) }, ErrInvalidRead},
		{"digest short", func(r *ImageRead) { r.Digest = "sha256:abc" }, ErrInvalidRead},
		{"repository empty", func(r *ImageRead) { r.Repository = "" }, ErrInvalidRead},
		{"repository with space", func(r *ImageRead) { r.Repository = "a b" }, ErrInvalidRead},
		{"host id empty", func(r *ImageRead) { r.HostID = "" }, ErrInvalidRead},
		{"package name with quote", func(r *ImageRead) { r.Packages[0].Name = `a"b` }, ErrInvalidRead},
		{"package version empty", func(r *ImageRead) { r.Packages[0].Version = "" }, ErrInvalidRead},
		{"source version without source", func(r *ImageRead) { r.Packages[0].Source = "" }, ErrInvalidRead},
		{"too many packages", func(r *ImageRead) {
			r.Packages = make([]ImagePackage, MaxImagePackages+1)
			for i := range r.Packages {
				r.Packages[i] = ImagePackage{Ecosystem: "debian", Name: "pkg", Version: "1"}
			}
		}, ErrLimit},
		{"read time in the future", func(r *ImageRead) { r.ReadAt = time.Now().Add(time.Hour) }, ErrInvalidRead},
		{"invalid utf-8 os name", func(r *ImageRead) { r.OSName = "\xff" }, ErrInvalidRead},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, db := openStore(t)
			ctx := context.Background()
			for at := int64(1); at <= ImageReadsKept; at++ {
				if _, err := s.PutImage(ctx, testImageRead(imgRepo, at)); err != nil {
					t.Fatal(err)
				}
			}
			bad := testImageRead(imgRepo, 100)
			tc.mutate(&bad)
			if _, err := s.PutImage(ctx, bad); !errors.Is(err, tc.want) {
				t.Fatalf("put: %v, want %v", err, tc.want)
			}
			var rows int
			if err := db.QueryRow(`SELECT count(*) FROM vuln_image_reads`).Scan(&rows); err != nil {
				t.Fatal(err)
			}
			if rows != ImageReadsKept {
				t.Fatalf("table holds %d rows after a refused read, want %d", rows, ImageReadsKept)
			}
		})
	}
}

// TestImageReadIsImmutable checks that the database refuses an UPDATE of a
// stored image read.
func TestImageReadIsImmutable(t *testing.T) {
	s, db := openStore(t)
	id, err := s.PutImage(context.Background(), testImageRead(imgRepo, 1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE vuln_image_reads SET complete = 0 WHERE id = ?`, id); err == nil {
		t.Fatal("update of an image read succeeded")
	}
}

// TestImageBodyLimitsMatchMigration checks the constants of images.go against
// migration 0053: the body and package-count CHECKs must carry the same
// numbers, and the worst-case encoded package must fit its constant.
func TestImageBodyLimitsMatchMigration(t *testing.T) {
	raw, err := os.ReadFile("../serverdb/migrations/0053_vuln_image_inventory.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	if want := strconv.Itoa(MaxImageBodyBytes); !strings.Contains(sql, "BETWEEN 2 AND "+want+")") {
		t.Errorf("migration 0053 body CHECK does not carry %d", MaxImageBodyBytes)
	}
	if want := strconv.Itoa(MaxImagePackages); !regexp.MustCompile(`packages BETWEEN 0 AND ` + want + `\)`).MatchString(sql) {
		t.Errorf("migration 0053 package CHECK does not carry %d", MaxImagePackages)
	}
	worst := ImagePackage{
		Ecosystem:     strings.Repeat("e", maxImageEcosystemBytes),
		Name:          strings.Repeat("n", maxImageNameBytes),
		Version:       strings.Repeat("v", maxImageVersionBytes),
		Source:        strings.Repeat("s", maxImageSourceBytes),
		SourceVersion: strings.Repeat("w", maxImageSourceVerBytes),
	}
	body, err := encodeImageBody([]ImagePackage{worst})
	if err != nil {
		t.Fatalf("encode worst package: %v", err)
	}
	if got := len(body) - 2; got+1 > maxImagePackageJSONBytes {
		t.Errorf("worst package encodes to %d bytes plus separator, constant allows %d", got, maxImagePackageJSONBytes)
	}
}

// TestImageBodyRefusesOverLimit checks that a full set of worst-case packages
// over the body limit is refused as a limit, not stored.
func TestImageBodyRefusesOverLimit(t *testing.T) {
	pkgs := make([]ImagePackage, MaxImagePackages)
	for i := range pkgs {
		pkgs[i] = ImagePackage{
			Ecosystem:     strings.Repeat("e", maxImageEcosystemBytes),
			Name:          strings.Repeat("n", maxImageNameBytes),
			Version:       strings.Repeat("v", maxImageVersionBytes),
			Source:        strings.Repeat("s", maxImageSourceBytes),
			SourceVersion: strings.Repeat("w", maxImageSourceVerBytes),
		}
	}
	if _, err := encodeImageBody(pkgs); err != nil {
		t.Fatalf("a full worst-case read must fit: %v", err)
	}
	pkgs = append(pkgs, ImagePackage{Ecosystem: "debian", Name: "x", Version: "1"})
	if _, err := encodeImageBody(pkgs); !errors.Is(err, ErrLimit) {
		t.Fatalf("over-limit read: %v, want ErrLimit", err)
	}
}
