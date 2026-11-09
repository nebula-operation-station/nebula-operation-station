// SPDX-License-Identifier: AGPL-3.0-or-later

package dockerhost

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

const (
	pkgDigestHex = "1111111111111111111111111111111111111111111111111111111111111111"
	pkgOtherHex  = "2222222222222222222222222222222222222222222222222222222222222222"
	pkgDigest    = "docker.io/library/nginx@sha256:" + pkgDigestHex
)

// Unsafe runes used by the tests, spelled as code points so the source
// stays free of invisible characters.
var (
	runeRLO     = string(rune(0x202e)) // right-to-left override
	runeRLM     = string(rune(0x200f)) // right-to-left mark
	runeLineSep = string(rune(0x2028)) // line separator
)

// trivyPkg is a test-side Trivy package entry.
type trivyPkg struct {
	Name       string `json:"Name"`
	Version    string `json:"Version"`
	Release    string `json:"Release,omitempty"`
	Epoch      int    `json:"Epoch,omitempty"`
	SrcName    string `json:"SrcName,omitempty"`
	SrcVersion string `json:"SrcVersion,omitempty"`
	SrcRelease string `json:"SrcRelease,omitempty"`
	SrcEpoch   int    `json:"SrcEpoch,omitempty"`
}

type trivyResult struct {
	Target   string     `json:"Target"`
	Class    string     `json:"Class"`
	Type     string     `json:"Type"`
	Packages []trivyPkg `json:"Packages"`
}

// trivyDocOpts builds a Trivy --list-all-pkgs JSON document.
type trivyDocOpts struct {
	artifact    string
	repoDigests []string
	family      string
	osName      string
	noOS        bool
	results     []trivyResult
}

func trivyJSON(t testing.TB, o trivyDocOpts) []byte {
	t.Helper()
	doc := map[string]any{
		"SchemaVersion": 2,
		"ArtifactName":  o.artifact,
		"ArtifactType":  "container_image",
		"Results":       o.results,
	}
	meta := map[string]any{
		"ImageID":     "sha256:" + pkgOtherHex,
		"RepoDigests": o.repoDigests,
		// Fields the parser must ignore and never keep.
		"ImageConfig": map[string]any{"config": map[string]any{"Env": []string{"SECRET_TOKEN=do-not-keep"}}},
	}
	if !o.noOS {
		meta["OS"] = map[string]any{"Family": o.family, "Name": o.osName}
	}
	doc["Metadata"] = meta
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func goodOpts() trivyDocOpts {
	return trivyDocOpts{
		artifact:    pkgDigest,
		repoDigests: []string{"nginx@sha256:" + pkgDigestHex},
		family:      "debian",
		osName:      "12.5",
		results: []trivyResult{
			{Target: "nginx (debian 12.5)", Class: "os-pkgs", Type: "debian", Packages: []trivyPkg{
				{Name: "libc6", Version: "2.36", Release: "9+deb12u4", SrcName: "glibc", SrcVersion: "2.36", SrcRelease: "9+deb12u4"},
				{Name: "libgcrypt20", Version: "1.10.1", Release: "3", Epoch: 0, SrcName: "libgcrypt20", SrcVersion: "1.10.1", SrcRelease: "3"},
				{Name: "libpam0g", Version: "1.5.2", Release: "6+deb12u1", SrcName: "pam", SrcVersion: "1.5.2", SrcRelease: "6+deb12u1"},
				{Name: "bsdutils", Version: "2.38.1", Release: "5+deb12u1", Epoch: 1, SrcName: "util-linux", SrcVersion: "2.38.1", SrcRelease: "5+deb12u1", SrcEpoch: 1},
			}},
			{Target: "usr/local/bin/app", Class: "lang-pkgs", Type: "gobinary", Packages: []trivyPkg{
				{Name: "golang.org/x/net", Version: "v0.17.0"},
			}},
		},
	}
}

func okRun(b []byte) TrivyPackagesRun { return TrivyPackagesRun{Present: true, ExitCode: 0, Output: b} }

func TestImagePackagesCompleteRead(t *testing.T) {
	got, err := ParseImagePackages(pkgDigest, okRun(trivyJSON(t, goodOpts())))
	if err != nil {
		t.Fatal(err)
	}
	if !got.Known || !got.Complete || got.Reason != "" {
		t.Fatalf("want known complete read, got %+v", got)
	}
	if got.Digest != pkgDigest {
		t.Fatalf("digest %q", got.Digest)
	}
	if got.OS != (ImageOS{Family: "debian", Name: "12.5"}) {
		t.Fatalf("os %+v", got.OS)
	}
	want := []ImagePackage{
		{Ecosystem: "debian", Name: "libc6", Version: "2.36-9+deb12u4", SrcName: "glibc", SrcVersion: "2.36-9+deb12u4"},
		{Ecosystem: "debian", Name: "libgcrypt20", Version: "1.10.1-3", SrcName: "libgcrypt20", SrcVersion: "1.10.1-3"},
		{Ecosystem: "debian", Name: "libpam0g", Version: "1.5.2-6+deb12u1", SrcName: "pam", SrcVersion: "1.5.2-6+deb12u1"},
		{Ecosystem: "debian", Name: "bsdutils", Version: "1:2.38.1-5+deb12u1", SrcName: "util-linux", SrcVersion: "1:2.38.1-5+deb12u1"},
		{Ecosystem: "gobinary", Name: "golang.org/x/net", Version: "v0.17.0"},
	}
	if len(got.Packages) != len(want) {
		t.Fatalf("packages %+v", got.Packages)
	}
	for i := range want {
		if got.Packages[i] != want[i] {
			t.Errorf("package %d: got %+v want %+v", i, got.Packages[i], want[i])
		}
	}
}

func TestImagePackagesDigestMatchesRepoDigestOnly(t *testing.T) {
	o := goodOpts()
	o.artifact = "nginx:latest"
	got, _ := ParseImagePackages(pkgDigest, okRun(trivyJSON(t, o)))
	if !got.Complete {
		t.Fatalf("repo digest match must count, got %+v", got)
	}
}

func TestTrivyAbsentIsUnknownNotEmpty(t *testing.T) {
	// Output is ignored when the host reports no Trivy, even a valid listing.
	for _, out := range [][]byte{nil, trivyJSON(t, goodOpts())} {
		got, err := ParseImagePackages(pkgDigest, TrivyPackagesRun{Present: false, Output: out})
		if err != nil {
			t.Fatal(err)
		}
		if got.Known || got.Complete || got.Packages != nil || got.Reason != ReasonTrivyAbsent {
			t.Fatalf("absent Trivy must be unknown, got %+v", got)
		}
		if got.Digest != pkgDigest {
			t.Fatalf("digest %q", got.Digest)
		}
	}
	var zero ImagePackages
	if zero.Known || zero.Complete {
		t.Fatal("zero value must read as unknown")
	}
}

func TestImagePackagesPartialConditions(t *testing.T) {
	good := trivyJSON(t, goodOpts())
	cases := []struct {
		name      string
		run       func(t *testing.T) TrivyPackagesRun
		reason    string
		known     bool
		wantPkgs  int
		wantNoPkg bool
	}{
		{"non-zero exit", func(t *testing.T) TrivyPackagesRun {
			return TrivyPackagesRun{Present: true, ExitCode: 1, Output: good}
		}, ReasonExitNonZero, true, 5, false},
		{"negative exit", func(t *testing.T) TrivyPackagesRun {
			return TrivyPackagesRun{Present: true, ExitCode: -1, Output: good}
		}, ReasonExitNonZero, true, 5, false},
		{"unparseable", func(t *testing.T) TrivyPackagesRun { return okRun([]byte(`{"SchemaVersion":2,`)) }, ReasonUnparseable, false, 0, true},
		{"empty output", func(t *testing.T) TrivyPackagesRun { return okRun(nil) }, ReasonUnparseable, false, 0, true},
		{"not an object", func(t *testing.T) TrivyPackagesRun { return okRun([]byte(`[]`)) }, ReasonUnparseable, false, 0, true},
		{"wrong schema", func(t *testing.T) TrivyPackagesRun {
			return okRun([]byte(strings.Replace(string(good), `"SchemaVersion":2`, `"SchemaVersion":3`, 1)))
		}, ReasonUnparseable, false, 0, true},
		{"trailing data", func(t *testing.T) TrivyPackagesRun {
			return okRun(append(append([]byte{}, good...), []byte(` {"x":1}`)...))
		}, ReasonUnparseable, false, 0, true},
		{"invalid utf-8", func(t *testing.T) TrivyPackagesRun {
			return okRun([]byte(strings.Replace(string(good), "libpam0g", "libpam\xff", 1)))
		}, ReasonUnparseable, false, 0, true},
		{"oversized output", func(t *testing.T) TrivyPackagesRun {
			return okRun(make([]byte, MaxImagePackagesOutput+1))
		}, ReasonUnparseable, false, 0, true},
		{"dropped entry", func(t *testing.T) TrivyPackagesRun {
			o := goodOpts()
			o.results[0].Packages[1].Name = "bad\nname"
			return okRun(trivyJSON(t, o))
		}, ReasonEntryDropped, true, 4, false},
		{"dropped result type", func(t *testing.T) TrivyPackagesRun {
			o := goodOpts()
			o.results[1].Type = "Bad Type"
			return okRun(trivyJSON(t, o))
		}, ReasonEntryDropped, true, 4, false},
		{"digest mismatch", func(t *testing.T) TrivyPackagesRun {
			o := goodOpts()
			o.artifact = "nginx@sha256:" + pkgOtherHex
			o.repoDigests = []string{"nginx@sha256:" + pkgOtherHex}
			return okRun(trivyJSON(t, o))
		}, ReasonDigestMismatch, true, 5, false},
		{"digest absent", func(t *testing.T) TrivyPackagesRun {
			o := goodOpts()
			o.artifact = ""
			o.repoDigests = nil
			return okRun(trivyJSON(t, o))
		}, ReasonDigestMismatch, true, 5, false},
		{"os missing", func(t *testing.T) TrivyPackagesRun {
			o := goodOpts()
			o.noOS = true
			return okRun(trivyJSON(t, o))
		}, ReasonOSUndetected, true, 5, false},
		{"os family empty", func(t *testing.T) TrivyPackagesRun {
			o := goodOpts()
			o.family = ""
			return okRun(trivyJSON(t, o))
		}, ReasonOSUndetected, true, 5, false},
		{"os release empty", func(t *testing.T) TrivyPackagesRun {
			o := goodOpts()
			o.osName = ""
			return okRun(trivyJSON(t, o))
		}, ReasonOSUndetected, true, 5, false},
		{"os invalid", func(t *testing.T) TrivyPackagesRun {
			o := goodOpts()
			o.osName = "12" + runeRLO + "5"
			return okRun(trivyJSON(t, o))
		}, ReasonOSUndetected, true, 5, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ParseImagePackages(pkgDigest, c.run(t))
			if err != nil {
				t.Fatal(err)
			}
			if got.Complete {
				t.Fatalf("must be partial: %+v", got)
			}
			if !hasReason(got.Reason, c.reason) {
				t.Fatalf("reason %q, want %q", got.Reason, c.reason)
			}
			if got.Known != c.known {
				t.Fatalf("known %v, want %v", got.Known, c.known)
			}
			if c.wantNoPkg && got.Packages != nil {
				t.Fatalf("unparseable output must carry no packages: %+v", got.Packages)
			}
			if len(got.Packages) != c.wantPkgs {
				t.Fatalf("packages %d, want %d", len(got.Packages), c.wantPkgs)
			}
			if got.Digest != pkgDigest {
				t.Fatalf("digest must be the requested one, got %q", got.Digest)
			}
		})
	}
}

func hasReason(reason, want string) bool {
	for _, r := range strings.Split(reason, ",") {
		if r == want {
			return true
		}
	}
	return false
}

func TestImagePackagesAllReasonsReported(t *testing.T) {
	o := goodOpts()
	o.noOS = true
	o.artifact = "nginx@sha256:" + pkgOtherHex
	o.repoDigests = nil
	o.results[0].Packages[0].Version = ""
	got, _ := ParseImagePackages(pkgDigest, TrivyPackagesRun{Present: true, ExitCode: 2, Output: trivyJSON(t, o)})
	for _, r := range []string{ReasonExitNonZero, ReasonEntryDropped, ReasonDigestMismatch, ReasonOSUndetected} {
		if !hasReason(got.Reason, r) {
			t.Errorf("reason %q lacks %q", got.Reason, r)
		}
	}
	if got.Complete {
		t.Fatal("must be partial")
	}
}

func TestImagePackagesLimitReached(t *testing.T) {
	for _, n := range []int{MaxImagePackages, MaxImagePackages + 1, MaxImagePackages + 50} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			o := goodOpts()
			pk := make([]trivyPkg, n)
			for i := range pk {
				pk[i] = trivyPkg{Name: fmt.Sprintf("pkg%d", i), Version: "1.0", SrcName: "src", SrcVersion: "1.0"}
			}
			o.results = []trivyResult{{Target: "x", Class: "os-pkgs", Type: "debian", Packages: pk}}
			got, _ := ParseImagePackages(pkgDigest, okRun(trivyJSON(t, o)))
			if got.Complete || !hasReason(got.Reason, ReasonLimitReached) {
				t.Fatalf("limit must mark partial: complete=%v reason=%q", got.Complete, got.Reason)
			}
			if len(got.Packages) != MaxImagePackages {
				t.Fatalf("packages %d", len(got.Packages))
			}
		})
	}
	o := goodOpts()
	pk := make([]trivyPkg, MaxImagePackages-1)
	for i := range pk {
		pk[i] = trivyPkg{Name: fmt.Sprintf("pkg%d", i), Version: "1.0"}
	}
	o.results = []trivyResult{{Target: "x", Class: "os-pkgs", Type: "debian", Packages: pk}}
	got, _ := ParseImagePackages(pkgDigest, okRun(trivyJSON(t, o)))
	if !got.Complete {
		t.Fatalf("below limit must be complete: %q", got.Reason)
	}
}

func TestImagePackagesInvalidEntriesDropped(t *testing.T) {
	long := strings.Repeat("a", maxImagePkgName+1)
	bad := []trivyPkg{
		{Name: "", Version: "1"},
		{Name: "x", Version: ""},
		{Name: long, Version: "1"},
		{Name: "x", Version: strings.Repeat("1", maxImagePkgVersion+1)},
		{Name: "x", Version: "1", Release: strings.Repeat("1", maxImagePkgVersion)}, // composed version too long
		{Name: "x" + runeRLM, Version: "1"},
		{Name: "x", Version: "1\t2"},
		{Name: "x", Version: "1", SrcName: "s\x00"},
		{Name: "x", Version: "1", SrcName: "s", SrcVersion: "v" + runeLineSep},
		{Name: "x", Version: "1", Epoch: -1},
		{Name: "x", Version: "1", Epoch: maxImagePkgEpoch + 1},
		{Name: "x", Version: "1", SrcName: "s", SrcVersion: "1", SrcEpoch: -3},
		{Name: "x", Version: "1", Release: "bad release"},
		{Name: "x", Version: "1", SrcVersion: "1"},               // source version without source name
		{Name: "x", Version: "1", SrcName: "s", SrcRelease: "1"}, // source release without source version
	}
	for i, p := range bad {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			o := goodOpts()
			o.results = []trivyResult{{Target: "x", Class: "os-pkgs", Type: "debian", Packages: []trivyPkg{p, {Name: "ok", Version: "1"}}}}
			got, _ := ParseImagePackages(pkgDigest, okRun(trivyJSON(t, o)))
			if got.Complete || got.Reason != ReasonEntryDropped {
				t.Fatalf("entry %+v must be dropped and mark partial, got complete=%v reason=%q", p, got.Complete, got.Reason)
			}
			if len(got.Packages) != 1 || got.Packages[0].Name != "ok" {
				t.Fatalf("packages %+v", got.Packages)
			}
		})
	}
}

func TestImagePackagesNullEntriesDropped(t *testing.T) {
	for name, results := range map[string]string{
		"null package": `[{"Target":"t","Class":"os-pkgs","Type":"alpine","Packages":[null,{"Name":"musl","Version":"1.2.4-r2"}]}]`,
		"null result":  `[null,{"Target":"t","Class":"os-pkgs","Type":"alpine","Packages":[{"Name":"musl","Version":"1.2.4-r2"}]}]`,
		"bad class":    `[{"Target":"t","Class":"secret","Type":"alpine","Packages":[{"Name":"a","Version":"1"}]},{"Target":"t","Class":"os-pkgs","Type":"alpine","Packages":[{"Name":"musl","Version":"1.2.4-r2"}]}]`,
	} {
		t.Run(name, func(t *testing.T) {
			b := []byte(`{"SchemaVersion":2,"ArtifactName":"` + pkgDigest + `","Metadata":{"OS":{"Family":"alpine","Name":"3.19.1"}},"Results":` + results + `}`)
			got, _ := ParseImagePackages(pkgDigest, okRun(b))
			if got.Complete || got.Reason != ReasonEntryDropped || len(got.Packages) != 1 {
				t.Fatalf("got %+v", got)
			}
		})
	}
}

func TestImagePackagesDuplicatesCollapsed(t *testing.T) {
	o := goodOpts()
	p := trivyPkg{Name: "golang.org/x/net", Version: "v0.17.0"}
	o.results = []trivyResult{
		{Target: "a", Class: "lang-pkgs", Type: "gobinary", Packages: []trivyPkg{p}},
		{Target: "b", Class: "lang-pkgs", Type: "gobinary", Packages: []trivyPkg{p}},
	}
	got, _ := ParseImagePackages(pkgDigest, okRun(trivyJSON(t, o)))
	if !got.Complete || len(got.Packages) != 1 {
		t.Fatalf("got %+v", got)
	}
}

func TestImagePackagesEmptyListingWithOSIsComplete(t *testing.T) {
	o := goodOpts()
	o.results = nil
	got, _ := ParseImagePackages(pkgDigest, okRun(trivyJSON(t, o)))
	if !got.Known || !got.Complete || got.Packages == nil || len(got.Packages) != 0 {
		t.Fatalf("got %+v", got)
	}
}

func TestImagePackagesRejectsBadRequestedDigest(t *testing.T) {
	for _, d := range []string{"", "nginx:latest", "sha256:" + pkgDigestHex, "nginx@sha256:abc", pkgDigest + "\n"} {
		_, err := ParseImagePackages(d, okRun(trivyJSON(t, goodOpts())))
		if !errors.Is(err, ErrImagePackagesDigest) {
			t.Fatalf("%q: err %v", d, err)
		}
	}
}

func TestImagePackagesKeepsNoRawOutput(t *testing.T) {
	o := goodOpts()
	o.results[0].Packages = append(o.results[0].Packages, trivyPkg{Name: "evil\x1b[31m", Version: "1"})
	runs := []TrivyPackagesRun{
		okRun(trivyJSON(t, o)),
		{Present: true, ExitCode: 3, Output: []byte(`SECRET_TOKEN=do-not-keep not json`)},
		okRun([]byte(`{"SchemaVersion":2,"ArtifactName":"SECRET_TOKEN=do-not-keep"`)),
	}
	for i, r := range runs {
		got, err := ParseImagePackages(pkgDigest, r)
		if err != nil {
			t.Fatal(err)
		}
		dump := fmt.Sprintf("%+v %#v", got, got)
		for _, banned := range []string{"SECRET_TOKEN", "do-not-keep", "ImageConfig", "evil", "\x1b"} {
			if strings.Contains(dump, banned) {
				t.Fatalf("run %d: result keeps raw output %q: %s", i, banned, dump)
			}
		}
	}
}
