// SPDX-License-Identifier: AGPL-3.0-or-later

package dockerhost

import (
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
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

// trivyTestOS, trivyTestMeta and trivyTestDoc keep Trivy's field order
// (SchemaVersion first, Metadata before Results).
type trivyTestOS struct {
	Family string `json:"Family"`
	Name   string `json:"Name"`
}

type trivyTestMeta struct {
	OS          *trivyTestOS   `json:"OS,omitempty"`
	ImageID     string         `json:"ImageID"`
	RepoDigests []string       `json:"RepoDigests"`
	ImageConfig map[string]any `json:"ImageConfig"`
}

type trivyTestDoc struct {
	SchemaVersion int           `json:"SchemaVersion"`
	ArtifactName  string        `json:"ArtifactName"`
	ArtifactType  string        `json:"ArtifactType"`
	Metadata      trivyTestMeta `json:"Metadata"`
	Results       []trivyResult `json:"Results"`
}

func trivyJSON(t testing.TB, o trivyDocOpts) []byte {
	t.Helper()
	doc := trivyTestDoc{
		SchemaVersion: 2,
		ArtifactName:  o.artifact,
		ArtifactType:  "container_image",
		Metadata: trivyTestMeta{
			ImageID:     "sha256:" + pkgOtherHex,
			RepoDigests: o.repoDigests,
			// Fields the parser must ignore and never keep.
			ImageConfig: map[string]any{"config": map[string]any{"Env": []string{"SECRET_TOKEN=do-not-keep"}}},
		},
		Results: o.results,
	}
	if !o.noOS {
		doc.Metadata.OS = &trivyTestOS{Family: o.family, Name: o.osName}
	}
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
		{Target: "os", Class: "os-pkgs", Type: "debian", Packages: []trivyPkg{{Name: "libc6", Version: "2.36"}}},
		{Target: "a", Class: "lang-pkgs", Type: "gobinary", Packages: []trivyPkg{p}},
		{Target: "b", Class: "lang-pkgs", Type: "gobinary", Packages: []trivyPkg{p}},
	}
	got, _ := ParseImagePackages(pkgDigest, okRun(trivyJSON(t, o)))
	if !got.Complete || len(got.Packages) != 2 {
		t.Fatalf("got %+v", got)
	}
}

// An image with a detected OS but no os-pkgs result (unreadable package DB,
// library-only scan) must never prove that every OS package was removed.
func TestImagePackagesDetectedOSWithoutOSResultIsPartial(t *testing.T) {
	langOnly := goodOpts()
	langOnly.results = langOnly.results[1:]
	otherFamily := goodOpts()
	otherFamily.results[0].Type = "alpine" // os-pkgs result for another OS than detected
	for name, o := range map[string]trivyDocOpts{
		"no results":         func() trivyDocOpts { o := goodOpts(); o.results = nil; return o }(),
		"lang-pkgs only":     langOnly,
		"os type not family": otherFamily,
	} {
		t.Run(name, func(t *testing.T) {
			got, _ := ParseImagePackages(pkgDigest, okRun(trivyJSON(t, o)))
			if !got.Known || got.Complete || !hasReason(got.Reason, ReasonOSPackagesMissing) {
				t.Fatalf("detected OS without os-pkgs result must be partial: %+v", got)
			}
			for _, p := range got.Packages {
				if p.Ecosystem == "alpine" {
					t.Fatalf("os-pkgs of another family kept: %+v", p)
				}
			}
		})
	}
}

// An os-pkgs result without any OS package does not show that the package
// DB was read: known, empty, but never complete.
func TestImagePackagesEmptyOSResultIsPartial(t *testing.T) {
	o := goodOpts()
	o.results = []trivyResult{{Target: "x", Class: "os-pkgs", Type: "debian", Packages: nil}}
	got, _ := ParseImagePackages(pkgDigest, okRun(trivyJSON(t, o)))
	if !got.Known || got.Complete || got.Reason != ReasonOSPackagesMissing || got.Packages == nil || len(got.Packages) != 0 {
		t.Fatalf("got %+v", got)
	}
}

// A language result must not place packages under an OS ecosystem.
func TestImagePackagesLangResultWithOSTypeDropped(t *testing.T) {
	for _, typ := range []string{"debian", "alpine", "ubuntu"} {
		t.Run(typ, func(t *testing.T) {
			o := goodOpts()
			o.results[1].Type = typ
			got, _ := ParseImagePackages(pkgDigest, okRun(trivyJSON(t, o)))
			if got.Complete || !hasReason(got.Reason, ReasonEntryDropped) || len(got.Packages) != 4 {
				t.Fatalf("got %+v", got)
			}
			for _, p := range got.Packages {
				if p.Name == "golang.org/x/net" {
					t.Fatalf("lang package kept under OS type: %+v", p)
				}
			}
		})
	}
}

// A type mismatch in one entry drops that entry only; the rest of the
// document is still read.
func TestImagePackagesEntryTypeMismatchDropsEntry(t *testing.T) {
	for name, entry := range map[string]string{
		"string epoch":       `{"Name":"x","Version":"1","Epoch":"1"}`,
		"epoch beyond int":   `{"Name":"x","Version":"1","Epoch":1e400}`,
		"fractional epoch":   `{"Name":"x","Version":"1","SrcEpoch":1.5}`,
		"numeric name":       `{"Name":7,"Version":"1"}`,
		"array version":      `{"Name":"x","Version":["1"]}`,
		"entry is a number":  `5`,
		"entry is a string":  `"musl"`,
		"entry is an array":  `[{"Name":"x","Version":"1"}]`,
		"object source name": `{"Name":"x","Version":"1","SrcName":{"a":1}}`,
	} {
		t.Run(name, func(t *testing.T) {
			b := []byte(`{"SchemaVersion":2,"ArtifactName":"` + pkgDigest + `","Metadata":{"OS":{"Family":"alpine","Name":"3.19.1"}},` +
				`"Results":[{"Target":"t","Class":"os-pkgs","Type":"alpine","Packages":[` + entry + `,{"Name":"musl","Version":"1.2.4-r2"}]}]}`)
			got, _ := ParseImagePackages(pkgDigest, okRun(b))
			if !got.Known || got.Complete || got.Reason != ReasonEntryDropped {
				t.Fatalf("type mismatch must drop the entry: %+v", got)
			}
			if len(got.Packages) != 1 || got.Packages[0].Name != "musl" {
				t.Fatalf("packages %+v", got.Packages)
			}
		})
	}
}

// Hostile output of many tiny entries must stop at the entry cap and keep
// the allocation of one read small, independent of the output size.
func TestImagePackagesEntryFloodBounded(t *testing.T) {
	head := `{"SchemaVersion":2,"ArtifactName":"` + pkgDigest + `","Metadata":{"OS":{"Family":"alpine","Name":"3.19.1"}},` +
		`"Results":[{"Class":"os-pkgs","Type":"alpine","Packages":[`
	for name, unit := range map[string]string{"empty objects": "{},", "nulls": "null,", "numbers": "0,"} {
		t.Run(name, func(t *testing.T) {
			var sb strings.Builder
			sb.Grow(MaxImagePackagesOutput)
			sb.WriteString(head)
			for sb.Len()+len(unit)+len("{}]}]}") <= MaxImagePackagesOutput {
				sb.WriteString(unit)
			}
			sb.WriteString("{}]}]}")
			b := []byte(sb.String())
			sb.Reset()
			if len(b) > MaxImagePackagesOutput || len(b) < MaxImagePackagesOutput-16 {
				t.Fatalf("stream size %d", len(b))
			}
			var got ImagePackages
			alloc := allocatedBytes(func() { got, _ = ParseImagePackages(pkgDigest, okRun(b)) })
			if !got.Known || got.Complete || !hasReason(got.Reason, ReasonLimitReached) || !hasReason(got.Reason, ReasonEntryDropped) {
				t.Fatalf("flood must stop at the cap: %+v", got)
			}
			if len(got.Packages) != 0 {
				t.Fatalf("packages %d", len(got.Packages))
			}
			t.Logf("one read allocated %d bytes", alloc)
			const budget = 4 << 20
			if alloc > budget {
				t.Fatalf("one read allocated %d bytes, budget %d", alloc, budget)
			}
		})
	}
}

// Every array and object the parser streams is capped, so large arrays
// outside Packages cannot make one read allocate per element either.
func TestImagePackagesOtherFloodsBounded(t *testing.T) {
	pre := `{"SchemaVersion":2,"ArtifactName":"` + pkgDigest + `",`
	osMeta := `"OS":{"Family":"alpine","Name":"3.19.1"}`
	const small = 4 << 20
	cases := map[string]struct {
		head, unit, tail string
		budget           uint64
	}{
		"repo digests": {pre + `"Metadata":{` + osMeta + `,"RepoDigests":[`, `"a",`, `"a"]},"Results":[]}`, small},
		"results":      {pre + `"Metadata":{` + osMeta + `},"Results":[`, `{},`, `{}]}`, small},
		"null results": {pre + `"Metadata":{` + osMeta + `},"Results":[`, `null,`, `null]}`, small},
		"keys":         {pre + `"Metadata":{` + osMeta + `,`, `"k":0,`, `"k":0},"Results":[]}`, small},
		"result keys":  {pre + `"Metadata":{` + osMeta + `},"Results":[{`, `"k":0,`, `"k":0}]}`, small},
		// A skipped value is walked on the raw bytes, never buffered.
		"skipped tree": {pre + `"Metadata":{` + osMeta + `,"ImageConfig":[`, `"aa",`, `"a"]},"Results":[]}`, small},
		"entry keys":   {pre + `"Metadata":{` + osMeta + `},"Results":[{"Class":"os-pkgs","Type":"alpine","Packages":[{`, `"k":0,`, `"k":0}]}]}`, small},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			var sb strings.Builder
			sb.Grow(MaxImagePackagesOutput)
			sb.WriteString(c.head)
			for sb.Len()+len(c.unit)+len(c.tail) <= MaxImagePackagesOutput {
				sb.WriteString(c.unit)
			}
			sb.WriteString(c.tail)
			b := []byte(sb.String())
			sb.Reset()
			var got ImagePackages
			alloc := allocatedBytes(func() { got, _ = ParseImagePackages(pkgDigest, okRun(b)) })
			if got.Complete {
				t.Fatalf("flood must not be complete: %+v", got)
			}
			t.Logf("one read allocated %d bytes", alloc)
			if alloc > c.budget {
				t.Fatalf("one read allocated %d bytes, budget %d", alloc, c.budget)
			}
		})
	}
}

// hugeValueSize is the size of the single hostile value in
// TestImagePackagesHugeSingleValueBounded: close to the output limit.
const hugeValueSize = 30 << 20

// jsonEsc spells JSON escapes in test documents: every '~' becomes a
// backslash, so "~u0061" is the JSON escape of "a".
func jsonEsc(s string) string { return strings.ReplaceAll(s, "~", `\`) }

// One huge string, key, number or skipped value must never be copied into
// memory: a read allocates at most a small fixed amount beyond the raw
// output it is given, whatever a single value in it holds.
func TestImagePackagesHugeSingleValueBounded(t *testing.T) {
	const budget = 1 << 20
	osMeta := `"Metadata":{"OS":{"Family":"alpine","Name":"3.19.1"}}`
	pre := `{"SchemaVersion":2,"ArtifactName":"` + pkgDigest + `",`
	musl := `{"Name":"musl","Version":"1.2.4-r2"}`
	pkgsHead := pre + osMeta + `,"Results":[{"Class":"os-pkgs","Type":"alpine","Packages":[`
	pkgsTail := `]}]}`
	results := `"Results":[{"Class":"os-pkgs","Type":"alpine","Packages":[` + musl + `]}]}`
	escA := jsonEsc("~u0061") // JSON escape of "a"
	type check func(t *testing.T, got ImagePackages)
	partial := func(reason string, pkgs int) check {
		return func(t *testing.T, got ImagePackages) {
			if !got.Known || got.Complete || !hasReason(got.Reason, reason) || len(got.Packages) != pkgs {
				t.Fatalf("want known partial %q with %d packages, got known=%v complete=%v reason=%q packages=%d",
					reason, pkgs, got.Known, got.Complete, got.Reason, len(got.Packages))
			}
		}
	}
	unparseable := func(t *testing.T, got ImagePackages) {
		if got.Known || got.Complete || got.Reason != ReasonUnparseable || got.Packages != nil {
			t.Fatalf("want unparseable, got known=%v complete=%v reason=%q", got.Known, got.Complete, got.Reason)
		}
	}
	complete := func(t *testing.T, got ImagePackages) {
		if !got.Complete || len(got.Packages) != 1 || got.Packages[0].Name != "musl" {
			t.Fatalf("want complete read of musl, got complete=%v reason=%q packages=%d", got.Complete, got.Reason, len(got.Packages))
		}
	}
	// Each case is head + unit repeated up to hugeValueSize + tail.
	cases := map[string]struct {
		head, unit, tail string
		check            check
	}{
		"package name":         {pkgsHead + `{"Name":"`, "a", `","Version":"1"},` + musl + pkgsTail, partial(ReasonEntryDropped, 1)},
		"escaped package name": {pkgsHead + `{"Name":"`, escA, `","Version":"1"},` + musl + pkgsTail, partial(ReasonEntryDropped, 1)},
		"package version":      {pkgsHead + `{"Name":"x","Version":"`, "1", `"},` + musl + pkgsTail, partial(ReasonEntryDropped, 1)},
		"source name":          {pkgsHead + `{"Name":"x","Version":"1","SrcName":"`, "s", `"},` + musl + pkgsTail, partial(ReasonEntryDropped, 1)},
		"package epoch":        {pkgsHead + `{"Name":"x","Version":"1","Epoch":1`, "0", `},` + musl + pkgsTail, partial(ReasonEntryDropped, 1)},
		"entry key":            {pkgsHead + `{"`, "k", `":1,"Name":"musl","Version":"1.2.4-r2"}` + pkgsTail, complete},
		"escaped entry key":    {pkgsHead + `{"`, escA, `":1,"Name":"musl","Version":"1.2.4-r2"}` + pkgsTail, complete},
		"entry skipped value":  {pkgsHead + `{"Licenses":["`, "l", `"],"Name":"musl","Version":"1.2.4-r2"}` + pkgsTail, complete},
		"result type": {pre + osMeta + `,"Results":[{"Class":"os-pkgs","Type":"`, "a",
			`","Packages":[` + musl + `]}]}`, partial(ReasonEntryDropped, 0)},
		"result class": {pre + osMeta + `,"Results":[{"Type":"alpine","Class":"`, "c",
			`","Packages":[` + musl + `]}]}`, partial(ReasonEntryDropped, 0)},
		"result key": {pre + osMeta + `,"Results":[{"`, "k",
			`":0,"Class":"os-pkgs","Type":"alpine","Packages":[` + musl + `]}]}`, unparseable},
		"escaped result key": {pre + osMeta + `,"Results":[{"`, escA,
			`":0,"Class":"os-pkgs","Type":"alpine","Packages":[` + musl + `]}]}`, unparseable},
		"document key":    {pre + `"`, "k", `":0,` + osMeta + `,` + results, unparseable},
		"metadata key":    {pre + `"Metadata":{"`, "k", `":0,"OS":{"Family":"alpine","Name":"3.19.1"}},` + results, unparseable},
		"os family":       {pre + `"Metadata":{"OS":{"Name":"3.19.1","Family":"`, "a", `"}},` + results, partial(ReasonOSUndetected, 1)},
		"os key":          {pre + `"Metadata":{"OS":{"Family":"alpine","Name":"3.19.1","`, "k", `":0}},` + results, complete},
		"artifact name":   {`{"SchemaVersion":2,"ArtifactName":"`, "a", `",` + osMeta + `,` + results, partial(ReasonDigestMismatch, 1)},
		"schema version":  {`{"SchemaVersion":2`, "0", `,` + osMeta + `,` + results, unparseable},
		"skipped string":  {pre + `"Metadata":{"OS":{"Family":"alpine","Name":"3.19.1"},"ImageConfig":"`, "x", `"},` + results, complete},
		"skipped escapes": {pre + `"Metadata":{"OS":{"Family":"alpine","Name":"3.19.1"},"ImageConfig":"`, jsonEsc("~n"), `"},` + results, complete},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			var sb strings.Builder
			sb.Grow(len(c.head) + hugeValueSize + len(c.tail))
			sb.WriteString(c.head)
			for n := 0; n+len(c.unit) <= hugeValueSize; n += len(c.unit) {
				sb.WriteString(c.unit)
			}
			sb.WriteString(c.tail)
			b := []byte(sb.String())
			sb.Reset()
			if len(b) > MaxImagePackagesOutput {
				t.Fatalf("output %d over limit", len(b))
			}
			var got ImagePackages
			alloc := allocatedBytes(func() { got, _ = ParseImagePackages(pkgDigest, okRun(b)) })
			c.check(t, got)
			t.Logf("one read allocated %d bytes", alloc)
			if alloc > budget {
				t.Fatalf("one read allocated %d bytes, budget %d", alloc, budget)
			}
		})
	}
}

// Escaped JSON strings (keys and values, including surrogate pairs) decode
// to the same values as unescaped ones.
func TestImagePackagesEscapedValues(t *testing.T) {
	// The skipped ImageConfig holds escaped quotes and backslashes next to
	// brackets, which must not end the string or the object early.
	b := []byte(jsonEsc(`{"SchemaVersion":2,"ArtifactName":"` + pkgDigest + `","Metadata":{"O~u0053":{"Family":"alp~u0069ne","Name":"3.19.1"},` +
		`"ImageConfig":{"k":"~~~"}]~~","l":["]~"",{"~~":"}"}]}},` +
		`"Results":[{"Cl~u0061ss":"os-pkgs","Type":"alpine","Packages":[{"N~u0061me":"mus~u006c","Version":"1.2.4~/r2","SrcName":"~u00e9t~u00E9~ud83d~ude00"}]}]}`))
	got, _ := ParseImagePackages(pkgDigest, okRun(b))
	if !got.Complete || len(got.Packages) != 1 {
		t.Fatalf("got %+v", got)
	}
	want := ImagePackage{Ecosystem: "alpine", Name: "musl", Version: "1.2.4/r2", SrcName: string([]rune{0xe9, 't', 0xe9, 0x1f600})}
	if got.Packages[0] != want || got.OS.Family != "alpine" {
		t.Fatalf("got %+v", got)
	}
}

// Field names match exactly; a repeated package field is ambiguous and
// drops the entry; a repeated OS field leaves the OS undetected.
func TestImagePackagesEntryFieldsExact(t *testing.T) {
	meta := `"Metadata":{"OS":{"Family":"alpine","Name":"3.19.1"}}`
	for name, entry := range map[string]string{
		"lower-case name": `{"name":"x","Version":"1"}`,
		"repeated name":   `{"Name":"x","Name":"y","Version":"1"}`,
		"repeated epoch":  `{"Name":"x","Version":"1","Epoch":1,"Epoch":2}`,
	} {
		t.Run(name, func(t *testing.T) {
			b := []byte(`{"SchemaVersion":2,"ArtifactName":"` + pkgDigest + `",` + meta + `,` +
				`"Results":[{"Class":"os-pkgs","Type":"alpine","Packages":[` + entry + `,{"Name":"musl","Version":"1.2.4-r2"}]}]}`)
			got, _ := ParseImagePackages(pkgDigest, okRun(b))
			if !got.Known || got.Complete || got.Reason != ReasonEntryDropped || len(got.Packages) != 1 {
				t.Fatalf("got %+v", got)
			}
		})
	}
	b := []byte(`{"SchemaVersion":2,"ArtifactName":"` + pkgDigest + `","Metadata":{"OS":{"Family":"alpine","Family":"debian","Name":"3.19.1"}},` +
		`"Results":[{"Class":"os-pkgs","Type":"alpine","Packages":[{"Name":"musl","Version":"1"}]}]}`)
	got, _ := ParseImagePackages(pkgDigest, okRun(b))
	if got.Complete || got.Reason != ReasonOSUndetected {
		t.Fatalf("got %+v", got)
	}
}

// Decoding stops at a cap; when that happens before SchemaVersion was read
// (Trivy writes it first), the output is unparseable, never complete.
func TestImagePackagesCapBeforeSchemaUnparseable(t *testing.T) {
	var sb strings.Builder
	sb.WriteString(`{"Results":[{"Class":"os-pkgs","Type":"alpine","Packages":[`)
	for i := 0; i <= maxImagePkgEntries; i++ {
		fmt.Fprintf(&sb, `{"Name":"p%d","Version":"1"},`, i)
	}
	sb.WriteString(`{}]}],"SchemaVersion":2}`)
	got, _ := ParseImagePackages(pkgDigest, okRun([]byte(sb.String())))
	if got.Known || got.Complete || got.Reason != ReasonUnparseable {
		t.Fatalf("got known=%v complete=%v reason=%q", got.Known, got.Complete, got.Reason)
	}
}

func TestImagePackagesDuplicateKeysUnparseable(t *testing.T) {
	meta := `"Metadata":{"OS":{"Family":"alpine","Name":"3.19.1"}}`
	res := `"Results":[{"Class":"os-pkgs","Type":"alpine","Packages":[{"Name":"musl","Version":"1"}]}]`
	for name, b := range map[string]string{
		"schema":   `{"SchemaVersion":2,"SchemaVersion":2,"ArtifactName":"` + pkgDigest + `",` + meta + `,` + res + `}`,
		"artifact": `{"SchemaVersion":2,"ArtifactName":"` + pkgDigest + `","ArtifactName":"x",` + meta + `,` + res + `}`,
		"metadata": `{"SchemaVersion":2,"ArtifactName":"` + pkgDigest + `",` + meta + `,` + meta + `,` + res + `}`,
		"os":       `{"SchemaVersion":2,"ArtifactName":"` + pkgDigest + `","Metadata":{"OS":null,"OS":{"Family":"alpine","Name":"3.19.1"}},` + res + `}`,
		"class":    `{"SchemaVersion":2,"ArtifactName":"` + pkgDigest + `",` + meta + `,"Results":[{"Class":"os-pkgs","Class":"lang-pkgs","Type":"alpine","Packages":[]}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			got, _ := ParseImagePackages(pkgDigest, okRun([]byte(b)))
			if got.Known || got.Complete || got.Reason != ReasonUnparseable {
				t.Fatalf("got %+v", got)
			}
		})
	}
}

// Results may name Class and Type after Packages; the order of keys does
// not change the outcome.
func TestImagePackagesResultKeyOrder(t *testing.T) {
	b := []byte(`{"Results":[{"Packages":[{"Name":"musl","Version":"1.2.4-r2"}],"Type":"alpine","Class":"os-pkgs"}],` +
		`"Metadata":{"RepoDigests":["alpine@sha256:` + pkgDigestHex + `"],"OS":{"Name":"3.19.1","Family":"alpine"}},"SchemaVersion":2}`)
	got, _ := ParseImagePackages(pkgDigest, okRun(b))
	if !got.Complete || len(got.Packages) != 1 || got.Packages[0].Ecosystem != "alpine" {
		t.Fatalf("got %+v", got)
	}
}

func TestImagePackagesStructuralErrorsUnparseable(t *testing.T) {
	meta := `"Metadata":{"OS":{"Family":"alpine","Name":"3.19.1"}}`
	for name, b := range map[string]string{
		"no schema":        `{"ArtifactName":"` + pkgDigest + `",` + meta + `,"Results":[]}`,
		"schema string":    `{"SchemaVersion":"2",` + meta + `}`,
		"results object":   `{"SchemaVersion":2,` + meta + `,"Results":{}}`,
		"result scalar":    `{"SchemaVersion":2,` + meta + `,"Results":[1]}`,
		"packages object":  `{"SchemaVersion":2,` + meta + `,"Results":[{"Class":"os-pkgs","Type":"alpine","Packages":{}}]}`,
		"metadata array":   `{"SchemaVersion":2,"Metadata":[]}`,
		"truncated":        `{"SchemaVersion":2,` + meta + `,"Results":[{"Class":"os-pkgs","Type":"alpine","Packages":[{"Name":"a"`,
		"syntax in entry":  `{"SchemaVersion":2,` + meta + `,"Results":[{"Class":"os-pkgs","Type":"alpine","Packages":[{"Name":"a",}]}]}`,
		"trailing garbage": `{"SchemaVersion":2,` + meta + `,"Results":[]} x`,
	} {
		t.Run(name, func(t *testing.T) {
			got, _ := ParseImagePackages(pkgDigest, okRun([]byte(b)))
			if got.Known || got.Complete || got.Packages != nil || got.Reason != ReasonUnparseable {
				t.Fatalf("got %+v", got)
			}
		})
	}
}

// An OS value of the wrong JSON type leaves the OS undetected; the rest of
// the document is still read.
func TestImagePackagesOSTypeMismatchUndetected(t *testing.T) {
	for name, osv := range map[string]string{
		"scalar":         `"alpine"`,
		"numeric family": `{"Family":1,"Name":"3.19.1"}`,
		"array":          `[]`,
	} {
		t.Run(name, func(t *testing.T) {
			b := []byte(`{"SchemaVersion":2,"ArtifactName":"` + pkgDigest + `","Metadata":{"OS":` + osv + `},` +
				`"Results":[{"Class":"os-pkgs","Type":"alpine","Packages":[{"Name":"musl","Version":"1"}]}]}`)
			got, _ := ParseImagePackages(pkgDigest, okRun(b))
			if !got.Known || got.Complete || got.Reason != ReasonOSUndetected || len(got.Packages) != 1 {
				t.Fatalf("got %+v", got)
			}
		})
	}
}

func allocatedBytes(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
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
