// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfinding

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestParseRecordAcceptsReferenceRecords(t *testing.T) {
	for name, s := range map[string]string{
		"host": validHostJSON, "image": validImageJSON, "device": validDeviceJSON,
		"reordered": validHostJSONReordered,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseRecord([]byte(s)); err != nil {
				t.Fatalf("ParseRecord: %v", err)
			}
		})
	}
}

func TestParseRecordSetsTrackerNote(t *testing.T) {
	f := mustParse(t, validHostJSON)
	if f.TrackerNote != "" {
		t.Fatalf("note for fixed state = %q", f.TrackerNote)
	}
	r := f.Record
	r.TrackerState = TrackerNoDSA
	r.Fix = Fix{State: FixNoFixYet}
	g, err := Validate(r)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if g.TrackerNote != "no DSA (may come in a point release)" {
		t.Fatalf("note = %q", g.TrackerNote)
	}
}

// setField returns validHostJSON with one top-level field replaced (or
// added) by raw JSON.
func setField(t *testing.T, base, key, raw string) string {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(base), &m); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	if raw == "" {
		delete(m, key)
	} else {
		m[key] = json.RawMessage(raw)
	}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return string(out)
}

// TestHermesSuppliedKeyIsRejected: NOS computes finding_key; a key (or any
// other NOS-owned field) in the record is an unknown field.
func TestHermesSuppliedKeyIsRejected(t *testing.T) {
	for _, field := range []string{"finding_key", "key", "nos_checked", "observer", "state"} {
		t.Run(field, func(t *testing.T) {
			s := setField(t, validHostJSON, field, `"355ae62bf858227c68327851cf17d236cdc68db9da6409a07e5f398779f8d611"`)
			_, err := ParseRecord([]byte(s))
			if !errors.Is(err, ErrUnknownField) {
				t.Fatalf("err = %v, want ErrUnknownField", err)
			}
		})
	}
	// Case-folded or Unicode-folded spellings must not slip through the
	// case-insensitive matching of encoding/json.
	for _, k := range []string{"Finding_Key", "FINDING_KEY", "Subject_Kind", "ſubject_kind"} {
		t.Run("folded "+k, func(t *testing.T) {
			s := strings.Replace(validHostJSON, `"subject_kind"`, `"`+k+`"`, 1)
			if k == "Finding_Key" || k == "FINDING_KEY" {
				s = strings.Replace(validHostJSON, "{\n", `{"`+k+`":"x",`, 1)
			}
			if _, err := ParseRecord([]byte(s)); !errors.Is(err, ErrMalformed) {
				t.Fatalf("key %q: err = %v, want ErrMalformed", k, err)
			}
		})
	}
}

func TestUnknownFieldsRejectedAtEveryLevel(t *testing.T) {
	cases := map[string]string{
		"top":        strings.Replace(validHostJSON, `"ecosystem"`, `"extra": 1, "ecosystem"`, 1),
		"component":  strings.Replace(validHostJSON, `"source_package"`, `"url": "x", "source_package"`, 1),
		"binary":     strings.Replace(validHostJSON, `{"name": "libssl3"`, `{"arch": "amd64", "name": "libssl3"`, 1),
		"vuln":       strings.Replace(validHostJSON, `"aliases"`, `"link": "x", "aliases"`, 1),
		"fix":        strings.Replace(validHostJSON, `{"state": "fixed"`, `{"date": "x", "state": "fixed"`, 1),
		"cvss":       strings.Replace(validHostJSON, `"base_score"`, `"temporal": 1, "base_score"`, 1),
		"basis":      strings.Replace(validHostJSON, `"snapshot_id": "sha256-0a1b2c"`, `"url": "x", "snapshot_id": "sha256-0a1b2c"`, 1),
		"evidence":   strings.Replace(validHostJSON, `"matcher_version"`, `"nos_checked": true, "matcher_version"`, 1),
		"assessment": strings.Replace(validHostJSON, `"backport_checked"`, `"score": 1, "backport_checked"`, 1),
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseRecord([]byte(s)); !errors.Is(err, ErrUnknownField) {
				t.Fatalf("err = %v, want ErrUnknownField", err)
			}
		})
	}
}

func TestMalformedJSONRejected(t *testing.T) {
	cases := map[string]string{
		"empty":         ``,
		"null":          `null`,
		"array":         `[]`,
		"string":        `"x"`,
		"truncated":     validHostJSON[:len(validHostJSON)-3],
		"trailing data": validHostJSON + ` {}`,
		"two objects":   validHostJSON + validHostJSON,
		"duplicate key": strings.Replace(validHostJSON, `"ecosystem": "debian:bookworm",`, `"ecosystem": "debian:bookworm", "ecosystem": "debian:trixie",`, 1),
		"duplicate nested key": strings.Replace(validHostJSON, `{"state": "fixed",`,
			`{"state": "no_fix_yet", "state": "fixed",`, 1),
		"wrong type": strings.Replace(validHostJSON, `"base_score": 9.8`, `"base_score": "9.8"`, 1),
		"too deep":   strings.Replace(validHostJSON, `"ecosystem"`, `"x":`+strings.Repeat("[", 40)+strings.Repeat("]", 40)+`, "ecosystem"`, 1),
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseRecord([]byte(s))
			if err == nil {
				t.Fatalf("accepted")
			}
		})
	}
}

func TestInvalidUTF8Rejected(t *testing.T) {
	cases := map[string]string{
		"raw byte in text":  strings.Replace(validHostJSON, "Likely reachable.", "Likely \xff reachable.", 1),
		"raw byte in key":   strings.Replace(validHostJSON, `"ecosystem"`, "\"eco\xc3system\"", 1),
		"overlong encoding": strings.Replace(validHostJSON, "Likely reachable.", "Likely \xc0\xaf reachable.", 1),
		"surrogate escape":  strings.Replace(validHostJSON, "Likely reachable.", `Likely \ud800 reachable.`, 1),
		"encoded surrogate": strings.Replace(validHostJSON, "Likely reachable.", "Likely \xed\xa0\x80 reachable.", 1),
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseRecord([]byte(s))
			if !errors.Is(err, ErrInvalidUTF8) {
				t.Fatalf("err = %v, want ErrInvalidUTF8", err)
			}
		})
	}
}

func TestRecordSizeLimit(t *testing.T) {
	big := strings.Replace(validHostJSON, "{\n", "{\n"+strings.Repeat(" ", MaxRecordBytes), 1)
	if _, err := ParseRecord([]byte(big)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
}

func TestEmptyBasisSourcesRejected(t *testing.T) {
	for name, raw := range map[string]string{
		"empty list": `{"basis_sources": [], "matcher_version": "1.4.0"}`,
		"null list":  `{"basis_sources": null, "matcher_version": "1.4.0"}`,
		"missing":    `{"matcher_version": "1.4.0"}`,
	} {
		t.Run(name, func(t *testing.T) {
			s := setField(t, validHostJSON, "evidence", raw)
			if _, err := ParseRecord([]byte(s)); !errors.Is(err, ErrEmptyBasisSources) {
				t.Fatalf("err = %v, want ErrEmptyBasisSources", err)
			}
		})
	}
}

func TestBasisSourceValidation(t *testing.T) {
	src := func(id, snap, mode string) string {
		return fmt.Sprintf(`{"source_id": %q, "snapshot_id": %q, "integrity": %q}`, id, snap, mode)
	}
	ok := src("osv", "snap-1", "none")
	many := make([]string, MaxBasisSources+1)
	for i := range many {
		many[i] = src(fmt.Sprintf("s%d", i), "snap", "none")
	}
	cases := map[string]string{
		"upper-case id":      src("OSV", "snap", "none"),
		"id too long":        src(strings.Repeat("a", 65), "snap", "none"),
		"id with slash":      src("osv/x", "snap", "none"),
		"empty snapshot":     src("osv", "", "none"),
		"bad integrity":      src("osv", "snap", "trusted"),
		"duplicate":          ok + "," + ok,
		"too many":           strings.Join(many, ","),
		"snapshot too long":  src("osv", strings.Repeat("a", 129), "none"),
		"snapshot with path": src("osv", "../x", "none"),
	}
	for name, list := range cases {
		t.Run(name, func(t *testing.T) {
			s := setField(t, validHostJSON, "evidence", `{"basis_sources": [`+list+`], "matcher_version": "1"}`)
			if _, err := ParseRecord([]byte(s)); !errors.Is(err, ErrInvalidField) {
				t.Fatalf("err = %v, want ErrInvalidField", err)
			}
		})
	}
	// Boundary: exactly 64-byte ID and MaxBasisSources entries are fine.
	exact := make([]string, MaxBasisSources)
	for i := range exact {
		exact[i] = src(fmt.Sprintf("s%d", i), "snap", "checksum")
	}
	exact[0] = src(strings.Repeat("a", 64), "snap", "signed")
	s := setField(t, validHostJSON, "evidence", `{"basis_sources": [`+strings.Join(exact, ",")+`], "matcher_version": "1"}`)
	if _, err := ParseRecord([]byte(s)); err != nil {
		t.Fatalf("boundary rejected: %v", err)
	}
	s = setField(t, validHostJSON, "evidence", `{"basis_sources": [`+ok+`]}`)
	if _, err := ParseRecord([]byte(s)); !errors.Is(err, ErrMissingField) {
		t.Fatalf("missing matcher_version: err = %v", err)
	}
}

func TestVulnIDRegex(t *testing.T) {
	good := []string{"CVE-2024-3400", "GHSA-xxxx-xxxx-xxxx", "DSA-5000-1", "USN-6000-1", "PAN-SA-2024-0004",
		"cisco-sa-iosxe-webui-privesc-j22SaA4z", "OSV-2024-1", "ab", "A" + strings.Repeat("b", 63), "RUSTSEC-2024:0001.x_y"}
	bad := []string{"", "a", "-CVE-1", ".x", "A" + strings.Repeat("b", 64), "CVE 2024", "CVE/2024", "CVE-2024-1\n",
		"https://x", "CVE-2024-ü", "<script>"}
	for _, id := range good {
		t.Run("good "+id, func(t *testing.T) {
			r := mustParse(t, validHostJSON).Record
			r.Vuln.ID = id
			r.Vuln.Aliases = nil
			if _, err := Validate(r); err != nil {
				t.Fatalf("rejected: %v", err)
			}
			r = mustParse(t, validHostJSON).Record
			r.Vuln.Aliases = []string{id}
			if _, err := Validate(r); err != nil && id != "CVE-2024-12345" {
				t.Fatalf("alias rejected: %v", err)
			}
		})
	}
	for _, id := range bad {
		t.Run(fmt.Sprintf("bad %q", id), func(t *testing.T) {
			r := mustParse(t, validHostJSON).Record
			r.Vuln.ID = id
			if _, err := Validate(r); err == nil {
				t.Fatalf("primary ID accepted")
			}
			r = mustParse(t, validHostJSON).Record
			r.Vuln.Aliases = []string{id}
			if _, err := Validate(r); !errors.Is(err, ErrInvalidField) {
				t.Fatalf("alias: err = %v, want ErrInvalidField", err)
			}
		})
	}
}

func TestAliasLimits(t *testing.T) {
	r := mustParse(t, validHostJSON).Record
	r.Vuln.Aliases = nil
	for i := 0; i < MaxAliases; i++ {
		r.Vuln.Aliases = append(r.Vuln.Aliases, fmt.Sprintf("DSA-%d-1", 1000+i))
	}
	if _, err := Validate(r); err != nil {
		t.Fatalf("%d aliases rejected: %v", MaxAliases, err)
	}
	r.Vuln.Aliases = append(r.Vuln.Aliases, "DSA-9999-1")
	if _, err := Validate(r); !errors.Is(err, ErrInvalidField) {
		t.Fatalf("%d aliases: err = %v", MaxAliases+1, err)
	}
	r.Vuln.Aliases = []string{"DSA-1-1", "DSA-1-1"}
	if _, err := Validate(r); !errors.Is(err, ErrInvalidField) {
		t.Fatalf("duplicate alias: err = %v", err)
	}
	r.Vuln.Aliases = []string{"cve-2024-12345"}
	if _, err := Validate(r); !errors.Is(err, ErrInvalidField) {
		t.Fatalf("alias equal to primary: err = %v", err)
	}
}

func TestAssessmentTextLimits(t *testing.T) {
	r := mustParse(t, validHostJSON).Record
	r.Assessment.Text = strings.Repeat("a", MaxAssessmentBytes)
	if _, err := Validate(r); err != nil {
		t.Fatalf("4 KiB rejected: %v", err)
	}
	r.Assessment.Text = strings.Repeat("ä", MaxAssessmentBytes/2) // exactly 4096 bytes
	if _, err := Validate(r); err != nil {
		t.Fatalf("4 KiB multibyte rejected: %v", err)
	}
	bad := map[string]string{
		"too long":          strings.Repeat("a", MaxAssessmentBytes+1),
		"too long by bytes": strings.Repeat("ä", MaxAssessmentBytes/2) + "a",
		"NUL":               "a\x00b",
		"escape":            "a\x1b[31mred",
		"carriage return":   "a\rb",
		"DEL":               "a\x7fb",
		"C1 control":        "a\u0085b",
		"bidi override":     "a‮b",
		"bidi isolate":      "a⁦b",
		"replacement char":  "a�b",
		"invalid utf8":      "a\xffb",
	}
	for name, text := range bad {
		t.Run(name, func(t *testing.T) {
			r := mustParse(t, validHostJSON).Record
			r.Assessment.Text = text
			if _, err := Validate(r); err == nil {
				t.Fatalf("accepted")
			}
		})
	}
	r.Assessment.Text = "line one\n\tline two – ünïcödé"
	if _, err := Validate(r); err != nil {
		t.Fatalf("printable text rejected: %v", err)
	}
}

func TestFixStates(t *testing.T) {
	base := mustParse(t, validImageJSON).Record
	cases := []struct {
		fix   Fix
		ok    bool
		opens bool
	}{
		{Fix{State: FixFixed, Version: "1.2.5-r1"}, true, true},
		{Fix{State: FixNoFixYet}, true, true},
		{Fix{State: FixWontFix}, true, true},
		{Fix{State: FixNotAffected}, true, false},
		{Fix{State: FixFixed}, false, false},                            // version missing
		{Fix{State: FixNoFixYet, Version: "1.2.5-r1"}, false, false},    // version not allowed
		{Fix{State: FixNotAffected, Version: "1.2.5-r1"}, false, false}, // version not allowed
		{Fix{State: FixFixed, Version: "1 2"}, false, false},
		{Fix{State: FixFixed, Version: strings.Repeat("1", 129)}, false, false},
		{Fix{State: "fixed_maybe"}, false, false},
		{Fix{}, false, false},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s/%s", tc.fix.State, tc.fix.Version), func(t *testing.T) {
			r := base
			r.Fix = tc.fix
			f, err := Validate(r)
			if tc.ok != (err == nil) {
				t.Fatalf("err = %v, want ok=%v", err, tc.ok)
			}
			if err == nil && f.Record.Fix.State.Opens() != tc.opens {
				t.Fatalf("Opens = %v", !tc.opens)
			}
		})
	}
}

func TestSubjectValidation(t *testing.T) {
	digest := "sha256:" + strings.Repeat("0", 64)
	cases := map[string]func(r *Record){
		"unknown kind":          func(r *Record) { r.SubjectKind = "vm" },
		"empty kind":            func(r *Record) { r.SubjectKind = "" },
		"empty id":              func(r *Record) { r.SubjectRef.ID = "" },
		"upper-case id":         func(r *Record) { r.SubjectRef.ID = "Web01" },
		"id too long":           func(r *Record) { r.SubjectRef.ID = strings.Repeat("a", 64) },
		"host with digest":      func(r *Record) { r.SubjectRef.ImageDigest = digest },
		"image without digest":  func(r *Record) { r.SubjectKind = SubjectImage },
		"image with bad digest": func(r *Record) { r.SubjectKind = SubjectImage; r.SubjectRef.ImageDigest = "sha256:ABC" },
		"image with md5": func(r *Record) {
			r.SubjectKind = SubjectImage
			r.SubjectRef.ImageDigest = "md5:" + strings.Repeat("0", 32)
		},
		"host on vendor ecosystem": func(r *Record) { r.Ecosystem = "vendor:paloalto:panos" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := mustParse(t, validHostJSON).Record
			mutate(&r)
			if _, err := Validate(r); err == nil {
				t.Fatalf("accepted")
			}
		})
	}
	d := mustParse(t, validDeviceJSON).Record
	d.Ecosystem = "debian:bookworm"
	if _, err := Validate(d); err == nil {
		t.Fatalf("device on distro ecosystem accepted")
	}
}

func TestEcosystemValidation(t *testing.T) {
	good := []string{"debian:bookworm", "debian:trixie", "ubuntu:24.04", "alpine:3.20", "Go", "npm", "PyPI", "crates.io"}
	bad := []string{"", "debian", "debian:", "debian:Bookworm", "ubuntu:noble", "alpine:edge", "golang", "pypi",
		"vendor:paloalto:panos", "debian:bookworm\n", "osv:Go"}
	for _, eco := range good {
		t.Run("good "+eco, func(t *testing.T) {
			r := mustParse(t, validImageJSON).Record
			r.Ecosystem = eco
			if _, err := Validate(r); err != nil {
				t.Fatalf("rejected: %v", err)
			}
		})
	}
	for _, eco := range bad {
		t.Run(fmt.Sprintf("bad %q", eco), func(t *testing.T) {
			r := mustParse(t, validImageJSON).Record
			r.Ecosystem = eco
			if _, err := Validate(r); err == nil {
				t.Fatalf("accepted")
			}
		})
	}
	r := mustParse(t, validImageJSON).Record
	r.Ecosystem = "proxmox"
	if _, err := Validate(r); !errors.Is(err, ErrCoverageOnly) {
		t.Fatalf("proxmox: err = %v, want ErrCoverageOnly", err)
	}
	for _, eco := range []string{"vendor:cisco:iosxe", "vendor:cisco:nxos", "vendor:paloalto:panos"} {
		d := mustParse(t, validDeviceJSON).Record
		d.Ecosystem = eco
		if _, err := Validate(d); err != nil {
			t.Fatalf("%s rejected: %v", eco, err)
		}
	}
	d := mustParse(t, validDeviceJSON).Record
	d.Ecosystem = "vendor:juniper:junos"
	if _, err := Validate(d); err == nil {
		t.Fatalf("unknown vendor accepted")
	}
}

func TestComponentValidation(t *testing.T) {
	cases := map[string]func(r *Record){
		"empty source package":   func(r *Record) { r.Component.SourcePackage = "" },
		"empty source version":   func(r *Record) { r.Component.SourceVersion = "" },
		"upper-case package":     func(r *Record) { r.Component.SourcePackage = "OpenSSL" },
		"package with space":     func(r *Record) { r.Component.SourcePackage = "open ssl" },
		"package too long":       func(r *Record) { r.Component.SourcePackage = "a" + strings.Repeat("b", 128) },
		"version with space":     func(r *Record) { r.Component.SourceVersion = "3.0 1" },
		"version too long":       func(r *Record) { r.Component.SourceVersion = strings.Repeat("1", 129) },
		"model on host":          func(r *Record) { r.Component.Model = "PA-440" },
		"firmware on host":       func(r *Record) { r.Component.Firmware = "11.1" },
		"bad binary name":        func(r *Record) { r.Component.Binaries = []Binary{{Name: "Lib SSL", Version: "1"}} },
		"bad binary version":     func(r *Record) { r.Component.Binaries = []Binary{{Name: "libssl3", Version: ""}} },
		"duplicate binary":       func(r *Record) { r.Component.Binaries = []Binary{{"libssl3", "1"}, {"libssl3", "2"}} },
		"too many binaries":      func(r *Record) { r.Component.Binaries = manyBinaries(MaxBinaries + 1) },
		"signed kernel source":   func(r *Record) { r.Component.SourcePackage = "linux-signed-amd64" },
		"meta kernel source":     func(r *Record) { r.Component.SourcePackage = "linux-meta" },
		"meta hwe kernel source": func(r *Record) { r.Component.SourcePackage = "linux-meta-hwe-6.8" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := mustParse(t, validHostJSON).Record
			mutate(&r)
			if _, err := Validate(r); err == nil {
				t.Fatalf("accepted")
			}
		})
	}
	r := mustParse(t, validHostJSON).Record
	r.Component.SourcePackage = "linux-signed-amd64"
	if _, err := Validate(r); !errors.Is(err, ErrKernelSourcePackage) {
		t.Fatalf("signed kernel: err = %v, want ErrKernelSourcePackage", err)
	}
	r = mustParse(t, validHostJSON).Record
	r.Component.SourcePackage = "linux"
	r.Component.Binaries = manyBinaries(MaxBinaries)
	if _, err := Validate(r); err != nil {
		t.Fatalf("unsigned kernel source with %d binaries rejected: %v", MaxBinaries, err)
	}
	for name, mutate := range map[string]func(r *Record){
		"missing model":     func(r *Record) { r.Component.Model = "" },
		"missing firmware":  func(r *Record) { r.Component.Firmware = "" },
		"source on device":  func(r *Record) { r.Component.SourcePackage = "panos" },
		"binary on device":  func(r *Record) { r.Component.Binaries = []Binary{{"x1", "1"}} },
		"model with space":  func(r *Record) { r.Component.Model = "PA 440" },
		"firmware too long": func(r *Record) { r.Component.Firmware = strings.Repeat("1", 129) },
	} {
		t.Run("device "+name, func(t *testing.T) {
			d := mustParse(t, validDeviceJSON).Record
			mutate(&d)
			if _, err := Validate(d); err == nil {
				t.Fatalf("accepted")
			}
		})
	}
}

func manyBinaries(n int) []Binary {
	out := make([]Binary, n)
	for i := range out {
		out[i] = Binary{Name: fmt.Sprintf("linux-image-6.1.0-%d-amd64", i), Version: "6.1.115-1"}
	}
	return out
}

func TestMatchBasisConsistency(t *testing.T) {
	cases := []struct {
		name  string
		json  string
		basis MatchBasis
		ok    bool
	}{
		{"distro tracker on alpine", validImageJSON, MatchDistroTracker, true},
		{"cpe on distro", validImageJSON, MatchCPE, false},
		{"vendor advisory on distro", validImageJSON, MatchVendorAdvisory, false},
		{"unknown basis", validImageJSON, "llm", false},
		{"empty basis", validImageJSON, "", false},
		{"osv on device", validDeviceJSON, MatchOSVRange, false},
		{"distro tracker on device", validDeviceJSON, MatchDistroTracker, false},
		{"cpe on device", validDeviceJSON, MatchCPE, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := mustParse(t, tc.json).Record
			r.MatchBasis = tc.basis
			_, err := Validate(r)
			if tc.ok != (err == nil) {
				t.Fatalf("err = %v, want ok=%v", err, tc.ok)
			}
		})
	}
	r := mustParse(t, validImageJSON).Record
	r.Ecosystem = "Go"
	r.Component.SourcePackage = "golang.org/x/net"
	r.Component.SourceVersion = "v0.17.0"
	r.MatchBasis = MatchCPE
	if _, err := Validate(r); err != nil {
		t.Fatalf("cpe on OSV ecosystem rejected: %v", err)
	}
}

func TestScoreValidation(t *testing.T) {
	cases := map[string]func(s *Scores){
		"cvss above 10":          func(s *Scores) { s.CVSS.BaseScore = 10.1 },
		"cvss negative":          func(s *Scores) { s.CVSS.BaseScore = -1 },
		"cvss two decimals":      func(s *Scores) { s.CVSS.BaseScore = 9.85 },
		"cvss bad version":       func(s *Scores) { s.CVSS.Version = "3.2" },
		"cvss vector mismatch":   func(s *Scores) { s.CVSS.Version = "4.0" },
		"cvss vector junk":       func(s *Scores) { s.CVSS.Vector = "CVSS:3.1/AV:N <b>" },
		"cvss vector too long":   func(s *Scores) { s.CVSS.Vector = "CVSS:3.1/" + strings.Repeat("A", 256) },
		"cvss bad source":        func(s *Scores) { s.CVSS.Source = "llm" },
		"kev without date":       func(s *Scores) { s.KEV.DateAdded = "" },
		"kev bad date":           func(s *Scores) { s.KEV.DateAdded = "2025-02-30" },
		"kev date with time":     func(s *Scores) { s.KEV.DateAdded = "2025-01-15T00:00:00Z" },
		"epss probability > 1":   func(s *Scores) { s.EPSS.Probability = 1.5 },
		"epss percentile < 0":    func(s *Scores) { s.EPSS.Percentile = -0.1 },
		"epss missing date":      func(s *Scores) { s.EPSS.Date = "" },
		"cvss v2 with v3 prefix": func(s *Scores) { s.CVSS.Version = "2.0" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := mustParse(t, validHostJSON)
			r := f.Record
			cvss, kev, epss := *r.Scores.CVSS, *r.Scores.KEV, *r.Scores.EPSS
			r.Scores = Scores{CVSS: &cvss, KEV: &kev, EPSS: &epss}
			mutate(&r.Scores)
			if _, err := Validate(r); !errors.Is(err, ErrInvalidField) {
				t.Fatalf("err = %v, want ErrInvalidField", err)
			}
		})
	}
	r := mustParse(t, validHostJSON).Record
	r.Scores.CVSS = &CVSS{Version: "2.0", Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P", BaseScore: 7.5, Source: CVSSSourceDistro}
	if _, err := Validate(r); err != nil {
		t.Fatalf("CVSS v2 rejected: %v", err)
	}
}

func TestOtherFieldErrorsDoNotEchoInput(t *testing.T) {
	r := mustParse(t, validHostJSON).Record
	r.Vuln.ID = "SECRET-MARKER-<x>"
	_, err := Validate(r)
	if err == nil || strings.Contains(err.Error(), "SECRET-MARKER") {
		t.Fatalf("err = %v", err)
	}
	s := strings.Replace(validHostJSON, `"ecosystem"`, `"secret_marker_field": 1, "ecosystem"`, 1)
	_, err = ParseRecord([]byte(s))
	if err == nil || strings.Contains(err.Error(), "secret_marker") {
		t.Fatalf("err = %v", err)
	}
}
