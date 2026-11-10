// SPDX-License-Identifier: AGPL-3.0-or-later

package dockerhost

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// Trivy output comes from a managed host: the image package parser never
// panics, never exceeds its bounds, keeps only validated tuples and never
// reports a complete read for a partial condition.
func FuzzParseImagePackages(f *testing.F) {
	f.Add(trivyJSON(f, goodOpts()), 0, true)
	f.Add([]byte(`{"SchemaVersion":2,"ArtifactName":"`+pkgDigest+`","Metadata":{"OS":{"Family":"alpine","Name":"3.19.1"}},"Results":[{"Class":"os-pkgs","Type":"alpine","Packages":[null,{"Name":"musl","Version":"1.2.4-r2","Epoch":2}]}]}`), 0, true)
	f.Add([]byte(`{}`), 1, true)
	f.Add([]byte(`[]`), 0, false)
	f.Add([]byte("\xff"), 0, true)
	f.Fuzz(func(t *testing.T, b []byte, exit int, present bool) {
		got, err := ParseImagePackages(pkgDigest, TrivyPackagesRun{Present: present, ExitCode: exit, Output: b})
		if err != nil {
			t.Fatalf("host data must not error: %v", err)
		}
		if got.Digest != pkgDigest {
			t.Fatalf("digest %q", got.Digest)
		}
		if !present && (got.Known || got.Complete || got.Packages != nil || got.Reason != ReasonTrivyAbsent) {
			t.Fatalf("absent Trivy must be unknown: %+v", got)
		}
		if got.Complete != (got.Reason == "") || (got.Complete && !got.Known) {
			t.Fatalf("complete/reason inconsistent: %+v", got)
		}
		if !got.Known && got.Packages != nil {
			t.Fatal("unknown read carries packages")
		}
		if exit != 0 && got.Complete {
			t.Fatal("non-zero exit reported complete")
		}
		if len(got.Packages) > MaxImagePackages {
			t.Fatalf("packages %d over limit", len(got.Packages))
		}
		if got.Complete && (got.OS.Family == "" || got.OS.Name == "") {
			t.Fatal("complete read without detected OS")
		}
		for _, p := range got.Packages {
			for _, s := range []string{p.Ecosystem, p.Name, p.Version, p.SrcName, p.SrcVersion} {
				if len(s) > maxImagePkgName || !utf8.ValidString(s) || !printable(s, maxImagePkgName) || strings.ContainsAny(s, " \t\r\n") {
					t.Fatalf("unbounded field %q", s)
				}
			}
			if p.Name == "" || p.Version == "" || len(p.Version) > maxImagePkgVersion || len(p.SrcVersion) > maxImagePkgVersion {
				t.Fatalf("invalid package %+v", p)
			}
		}
	})
}
