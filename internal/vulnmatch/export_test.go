// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnmatch

import (
	"errors"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnagent/nosclient"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

func part(id string, n int, last bool, comps ...nosclient.Component) nosclient.SubjectPart {
	return nosclient.SubjectPart{Kind: vulnfinding.SubjectHost, Ref: vulnfinding.SubjectRef{ID: id}, Ecosystem: "debian:bookworm",
		Kernel: &nosclient.Kernel{Release: "6.1.0-27-amd64", Mapped: true, SourcePackage: "linux", SourceVersion: "6.1.115-1"},
		Part:   n, LastPart: last, Components: comps}
}

func TestSubjectsFromExportMergesParts(t *testing.T) {
	c := func(p, v string) nosclient.Component {
		return nosclient.Component{SourcePackage: p, SourceVersion: v, Binaries: []nosclient.Binary{{Name: p, Version: v + "+b1", Arch: "amd64"}}}
	}
	subs, err := SubjectsFromExport([]nosclient.SubjectPart{
		part("h1", 0, false, c("openssl", "3.0.14-1~deb12u2")),
		part("h2", 0, true, c("zlib", "1:1.2.13.dfsg-1")),
		part("h1", 1, true, c("linux", "6.1.115-1")),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(subs) != 2 || len(subs[0].Components) != 2 || subs[0].Kernel == nil || subs[0].Kernel.SourceVersion != "6.1.115-1" {
		t.Fatalf("subjects = %+v", subs)
	}
	if b := subs[0].Components[0].Binaries[0]; b.SourceVersion != "" || b.Version != "3.0.14-1~deb12u2+b1" {
		t.Fatalf("binary = %+v", b)
	}
}

func TestSubjectsFromExportRejectsIncompleteSubjects(t *testing.T) {
	tests := []struct {
		name  string
		parts []nosclient.SubjectPart
	}{
		{"missing last part", []nosclient.SubjectPart{part("h1", 0, false)}},
		{"part out of order", []nosclient.SubjectPart{part("h1", 1, true)}},
		{"part after last part", []nosclient.SubjectPart{part("h1", 0, true), part("h1", 1, true)}},
		{"repeated part", []nosclient.SubjectPart{part("h1", 0, false), part("h1", 0, true)}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := SubjectsFromExport(tc.parts); !errors.Is(err, ErrIncompleteSubject) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}
