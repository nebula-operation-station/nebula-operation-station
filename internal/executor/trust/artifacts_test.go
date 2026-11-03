// SPDX-License-Identifier: AGPL-3.0-or-later

package trust

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

var (
	shaA = strings.Repeat("a", 64)
	shaB = strings.Repeat("b", 64)
	shaC = strings.Repeat("c", 64)
)

func artifactReview() Review {
	return Review{ReleaseVersion: "2026.12.0", Modules: []ModuleReview{
		{Name: "docker", Status: StatusChanged, OldVersion: "1.0.0", NewVersion: "1.1.0", Actions: []ActionReview{
			{ActionID: "docker.restart", Status: StatusUnchanged, NewRisk: "LOW", NewArtifactSHA256: shaA, OldArtifactSHA256: shaA},
			{ActionID: "docker.stop", Status: StatusChanged, NewRisk: "MEDIUM", NewArtifactSHA256: shaB, OldArtifactSHA256: shaC},
			{ActionID: "docker.kill", Status: StatusRemoved, OldRisk: "HIGH", OldArtifactSHA256: shaC},
		}},
		{Name: "package", Status: StatusUnchanged, OldVersion: "2.0.0", NewVersion: "2.0.0"},
		{Name: "service", Status: StatusNew, NewVersion: "1.0.0", Actions: []ActionReview{
			{ActionID: "service.status", Status: StatusNew, NewRisk: "LOW", NewArtifactSHA256: shaC},
		}},
		{Name: "system", Status: StatusRemoved, OldVersion: "3.0.0", Actions: []ActionReview{
			{ActionID: "system.reboot", Status: StatusRemoved, OldRisk: "HIGH", OldArtifactSHA256: shaA},
		}},
		{Name: "zfs", Status: StatusReactivated, OldVersion: "1.2.0", NewVersion: "1.1.0", Actions: []ActionReview{
			{ActionID: "zfs.list", Status: StatusChanged, NewRisk: "LOW", NewArtifactSHA256: shaB},
		}},
	}}
}

// Every action of every newly committed version is trusted with its exact
// artifact hash at the new module version; unchanged modules, removed
// actions and removed modules add nothing; retired versions are revoked
// by module family and version.
func TestArtifactTrustForCommittedReview(t *testing.T) {
	got, err := ArtifactTrustFor(artifactReview(), []string{"docker@1.0.0", "system@3.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	want := ArtifactTrust{
		Trust: []ArtifactTuple{
			{ActionID: "docker.restart", ModuleVersion: "1.1.0", SHA256: shaA, Risk: "LOW"},
			{ActionID: "docker.stop", ModuleVersion: "1.1.0", SHA256: shaB, Risk: "MEDIUM"},
			{ActionID: "service.status", ModuleVersion: "1.0.0", SHA256: shaC, Risk: "LOW"},
			{ActionID: "zfs.list", ModuleVersion: "1.1.0", SHA256: shaB, Risk: "LOW"},
		},
		Retire: []VersionRef{{Module: "docker", Version: "1.0.0"}, {Module: "system", Version: "3.0.0"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %+v\nwant %+v", got, want)
	}
}

// Retained (pinned) old versions are not revoked.
func TestArtifactTrustForRetainedKeepsOldVersion(t *testing.T) {
	got, err := ArtifactTrustFor(artifactReview(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Retire) != 0 {
		t.Fatalf("retire = %+v, want none", got.Retire)
	}
}

// A review whose actions would grant trust outside their own module
// family, or that lacks the exact artifact hash, implies no trust at all.
func TestArtifactTrustForRejectsMalformed(t *testing.T) {
	cases := map[string]func(*Review) []string{
		"foreign action": func(r *Review) []string {
			r.Modules[2].Actions[0].ActionID = "system.reboot"
			return nil
		},
		"prefix family": func(r *Review) []string {
			r.Modules[0].Actions[0].ActionID = "dockerx.restart"
			return nil
		},
		"missing hash": func(r *Review) []string {
			r.Modules[2].Actions[0].NewArtifactSHA256 = ""
			return nil
		},
		"missing version": func(r *Review) []string {
			r.Modules[2].NewVersion = ""
			return nil
		},
		"retire ref": func(*Review) []string { return []string{"docker"} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := artifactReview()
			retired := mutate(&r)
			if _, err := ArtifactTrustFor(r, retired); !errors.Is(err, ErrArtifactTrust) {
				t.Fatalf("err = %v, want ErrArtifactTrust", err)
			}
		})
	}
}
