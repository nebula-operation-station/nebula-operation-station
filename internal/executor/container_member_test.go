// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
)

func hexOf(c string) string    { return strings.Repeat(c, 64) }
func digestOf(c string) string { return "sha256:" + hexOf(c) }

// testComposeUpdate is a valid same-tag compose update binding of one
// service with one replica and one dependency.
func testComposeUpdate() canonical.BatchContainerUpdate {
	return canonical.BatchContainerUpdate{
		Kind: canonical.ContainerUpdateKindUpdate, Form: canonical.ContainerUpdateFormCompose,
		Images: []canonical.ContainerUpdateImage{{Service: "web", Repository: "docker.io/library/nginx", Platform: "linux/amd64",
			OldTag: "1.27", NewTag: "1.27", OldDigests: []string{digestOf("a")}, NewIndexDigest: digestOf("b"),
			NewPlatformDigest: digestOf("c"), OldImageID: digestOf("d")}},
		Targets: []canonical.ContainerUpdateTarget{{Service: "web", ContainerID: hexOf("1"), ContainerName: "site-web-1",
			ImageID: digestOf("d"), RunningReference: "nginx:1.27", ConfigurationDigest: hexOf("2")}},
		Dependencies: []canonical.ContainerUpdateDependency{{Service: "db", Relation: canonical.ContainerDependencyRequires,
			Containers: []canonical.ContainerDependencyMember{{ContainerID: hexOf("3"), ContainerName: "site-db-1", ConfigurationDigest: hexOf("4")}}}},
		SourceDigest: hexOf("5"), Project: "site", WorkingDirHash: hexOf("6"), ConfigFilesHash: hexOf("7"),
	}
}

// testComposeArtifact stands in for the binding-consuming
// docker.compose_update artifact in unit tests: the pin names its digest.
var testComposeArtifact = []byte("#!/bin/sh\n# binding-consuming stand-in\nexit 0\n")

// testComposePin pins testComposeArtifact as the 2.0.0 artifact.
func testComposePin() containerArtifact {
	return containerArtifact{ModuleVersion: composeUpdateVersion, SHA256: sha256Hex(testComposeArtifact)}
}

// testContainerMember returns a compose update member and its parameter
// document, rendered from the binding as the approved plan holds them. The
// member names the pinned module version and artifact.
func testContainerMember(t *testing.T, u canonical.BatchContainerUpdate) (canonical.BatchMember, []byte) {
	t.Helper()
	params, hash, err := canonical.ContainerUpdateParameters(u)
	if err != nil {
		t.Fatal(err)
	}
	return canonical.BatchMember{MemberID: "member-0", ContainerUpdate: &u,
		Request: canonical.Request{ActionID: composeUpdateAction, ModuleVersion: composeUpdateVersion,
			ArtifactSHA256: sha256Hex(testComposeArtifact), ParametersHash: hash}}, params
}

// composeUpdateV1 is the inspect-based docker.compose_update 1.0.0 script, a
// byte copy of internal/executions/actions/scripts/docker_compose_update.sh
// as of this branch: it reads the project's directory and Compose files from
// `docker inspect` labels and pulls floating tags.
func composeUpdateV1(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "docker_compose_update_1.0.0.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "docker.compose_update 1.0.0") || !strings.Contains(string(b), "docker inspect") {
		t.Fatal("testdata is not the inspect-based 1.0.0 script")
	}
	return b
}

// A compose update member passes only with its binding and exactly the
// parameters rendered from it; every other shape is refused before the
// claim, one refusal per case.
func TestContainerMemberRefusals(t *testing.T) {
	good, goodParams := testContainerMember(t, testComposeUpdate())
	if err := checkContainerMember(good, goodParams, testComposePin()); err != nil {
		t.Fatalf("valid member refused: %v", err)
	}
	cases := []struct {
		name string
		want error
		mut  func(m *canonical.BatchMember, params *[]byte)
	}{
		{"no binding", errContainerBinding, func(m *canonical.BatchMember, _ *[]byte) { m.ContainerUpdate = nil }},
		{"inspect binding instead of a definition", errContainerBinding, func(m *canonical.BatchMember, _ *[]byte) {
			m.Container = &canonical.BatchContainer{}
		}},
		{"rollback action", errContainerUnsupported, func(m *canonical.BatchMember, _ *[]byte) { m.Request.ActionID = "docker.compose_rollback" }},
		{"standalone action", errContainerUnsupported, func(m *canonical.BatchMember, _ *[]byte) { m.Request.ActionID = "docker.update" }},
		{"rollback kind", errContainerUnsupported, func(m *canonical.BatchMember, _ *[]byte) {
			u := m.ContainerUpdate.Clone()
			u.Kind = canonical.ContainerUpdateKindRollback
			m.ContainerUpdate = &u
		}},
		{"standalone form", errContainerUnsupported, func(m *canonical.BatchMember, _ *[]byte) {
			u := m.ContainerUpdate.Clone()
			u.Form = canonical.ContainerUpdateFormAlone
			m.ContainerUpdate = &u
		}},
		{"private registry", errContainerUnsupported, func(m *canonical.BatchMember, _ *[]byte) {
			u := m.ContainerUpdate.Clone()
			u.Registry = &canonical.ContainerUpdateRegistry{RegistryID: "reg", RecordDigest: hexOf("8"), CredentialID: "c", CredentialVersion: 1}
			m.ContainerUpdate = &u
		}},
		{"parameters not the rendering", errContainerParameters, func(_ *canonical.BatchMember, p *[]byte) {
			*p = []byte(`{"project":"site"}`)
		}},
		{"parameters of another binding", errContainerParameters, func(m *canonical.BatchMember, p *[]byte) {
			u := m.ContainerUpdate.Clone()
			u.Images[0].NewPlatformDigest = digestOf("e")
			other, _, err := canonical.ContainerUpdateParameters(u)
			if err != nil {
				t.Fatal(err)
			}
			*p = other
		}},
		{"parameters with a secret reference", errContainerParameters, func(_ *canonical.BatchMember, p *[]byte) {
			*p = append([]byte(nil), (*p)[:len(*p)-1]...)
			*p = append(*p, []byte(`,"token":{"secret_ref":"x"}}`)...)
		}},
		{"parameters hash not the binding's", errContainerParameters, func(m *canonical.BatchMember, _ *[]byte) {
			m.Request.ParametersHash = hexOf("9")
		}},
		{"inspect-based 1.0.0 artifact as 1.0.0", errContainerArtifact, func(m *canonical.BatchMember, _ *[]byte) {
			m.Request.ModuleVersion = "1.0.0"
			m.Request.ArtifactSHA256 = sha256Hex(composeUpdateV1(t))
		}},
		{"inspect-based 1.0.0 artifact labelled 2.0.0", errContainerArtifact, func(m *canonical.BatchMember, _ *[]byte) {
			m.Request.ArtifactSHA256 = sha256Hex(composeUpdateV1(t))
		}},
		{"another artifact", errContainerArtifact, func(m *canonical.BatchMember, _ *[]byte) {
			m.Request.ArtifactSHA256 = hexOf("a")
		}},
		{"pinned artifact under another version", errContainerArtifact, func(m *canonical.BatchMember, _ *[]byte) {
			m.Request.ModuleVersion = "2.0.1"
		}},
		{"pinned artifact under the old version", errContainerArtifact, func(m *canonical.BatchMember, _ *[]byte) {
			m.Request.ModuleVersion = "1.0.0"
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, params := testContainerMember(t, testComposeUpdate())
			c.mut(&m, &params)
			if err := checkContainerMember(m, params, testComposePin()); !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
		})
	}
}

// As shipped, the executor pins no binding-consuming artifact (the
// docker.compose_update 2.0.0 script does not exist yet), so every compose
// update member is refused, whatever artifact and version it names: there is
// no fallback to some other trusted artifact. An empty pin refuses too.
func TestContainerMemberRefusedWithoutPinnedArtifact(t *testing.T) {
	m, params := testContainerMember(t, testComposeUpdate())
	for _, pin := range []containerArtifact{shippedComposeUpdatePin(), {}, {ModuleVersion: composeUpdateVersion}} {
		if err := checkContainerMember(m, params, pin); !errors.Is(err, errContainerArtifact) {
			t.Fatalf("pin %+v: err = %v, want %v", pin, err, errContainerArtifact)
		}
	}
	v1 := composeUpdateV1(t)
	for _, version := range []string{"1.0.0", composeUpdateVersion} {
		m.Request.ModuleVersion, m.Request.ArtifactSHA256 = version, sha256Hex(v1)
		if err := checkContainerMember(m, params, shippedComposeUpdatePin()); !errors.Is(err, errContainerArtifact) {
			t.Fatalf("1.0.0 artifact as %s: err = %v", version, err)
		}
	}
}

// The shipped pin names module version 2.0.0 and never the inspect-based
// 1.0.0 script; a set digest is well-formed.
func TestShippedComposeUpdatePin(t *testing.T) {
	pin := shippedComposeUpdatePin()
	if pin.ModuleVersion != "2.0.0" {
		t.Fatalf("pin %+v", pin)
	}
	v1 := sha256.Sum256(composeUpdateV1(t))
	if pin.SHA256 == canonical.Digest(v1).String() {
		t.Fatal("the inspect-based 1.0.0 script is pinned as the binding-consuming artifact")
	}
	if pin.SHA256 != "" {
		if _, err := canonical.ParseDigest(pin.SHA256); err != nil {
			t.Fatalf("pinned digest %q: %v", pin.SHA256, err)
		}
	}
}

// The executor chooses the durable transport from the frozen action ID
// (Decision 5): every container mutation ID and any member carrying an
// update binding is a container member; nothing the server sends decides.
func TestContainerMemberChosenByFrozenActionID(t *testing.T) {
	for _, id := range []string{"docker.compose_update", "docker.compose_rollback", "docker.update", "docker.rollback"} {
		if !isContainerMember(canonical.BatchMember{Request: canonical.Request{ActionID: id}}) {
			t.Errorf("%s is not a container member", id)
		}
	}
	u := testComposeUpdate()
	if !isContainerMember(canonical.BatchMember{ContainerUpdate: &u, Request: canonical.Request{ActionID: "package.upgrade"}}) {
		t.Error("a member with an update binding is not a container member")
	}
	for _, id := range []string{"package.upgrade", "docker.restart", "docker.inspect"} {
		if isContainerMember(canonical.BatchMember{Request: canonical.Request{ActionID: id}}) {
			t.Errorf("%s is a container member", id)
		}
	}
}

// Only a job that ended with a result read (or never started) is over; a
// run closed without a result may still run on the host (Q15).
func TestDurableJobOverOnlyWithResult(t *testing.T) {
	for class, want := range map[string]bool{
		"success": true, "script_failed": true, "precheck_failed": true, classNotExecuted: true,
		classUnknown: false, "script_interrupted": false, "execution_timeout": false,
	} {
		if got := durableJobOver(class); got != want {
			t.Errorf("%s: %v, want %v", class, got, want)
		}
	}
}
