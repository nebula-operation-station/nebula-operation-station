// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
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
	return containerArtifact{ActionID: composeUpdateAction, ModuleVersion: composeUpdateVersion, SHA256: sha256Hex(testComposeArtifact)}
}

// testRollbackArtifact stands in for the docker.compose_rollback artifact.
var testRollbackArtifact = []byte("#!/bin/sh\n# rollback stand-in\nexit 0\n")

// testRollbackPin pins testRollbackArtifact as the rollback 1.0.0 artifact.
func testRollbackPin() containerArtifact {
	return containerArtifact{ActionID: composeRollbackAction, ModuleVersion: composeRollbackVersion, SHA256: sha256Hex(testRollbackArtifact)}
}

// testRollbackMember is a rollback member of binding rb with its rendered
// parameters, naming the rollback stand-in artifact.
func testRollbackMember(t *testing.T, rb canonical.BatchContainerUpdate) (canonical.BatchMember, []byte) {
	t.Helper()
	params, hash, err := canonical.ContainerUpdateParameters(rb)
	if err != nil {
		t.Fatal(err)
	}
	return canonical.BatchMember{MemberID: "member-0", ContainerUpdate: &rb,
		Request: canonical.Request{ActionID: composeRollbackAction, ModuleVersion: composeRollbackVersion,
			ArtifactSHA256: sha256Hex(testRollbackArtifact), ParametersHash: hash}}, params
}

// A rollback member passes the member check only as docker.compose_rollback
// with a rollback binding, with the rollback pin (never the update's, and
// an update member never with the rollback's), and with exactly the
// parameters rendered from its binding.
func TestRollbackMemberNeedsItsOwnPin(t *testing.T) {
	_, _, rb := rollbackFixture(t, time.Now())
	m, params := testRollbackMember(t, rb)
	if err := checkContainerMember(m, params, testComposePin(), testRollbackPin()); err != nil {
		t.Fatalf("valid rollback member refused: %v", err)
	}
	if err := checkContainerMember(m, params, testComposePin()); !errors.Is(err, errContainerArtifact) {
		t.Fatalf("rollback member with only the update pin: %v", err)
	}
	// The rollback stand-in pinned for the update action admits nothing here.
	crossed := testRollbackPin()
	crossed.ActionID = composeUpdateAction
	if err := checkContainerMember(m, params, crossed); !errors.Is(err, errContainerArtifact) {
		t.Fatalf("rollback artifact pinned for the update action: %v", err)
	}
	// The update pin's artifact named by a rollback member.
	m2 := m
	m2.Request.ArtifactSHA256, m2.Request.ModuleVersion = sha256Hex(testComposeArtifact), composeUpdateVersion
	if err := checkContainerMember(m2, params, testComposePin(), testRollbackPin()); !errors.Is(err, errContainerArtifact) {
		t.Fatalf("rollback member naming the update artifact: %v", err)
	}
	// An update member naming the rollback artifact.
	um, uparams := testContainerMember(t, testComposeUpdate())
	um.Request.ArtifactSHA256, um.Request.ModuleVersion = sha256Hex(testRollbackArtifact), composeRollbackVersion
	if err := checkContainerMember(um, uparams, testComposePin(), testRollbackPin()); !errors.Is(err, errContainerArtifact) {
		t.Fatalf("update member naming the rollback artifact: %v", err)
	}
	// A pin without an action admits nothing.
	noAction := testRollbackPin()
	noAction.ActionID = ""
	if err := checkContainerMember(m, params, noAction); !errors.Is(err, errContainerArtifact) {
		t.Fatalf("pin without action: %v", err)
	}
	// Parameters of another rollback binding.
	other := rb.Clone()
	other.RecoveryPlanDigest = hexOf("0")
	op, _, err := canonical.ContainerUpdateParameters(other)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkContainerMember(m, op, testRollbackPin()); !errors.Is(err, errContainerParameters) {
		t.Fatalf("parameters of another rollback: %v", err)
	}
	// docker.compose_rollback with an update binding.
	um.Request.ActionID = composeRollbackAction
	if err := checkContainerMember(um, uparams, testRollbackPin()); !errors.Is(err, errContainerUnsupported) {
		t.Fatalf("rollback action with an update binding: %v", err)
	}
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
// before 2.0.0 replaced it in the catalog (Q3): it reads the project's
// directory and Compose files from `docker inspect` labels and pulls
// floating tags. Hosts or servers may still hold it, so it stays refused.
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
		{"private registry added after rendering", errContainerParameters, func(m *canonical.BatchMember, _ *[]byte) {
			u := m.ContainerUpdate.Clone()
			u.Registry = testRegistryBinding()
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

func testRegistryBinding() *canonical.ContainerUpdateRegistry {
	return &canonical.ContainerUpdateRegistry{RegistryID: "reg", RecordDigest: hexOf("8"), CredentialID: "c", CredentialVersion: 1}
}

// A private registry binding (cu06) is admitted on a compose update only,
// with parameters rendered from the binding that names it; a standalone
// update or a rollback naming one is refused before the claim.
func TestContainerMemberPrivateRegistryOnlyOnComposeUpdate(t *testing.T) {
	u := testComposeUpdate()
	u.Registry = testRegistryBinding()
	m, params := testContainerMember(t, u)
	if err := checkContainerMember(m, params, testComposePin()); err != nil {
		t.Fatalf("private compose update refused: %v", err)
	}
	su := testStandaloneUpdate("def-1", 1)
	su.Registry = testRegistryBinding()
	sm, sparams := testContainerMember(t, su)
	sm.Request.ActionID = standaloneUpdateAction
	if err := checkContainerMember(sm, sparams, testComposePin(), shippedStandaloneUpdatePin()); !errors.Is(err, errContainerUnsupported) {
		t.Fatalf("private standalone update: %v", err)
	}
	_, _, rb := rollbackFixture(t, time.Now())
	rb.Registry = testRegistryBinding()
	rm, rparams := testRollbackMember(t, rb)
	if err := checkContainerMember(rm, rparams, testRollbackPin()); !errors.Is(err, errContainerUnsupported) {
		t.Fatalf("private rollback: %v", err)
	}
}

// A compose update member whose artifact is not the pinned one is refused,
// whatever artifact and version it names: the shipped pin admits only the
// shipped 2.0.0 script, there is no fallback to some other trusted artifact,
// and an empty or digest-less pin admits nothing. The inspect-based 1.0.0
// script is refused under 1.0.0 and when labelled 2.0.0.
func TestContainerMemberRefusedWithoutPinnedArtifact(t *testing.T) {
	m, params := testContainerMember(t, testComposeUpdate())
	for _, pin := range []containerArtifact{shippedComposeUpdatePin(), shippedComposeRollbackPin(), {}, {ModuleVersion: composeUpdateVersion},
		{ModuleVersion: composeUpdateVersion, SHA256: sha256Hex(testComposeArtifact)}} {
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
	if _, err := canonical.ParseDigest(pin.SHA256); err != nil {
		t.Fatalf("pinned digest %q: %v", pin.SHA256, err)
	}
}

// The pin is the digest of the docker.compose_update 2.0.0 script the server
// ships (the bytes embedded in the actions catalog). Changing the script
// without a reviewed pin update fails here, and the pinned artifact is the
// binding-consuming 2.0.0, not some other version.
func TestShippedComposeUpdatePinMatchesEmbeddedScript(t *testing.T) {
	a, ok := actions.Lookup(composeUpdateAction)
	if !ok {
		t.Fatal("docker.compose_update is not in the catalog")
	}
	if a.Version != composeUpdateVersion || !a.Durable {
		t.Fatalf("catalog has %s %s (durable %v), the executor pins %s", a.ID, a.Version, a.Durable, composeUpdateVersion)
	}
	if got := sha256Hex(a.Script); got != composeUpdateArtifactSHA256 || a.SHA256() != composeUpdateArtifactSHA256 {
		t.Fatalf("the embedded docker.compose_update %s script has digest %s, the executor pins %q: update composeUpdateArtifactSHA256 after review",
			a.Version, got, composeUpdateArtifactSHA256)
	}
	s := string(a.Script)
	if !strings.Contains(s, "docker.compose_update 2.0.0") || !strings.Contains(s, `"container_update"`) ||
		!strings.Contains(s, "compose-update-v2") {
		t.Fatal("the pinned script is not the binding-consuming 2.0.0")
	}
	// The pin admits exactly that artifact at exactly that version.
	m, params := testContainerMember(t, testComposeUpdate())
	m.Request.ArtifactSHA256 = sha256Hex(a.Script)
	if err := checkContainerMember(m, params, shippedComposeUpdatePin()); err != nil {
		t.Fatalf("shipped artifact refused: %v", err)
	}
	for _, version := range []string{"1.0.0", "2.0.1", "2.1.0", "3.0.0"} {
		m.Request.ModuleVersion = version
		if err := checkContainerMember(m, params, shippedComposeUpdatePin()); !errors.Is(err, errContainerArtifact) {
			t.Fatalf("shipped artifact as %s: err = %v", version, err)
		}
	}
}

// The rollback pin is the digest of the docker.compose_rollback 1.0.0
// script the server ships (the bytes embedded in the actions catalog), for
// that action and version only. Changing the script without a reviewed pin
// update fails here.
func TestShippedComposeRollbackPinMatchesEmbeddedScript(t *testing.T) {
	a, ok := actions.Lookup(composeRollbackAction)
	if !ok {
		t.Fatal("docker.compose_rollback is not in the catalog")
	}
	if a.Version != composeRollbackVersion || !a.Durable || a.Timeout != containerMutationTimeout {
		t.Fatalf("catalog has %s %s (durable %v, %v), the executor pins %s", a.ID, a.Version, a.Durable, a.Timeout, composeRollbackVersion)
	}
	if got := sha256Hex(a.Script); got != composeRollbackArtifactSHA256 || a.SHA256() != composeRollbackArtifactSHA256 {
		t.Fatalf("the embedded docker.compose_rollback %s script has digest %s, the executor pins %q: update composeRollbackArtifactSHA256 after review",
			a.Version, got, composeRollbackArtifactSHA256)
	}
	s := string(a.Script)
	if !strings.Contains(s, "docker.compose_rollback 1.0.0") || !strings.Contains(s, `"container_update"`) ||
		!strings.Contains(s, composeRollbackFormat) || !strings.Contains(s, `u["kind"] == "rollback"`) {
		t.Fatal("the pinned script is not the binding-consuming rollback 1.0.0")
	}
	pin := shippedComposeRollbackPin()
	if pin.ActionID != composeRollbackAction || pin.ModuleVersion != "1.0.0" || pin.SHA256 == composeUpdateArtifactSHA256 {
		t.Fatalf("pin %+v", pin)
	}
	if !slices.Equal(shippedContainerPins(), []containerArtifact{shippedComposeUpdatePin(), pin,
		shippedStandaloneUpdatePin(), shippedStandaloneRollbackPin()}) {
		t.Fatalf("shipped pins %+v", shippedContainerPins())
	}
	_, _, rb := rollbackFixture(t, time.Now())
	m, params := testRollbackMember(t, rb)
	m.Request.ArtifactSHA256 = sha256Hex(a.Script)
	if err := checkContainerMember(m, params, shippedContainerPins()...); err != nil {
		t.Fatalf("shipped rollback artifact refused: %v", err)
	}
	for _, version := range []string{"1.0.1", "2.0.0"} {
		m.Request.ModuleVersion = version
		if err := checkContainerMember(m, params, shippedContainerPins()...); !errors.Is(err, errContainerArtifact) {
			t.Fatalf("shipped rollback artifact as %s: err = %v", version, err)
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
