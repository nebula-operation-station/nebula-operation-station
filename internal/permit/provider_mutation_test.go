// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
)

var mutationArtifact = []byte("pve.guest.start 1.0.0\nStart one exact guest.\n")

func mutationTarget() ProviderMutationTarget {
	return ProviderMutationTarget{
		RemoteID: "pve-lab", TrustPin: strings.Repeat("ab", 32), TrustGeneration: 3,
		CredentialRef: "pve-0011223344556677-action", CredentialVersion: 2,
		APIEndpoints: []pvecontract.Endpoint{{Host: "pve1.lab.test", Port: 8006}, {Host: "pve2.lab.test", Port: 8006}},
		Kind:         ProviderKindQemu, Node: "pve1", VMID: 101, ConfigDigest: strings.Repeat("cd", 32),
	}
}

func mutation(t ProviderMutationTarget) ProviderMutation {
	return ProviderMutation{Target: t, ActionID: "pve.guest.start", ModuleVersion: "1.0.0",
		Artifact: mutationArtifact, Parameters: json.RawMessage(`{"timeout_s":60}`)}
}

var mutationSeq int

// approvedMutation proposes and approves (MEDIUM, presence) a mutation of t.
func (e *env) approvedMutation(t ProviderMutationTarget) canonical.Digest {
	e.t.Helper()
	mutationSeq++
	id := fmt.Sprintf("00000000-0000-4000-9000-%012d", mutationSeq)
	rq, params, err := ProviderMutationRequest(mutation(t), id, canonical.RiskMedium, strings.Repeat("c", 64), e.clk.Now().Add(time.Hour))
	if err != nil {
		e.t.Fatal(err)
	}
	res, err := e.auth.Propose(rq, params)
	if err != nil {
		e.t.Fatalf("propose: %v", err)
	}
	e.openSession()
	if _, err := e.auth.SubmitAssertion(res.Permit.Digest, e.sign(res.Permit.Challenge), 0); err != nil {
		e.t.Fatalf("approve: %v", err)
	}
	return res.Permit.Digest
}

func TestProviderMutationPermitBindsExactTarget(t *testing.T) {
	cases := map[string]func(*ProviderMutationTarget){
		"other remote":         func(x *ProviderMutationTarget) { x.RemoteID = "pve-other" },
		"re-pinned trust":      func(x *ProviderMutationTarget) { x.TrustPin = strings.Repeat("ef", 32) },
		"new trust generation": func(x *ProviderMutationTarget) { x.TrustGeneration++ },
		"rotated action token": func(x *ProviderMutationTarget) { x.CredentialVersion++ },
		"read token instead":   func(x *ProviderMutationTarget) { x.CredentialRef = "pve-0011223344556677-read" },
		"added api endpoint": func(x *ProviderMutationTarget) {
			x.APIEndpoints = append(slices.Clone(x.APIEndpoints), pvecontract.Endpoint{Host: "evil.example", Port: 8006})
		},
		"replaced api endpoint": func(x *ProviderMutationTarget) {
			x.APIEndpoints = []pvecontract.Endpoint{{Host: "evil.example", Port: 8006}, x.APIEndpoints[1]}
		},
		"reordered api endpoints": func(x *ProviderMutationTarget) {
			x.APIEndpoints = []pvecontract.Endpoint{x.APIEndpoints[1], x.APIEndpoints[0]}
		},
		"guest moved to node":   func(x *ProviderMutationTarget) { x.Node = "pve2" },
		"other vmid":            func(x *ProviderMutationTarget) { x.VMID = 102 },
		"lxc with same vmid":    func(x *ProviderMutationTarget) { x.Kind = ProviderKindLXC },
		"configuration changed": func(x *ProviderMutationTarget) { x.ConfigDigest = strings.Repeat("00", 32) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
			d := e.approvedMutation(mutationTarget())
			changed := mutationTarget()
			mutate(&changed)
			_, err := e.auth.AuthorizeProviderMutation(d, mutation(changed))
			wantCode(t, err, CodeTargetNotPermitted)
			// The refusal consumed nothing: the exact target still works once.
			c, err := e.auth.AuthorizeProviderMutation(d, mutation(mutationTarget()))
			if err != nil {
				t.Fatalf("exact target refused: %v", err)
			}
			if err := c.Check(); err != nil {
				t.Fatalf("fresh claim: %v", err)
			}
		})
	}
}

func TestProviderMutationPermitIsSingleUse(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	d := e.approvedMutation(mutationTarget())
	if _, err := e.auth.AuthorizeProviderMutation(d, mutation(mutationTarget())); err != nil {
		t.Fatal(err)
	}
	_, err := e.auth.AuthorizeProviderMutation(d, mutation(mutationTarget()))
	wantCode(t, err, CodeHostAlreadyRun)
}

func TestProviderMutationPermitChecksActionAndParameters(t *testing.T) {
	cases := map[string]func(*ProviderMutation){
		"other action":     func(m *ProviderMutation) { m.ActionID = "pve.guest.stop" },
		"other artifact":   func(m *ProviderMutation) { m.Artifact = []byte("pve.guest.start 9\n") },
		"other parameters": func(m *ProviderMutation) { m.Parameters = json.RawMessage(`{"timeout_s":61}`) },
	}
	want := map[string]Code{"other action": CodeActionMismatch, "other artifact": CodeArtifactMismatch, "other parameters": CodeParametersMismatch}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
			d := e.approvedMutation(mutationTarget())
			m := mutation(mutationTarget())
			mutate(&m)
			_, err := e.auth.AuthorizeProviderMutation(d, m)
			wantCode(t, err, want[name])
		})
	}
}

func TestProviderMutationRejectsMalformedTarget(t *testing.T) {
	cases := map[string]func(*ProviderMutation){
		"non pve action":   func(m *ProviderMutation) { m.ActionID = "patching.install_security" },
		"node with vmid":   func(m *ProviderMutation) { m.Target.Kind = ProviderKindNode },
		"vmid below range": func(m *ProviderMutation) { m.Target.VMID = 99 },
		"bad digest":       func(m *ProviderMutation) { m.Target.ConfigDigest = "XYZ" },
		"bad node":         func(m *ProviderMutation) { m.Target.Node = "../etc" },
		"zero generation":  func(m *ProviderMutation) { m.Target.TrustGeneration = 0 },
		"no credential":    func(m *ProviderMutation) { m.Target.CredentialRef = "" },
		"no api endpoints": func(m *ProviderMutation) { m.Target.APIEndpoints = nil },
		"bad api endpoint": func(m *ProviderMutation) {
			m.Target.APIEndpoints = []pvecontract.Endpoint{{Host: "../x", Port: 8006}}
		},
		"duplicate api endpoint": func(m *ProviderMutation) {
			m.Target.APIEndpoints = []pvecontract.Endpoint{{Host: "a.test", Port: 8006}, {Host: "a.test", Port: 8006}}
		},
		"array params": func(m *ProviderMutation) { m.Parameters = json.RawMessage(`[1]`) },
		"huge params": func(m *ProviderMutation) {
			m.Parameters = json.RawMessage(`{"x":"` + strings.Repeat("a", maxProviderMutationParams) + `"}`)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := mutation(mutationTarget())
			mutate(&m)
			if _, _, err := ProviderMutationRequest(m, "00000000-0000-4000-9000-000000000000", canonical.RiskMedium, strings.Repeat("c", 64), time.Now().Add(time.Hour)); err == nil {
				t.Fatal("malformed mutation accepted")
			}
		})
	}
}

func TestProviderMutationRefusesNonMutationPermit(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	p := e.propose(e.request(canonical.RiskMedium))
	e.openSession()
	if _, err := e.auth.SubmitAssertion(p.Digest, e.sign(p.Challenge), 0); err != nil {
		t.Fatal(err)
	}
	_, err := e.auth.AuthorizeProviderMutation(p.Digest, mutation(mutationTarget()))
	wantCode(t, err, CodeTargetNotPermitted)
}

func TestProviderMutationClaimVoidAfterLockOrRevoke(t *testing.T) {
	cases := map[string]func(*env){
		"lock":          func(e *env) { e.auth.Lock("admin") },
		"remote revoke": func(e *env) { e.auth.RevokeProviderMutations("pve-lab", "admin") },
		"expiry":        func(e *env) { e.clk.Add(2 * time.Hour) },
	}
	for name, revoke := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
			d := e.approvedMutation(mutationTarget())
			c, err := e.auth.AuthorizeProviderMutation(d, mutation(mutationTarget()))
			if err != nil {
				t.Fatal(err)
			}
			revoke(e)
			if err := c.Check(); err == nil {
				t.Fatal("claim still valid after " + name)
			}
		})
	}
}

func TestRevokeProviderMutationsOnlyTouchesThatRemote(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	other := mutationTarget()
	other.RemoteID = "pve-other"
	dLab := e.approvedMutation(mutationTarget())
	dOther := e.approvedMutation(other)
	ssh := e.propose(e.request(canonical.RiskMedium))
	if n := e.auth.RevokeProviderMutations("pve-lab", "admin"); n != 1 {
		t.Fatalf("revoked %d, want 1", n)
	}
	if _, ok := e.auth.PermitState(dLab); ok {
		t.Fatal("pve-lab permit survived revocation")
	}
	if _, ok := e.auth.PermitState(dOther); !ok {
		t.Fatal("pve-other permit revoked")
	}
	if _, ok := e.auth.PermitState(ssh.Digest); !ok {
		t.Fatal("SSH permit revoked")
	}
}
