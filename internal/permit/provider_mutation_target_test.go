// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
)

func TestProviderMutationNodeTargetHasNoGeneration(t *testing.T) {
	tg := mutationTarget()
	tg.Kind, tg.VMID, tg.Generation = ProviderKindNode, 0, ""
	if err := tg.Validate(); err != nil {
		t.Fatalf("node target refused: %v", err)
	}
}

func TestValidPveNodeNameIsOneLabel(t *testing.T) {
	cases := map[string]bool{
		"pve1": true, "a": true, "pve-node-2": true, strings.Repeat("a", 63): true,
		"PVE1": false, "": false, "-pve": false, "pve-": false, "pve1.lab": false, "pve_1": false,
		strings.Repeat("a", 64): false, "pve 1": false, "pve1\n": false,
	}
	for name, want := range cases {
		if got := ValidPveNodeName(name); got != want {
			t.Errorf("ValidPveNodeName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestValidateProviderMutationShape(t *testing.T) {
	cases := []struct {
		kind, node string
		vmid       uint64
		ok         bool
	}{
		{ProviderKindQemu, "pve1", 101, true},
		{ProviderKindLXC, "pve1", pvecontract.MaxVMID, true},
		{ProviderKindNode, "pve1", 0, true},
		{ProviderKindQemu, "pve1", 99, false},
		{ProviderKindQemu, "pve1", pvecontract.MaxVMID + 1, false},
		{ProviderKindNode, "pve1", 101, false},
		{"storage", "pve1", 101, false},
		{ProviderKindQemu, "pve1.lab.test", 101, false},
		{ProviderKindQemu, "../etc", 101, false},
	}
	for _, c := range cases {
		err := ValidateProviderMutationShape(c.kind, c.node, c.vmid)
		if (err == nil) != c.ok {
			t.Errorf("shape %s/%s/%d: %v, want ok=%v", c.kind, c.node, c.vmid, err, c.ok)
		}
	}
}

func TestProviderMutationBindingCarriesVersionedTarget(t *testing.T) {
	b, err := mutation(mutationTarget()).BindingJSON()
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Binding string                     `json:"binding"`
		Target  map[string]json.RawMessage `json:"provider_target"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Binding != "pve-mutation-v2" || string(doc.Target["target_version"]) != `"pve-target-v1"` ||
		string(doc.Target["generation"]) != `"`+strings.Repeat("9f", 20)+`"` {
		t.Fatalf("binding %s", b)
	}
}

func TestProviderMutationClaimReleaseMakesPermitUsableAgain(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	d := e.approvedMutation(mutationTarget())
	c, err := e.auth.AuthorizeProviderMutation(d, mutation(mutationTarget()))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Release("target busy") {
		t.Fatal("release refused")
	}
	if c.Release("target busy") {
		t.Fatal("second release of an unused permit succeeded")
	}
	if _, err := e.auth.AuthorizeProviderMutation(d, mutation(mutationTarget())); err != nil {
		t.Fatalf("released permit refused: %v", err)
	}
	_, err = e.auth.AuthorizeProviderMutation(d, mutation(mutationTarget()))
	wantCode(t, err, CodeHostAlreadyRun)
}

// TestProviderMutationStaleClaimReleaseKeepsLaterUse: once a claim was
// released and the permit authorized again, the stale first claim can no
// longer release it, so the permit is not usable a third time.
func TestProviderMutationStaleClaimReleaseKeepsLaterUse(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	d := e.approvedMutation(mutationTarget())
	first, err := e.auth.AuthorizeProviderMutation(d, mutation(mutationTarget()))
	if err != nil {
		t.Fatal(err)
	}
	if !first.Release("target busy") {
		t.Fatal("release refused")
	}
	second, err := e.auth.AuthorizeProviderMutation(d, mutation(mutationTarget()))
	if err != nil {
		t.Fatalf("released permit refused: %v", err)
	}
	if first.Release("stale") {
		t.Fatal("stale claim released a later claim's use")
	}
	_, err = e.auth.AuthorizeProviderMutation(d, mutation(mutationTarget()))
	wantCode(t, err, CodeHostAlreadyRun)
	// The owning claim still can.
	if !second.Release("target busy") {
		t.Fatal("owning claim's release refused")
	}
}

func TestProviderMutationClaimReleaseRefusedAfterLockOrRevoke(t *testing.T) {
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
			if c.Release("target busy") {
				t.Fatal("released after " + name)
			}
		})
	}
	if (MutationClaim{}).Release("x") {
		t.Fatal("zero claim released")
	}
}

// mutationRun is the plain host run AuthorizeProviderMutation authorizes
// for m.
func mutationRun(t *testing.T, m ProviderMutation) Run {
	t.Helper()
	params, err := m.BindingJSON()
	if err != nil {
		t.Fatal(err)
	}
	target, err := m.Target.canonicalTarget()
	if err != nil {
		t.Fatal(err)
	}
	return Run{
		HostID: target.HostID, HostKeyFingerprint: target.HostKeyFingerprint, ActionID: m.ActionID,
		ModuleVersion: m.ModuleVersion, Artifact: m.Artifact, ParametersJSON: params, CredentialRef: m.Target.CredentialRef,
	}
}

// TestProviderMutationReleaseHostClearsClaim: ReleaseHost ends the claim's
// use, so the claim must not release a later use it did not make.
func TestProviderMutationReleaseHostClearsClaim(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	d := e.approvedMutation(mutationTarget())
	m := mutation(mutationTarget())
	c, err := e.auth.AuthorizeProviderMutation(d, m)
	if err != nil {
		t.Fatal(err)
	}
	if !e.auth.ReleaseHost(d, mutationRun(t, m).HostID) {
		t.Fatal("ReleaseHost refused")
	}
	if _, err := e.auth.AuthorizeGrant(d, mutationRun(t, m)); err != nil {
		t.Fatalf("released permit refused: %v", err)
	}
	if c.Release("stale") {
		t.Fatal("claim released a use made after ReleaseHost")
	}
	_, err = e.auth.AuthorizeProviderMutation(d, m)
	wantCode(t, err, CodeHostAlreadyRun)
}

// TestProviderMutationClaimOwnsItsUse: the claim token is set together
// with the use; a plain grant leaves the permit without an owning claim.
func TestProviderMutationClaimOwnsItsUse(t *testing.T) {
	e := newEnv(t, ModeStandard, virtualwebauthn.AuthenticatorOptions{})
	d := e.approvedMutation(mutationTarget())
	m := mutation(mutationTarget())
	c, err := e.auth.AuthorizeProviderMutation(d, m)
	if err != nil {
		t.Fatal(err)
	}
	claimOf := func() uint64 {
		e.auth.mu.Lock()
		defer e.auth.mu.Unlock()
		return e.auth.permits[d].claim
	}
	if c.token == 0 || claimOf() != c.token {
		t.Fatalf("claim token %d, permit claim %d", c.token, claimOf())
	}
	if !c.Release("target busy") {
		t.Fatal("release refused")
	}
	if claimOf() != 0 {
		t.Fatal("release left the claim token")
	}
	if _, err := e.auth.AuthorizeGrant(d, mutationRun(t, m)); err != nil {
		t.Fatal(err)
	}
	if claimOf() != 0 {
		t.Fatal("plain grant carries a claim token")
	}
}
