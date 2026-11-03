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
