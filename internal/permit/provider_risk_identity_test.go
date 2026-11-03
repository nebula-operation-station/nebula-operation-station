// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
)

// TestProviderRiskTargetsHaveDistinctFingerprints: the guest and node risk
// targets of one remote, and the targets of two nodes or two guests, each
// have their own fingerprint, none of which is the bare trust pin, so the
// executor can hold one exact criticality record for each (one record per
// fingerprint, executordb).
func TestProviderRiskTargetsHaveDistinctFingerprints(t *testing.T) {
	pin, _ := hex.DecodeString(strings.Repeat("ab", 32))
	pinFP := "SHA256:" + base64.RawStdEncoding.EncodeToString(pin)

	guest := mutationTarget()
	guest2 := mutationTarget()
	guest2.VMID = 102
	node := mutationTarget()
	node.Kind, node.VMID, node.Generation = ProviderKindNode, 0, ""
	node2 := node
	node2.Node = "pve2"

	seenID, seenFP := map[string]string{}, map[string]string{}
	for name, tg := range map[string]ProviderMutationTarget{"guest": guest, "guest2": guest2, "node": node, "node2": node2} {
		rt, err := tg.RiskTarget()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !canonical.ValidHostID(rt.HostID) || !canonical.ValidHostKeyFingerprint(rt.HostKeyFingerprint) {
			t.Fatalf("%s: malformed risk target %+v", name, rt)
		}
		if rt.HostKeyFingerprint == pinFP {
			t.Fatalf("%s: fingerprint is the bare trust pin", name)
		}
		if other, dup := seenID[rt.HostID]; dup {
			t.Fatalf("%s and %s share host ID %s", name, other, rt.HostID)
		}
		if other, dup := seenFP[rt.HostKeyFingerprint]; dup {
			t.Fatalf("%s and %s share fingerprint %s", name, other, rt.HostKeyFingerprint)
		}
		seenID[rt.HostID], seenFP[rt.HostKeyFingerprint] = name, name
		again, _ := tg.RiskTarget()
		if again != rt {
			t.Fatalf("%s: unstable risk target", name)
		}
		fp, err := ProviderRiskFingerprint(tg.TrustPin, rt.HostID)
		if err != nil || fp != rt.HostKeyFingerprint {
			t.Fatalf("%s: ProviderRiskFingerprint = %q, %v; want %q", name, fp, err, rt.HostKeyFingerprint)
		}
	}
}

// TestProviderRiskTargetFollowsTrustPin: a re-pinned remote keeps the
// target's host ID (so an old record still raises it) but changes its
// fingerprint (so the old record is no longer exact: fail closed).
func TestProviderRiskTargetFollowsTrustPin(t *testing.T) {
	a := mutationTarget()
	b := mutationTarget()
	b.TrustPin = strings.Repeat("cd", 32)
	ra, _ := a.RiskTarget()
	rb, err := b.RiskTarget()
	if err != nil {
		t.Fatal(err)
	}
	if ra.HostID != rb.HostID || ra.HostKeyFingerprint == rb.HostKeyFingerprint {
		t.Fatalf("re-pinned target %+v, before %+v", rb, ra)
	}
}

func TestProviderRiskFingerprintRejectsMalformedInput(t *testing.T) {
	rt, _ := mutationTarget().RiskTarget()
	for name, c := range map[string][2]string{
		"short pin":     {"abcd", rt.HostID},
		"non-hex pin":   {strings.Repeat("zz", 32), rt.HostID},
		"bad host id":   {strings.Repeat("ab", 32), "not a host id!"},
		"empty host id": {strings.Repeat("ab", 32), ""},
	} {
		if _, err := ProviderRiskFingerprint(c[0], c[1]); !errors.Is(err, ErrProviderMutationTarget) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}
