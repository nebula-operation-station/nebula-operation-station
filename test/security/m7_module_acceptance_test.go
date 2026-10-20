// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"os"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"

	"github.com/nebula-operation-station/nebula-operation-station/internal/modulelock"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Fixtures in testdata/module: two lock versions of module "demo", signed
// with OpenSSH's ssh-keygen -Y sign by two throwaway keys (a, b) whose
// private halves were deleted.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/module/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (h *harness) registerReq(version, signer string) *pb.RegisterModuleRequest {
	return &pb.RegisterModuleRequest{LockJson: fixture(h.t, "lock-"+version+".json"), Signature: fixture(h.t, "lock-"+version+"."+signer+".sig"),
		Scripts: map[string][]byte{"actions/hello.sh": fixture(h.t, "hello.sh"), "actions/restart.sh": fixture(h.t, "restart.sh")}}
}

func (h *harness) trusted(action, version string) *pb.GetArtifactTrustResponse {
	h.t.Helper()
	l, _, err := modulelock.Parse(fixture(h.t, "lock-"+version+".json"))
	if err != nil {
		h.t.Fatal(err)
	}
	script := map[string]string{"hello": "hello.sh", "restart": "restart.sh"}[action]
	_, sum, err := l.Artifact(action, fixture(h.t, script))
	if err != nil {
		h.t.Fatal(err)
	}
	g, err := h.client.GetArtifactTrust(h.ctx(), &pb.GetArtifactTrustRequest{ArtifactSha256: sum, ActionId: "demo." + action, ModuleVersion: version})
	if err != nil {
		h.t.Fatal(err)
	}
	return g
}

// Spec 10: a module signed by a trusted signer runs at its declared risk;
// the executor verifies signature and scripts itself; a different signer
// needs manual review; removing a signer removes its trust.
func TestM7_SignedModules(t *testing.T) {
	h := newHarness(t, harnessOptions{untrusted: true})
	_, err := h.client.RegisterModule(h.ctx(), h.registerReq("1.0.0", "a"))
	wantCode(t, err, codes.PermissionDenied, "signer_untrusted")

	for _, k := range []string{"a.pub", "b.pub"} {
		if _, err := h.client.AddSigner(h.ctx(), &pb.AddSignerRequest{PublicKey: string(fixture(t, k)), Name: k}); err != nil {
			t.Fatal(err)
		}
	}
	_, err = h.client.AddSigner(h.ctx(), &pb.AddSignerRequest{PublicKey: "ssh-rsa AAAA x", Name: "rsa"})
	wantCode(t, err, codes.InvalidArgument, "")

	// Tampering: another script, a missing script, another signature.
	bad := h.registerReq("1.0.0", "a")
	bad.Scripts["actions/hello.sh"] = append(bad.Scripts["actions/hello.sh"], '#')
	_, err = h.client.RegisterModule(h.ctx(), bad)
	wantCode(t, err, codes.InvalidArgument, "does not hash")
	bad = h.registerReq("1.0.0", "a")
	delete(bad.Scripts, "actions/restart.sh")
	_, err = h.client.RegisterModule(h.ctx(), bad)
	wantCode(t, err, codes.InvalidArgument, "")
	bad = h.registerReq("1.0.0", "a")
	bad.Signature = fixture(t, "lock-1.1.0.a.sig")
	_, err = h.client.RegisterModule(h.ctx(), bad)
	wantCode(t, err, codes.PermissionDenied, "signature_invalid")
	if h.trusted("hello", "1.0.0").GetTrusted() {
		t.Fatal("trusted after refused registrations")
	}

	r, err := h.client.RegisterModule(h.ctx(), h.registerReq("1.0.0", "a"))
	if err != nil || r.GetName() != "demo" || len(r.GetActions()) != 2 {
		t.Fatalf("%v %v", r, err)
	}
	if g := h.trusted("hello", "1.0.0"); !g.GetTrusted() || g.GetRiskClass() != riskLow {
		t.Fatalf("hello: %v", g)
	}
	if g := h.trusted("restart", "1.0.0"); !g.GetTrusted() || g.GetRiskClass() != riskMedium {
		t.Fatalf("restart declares requires_root: %v", g)
	}
	h.requireAudit("module_registered", "demo", "1.0.0")
	if _, err := h.client.RegisterModule(h.ctx(), h.registerReq("1.0.0", "a")); err != nil {
		t.Fatal("registering the same version again:", err)
	}

	// Version 1.1.0 signed by b: manual review first.
	_, err = h.client.RegisterModule(h.ctx(), h.registerReq("1.1.0", "b"))
	wantCode(t, err, codes.FailedPrecondition, "signer_changed")
	fpB := r.GetSignerFingerprint() // a's, replaced below
	signers, _ := h.client.ListSigners(h.ctx(), &pb.ListSignersRequest{})
	for _, s := range signers.GetSigners() {
		if s.GetName() == "b.pub" {
			fpB = s.GetFingerprint()
		}
	}
	// The admin confirms against the signer they reviewed.
	_, err = h.client.ConfirmModuleSigner(h.ctx(), &pb.ConfirmModuleSignerRequest{Module: "demo", Fingerprint: fpB, ExpectedPrevious: fpB})
	wantCode(t, err, codes.FailedPrecondition, "not the one you reviewed")
	conf, err := h.client.ConfirmModuleSigner(h.ctx(), &pb.ConfirmModuleSignerRequest{Module: "demo", Fingerprint: fpB, ExpectedPrevious: r.GetSignerFingerprint()})
	if err != nil || conf.GetPrevious() != r.GetSignerFingerprint() {
		t.Fatal(conf, err)
	}
	if !strings.Contains(h.logs.String(), `"previous":"`+r.GetSignerFingerprint()+`"`) {
		t.Fatal("the previous signer is not in the audit line")
	}
	if l, _ := h.client.ListSigners(h.ctx(), &pb.ListSignersRequest{}); len(l.GetModules()) != 1 || l.GetModules()[0].GetFingerprint() != fpB {
		t.Fatal("module binding not listed")
	}
	if _, err := h.client.RegisterModule(h.ctx(), h.registerReq("1.1.0", "b")); err != nil {
		t.Fatal(err)
	}
	if !h.trusted("hello", "1.1.0").GetTrusted() {
		t.Fatal("1.1.0 not trusted")
	}
	rm, err := h.client.RemoveSigner(h.ctx(), &pb.RemoveSignerRequest{Fingerprint: fpB})
	if err != nil || !rm.GetRemoved() || rm.GetTrustEntriesRemoved() != 2 {
		t.Fatalf("%v %v", rm, err)
	}
	if h.trusted("hello", "1.1.0").GetTrusted() || !h.trusted("hello", "1.0.0").GetTrusted() {
		t.Fatal("removing b must remove exactly b's trust")
	}
	h.requireAudit("signer_removed", fpB)
}

func TestM7_SignerAdministrationIsAdminOnly(t *testing.T) {
	uid := uint32(os.Getuid())
	h := newHarness(t, harnessOptions{uidRoles: map[uint32][]peercred.Role{uid: {peercred.RoleServer}}})
	_, err := h.client.AddSigner(h.ctx(), &pb.AddSignerRequest{PublicKey: string(fixture(t, "a.pub")), Name: "a"})
	wantCode(t, err, codes.PermissionDenied, "")
	_, err = h.client.ConfirmModuleSigner(h.ctx(), &pb.ConfirmModuleSignerRequest{})
	wantCode(t, err, codes.PermissionDenied, "")
	_, err = h.client.RemoveSigner(h.ctx(), &pb.RemoveSignerRequest{})
	wantCode(t, err, codes.PermissionDenied, "")
}
