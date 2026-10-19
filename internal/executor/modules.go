// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"errors"
	"strings"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/modulelock"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/sshsig"
)

// Signed modules (M7-5, spec 10): the executor verifies the signature and
// the scripts itself; server-side trust status alone is never enough.

// RegisterModule verifies a signed module and trusts its actions.
func (s *Service) RegisterModule(_ context.Context, req *pb.RegisterModuleRequest) (*pb.RegisterModuleResponse, error) {
	lock, lockSum, err := modulelock.Parse(req.GetLockJson())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	key, ns, err := sshsig.Parse(req.GetSignature())
	if err != nil || ns != modulelock.Namespace {
		return nil, status.Error(codes.InvalidArgument, "signature_invalid: not an SSH signature for namespace "+modulelock.Namespace)
	}
	fp := sshsig.Fingerprint(key)
	signer, ok, err := s.db.Signer(fp)
	if err != nil {
		return nil, s.adminStoreError("register_module", err)
	}
	if !ok {
		s.log.Warn("audit", "kind", "module_refused", "module", lock.Name, "version", lock.Version, "signer", fp, "reason", "signer not trusted")
		return nil, status.Errorf(codes.PermissionDenied, "signer_untrusted: %s is not a trusted signer", fp)
	}
	trusted, _, _, _, err := ssh.ParseAuthorizedKey([]byte(signer.PublicKey))
	if err != nil {
		return nil, s.adminStoreError("register_module", err)
	}
	if err := sshsig.Verify(trusted, modulelock.Namespace, req.GetLockJson(), req.GetSignature()); err != nil {
		s.log.Warn("audit", "kind", "module_refused", "module", lock.Name, "version", lock.Version, "signer", fp, "reason", err.Error())
		return nil, status.Error(codes.PermissionDenied, "signature_invalid: the signature does not verify")
	}
	if !sameScripts(lock, req.GetScripts()) {
		return nil, status.Error(codes.InvalidArgument, "module_invalid: scripts must be exactly the files the lock names")
	}
	out := &pb.RegisterModuleResponse{Name: lock.Name, Version: lock.Version, LockSha256: lockSum, SignerFingerprint: fp, SignerName: signer.Name}
	var arts []executordb.TrustedArtifact
	for _, name := range lock.Names() {
		a := lock.Actions[name]
		_, sum, err := lock.Artifact(name, req.GetScripts()[a.Script])
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		risk := canonical.Risk(a.TrustRisk())
		arts = append(arts, executordb.TrustedArtifact{SHA256: sum, ActionID: lock.ActionID(name), ModuleVersion: lock.Version, Risk: risk,
			Label: "module " + lock.Name + " " + lock.Version + " signed by " + signer.Name, TrustedBy: executordb.SignerPrefix + fp})
		out.Actions = append(out.Actions, &pb.ModuleAction{ActionId: lock.ActionID(name), ModuleVersion: lock.Version, ArtifactSha256: sum, RiskClass: riskToProto(risk)})
	}
	err = s.db.RegisterModule(executordb.ModuleVersion{Name: lock.Name, Version: lock.Version, LockSHA256: lockSum, Fingerprint: fp}, arts)
	switch {
	case errors.Is(err, executordb.ErrSignerChanged):
		s.log.Warn("audit", "kind", "module_refused", "module", lock.Name, "version", lock.Version, "signer", fp, "reason", "signer changed")
		return nil, status.Errorf(codes.FailedPrecondition, "signer_changed: %s was signed by another signer before; review it and run `nebula module confirm-signer %s %s` on the executor host", lock.Name, lock.Name, fp)
	case errors.Is(err, executordb.ErrVersionChanged):
		return nil, status.Errorf(codes.FailedPrecondition, "version_changed: %s %s was registered with another lock; publish a new version", lock.Name, lock.Version)
	case err != nil:
		return nil, s.adminStoreError("register_module", err)
	}
	s.log.Info("audit", "kind", "module_registered", "module", lock.Name, "version", lock.Version, "lock_sha256", lockSum,
		"signer", fp, "actions", len(arts))
	return out, nil
}

// sameScripts reports whether scripts holds exactly the lock's files
// (actions may share a script).
func sameScripts(lock modulelock.Lock, scripts map[string][]byte) bool {
	want := map[string]bool{}
	for _, a := range lock.Actions {
		want[a.Script] = true
	}
	if len(want) != len(scripts) {
		return false
	}
	for p := range scripts {
		if !want[p] {
			return false
		}
	}
	return true
}

// AddSigner trusts an Ed25519 signing key (admin, CRITICAL).
func (s *Service) AddSigner(ctx context.Context, req *pb.AddSignerRequest) (*pb.AddSignerResponse, error) {
	key, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(req.GetPublicKey()))
	if err != nil || len(strings.TrimSpace(string(rest))) > 0 {
		return nil, status.Error(codes.InvalidArgument, "public_key must be one authorized_keys line")
	}
	if key.Type() != ssh.KeyAlgoED25519 {
		return nil, status.Error(codes.InvalidArgument, "only Ed25519 signing keys are accepted")
	}
	fp := sshsig.Fingerprint(key)
	who := callerName(ctx)
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	if err := s.db.AddSigner(executordb.Signer{Fingerprint: fp, PublicKey: line, Name: req.GetName(), AddedBy: who}); err != nil {
		return nil, s.adminStoreError("add_signer", err)
	}
	s.log.Info("audit", "kind", "signer_added", "by", who, "signer", fp, "name", req.GetName())
	return &pb.AddSignerResponse{Fingerprint: fp}, nil
}

// RemoveSigner removes a signer and the trust its modules created.
func (s *Service) RemoveSigner(ctx context.Context, req *pb.RemoveSignerRequest) (*pb.RemoveSignerResponse, error) {
	removed, n, err := s.db.RemoveSigner(req.GetFingerprint())
	if err != nil {
		return nil, s.adminStoreError("remove_signer", err)
	}
	if removed || n > 0 {
		s.log.Info("audit", "kind", "signer_removed", "by", callerName(ctx), "signer", req.GetFingerprint(), "trust_entries", n)
	}
	return &pb.RemoveSignerResponse{Removed: removed, TrustEntriesRemoved: n}, nil
}

// ConfirmModuleSigner accepts a new signer for a module (manual review).
func (s *Service) ConfirmModuleSigner(ctx context.Context, req *pb.ConfirmModuleSignerRequest) (*pb.ConfirmModuleSignerResponse, error) {
	if _, ok, err := s.db.Signer(req.GetFingerprint()); err != nil {
		return nil, s.adminStoreError("confirm_module_signer", err)
	} else if !ok {
		return nil, status.Error(codes.FailedPrecondition, "the signer is not trusted; add it first")
	}
	who := callerName(ctx)
	if err := s.db.ConfirmModuleSigner(req.GetModule(), req.GetFingerprint(), who); err != nil {
		return nil, s.adminStoreError("confirm_module_signer", err)
	}
	s.log.Info("audit", "kind", "module_signer_confirmed", "by", who, "module", req.GetModule(), "signer", req.GetFingerprint())
	return &pb.ConfirmModuleSignerResponse{}, nil
}

// ListSigners lists the trusted signers.
func (s *Service) ListSigners(context.Context, *pb.ListSignersRequest) (*pb.ListSignersResponse, error) {
	list, err := s.db.Signers()
	if err != nil {
		return nil, s.adminStoreError("list_signers", err)
	}
	out := &pb.ListSignersResponse{}
	for _, x := range list {
		out.Signers = append(out.Signers, &pb.Signer{Fingerprint: x.Fingerprint, Name: x.Name, AddedUnix: x.AddedAt.Unix(), AddedBy: x.AddedBy})
	}
	return out, nil
}
