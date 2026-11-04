// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/keyring"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// maxBatchCredentialRefs bounds the references of one
// GetBatchCredentialVersions request.
const maxBatchCredentialRefs = 32

// ErrCredentialRotated means a batch member binds another version of a
// credential than the key the executor holds for the reference now: the key
// was rotated after the plan was made. The member must not be proposed,
// approved or dispatched; the server plans again.
var ErrCredentialRotated = errors.New("batch: credential rotated since the plan was made")

// CredentialVersionOf is the batch credential version of an SSH credential
// (canonical.CredentialVersion.Version): the first eight bytes of the
// SHA-256 of the public key's wire encoding, big-endian, masked to the 53
// bits a canonical batch integer can carry (canonical.MaxCredentialVersion)
// and never zero, so it is always in 1..canonical.MaxCredentialVersion. It
// is derived from public data only and changes whenever the key behind a
// reference changes. A nil key has no version (0).
func CredentialVersionOf(pub ssh.PublicKey) uint64 {
	if pub == nil {
		return 0
	}
	sum := sha256.Sum256(pub.Marshal())
	if v := binary.BigEndian.Uint64(sum[:8]) & canonical.MaxCredentialVersion; v != 0 {
		return v
	}
	return 1
}

// CredentialVersion returns the current batch version of the SSH credential
// behind ref (CredentialVersionOf its public key). The error is the
// keyring's: keyring.ErrLocked, keyring.ErrUnknownRef or another failure.
// It never returns key material.
func (s *Service) CredentialVersion(ref string) (uint64, error) {
	signer, err := s.keys.Signer(ref)
	if err != nil {
		return 0, err
	}
	return CredentialVersionOf(signer.PublicKey()), nil
}

// credentialStatus maps a keyring error to the gRPC status of the batch
// credential checks.
func credentialStatus(err error) error {
	switch {
	case errors.Is(err, keyring.ErrLocked):
		return status.Error(codes.FailedPrecondition, "keyring is locked; run `nebula unlock`")
	case errors.Is(err, keyring.ErrUnknownRef):
		return status.Error(codes.NotFound, "batch: a credential reference is not loaded")
	case errors.Is(err, ErrCredentialRotated):
		return status.Error(codes.FailedPrecondition, ErrCredentialRotated.Error()+"; propose a fresh plan")
	default:
		return status.Error(codes.Internal, "keyring error")
	}
}

// checkMemberCredentials compares every credential version member binds
// with the version of the key the executor holds for the reference now. It
// fails closed: a locked keyring, an unknown reference or a different
// version is an error (ErrCredentialRotated for a different version, which
// is audited with versions only, never key material).
func (s *Service) checkMemberCredentials(where string, member canonical.BatchMember) error {
	for _, v := range member.CredentialVersions {
		cur, err := s.CredentialVersion(v.Reference)
		if err != nil {
			return err
		}
		if cur != v.Version {
			s.log.Warn("audit", "kind", "batch_credential_rotated", "at", where, "member", member.MemberID,
				"execution", member.Request.ExecutionID, "credential_ref", v.Reference,
				"bound_version", v.Version, "current_version", cur)
			return fmt.Errorf("%w: member %s, credential %s", ErrCredentialRotated, member.MemberID, v.Reference)
		}
	}
	return nil
}

// GetBatchCredentialVersions returns the current version of each requested
// SSH credential reference (server and admin roles, read-only), so the
// server can bind exact versions into a batch plan. It returns versions and
// public-key fingerprints only. Like the other batch RPCs it is
// Unimplemented while no batch authority is wired. The response also says
// whether approved batch members are executed (batch_execution_available),
// which is false unless SetBatchExecutionAvailable was called.
func (s *Service) GetBatchCredentialVersions(_ context.Context, req *pb.GetBatchCredentialVersionsRequest) (*pb.GetBatchCredentialVersionsResponse, error) {
	if err := validateBatchMessage(req); err != nil {
		return nil, err
	}
	refs := req.GetCredentialRefs()
	if len(refs) > maxBatchCredentialRefs {
		return nil, status.Errorf(codes.InvalidArgument, "batch: at most %d credential references", maxBatchCredentialRefs)
	}
	seen := make(map[string]bool, len(refs))
	for _, ref := range refs {
		if !canonical.ValidCredentialRef(ref) || seen[ref] {
			return nil, status.Error(codes.InvalidArgument, "batch: invalid or duplicate credential reference")
		}
		seen[ref] = true
	}
	if s.batchAuth == nil {
		return nil, errBatchUnconfigured
	}
	out := &pb.GetBatchCredentialVersionsResponse{
		Versions:                make([]*pb.BatchCredentialVersion, 0, len(refs)),
		BatchExecutionAvailable: s.batchExecution,
	}
	for _, ref := range refs {
		signer, err := s.keys.Signer(ref)
		if err != nil {
			return nil, credentialStatus(err)
		}
		pub := signer.PublicKey()
		out.Versions = append(out.Versions, &pb.BatchCredentialVersion{
			CredentialRef:        ref,
			Version:              CredentialVersionOf(pub),
			PublicKeyFingerprint: ssh.FingerprintSHA256(pub),
		})
	}
	return out, nil
}
