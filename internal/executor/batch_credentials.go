// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/keyring"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

const (
	// maxBatchCredentialRefs bounds the references of one
	// GetBatchCredentialVersions request.
	maxBatchCredentialRefs = 32
	// maxBatchCredentialRefBytes bounds one credential reference.
	maxBatchCredentialRefBytes = 128
)

// CredentialVersionOf is the batch credential version of an SSH credential
// (canonical.CredentialVersion.Version): the first eight bytes of the
// SHA-256 of the public key's wire encoding, big-endian, never zero. It is
// derived from public data only and changes whenever the key behind a
// reference changes. A nil key has no version (0).
func CredentialVersionOf(pub ssh.PublicKey) uint64 {
	if pub == nil {
		return 0
	}
	sum := sha256.Sum256(pub.Marshal())
	if v := binary.BigEndian.Uint64(sum[:8]); v != 0 {
		return v
	}
	return 1
}

// validBatchCredentialRef reports whether ref is a bounded, printable UTF-8
// credential reference.
func validBatchCredentialRef(ref string) bool {
	if ref == "" || len(ref) > maxBatchCredentialRefBytes || !utf8.ValidString(ref) {
		return false
	}
	for _, r := range ref {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// GetBatchCredentialVersions returns the current version of each requested
// SSH credential reference (server and admin roles, read-only), so the
// server can bind exact versions into a batch plan. It returns versions and
// public-key fingerprints only. Like the other batch RPCs it is
// Unimplemented while no batch authority is wired.
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
		if !validBatchCredentialRef(ref) || seen[ref] {
			return nil, status.Error(codes.InvalidArgument, "batch: invalid or duplicate credential reference")
		}
		seen[ref] = true
	}
	if s.batchAuth == nil {
		return nil, errBatchUnconfigured
	}
	out := &pb.GetBatchCredentialVersionsResponse{Versions: make([]*pb.BatchCredentialVersion, 0, len(refs))}
	for _, ref := range refs {
		signer, err := s.keys.Signer(ref)
		switch {
		case errors.Is(err, keyring.ErrLocked):
			return nil, status.Error(codes.FailedPrecondition, "keyring is locked; run `nebula unlock`")
		case errors.Is(err, keyring.ErrUnknownRef):
			return nil, status.Error(codes.NotFound, "batch: a credential reference is not loaded")
		case err != nil:
			return nil, status.Error(codes.Internal, "keyring error")
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
