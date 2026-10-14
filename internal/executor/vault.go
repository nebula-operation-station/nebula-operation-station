// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vault"
)

func (s *Service) vaultState() pb.VaultState {
	st, err := s.vault.State()
	if err != nil {
		s.log.Error("audit", "kind", "store_error", "op", "vault_state", "detail", err.Error())
		return pb.VaultState_VAULT_STATE_UNSPECIFIED
	}
	switch st {
	case vault.StateNotInitialized:
		return pb.VaultState_VAULT_STATE_NOT_INITIALIZED
	case vault.StateLocked:
		return pb.VaultState_VAULT_STATE_LOCKED
	default:
		return pb.VaultState_VAULT_STATE_UNLOCKED
	}
}

// vaultError maps vault errors. Messages never contain secret values: the
// vault package does not put them into errors.
func (s *Service) vaultError(op string, err error) error {
	switch {
	case errors.Is(err, vault.ErrLocked), errors.Is(err, vault.ErrNotInitialized), errors.Is(err, vault.ErrInitialized):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, vault.ErrWeakPassphrase), errors.Is(err, vault.ErrInvalidID), errors.Is(err, vault.ErrInvalidValue):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, vault.ErrNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, vault.ErrConcurrentChange):
		return status.Error(codes.Aborted, err.Error())
	case errors.Is(err, vault.ErrCorrupt):
		s.log.Error("audit", "kind", "vault_corrupt", "op", op)
		return status.Error(codes.DataLoss, err.Error())
	}
	return s.adminStoreError(op, err)
}

func (s *Service) InitVault(ctx context.Context, req *pb.InitVaultRequest) (*pb.InitVaultResponse, error) {
	who := callerName(ctx)
	if err := s.vault.Init(req.GetPassphrase(), s.vaultParams, who); err != nil {
		return nil, s.vaultError("init_vault", err)
	}
	s.log.Info("audit", "kind", "vault_initialized", "by", who,
		"kdf_time", s.vaultParams.Time, "kdf_memory_kib", s.vaultParams.MemoryKiB)
	return &pb.InitVaultResponse{}, nil
}

func (s *Service) SetSecret(ctx context.Context, req *pb.SetSecretRequest) (*pb.SetSecretResponse, error) {
	who := callerName(ctx)
	v, err := s.vault.Put(req.GetId(), req.GetValue(), who)
	if err != nil {
		return nil, s.vaultError("set_secret", err)
	}
	s.log.Info("audit", "kind", "secret_set", "by", who, "secret", req.GetId(), "version", v)
	return &pb.SetSecretResponse{Version: v}, nil
}

func (s *Service) ListSecrets(_ context.Context, _ *pb.ListSecretsRequest) (*pb.ListSecretsResponse, error) {
	list, err := s.vault.List()
	if err != nil {
		return nil, s.vaultError("list_secrets", err)
	}
	out := &pb.ListSecretsResponse{VaultState: s.vaultState()}
	for _, i := range list {
		out.Secrets = append(out.Secrets, &pb.SecretInfo{Id: i.ID, Version: i.Version, UpdatedAtUnix: i.UpdatedAt.Unix(), UpdatedBy: i.UpdatedBy})
	}
	return out, nil
}

func (s *Service) DeleteSecret(ctx context.Context, req *pb.DeleteSecretRequest) (*pb.DeleteSecretResponse, error) {
	who := callerName(ctx)
	if err := s.vault.Delete(req.GetId()); err != nil {
		return nil, s.vaultError("delete_secret", err)
	}
	s.log.Info("audit", "kind", "secret_deleted", "by", who, "secret", req.GetId())
	return &pb.DeleteSecretResponse{}, nil
}
