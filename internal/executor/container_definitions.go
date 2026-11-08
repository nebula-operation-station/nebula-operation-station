// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executor/containerdef"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vault"
)

// Standalone container definitions (ADR 0006 P2-03, container update plan
// cu05, storage part). The admin stores the exact `docker create`
// definition of a standalone container; it holds env values, so it lives
// only in the executor vault as one write-once secret per version
// (executordb.ContainerDefinitionSecretID) and never leaves the executor:
// responses, errors and log lines carry metadata only (host, container
// name, definition ID, version, author, time), never content and never a
// digest of it (Q20). Dispatch reads it again in cu05b.

// PutContainerDefinition validates and stores a new version of a
// standalone container definition (admin role). The previous versions are
// kept.
func (s *Service) PutContainerDefinition(ctx context.Context, in *pb.PutContainerDefinitionRequest) (*pb.PutContainerDefinitionResponse, error) {
	who := callerName(ctx)
	host, name := in.GetHostId(), in.GetContainerName()
	if !canonical.ValidHostID(host) {
		return nil, status.Error(codes.InvalidArgument, "invalid host ID")
	}
	def := containerdef.Definition{Format: containerdef.Format, ContainerName: name,
		Options: in.GetOptions(), Command: in.GetCommand()}
	for _, e := range in.GetEnv() {
		def.Env = append(def.Env, containerdef.EnvVar{Name: e.GetName(), Value: e.GetValue()})
	}
	// The shape errors name positions and flags, never a value.
	raw, err := containerdef.Encode(def, name)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	defer clear(raw)
	if st, err := s.vault.State(); err != nil || st != vault.StateUnlocked {
		return nil, status.Error(codes.FailedPrecondition, "the executor vault is locked")
	}
	newID, err := newExecutionID()
	if err != nil {
		return nil, status.Error(codes.Internal, "random source unavailable")
	}
	next, err := s.db.NextContainerDefinition(host, name, newID)
	if err != nil {
		return nil, s.definitionError("put_container_definition", err)
	}
	next.CreatedBy = who
	// The secret and the metadata row commit together; a secret that
	// already exists is never replaced (version 1 only).
	if _, err := s.vault.PutWithCommit(next.VaultSecretID, raw, who, func(sec executordb.VaultSecret) error {
		return s.db.AddContainerDefinition(next, sec)
	}); err != nil {
		return nil, s.definitionError("put_container_definition", err)
	}
	s.log.Info("audit", "kind", "container_definition_put", "by", who, "host", host, "container", name,
		"definition_id", next.DefinitionID, "version", next.Version)
	versions, err := s.db.ContainerDefinitionVersions(host, name)
	if err != nil {
		return nil, s.definitionError("put_container_definition", err)
	}
	for _, v := range versions {
		if v.Version == next.Version {
			return &pb.PutContainerDefinitionResponse{Definition: definitionInfo(v, true)}, nil
		}
	}
	return nil, status.Error(codes.Aborted, "the container definition changed concurrently")
}

// RemoveContainerDefinition removes every version of a definition
// (version 0) or one older version, with their vault secrets (admin role).
// It is refused while a container recreation in intent or inside its
// rollback window references a version it would drop.
func (s *Service) RemoveContainerDefinition(ctx context.Context, in *pb.RemoveContainerDefinitionRequest) (*pb.RemoveContainerDefinitionResponse, error) {
	who := callerName(ctx)
	host, name := in.GetHostId(), in.GetContainerName()
	if !canonical.ValidHostID(host) || name == "" {
		return nil, status.Error(codes.InvalidArgument, "invalid host ID or container name")
	}
	if in.GetVersion() > executordb.MaxContainerDefinitionVersion {
		return nil, status.Error(codes.InvalidArgument, "invalid version")
	}
	// Like a vault delete: a locked executor cannot be made to lose secrets.
	if st, err := s.vault.State(); err != nil || st != vault.StateUnlocked {
		return nil, status.Error(codes.FailedPrecondition, "the executor vault is locked")
	}
	dropped, err := s.db.RemoveContainerDefinition(host, name, in.GetVersion())
	if err != nil {
		return nil, s.definitionError("remove_container_definition", err)
	}
	out := &pb.RemoveContainerDefinitionResponse{}
	for _, d := range dropped {
		out.Versions = append(out.Versions, d.Version)
	}
	s.log.Info("audit", "kind", "container_definition_removed", "by", who, "host", host, "container", name,
		"definition_id", dropped[0].DefinitionID, "versions", out.Versions)
	return out, nil
}

// ListContainerDefinitions lists the metadata of every kept version (admin
// role). It works while the vault is locked: nothing is opened.
func (s *Service) ListContainerDefinitions(_ context.Context, in *pb.ListContainerDefinitionsRequest) (*pb.ListContainerDefinitionsResponse, error) {
	if h := in.GetHostId(); h != "" && !canonical.ValidHostID(h) {
		return nil, status.Error(codes.InvalidArgument, "invalid host ID")
	}
	rows, err := s.db.ListContainerDefinitions(in.GetHostId())
	if err != nil {
		return nil, s.definitionError("list_container_definitions", err)
	}
	out := &pb.ListContainerDefinitionsResponse{}
	for i, d := range rows {
		latest := i+1 == len(rows) || rows[i+1].DefinitionID != d.DefinitionID
		out.Definitions = append(out.Definitions, definitionInfo(d, latest))
	}
	return out, nil
}

// definitionInfo is the metadata a response may carry: no content, no
// digest and no vault secret ID.
func definitionInfo(d executordb.ContainerDefinition, latest bool) *pb.ContainerDefinitionInfo {
	return &pb.ContainerDefinitionInfo{HostId: d.HostID, ContainerName: d.ContainerName, DefinitionId: d.DefinitionID,
		Version: d.Version, CreatedBy: d.CreatedBy, CreatedAtUnix: d.CreatedAt.Unix(), Latest: latest}
}

// definitionError maps store errors; no message carries definition content.
func (s *Service) definitionError(op string, err error) error {
	switch {
	case errors.Is(err, executordb.ErrNoContainerDefinition):
		return status.Error(codes.NotFound, "container definition not found")
	case errors.Is(err, executordb.ErrDefinitionInWindow):
		return status.Error(codes.FailedPrecondition, "a container recreation inside its rollback window references the definition; it is kept until the window ends")
	case errors.Is(err, executordb.ErrDefinitionLatest):
		return status.Error(codes.FailedPrecondition, "the newest version is removed only with the whole definition (version 0)")
	case errors.Is(err, executordb.ErrDefinitionLimit):
		return status.Error(codes.ResourceExhausted, err.Error())
	case errors.Is(err, executordb.ErrDefinitionExists), errors.Is(err, executordb.ErrSecretVersion):
		return status.Error(codes.Aborted, "the container definition changed concurrently; retry")
	}
	return s.vaultError(op, err)
}

// errDefinitionSecretManaged refuses generic vault writes to definition
// secrets: only the definition RPCs write (once) or delete them.
var errDefinitionSecretManaged = status.Error(codes.PermissionDenied,
	"container definition secrets are managed by the container definition RPCs only")
