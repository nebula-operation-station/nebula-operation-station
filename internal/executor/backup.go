// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"syscall"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/version"
)

// Backup limits (M10-2): the whole part must fit one response.
const (
	maxBackupTotal   = 48 << 20
	maxBackupKeyFile = 1 << 20
)

var backupKeyRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}\.(key|pub)$`)

// SetBackupDirs tells the service where executor.db and the SSH key files
// live, for BackupExecutor. Unset, BackupExecutor is refused.
func (s *Service) SetBackupDirs(dataDir, keysDir string) { s.dataDir, s.keysDir = dataDir, keysDir }

// BackupExecutor returns the executor's part of a backup: a snapshot of
// executor.db checked with PRAGMA integrity_check, and the SSH key files
// as they are on disk (encrypted with the passphrase). The event key and
// anything decrypted are never part of it.
func (s *Service) BackupExecutor(ctx context.Context, _ *pb.BackupExecutorRequest) (*pb.BackupExecutorResponse, error) {
	if s.dataDir == "" || s.keysDir == "" {
		return nil, status.Error(codes.FailedPrecondition, "backup is not set up")
	}
	tmp, err := os.MkdirTemp(s.dataDir, ".backup-")
	if err != nil {
		return nil, s.adminStoreError("backup", err)
	}
	defer os.RemoveAll(tmp)
	snap := filepath.Join(tmp, executordb.FileName)
	schema, err := s.db.Snapshot(snap)
	if err != nil {
		return nil, s.adminStoreError("backup", err)
	}
	b, err := readBounded(snap, maxBackupTotal)
	if err != nil {
		return nil, status.Error(codes.ResourceExhausted, "executor.db is too large for an online backup; stop the executor and copy the data directory")
	}
	resp := &pb.BackupExecutorResponse{SchemaVersion: int32(schema), Version: version.String(),
		Files: []*pb.BackupFile{{Name: executordb.FileName, Mode: 0o600, Data: b}}}
	total := len(b)
	entries, err := os.ReadDir(s.keysDir)
	if err != nil {
		return nil, s.adminStoreError("backup", err)
	}
	for _, e := range entries {
		if !backupKeyRe.MatchString(e.Name()) {
			continue
		}
		kb, err := readBounded(filepath.Join(s.keysDir, e.Name()), maxBackupKeyFile)
		if err != nil {
			continue // not a regular file, or too large: never a key file
		}
		total += len(kb)
		if total > maxBackupTotal {
			return nil, status.Error(codes.ResourceExhausted, "the backup is too large")
		}
		mode := uint32(0o600)
		if filepath.Ext(e.Name()) == ".pub" {
			mode = 0o644
		}
		resp.Files = append(resp.Files, &pb.BackupFile{Name: "keys/" + e.Name(), Mode: mode, Data: kb})
	}
	s.log.Info("audit", "kind", "backup_made", "by", callerName(ctx), "files", len(resp.Files), "bytes", total, "schema", schema)
	return resp, nil
}

// readBounded reads a regular file (no symlink) of at most limit bytes.
func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > limit {
		return nil, os.ErrInvalid
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, os.ErrInvalid
	}
	return b, nil
}
