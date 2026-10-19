// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"

	"github.com/nebula-operation-station/nebula-operation-station/internal/backup"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// M10-2: the executor's part of a backup is a checked snapshot and the SSH
// key files as they are on disk (encrypted); never the event key, never a
// decrypted key, even while unlocked; only the admin role gets it.
func TestBackupExecutorPart(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.unlock()
	resp, err := h.client.BackupExecutor(h.ctx(), &pb.BackupExecutorRequest{})
	if err != nil {
		t.Fatal(err)
	}
	names := map[string][]byte{}
	for _, f := range resp.GetFiles() {
		names[f.GetName()] = f.GetData()
	}
	if names["executor.db"] == nil || names["keys/"+credRef+".key"] == nil {
		t.Fatalf("files: %v", keys(names))
	}
	for n, b := range names {
		if strings.Contains(n, "events") || bytes.Contains(b, []byte("PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU")) {
			t.Fatalf("%s must not be in a backup", n)
		}
	}
	onDisk, _ := os.ReadFile(filepath.Join(h.dataDir, "testkeys", credRef+".key"))
	if !bytes.Equal(onDisk, names["keys/"+credRef+".key"]) {
		t.Fatal("the key file is not the encrypted file on disk")
	}
	snap := filepath.Join(t.TempDir(), "executor.db")
	_ = os.WriteFile(snap, names["executor.db"], 0o600)
	if v, err := backup.CheckSQLite(snap); err != nil || v != int(resp.GetSchemaVersion()) {
		t.Fatal(v, err)
	}
	if !strings.Contains(h.logs.String(), `"kind":"backup_made"`) {
		t.Fatal("no audit line")
	}
	// The server role cannot take a backup.
	uid := uint32(os.Getuid())
	hs := newHarness(t, harnessOptions{uidRoles: map[uint32][]peercred.Role{uid: {peercred.RoleServer}}})
	_, err = hs.client.BackupExecutor(hs.ctx(), &pb.BackupExecutorRequest{})
	wantCode(t, err, codes.PermissionDenied, "")
}

func keys(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
