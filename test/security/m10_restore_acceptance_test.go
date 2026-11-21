// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"

	"github.com/nebula-operation-station/nebula-operation-station/internal/backup"
	"github.com/nebula-operation-station/nebula-operation-station/internal/events"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executorclient"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
)

// M10-2 end to end (admin guide 12, ADR 0004): a backup taken from a real
// executor over gRPC and a real server.db, written with age, restored with
// backup.Restore into an empty root, and the real executor and serverdb
// started on what was restored. No root: the System below only records
// Stop, Start and Chown.

// restoreNow is the restore time; it names the from-backup directory.
var restoreNow = time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)

const (
	restoreTS     = "20261121-100000"
	inventoryHost = "web-01"
	serverJSON    = `{"public_origin":"https://nebula.example.org"}`
)

// Files the server keeps in its data directory that a backup does not hold.
// The names are unexported constants of cmd/nebula-server (ops.go
// opsNotesDir/opsNotesFile, software.go iconStoreDirName,
// leasewatch_wiring.go leaseWatchStateFile, vuln.go vulnNotifyStateFile);
// the source that keeps them out is backup.ValidPath.
var notBackedUp = []string{"opsnotes/notes.db", "icons/web-01.png", "leasewatch-state.json", "vuln-notify-state.json"}

// recordingSystem is a backup.System that executes nothing.
type recordingSystem struct {
	mu     sync.Mutex
	stops  [][]string
	starts [][]string
	chowns map[string][]string // path -> users, in call order
}

func newRecordingSystem() *recordingSystem {
	return &recordingSystem{chowns: map[string][]string{}}
}

func (s *recordingSystem) Stop(units ...string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stops = append(s.stops, append([]string(nil), units...))
	return nil
}

func (s *recordingSystem) Start(units ...string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.starts = append(s.starts, append([]string(nil), units...))
	return nil
}

func (s *recordingSystem) Chown(path, user string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.chowns[path] = append(s.chowns[path], user)
	return nil
}

func (s *recordingSystem) calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.stops) + len(s.starts) + len(s.chowns)
}

// serverSource builds a server installation below a fresh root: server.db
// with one inventory host and one web session, the state files the server
// keeps next to it, and /etc/nebula/server.json. It returns the root and
// the session token.
func serverSource(t *testing.T) (root, token string) {
	t.Helper()
	root = t.TempDir()
	dir := filepath.Join(root, "var", "lib", "nebula", "server")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	db, err := serverdb.Open(filepath.Join(dir, "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := inventory.New(db).Create(ctx, inventory.Host{
		ID: inventoryHost, DisplayName: "Web 01", Environment: inventory.EnvProd, Criticality: inventory.CriticalityMedium,
		Endpoints: []inventory.Endpoint{{Address: "10.0.0.5"}},
	}, inventory.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if token, _, err = auth.NewStore(db, nil).Create(ctx, "cred-admin", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	for _, p := range notBackedUp {
		full := filepath.Join(dir, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("state"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "etc", "nebula"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "nebula", "server.json"), []byte(serverJSON), 0o640); err != nil {
		t.Fatal(err)
	}
	return root, token
}

// serverPart forms the server's part of a backup. The function `nebula
// backup` uses (readServerPart in cmd/nebula/backup.go) is not exported
// from internal/backup, so this does what it does with the same building
// blocks: backup.SnapshotSQLite of server.db into backup.ServerDB and
// /etc/nebula/server.json as server/config/server.json (mode 0640).
func serverPart(t *testing.T, root string) ([]backup.File, int) {
	t.Helper()
	snap := filepath.Join(t.TempDir(), "server.db")
	v, err := backup.SnapshotSQLite(filepath.Join(root, "var", "lib", "nebula", "server", "server.db"), snap)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(snap)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := os.ReadFile(filepath.Join(root, "etc", "nebula", "server.json"))
	if err != nil {
		t.Fatal(err)
	}
	return []backup.File{
		{Path: backup.ServerDB, Mode: 0o600, Data: b},
		{Path: "server/config/server.json", Mode: 0o640, Data: cfg},
	}, v
}

// writeBackup assembles the archive as backupCmd does: the server's part,
// the executor's part (each file under executor/), a manifest with both
// schema versions, encrypted with age to rcpt.
func writeBackup(t *testing.T, resp *pb.BackupExecutorResponse, srcRoot string, rcpt age.Recipient) []byte {
	t.Helper()
	files, sv := serverPart(t, srcRoot)
	for _, f := range resp.GetFiles() {
		files = append(files, backup.File{Path: "executor/" + f.GetName(), Mode: f.GetMode(), Data: f.GetData()})
	}
	m := backup.Manifest{Version: "test", CreatedAt: "2026-11-21T09:00:00Z", Host: "nebula", Kind: "full",
		Schemas: map[string]int{"server": sv, "executor": int(resp.GetSchemaVersion())}}
	var out bytes.Buffer
	if err := backup.Write(&out, m, files, []age.Recipient{rcpt}); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(out.Bytes(), []byte("age-encryption.org/v1\n")) || bytes.Contains(out.Bytes(), []byte("OPENSSH")) {
		t.Fatal("the archive is not age-encrypted")
	}
	return out.Bytes()
}

// latestSchemas is what restoreWith passes to backup.Restore.
func latestSchemas(t *testing.T) map[string]int {
	t.Helper()
	sv, err := serverdb.LatestVersion()
	if err != nil {
		t.Fatal(err)
	}
	ev, err := executordb.LatestVersion()
	if err != nil {
		t.Fatal(err)
	}
	return map[string]int{"server": sv, "executor": ev}
}

func ageIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func wantMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != want {
		t.Errorf("%s has mode %o, want %o", path, fi.Mode().Perm(), want)
	}
}

func wantMissing(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("%s exists after the restore (err %v)", path, err)
	}
}

// treeState describes every entry below root: type and mode, size and
// SHA-256 of regular files, the target of symbolic links.
func treeState(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		desc := fi.Mode().String()
		switch {
		case fi.Mode().IsRegular():
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			desc += " " + hexSum(b)
		case fi.Mode()&fs.ModeSymlink != 0:
			l, err := os.Readlink(p)
			if err != nil {
				return err
			}
			desc += " -> " + l
		}
		out[p] = desc
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestRestoreIntoEmptyRootRestartsExecutorAndServer(t *testing.T) {
	// The state to back up: a registered credential (newHarness), the
	// trusted test script (trustDefaults), a pinned hostruntest host, the
	// encrypted SSH key (writeEncryptedKey) with its public half, and
	// signed events from unlock, session and pin.
	h := newHarness(t, harnessOptions{})
	h.unlock()
	host := h.pinnedRunHost("runhost")
	pubLine := ssh.MarshalAuthorizedKey(h.userKey)
	if err := os.WriteFile(filepath.Join(h.dataDir, "testkeys", credRef+".pub"), pubLine, 0o644); err != nil {
		t.Fatal(err)
	}
	before, err := h.client.ListEvents(h.ctx(), &pb.ListEventsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	oldEventKey := ed25519.PublicKey(before.GetPublicKey())
	oldEvents := records(before.GetEvents())
	if len(oldEvents) < 2 || events.Verify(oldEventKey, oldEvents, nil) != nil {
		t.Fatalf("%d events before the backup", len(oldEvents))
	}
	srcRoot, token := serverSource(t)

	// Backup: the executor's part over the real RPC.
	resp, err := h.client.BackupExecutor(h.ctx(), &pb.BackupExecutorRequest{})
	if err != nil {
		t.Fatal(err)
	}
	id := ageIdentity(t)
	archive := writeBackup(t, resp, srcRoot, id.Recipient())
	identity, userKey := h.id, h.userKey
	h.stop() // the old executor is gone (a new machine)

	// Restore into an empty root, as restoreWith does: Read, then Restore.
	m, files, err := backup.Read(bytes.NewReader(archive), []age.Identity{id})
	if err != nil {
		t.Fatal(err)
	}
	l := backup.Layout{Root: t.TempDir()}
	sys := newRecordingSystem()
	rep, err := backup.Restore(m, files, l, sys, latestSchemas(t), restoreNow)
	if err != nil {
		t.Fatal(err)
	}
	cfgDir := filepath.Join(l.ConfigDir(), "from-backup-"+restoreTS)
	if len(rep.MovedAside) != 0 || !reflect.DeepEqual(rep.Config, []string{filepath.Join(cfgDir, "server.json")}) {
		t.Fatalf("report %+v", rep)
	}

	// Modes as internal/backup/restore.go sets them.
	sd, ed := l.ServerDir(), l.ExecutorDir()
	keysDir := filepath.Join(ed, "keys")
	wantMode(t, sd, 0o750)
	wantMode(t, ed, 0o700)
	wantMode(t, keysDir, 0o700)
	wantMode(t, filepath.Join(sd, "server.db"), 0o600)
	wantMode(t, filepath.Join(ed, executordb.FileName), 0o600)
	wantMode(t, filepath.Join(keysDir, credRef+".key"), 0o600)
	wantMode(t, filepath.Join(keysDir, credRef+".pub"), 0o644)
	wantMode(t, filepath.Join(cfgDir, "server.json"), 0o640)
	if b, _ := os.ReadFile(filepath.Join(cfgDir, "server.json")); string(b) != serverJSON {
		t.Fatalf("server.json from the backup: %q", b)
	}
	if _, err := os.Lstat(filepath.Join(l.ConfigDir(), "server.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the backup's configuration was applied")
	}

	// Every file and directory restore.go writes got exactly one Chown
	// with its owner; nothing else did.
	wantChown := map[string][]string{
		sd:                                     {"nebula-server"},
		ed:                                     {"nebula-executor"},
		keysDir:                                {"nebula-executor"},
		filepath.Join(sd, "server.db"):         {"nebula-server"},
		filepath.Join(ed, executordb.FileName): {"nebula-executor"},
		filepath.Join(keysDir, credRef+".key"): {"nebula-executor"},
		filepath.Join(keysDir, credRef+".pub"): {"nebula-executor"},
		filepath.Join(cfgDir, "server.json"):   {"root"},
	}
	if !reflect.DeepEqual(sys.chowns, wantChown) {
		t.Fatalf("chown calls:\n got %v\nwant %v", sys.chowns, wantChown)
	}
	if !reflect.DeepEqual(sys.stops, [][]string{backup.StopUnits}) || !reflect.DeepEqual(sys.starts, [][]string{backup.StartUnits}) {
		t.Fatalf("stop %v, start %v", sys.stops, sys.starts)
	}

	// What is not in a backup (guide 12; backup.ValidPath is the source):
	// the event key, the executor's install marker, and the server's
	// state files next to server.db.
	wantMissing(t, filepath.Join(ed, events.KeyFile))
	wantMissing(t, filepath.Join(ed, executordb.MarkerName))
	for _, p := range notBackedUp {
		wantMissing(t, filepath.Join(sd, p))
		if backup.ValidPath("server/" + p) {
			t.Errorf("server/%s is a backup path", p)
		}
	}
	wantMissing(t, filepath.Join(sd, "opsnotes"))
	wantMissing(t, filepath.Join(sd, "icons"))
	if backup.ValidPath("executor/" + events.KeyFile) {
		t.Error("the event key is a backup path")
	}

	// Restart on the restored state. The harness reads its SSH keys from
	// <dataDir>/testkeys; production reads <dataDir>/keys, where the restore
	// put them. A relative link makes the harness read exactly the restored
	// files. No credential and no trust data is added by the harness: both
	// must come from the restored executor.db.
	if err := os.Symlink("keys", filepath.Join(ed, "testkeys")); err != nil {
		t.Fatal(err)
	}
	h2 := newHarness(t, harnessOptions{dataDir: ed, identity: identity, untrusted: true, noCredential: true})
	if !bytes.Equal(h2.userKey.Marshal(), userKey.Marshal()) {
		t.Fatal("the restarted executor does not hold the old SSH key")
	}
	st, err := h2.client.GetStatus(h2.ctx(), &pb.GetStatusRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if st.GetUnlocked() {
		t.Fatal("the restored executor started unlocked")
	}
	h2.unlock()
	st, err = h2.client.GetStatus(h2.ctx(), &pb.GetStatusRequest{})
	if err != nil || !reflect.DeepEqual(st.GetLoadedCredentialRefs(), []string{credRef}) {
		t.Fatalf("status after unlock: %v %v", st, err)
	}
	wantMode(t, filepath.Join(ed, executordb.MarkerName), 0o600) // written by the first open

	if pin := h2.pinOf("runhost"); pin.GetFingerprint() != host.fp {
		t.Fatalf("restored pin %s, want %s", pin.GetFingerprint(), host.fp)
	}
	arts, err := h2.client.ListTrustedArtifacts(h2.ctx(), &pb.ListTrustedArtifactsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	trusted := false
	for _, a := range arts.GetArtifacts() {
		trusted = trusted || (a.GetArtifactSha256() == hexSum(script) && a.GetActionId() == testAction)
	}
	if !trusted {
		t.Fatalf("the trusted artifact was not restored: %v", arts.GetArtifacts())
	}

	// The event key is new; the restored chain still verifies with the old.
	after, err := h2.client.ListEvents(h2.ctx(), &pb.ListEventsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if ed25519.PublicKey(after.GetPublicKey()).Equal(oldEventKey) {
		t.Fatal("the event key came back from the backup")
	}
	restored := records(after.GetEvents())
	if len(restored) <= len(oldEvents) {
		t.Fatalf("%d events after the restart, %d before", len(restored), len(oldEvents))
	}
	if err := events.Verify(oldEventKey, restored[:len(oldEvents)], nil); err != nil {
		t.Fatalf("the restored chain: %v", err)
	}

	// A run on the pinned host: the restored credential approves it in a
	// privileged session, the restored pin and key reach the host (which
	// accepts only the old key).
	d := h2.approvedRun(host)
	r, err := h2.client.RunAttached(h2.ctx(), runReq(d, host, runScript, credRef))
	if err != nil {
		t.Fatal(err)
	}
	if r.GetClass() != "success" || len(host.srv.Commands()) != 1 {
		t.Fatalf("run after restore: %+v, %d commands", r, len(host.srv.Commands()))
	}

	// The server's database opens on the restored file and has the data.
	sdb, err := serverdb.Open(filepath.Join(sd, "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer sdb.Close()
	got, err := inventory.New(sdb).Get(context.Background(), inventoryHost)
	if err != nil || got.DisplayName != "Web 01" || len(got.Endpoints) != 1 || got.Endpoints[0].Address != "10.0.0.5" {
		t.Fatalf("inventory host after restore: %+v %v", got, err)
	}
	if s, err := auth.NewStore(sdb, nil).Lookup(context.Background(), token); err != nil || s.UserName != "admin" {
		t.Fatalf("session after restore: %+v %v", s, err)
	}
}

// reencrypt writes an age-encrypted tar.gz with the given manifest and
// files exactly as given, so a manifest can disagree with its files.
func reencrypt(t *testing.T, m backup.Manifest, files []backup.File, rcpt age.Recipient) []byte {
	t.Helper()
	man, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	enc, err := age.Encrypt(&out, rcpt)
	if err != nil {
		t.Fatal(err)
	}
	zw := gzip.NewWriter(enc)
	tw := tar.NewWriter(zw)
	add := func(name string, b []byte) {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(b)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	add("manifest.json", man)
	for _, f := range files {
		add(f.Path, f.Data)
	}
	for _, c := range []interface{ Close() error }{tw, zw, enc} {
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return out.Bytes()
}

// A manipulated archive and one with a newer schema change nothing: the
// target keeps every file, mode and byte, and no service is touched.
func TestRestoreRefusalsLeaveTargetUnchanged(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.unlock()
	resp, err := h.client.BackupExecutor(h.ctx(), &pb.BackupExecutorRequest{})
	if err != nil {
		t.Fatal(err)
	}
	srcRoot, _ := serverSource(t)
	id := ageIdentity(t)
	archive := writeBackup(t, resp, srcRoot, id.Recipient())
	m, files, err := backup.Read(bytes.NewReader(archive), []age.Identity{id})
	if err != nil {
		t.Fatal(err)
	}
	latest := latestSchemas(t)

	// A populated target: a first restore.
	target := backup.Layout{Root: t.TempDir()}
	if _, err := backup.Restore(m, files, target, newRecordingSystem(), latest, restoreNow); err != nil {
		t.Fatal(err)
	}
	empty := backup.Layout{Root: t.TempDir()}

	flipped := append([]byte(nil), archive...)
	flipped[len(flipped)-20] ^= 0x01

	tamperedFiles := make([]backup.File, len(files))
	copy(tamperedFiles, files)
	for i, f := range tamperedFiles {
		if f.Path == backup.ExecutorDB {
			d := append([]byte(nil), f.Data...)
			d[len(d)/2] ^= 0xff
			tamperedFiles[i].Data = d
		}
	}
	// Same manifest (checksums of the real files), changed executor.db,
	// encrypted again to the backup recipient: anyone with the public
	// recipient can produce this.
	tamperedArchive := reencrypt(t, m, tamperedFiles, id.Recipient())

	newer := backup.Manifest{Version: m.Version, CreatedAt: m.CreatedAt, Host: m.Host, Kind: m.Kind,
		Schemas: map[string]int{"server": m.Schemas["server"], "executor": latest["executor"] + 1}}
	var newerArchive bytes.Buffer
	if err := backup.Write(&newerArchive, newer, append([]backup.File(nil), files...), []age.Recipient{id.Recipient()}); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		archive []byte
		want    string
	}{
		// age authenticates per chunk: the damaged last chunk fails while
		// gzip reads it, so Read reports ErrNotBackup.
		{"flipped ciphertext byte", flipped, backup.ErrNotBackup.Error()},
		{"file changed, manifest kept", tamperedArchive, "checksum"},
		{"newer executor schema", newerArchive.Bytes(), "newer than this Nebula knows"},
	}
	for _, c := range cases {
		for _, l := range []backup.Layout{target, empty} {
			beforeState := treeState(t, l.Root)
			sys := newRecordingSystem()
			// restoreWith: Read; on success CheckSchemas and Restore.
			m2, f2, err := backup.Read(bytes.NewReader(c.archive), []age.Identity{id})
			if err == nil {
				_, err = backup.Restore(m2, f2, l, sys, latest, restoreNow.Add(time.Hour))
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("%s: err %v, want %q", c.name, err, c.want)
			}
			if sys.calls() != 0 {
				t.Fatalf("%s: the system was touched: stop %v start %v chown %v", c.name, sys.stops, sys.starts, sys.chowns)
			}
			if after := treeState(t, l.Root); !reflect.DeepEqual(beforeState, after) {
				t.Fatalf("%s: %s changed:\nbefore %v\nafter  %v", c.name, l.Root, beforeState, after)
			}
		}
	}

	// Restore itself also refuses a damaged database it is handed directly
	// (it checks both before it stops anything). A changed byte inside a
	// record passes PRAGMA integrity_check (only the manifest checksum in
	// Read catches that, see above); a broken SQLite header does not.
	damagedFiles := make([]backup.File, len(files))
	copy(damagedFiles, files)
	for i, f := range damagedFiles {
		if f.Path == backup.ExecutorDB {
			d := append([]byte(nil), f.Data...)
			copy(d, "not a database!!")
			damagedFiles[i].Data = d
		}
	}
	// The populated target stays
	// as it was. Ist-Stand for an empty root: Restore creates var/lib/nebula
	// (for its staging directory) before the check and leaves that empty
	// directory behind; no data directory and no file appear.
	for _, l := range []backup.Layout{target, empty} {
		beforeState := treeState(t, l.Root)
		sys := newRecordingSystem()
		if _, err := backup.Restore(m, damagedFiles, l, sys, latest, restoreNow.Add(time.Hour)); err == nil {
			t.Fatal("a damaged executor.db was restored")
		}
		if sys.calls() != 0 {
			t.Fatalf("damaged db: the system was touched: stop %v start %v chown %v", sys.stops, sys.starts, sys.chowns)
		}
		after := treeState(t, l.Root)
		if l == target {
			if !reflect.DeepEqual(beforeState, after) {
				t.Fatalf("damaged db: the target changed:\nbefore %v\nafter  %v", beforeState, after)
			}
			continue
		}
		var paths []string
		for p, desc := range after {
			if !strings.HasPrefix(desc, "d") {
				t.Errorf("damaged db: %s appeared in the empty root (%s)", p, desc)
			}
			paths = append(paths, p)
		}
		sort.Strings(paths)
		want := []string{l.Root, filepath.Join(l.Root, "var"), filepath.Join(l.Root, "var", "lib"), filepath.Join(l.Root, "var", "lib", "nebula")}
		if !reflect.DeepEqual(paths, want) {
			t.Fatalf("damaged db: empty root holds %v, want %v", paths, want)
		}
	}
}

// A backup larger than gRPC's default 4 MiB receive limit (the harness
// client's) arrives complete through a client with the receive limit of
// internal/executorclient, and restores.
func TestBackupOverFourMiBArrivesThroughExecutorClient(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.unlock()
	// Five key files of 1 MiB each (the per-file limit of BackupExecutor).
	keyDir := filepath.Join(h.dataDir, "testkeys")
	want := map[string][]byte{}
	for i := range 5 {
		b := make([]byte, 1<<20)
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		name := fmt.Sprintf("bulk-%d.pub", i)
		if err := os.WriteFile(filepath.Join(keyDir, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
		want["keys/"+name] = b
	}
	if kb, err := os.ReadFile(filepath.Join(keyDir, credRef+".key")); err != nil {
		t.Fatal(err)
	} else {
		want["keys/"+credRef+".key"] = kb
	}

	// The harness client keeps gRPC's default receive limit.
	_, err := h.client.BackupExecutor(h.ctx(), &pb.BackupExecutorRequest{})
	wantCode(t, err, codes.ResourceExhausted, "")

	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	c, err := executorclient.New(h.ctx(), executorclient.Options{SocketPath: h.socket, ExecutorUser: u.Username})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.BackupExecutor(h.ctx(), &pb.BackupExecutorRequest{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]byte{}
	total := 0
	for _, f := range resp.GetFiles() {
		got[f.GetName()] = f.GetData()
		total += len(f.GetData())
	}
	if total <= 4<<20 {
		t.Fatalf("the backup is only %d bytes", total)
	}
	for n, b := range want {
		if !bytes.Equal(got[n], b) {
			t.Fatalf("%s did not arrive complete (%d of %d bytes)", n, len(got[n]), len(b))
		}
	}
	if len(got) != len(want)+1 || got[executordb.FileName] == nil {
		t.Fatalf("files: %v", keys(got))
	}

	srcRoot, _ := serverSource(t)
	id := ageIdentity(t)
	archive := writeBackup(t, resp, srcRoot, id.Recipient())
	m, files, err := backup.Read(bytes.NewReader(archive), []age.Identity{id})
	if err != nil {
		t.Fatal(err)
	}
	l := backup.Layout{Root: t.TempDir()}
	if _, err := backup.Restore(m, files, l, newRecordingSystem(), latestSchemas(t), restoreNow); err != nil {
		t.Fatal(err)
	}
	for n, b := range want {
		r, err := os.ReadFile(filepath.Join(l.ExecutorDir(), n))
		if err != nil || !bytes.Equal(r, b) {
			t.Fatalf("restored %s differs (%v)", n, err)
		}
	}
	if r, _ := os.ReadFile(filepath.Join(l.ExecutorDir(), executordb.FileName)); !bytes.Equal(r, got[executordb.FileName]) {
		t.Fatal("the restored executor.db differs")
	}
}
