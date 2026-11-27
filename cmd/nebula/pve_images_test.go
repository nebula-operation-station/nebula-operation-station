// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/keyring"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
	"github.com/nebula-operation-station/nebula-operation-station/internal/riskpolicy"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnreg"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

const pveImageTestSHA = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// pveImageTestDataDir returns the executor's data directory (0700); the
// CLI never gets it.
func pveImageTestDataDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "keys"), 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// startPveImageExecutor starts the real executor service on dir and serves
// it on a fresh Unix socket in a temporary directory, with the test's UID
// mapped to role. It points the CLI at that socket (and at a client-side
// data directory that does not exist) and returns a stop function, also
// run at cleanup; stopping releases the database so the executor can be
// started again on the same directory.
func startPveImageExecutor(t *testing.T, dir string, role peercred.Role) func() {
	t.Helper()
	db, err := executordb.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := webauthnverify.New(webauthnverify.Config{RPID: "pve.test", Origins: []string{"https://pve.test"}, Counters: db}, nil)
	if err != nil {
		t.Fatal(err)
	}
	risk, err := riskpolicy.New(db)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := permit.New(permit.Options{Verifier: verifier, Store: db, RiskPolicy: risk})
	if err != nil {
		t.Fatal(err)
	}
	reg, err := webauthnreg.New(webauthnreg.Config{RPID: "pve.test", Origins: []string{"https://pve.test"}}, verifier, db)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	keysDir := filepath.Join(dir, "keys")
	svc := executor.NewService(auth, keyring.New(keysDir), db, reg, log)
	svc.SetBackupDirs(dir, keysDir)
	policy := peercred.NewPolicy(map[uint32][]peercred.Role{uint32(os.Getuid()): {role}}, executor.MethodRoles())
	server := executor.NewGRPCServer(svc, policy, log)
	socket := filepath.Join(t.TempDir(), "executor.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(listener) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			server.Stop()
			_ = listener.Close()
			_ = db.Close()
		})
	}
	t.Cleanup(stop)
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("NEBULA_EXECUTOR_USER", u.Username)
	t.Setenv("NEBULA_EXECUTOR_SOCKET", socket)
	t.Setenv("NEBULA_EXECUTOR_DATA_DIR", filepath.Join(dir, "not-client-accessible"))
	return stop
}

func pveImageNoPrompt(string) ([]byte, error) {
	return nil, errors.New("the image commands ask for no secret")
}

// pveImageRun runs `nebula pve image ...` with the given stdin.
func pveImageRun(args []string, stdin string) (string, error) {
	var out bytes.Buffer
	err := pveCmd(append([]string{"image"}, args...), strings.NewReader(stdin), pveImageNoPrompt, &out)
	return out.String(), err
}

func pveImageAddArgs(id string) []string {
	return []string{"add", id, "--os", "rocky", "--release", "9.4", "--arch", "amd64",
		"--url", "https://mirror.example.org/rocky/9/Rocky-9-GenericCloud.qcow2", "--sha256", pveImageTestSHA, "--disk-format", "qcow2"}
}

// pveImageAddArgsWith is pveImageAddArgs(id) with flag name set to value.
func pveImageAddArgsWith(id, name, value string) []string {
	args := pveImageAddArgs(id)
	for i := range args {
		if args[i] == name {
			args[i+1] = value
		}
	}
	return args
}

// pveImageListed reports whether `nebula pve image list` shows id.
func pveImageListed(t *testing.T, id string) bool {
	t.Helper()
	out, err := pveImageRun([]string{"list"}, "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	return strings.Contains(out, id)
}

func TestPveImageUsageRefusedBeforeDial(t *testing.T) {
	// No executor socket: every case must fail on its arguments. The
	// executor user is the test's own, so a case that wrongly passes the
	// CLI checks gets past the user lookup and fails on absent.sock.
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("NEBULA_EXECUTOR_USER", u.Username)
	t.Setenv("NEBULA_EXECUTOR_SOCKET", filepath.Join(t.TempDir(), "absent.sock"))
	long := func(n int) string { return strings.Repeat("a", n) }
	withFlag := func(name, value string) []string { return pveImageAddArgsWith("local-rocky-9", name, value) }
	for name, args := range map[string][]string{
		"no subcommand":     {},
		"unknown":           {"bogus"},
		"add without id":    {"add", "--os", "rocky"},
		"add missing flags": {"add", "local-x", "--os", "rocky"},
		"add extra arg":     append(pveImageAddArgs("local-rocky-9"), "extra"),
		"add long id":       pveImageAddArgs("local-" + long(maxPveImageIDArg)),
		"add long os":       withFlag("--os", long(maxPveImageOSArg+1)),
		"add long release":  withFlag("--release", long(maxPveImageReleaseArg+1)),
		"add long arch":     withFlag("--arch", long(maxPveImageArchArg+1)),
		"add long url":      withFlag("--url", "https://example.org/"+long(release.MaxImageURL)),
		"add long sha256":   withFlag("--sha256", pveImageTestSHA+"0"),
		"add long format":   withFlag("--disk-format", long(maxPveImageFormatArg+1)),
		"add bad utf8":      withFlag("--os", "rock\xff"),
		"remove without id": {"remove"},
		"remove two ids":    {"remove", "local-a", "local-b"},
		"remove long id":    {"remove", "local-" + long(maxPveImageIDArg)},
		"list extra arg":    {"list", "x"},
	} {
		if _, err := pveImageRun(args, "yes\n"); err == nil {
			t.Errorf("%s: %v accepted", name, args)
		} else if strings.Contains(err.Error(), "absent.sock") {
			t.Errorf("%s: reached the executor socket: %v", name, err)
		}
	}
}

// TestPveImageAddRemoveSurvivesRestart: an entry added over the admin
// socket is listed, survives an executor restart, is removed and stays
// removed after another restart. The CLI writes no file: only the
// executor's data directory holds the entry.
func TestPveImageAddRemoveSurvivesRestart(t *testing.T) {
	dir := pveImageTestDataDir(t)
	stop := startPveImageExecutor(t, dir, peercred.RoleAdmin)
	const id = "local-rocky-9"
	out, err := pveImageRun(pveImageAddArgs(id), "yes\n")
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if !strings.Contains(out, id) {
		t.Fatalf("add output %q", out)
	}
	listOut, err := pveImageRun([]string{"list"}, "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, want := range []string{id, "local", "rocky", "9.4", "amd64", "qcow2", pveImageTestSHA} {
		if !strings.Contains(listOut, want) {
			t.Fatalf("list output lacks %q: %s", want, listOut)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "not-client-accessible")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("client-side data directory created: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "pve-catalog-local.json"))
	if err != nil || !bytes.Contains(raw, []byte(id)) {
		t.Fatalf("executor did not persist the entry: %v", err)
	}

	stop()
	stop = startPveImageExecutor(t, dir, peercred.RoleAdmin)
	if !pveImageListed(t, id) {
		t.Fatal("entry lost across an executor restart")
	}

	if _, err := pveImageRun([]string{"remove", id}, "yes\n"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if pveImageListed(t, id) {
		t.Fatal("entry still listed after remove")
	}
	stop()
	startPveImageExecutor(t, dir, peercred.RoleAdmin)
	if pveImageListed(t, id) {
		t.Fatal("removed entry back after an executor restart")
	}
	if _, err := pveImageRun([]string{"remove", id}, "yes\n"); err == nil || !strings.Contains(err.Error(), "no local image") {
		t.Fatalf("removing an absent entry: %v", err)
	}
}

func TestPveImageChangesNeedTypedYes(t *testing.T) {
	dir := pveImageTestDataDir(t)
	startPveImageExecutor(t, dir, peercred.RoleAdmin)
	const id = "local-rocky-9"
	if _, err := pveImageRun(pveImageAddArgs(id), "no\n"); err == nil {
		t.Fatal("add accepted a 'no' confirmation")
	}
	if pveImageListed(t, id) {
		t.Fatal("entry added although not confirmed")
	}
	if _, err := pveImageRun(pveImageAddArgs(id), "yes\n"); err != nil {
		t.Fatalf("add: %v", err)
	}
	if _, err := pveImageRun([]string{"remove", id}, "no\n"); err == nil {
		t.Fatal("remove accepted a 'no' confirmation")
	}
	if !pveImageListed(t, id) {
		t.Fatal("entry removed although not confirmed")
	}
}

// TestPveImageExecutorRefusalsAreReported: the executor, not the CLI,
// refuses an ID without the local- prefix and an entry that fails the
// catalog grammar; the CLI reports its text and nothing is stored.
func TestPveImageExecutorRefusalsAreReported(t *testing.T) {
	dir := pveImageTestDataDir(t)
	startPveImageExecutor(t, dir, peercred.RoleAdmin)
	for name, args := range map[string][]string{
		"no local- prefix":  pveImageAddArgs("rocky-9"),
		"http url":          pveImageAddArgsWith("local-rocky-9", "--url", "http://mirror.example.org/rocky.qcow2"),
		"upper-case sha256": pveImageAddArgsWith("local-rocky-9", "--sha256", strings.ToUpper(pveImageTestSHA)),
		"bad arch":          pveImageAddArgsWith("local-rocky-9", "--arch", "riscv"),
	} {
		_, err := pveImageRun(args, "yes\n")
		if err == nil || !strings.Contains(err.Error(), "InvalidArgument") || !strings.Contains(err.Error(), `must start with "local-"`) {
			t.Fatalf("%s: want the executor's InvalidArgument text, got %v", name, err)
		}
	}
	if _, err := pveImageRun([]string{"remove", "rocky-9"}, "yes\n"); err == nil || !strings.Contains(err.Error(), `must start with "local-"`) {
		t.Fatalf("remove without prefix: %v", err)
	}
	out, err := pveImageRun([]string{"list"}, "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if strings.Contains(out, "rocky") {
		t.Fatalf("refused entry listed: %s", out)
	}
	if _, err := os.Stat(filepath.Join(dir, "pve-catalog-local.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("local entries file written for refused entries: %v", err)
	}
}

// TestPveImageNonAdminPeerRefused: a peer whose UID maps to the server role
// cannot add or remove a local entry.
func TestPveImageNonAdminPeerRefused(t *testing.T) {
	dir := pveImageTestDataDir(t)
	stop := startPveImageExecutor(t, dir, peercred.RoleAdmin)
	const kept = "local-kept"
	if _, err := pveImageRun(pveImageAddArgs(kept), "yes\n"); err != nil {
		t.Fatalf("admin add: %v", err)
	}
	stop()
	stop = startPveImageExecutor(t, dir, peercred.RoleServer)
	if _, err := pveImageRun(pveImageAddArgs("local-rocky-9"), "yes\n"); err == nil || !strings.Contains(err.Error(), "PermissionDenied") {
		t.Fatalf("server-role add: %v", err)
	}
	if _, err := pveImageRun([]string{"remove", kept}, "yes\n"); err == nil || !strings.Contains(err.Error(), "PermissionDenied") {
		t.Fatalf("server-role remove: %v", err)
	}
	stop()
	startPveImageExecutor(t, dir, peercred.RoleAdmin)
	if pveImageListed(t, "local-rocky-9") {
		t.Fatal("server-role add stored an entry")
	}
	if !pveImageListed(t, kept) {
		t.Fatal("server-role remove removed an entry")
	}
}

func TestPveImageListEmpty(t *testing.T) {
	startPveImageExecutor(t, pveImageTestDataDir(t), peercred.RoleAdmin)
	out, err := pveImageRun([]string{"list"}, "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if !strings.Contains(out, "no pve images") || !strings.Contains(out, "no signed catalog") {
		t.Fatalf("list output %q", out)
	}
}
