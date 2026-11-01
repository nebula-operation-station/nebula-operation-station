// SPDX-License-Identifier: AGPL-3.0-or-later

package bootstrap

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/modulelock"
	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
)

// testScript is a minimal valid module script.
const testScript = "#!/bin/sh\nprintf '{\"ok\":true}\\n' > \"$NEBULA_RESULT\"\n"

// writeTree writes a synthetic bootstrap module dir with the four
// required actions; the lock is not written.
func writeTree(t *testing.T, root string) string {
	t.Helper()
	dir := filepath.Join(root, "alpha")
	if err := os.MkdirAll(filepath.Join(dir, "actions"), 0o755); err != nil {
		t.Fatal(err)
	}
	yaml := `name: alpha
version: 1.2.3
title: Alpha
description: A synthetic bootstrap module for tests.
actions:
  install:
    title: Install alpha
    description: Installs the component.
    script: actions/install.sh
    risk: medium
    durable: true
    timeout: 300s
    params:
      - name: thing
        label: Thing
        type: name
    secrets: [token]
    declares: [requires_root, writes_config]
  verify:
    title: Verify alpha
    description: Checks the component.
    script: actions/verify.sh
    risk: low
    durable: false
    timeout: 120s
    params: []
    secrets: []
    declares: []
  update:
    title: Update alpha
    description: Updates the component.
    script: actions/update.sh
    risk: medium
    durable: true
    timeout: 300s
    params: []
    secrets: []
    declares: [writes_config]
  uninstall:
    title: Uninstall alpha
    description: Removes the component.
    script: actions/uninstall.sh
    risk: high
    durable: true
    timeout: 300s
    params: []
    secrets: []
    declares: [requires_root]
`
	if err := os.WriteFile(filepath.Join(dir, "module.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"install", "verify", "update", "uninstall"} {
		if err := os.WriteFile(filepath.Join(dir, "actions", a+".sh"), []byte(testScript), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// packAndLoad packs the synthetic module, writes the lock and loads it.
func packAndLoad(t *testing.T, dir string) Module {
	t.Helper()
	lock, err := Pack(dir)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, LockFile), lock, 0o644); err != nil {
		t.Fatal(err)
	}
	ms, err := Load(filepath.Dir(dir))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(ms) != 1 {
		t.Fatalf("Load returned %d modules, want 1", len(ms))
	}
	return ms[0]
}

func TestPackLoadRoundTrip(t *testing.T) {
	dir := writeTree(t, t.TempDir())
	m := packAndLoad(t, dir)
	if m.Name != "alpha" || m.Version != "1.2.3" {
		t.Fatalf("got %s %s", m.Name, m.Version)
	}
	for _, a := range RequiredActions {
		if _, ok := m.Lock.Actions[a]; !ok {
			t.Fatalf("missing action %s", a)
		}
		if _, ok := m.Scripts["actions/"+a+".sh"]; !ok {
			t.Fatalf("missing script for action %s", a)
		}
	}
	install := m.Lock.Actions[ActionInstall]
	if len(install.Secrets) != 1 || install.Secrets[0] != "token" {
		t.Fatalf("install secrets = %v", install.Secrets)
	}
	if install.TrustRisk() != "MEDIUM" {
		t.Fatalf("install trust risk = %s, want MEDIUM (declares root)", install.TrustRisk())
	}
	if m.Lock.Actions[ActionVerify].Risk != "LOW" {
		t.Fatalf("verify risk = %s", m.Lock.Actions[ActionVerify].Risk)
	}
}

func TestTarVerifiesWithRelease(t *testing.T) {
	dir := writeTree(t, t.TempDir())
	m := packAndLoad(t, dir)
	tar, err := m.Tar()
	if err != nil {
		t.Fatalf("Tar: %v", err)
	}
	sum := sha256.Sum256(tar)
	md := release.Module{Name: m.Name, Version: m.Version, Size: int64(len(tar)), SHA256: hex.EncodeToString(sum[:])}
	mb, err := release.ParseModuleTar(md, tar)
	if err != nil {
		t.Fatalf("release.ParseModuleTar: %v", err)
	}
	if len(mb.Files) != 5 {
		t.Fatalf("tar holds %d files, want 5 (lock + 4 scripts)", len(mb.Files))
	}
	for i := 1; i < len(mb.Paths); i++ {
		if mb.Paths[i-1] >= mb.Paths[i] {
			t.Fatalf("tar paths are not in ASCII order: %v", mb.Paths)
		}
	}
	if _, _, err := mb.Lock.Artifact("install", mb.Files["actions/install.sh"]); err != nil {
		t.Fatalf("artifact from tar: %v", err)
	}
}

func TestLoadRejectsStaleScript(t *testing.T) {
	dir := writeTree(t, t.TempDir())
	packAndLoad(t, dir)
	p := filepath.Join(dir, "actions", "install.sh")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, append(b, []byte("# changed\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(filepath.Dir(dir)); err == nil || !strings.Contains(err.Error(), "hash") {
		t.Fatalf("Load after script change: %v, want hash mismatch", err)
	}
}

func TestLoadRejectsStrayFile(t *testing.T) {
	dir := writeTree(t, t.TempDir())
	packAndLoad(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(filepath.Dir(dir)); err == nil || !strings.Contains(err.Error(), "not part of the module") {
		t.Fatalf("Load with stray file: %v", err)
	}
}

func TestLoadRejectsMissingRequiredAction(t *testing.T) {
	dir := writeTree(t, t.TempDir())
	y, err := os.ReadFile(filepath.Join(dir, "module.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	y = []byte(strings.ReplaceAll(string(y), `  update:
    title: Update alpha
    description: Updates the component.
    script: actions/update.sh
    risk: medium
    durable: true
    timeout: 300s
    params: []
    secrets: []
    declares: [writes_config]
`, ""))
	if err := os.WriteFile(filepath.Join(dir, "module.yaml"), y, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "actions", "update.sh")); err != nil {
		t.Fatal(err)
	}
	lock, err := Pack(dir)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, LockFile), lock, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(filepath.Dir(dir)); err == nil || !strings.Contains(err.Error(), "required action update") {
		t.Fatalf("Load without update: %v", err)
	}
}

func TestLoadRejectsDurableVerify(t *testing.T) {
	dir := writeTree(t, t.TempDir())
	y, err := os.ReadFile(filepath.Join(dir, "module.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	y = []byte(strings.Replace(string(y), "    script: actions/verify.sh\n    risk: low\n    durable: false",
		"    script: actions/verify.sh\n    risk: low\n    durable: true", 1))
	if err := os.WriteFile(filepath.Join(dir, "module.yaml"), y, 0o644); err != nil {
		t.Fatal(err)
	}
	lock, err := Pack(dir)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, LockFile), lock, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(filepath.Dir(dir)); err == nil || !strings.Contains(err.Error(), "verify must not be durable") {
		t.Fatalf("Load with durable verify: %v", err)
	}
}

func TestLoadRejectsVerifyWithSecrets(t *testing.T) {
	dir := writeTree(t, t.TempDir())
	y, err := os.ReadFile(filepath.Join(dir, "module.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	y = []byte(strings.Replace(string(y), "    script: actions/verify.sh\n    risk: low\n    durable: false\n    timeout: 120s\n    params: []\n    secrets: []",
		"    script: actions/verify.sh\n    risk: low\n    durable: false\n    timeout: 120s\n    params: []\n    secrets: [token]", 1))
	if err := os.WriteFile(filepath.Join(dir, "module.yaml"), y, 0o644); err != nil {
		t.Fatal(err)
	}
	lock, err := Pack(dir)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, LockFile), lock, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(filepath.Dir(dir)); err == nil || !strings.Contains(err.Error(), "verify must not take secret slots") {
		t.Fatalf("Load with verify secret: %v", err)
	}
}

func TestLoadRejectsNameMismatch(t *testing.T) {
	dir := writeTree(t, t.TempDir())
	packAndLoad(t, dir)
	if err := os.Rename(dir, filepath.Join(filepath.Dir(dir), "beta")); err != nil {
		t.Fatal(err)
	}
	_, err := Load(filepath.Dir(dir))
	if err == nil || !strings.Contains(err.Error(), "lock names module") {
		t.Fatalf("Load with renamed dir: %v", err)
	}
}

func TestPackAllowsReservedFirstPartyName(t *testing.T) {
	// "docker" is reserved for third parties but allowed first-party:
	// the bootstrap set names a module after the component it manages.
	root := t.TempDir()
	dir := filepath.Join(root, "docker")
	if err := os.MkdirAll(filepath.Join(dir, "actions"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "module.yaml"), []byte("name: docker\nversion: 1.0.0\ntitle: Docker\ndescription: Manages docker.\nactions:\n  install:\n    title: Install\n    description: Installs docker.\n    script: actions/install.sh\n    risk: medium\n    durable: true\n    timeout: 300s\n    params: []\n    secrets: []\n    declares: [requires_root]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "actions", "install.sh"), []byte(testScript), 0o644); err != nil {
		t.Fatal(err)
	}
	lock, err := Pack(dir)
	if err != nil {
		t.Fatalf("Pack of a reserved first-party name: %v", err)
	}
	if _, _, err := modulelock.Parse(lock); err == nil {
		t.Fatal("third-party Parse accepted the reserved name")
	}
}

func TestPackRejectsUnknownField(t *testing.T) {
	dir := writeTree(t, t.TempDir())
	y, err := os.ReadFile(filepath.Join(dir, "module.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "module.yaml"), append(y, []byte("bogus: 1\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Pack(dir); err == nil {
		t.Fatal("Pack accepted an unknown field")
	}
}

func TestPackRejectsBadTimeout(t *testing.T) {
	dir := writeTree(t, t.TempDir())
	y, err := os.ReadFile(filepath.Join(dir, "module.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	y = []byte(strings.Replace(string(y), "timeout: 300s", "timeout: 5s", 1))
	if err := os.WriteFile(filepath.Join(dir, "module.yaml"), []byte(y), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Pack(dir); err == nil {
		t.Fatal("Pack accepted a sub-10s timeout")
	}
}

func TestLoadRejectsEmptyRoot(t *testing.T) {
	if _, err := Load(t.TempDir()); err == nil {
		t.Fatal("Load of an empty root succeeded, want error")
	}
}
