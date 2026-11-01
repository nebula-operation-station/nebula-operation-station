// SPDX-License-Identifier: AGPL-3.0-or-later

package bootstrap

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
)

// treeRoot is the first-party bootstrap tree in the repository.
const treeRoot = "../../../modules/bootstrap"

// expectedModules are the ten modules of the Ubuntu Server Bootstrap
// Toolkit (ADR 0008 section 5), in the sorted order Load returns.
var expectedModules = []string{
	"docker", "firewall", "netbird", "packages", "pkg-report",
	"qemu-guest-agent", "ssh-hardening", "telegraf", "timezone", "user",
}

// TestBootstrapTreeContract checks the ADR 0008 section 5 contract on
// the real tree: the four actions per module, verify read-only (not
// durable, no secrets, LOW or MEDIUM risk), the mutating actions
// durable and idempotent by contract, and only the known secret slots.
func TestBootstrapTreeContract(t *testing.T) {
	ms, err := Load(treeRoot)
	if err != nil {
		t.Fatalf("Load(%s): %v", treeRoot, err)
	}
	if len(ms) != len(expectedModules) {
		t.Fatalf("loaded %d modules, want %d", len(ms), len(expectedModules))
	}
	allowedSecrets := map[string]bool{"setup_key": true, "ssh_public_key": true, "influx_token": true}
	for i, m := range ms {
		if m.Name != expectedModules[i] {
			t.Fatalf("module %d is %s, want %s", i, m.Name, expectedModules[i])
		}
		for _, a := range RequiredActions {
			act, ok := m.Lock.Actions[a]
			if !ok {
				t.Fatalf("%s: missing required action %s", m.Name, a)
			}
			if a == ActionVerify {
				if act.Durable {
					t.Errorf("%s: verify must not be durable", m.Name)
				}
				if act.Risk != "LOW" && act.Risk != "MEDIUM" {
					t.Errorf("%s: verify risk is %s, want LOW or MEDIUM", m.Name, act.Risk)
				}
				if len(act.Secrets) != 0 {
					t.Errorf("%s: verify takes secret slots %v", m.Name, act.Secrets)
				}
				continue
			}
			if !act.Durable {
				t.Errorf("%s: action %s must be durable (idempotent, reconcile-first)", m.Name, a)
			}
			for _, s := range act.Secrets {
				if !allowedSecrets[s] {
					t.Errorf("%s: action %s uses unknown secret slot %s", m.Name, a, s)
				}
			}
		}
	}
}

// TestBootstrapTreeLocksInSync regenerates every lock from module.yaml
// and the scripts and compares: a committed lock that drifts from its
// author file is a supply-chain break, so it fails the build.
func TestBootstrapTreeLocksInSync(t *testing.T) {
	ms, err := Load(treeRoot)
	if err != nil {
		t.Fatalf("Load(%s): %v", treeRoot, err)
	}
	for _, m := range ms {
		want, err := Pack(filepath.Join(treeRoot, m.Name))
		if err != nil {
			t.Fatalf("%s: Pack: %v", m.Name, err)
		}
		if string(want) != string(m.LockBytes) {
			t.Errorf("%s: module.lock.json drifts from module.yaml and scripts; regenerate with packlock", m.Name)
		}
	}
}

// TestBootstrapTreeTars verifies every module tar with the release
// bundle's own verifier: exact size and hash, strict ustar, lock and
// script hashes, prelude-built artifacts, no stray files.
func TestBootstrapTreeTars(t *testing.T) {
	ms, err := Load(treeRoot)
	if err != nil {
		t.Fatalf("Load(%s): %v", treeRoot, err)
	}
	for _, m := range ms {
		tar, err := m.Tar()
		if err != nil {
			t.Fatalf("%s: Tar: %v", m.Name, err)
		}
		sum := sha256.Sum256(tar)
		md := release.Module{Name: m.Name, Version: m.Version, Size: int64(len(tar)),
			SHA256: hex.EncodeToString(sum[:])}
		if _, err := release.ParseModuleTar(md, tar); err != nil {
			t.Errorf("%s: release.ParseModuleTar: %v", m.Name, err)
		}
	}
}

// TestBootstrapTreeScriptsAreShell runs sh -n on every script body and
// on the full prelude artifact, so a syntax error in a toolkit script is
// a build failure, not a run-time surprise on the guest.
func TestBootstrapTreeScriptsAreShell(t *testing.T) {
	ms, err := Load(treeRoot)
	if err != nil {
		t.Fatalf("Load(%s): %v", treeRoot, err)
	}
	for _, m := range ms {
		dir := t.TempDir()
		for _, name := range m.Lock.Names() {
			act := m.Lock.Actions[name]
			body := m.Scripts[act.Script]
			bodyPath := filepath.Join(dir, "body.sh")
			if err := os.WriteFile(bodyPath, body, 0o644); err != nil {
				t.Fatal(err)
			}
			if out, err := shCheck(bodyPath); err != nil {
				t.Errorf("%s: action %s body: sh -n: %v: %s", m.Name, name, err, out)
			}
			art, _, err := m.Lock.Artifact(name, body)
			if err != nil {
				t.Fatalf("%s: action %s: Artifact: %v", m.Name, name, err)
			}
			artPath := filepath.Join(dir, "artifact.sh")
			if err := os.WriteFile(artPath, art, 0o644); err != nil {
				t.Fatal(err)
			}
			if out, err := shCheck(artPath); err != nil {
				t.Errorf("%s: action %s artifact: sh -n: %v: %s", m.Name, name, err, out)
			}
		}
	}
}

func shCheck(path string) (string, error) {
	out, err := exec.Command("sh", "-n", path).CombinedOutput()
	return string(out), err
}
