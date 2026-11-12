// SPDX-License-Identifier: AGPL-3.0-or-later

package actions_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/fimscan"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// The fim.scan contract the server plans with (fimscan.Action) is the one
// the executor pins for read leases: read-only LOW, the embedded script
// (no second copy), exactly the profile and mode parameters, and the same
// script and parameter hashes.
func TestFimScanContractMatchesLeasePins(t *testing.T) {
	a := fimscan.Action()
	if a.ID != permit.FimScanActionID || a.Version != permit.FimScanModuleVersion || !a.ReadOnly || a.Durable ||
		a.Risk != pb.RiskClass_RISK_CLASS_LOW || a.Retry != actions.RetrySafe || len(a.Secrets) != 0 {
		t.Fatalf("contract %s@%s read-only=%v durable=%v risk=%s retry=%s", a.ID, a.Version, a.ReadOnly, a.Durable, a.Risk, a.Retry)
	}
	if !bytes.Equal(a.Script, fimscan.Script) || a.SHA256() != permit.FimScanArtifactSHA256 {
		t.Fatalf("script %s, pinned %s", a.SHA256(), permit.FimScanArtifactSHA256)
	}
	if !permit.InReadOnlyAllowlist(a.ID) {
		t.Fatal("fim.scan is not leasable")
	}
	names := map[string]bool{}
	for _, p := range a.Params {
		names[p.Name] = true
	}
	if len(names) != 2 || !names["mode"] || !names["profile"] {
		t.Fatalf("parameters %v, want exactly mode and profile", names)
	}
	for _, p := range []map[string]string{
		{"mode": "full", "profile": "fim-other-v1"},
		{"mode": "full", "profile": fimscan.DefaultProfileID, "path": "/root"},
		{"mode": "incremental", "path": "/"},
		{"mode": "full; rm -rf /", "profile": fimscan.DefaultProfileID},
	} {
		if err := a.ValidParams(p); err == nil {
			t.Errorf("parameters %q accepted", p)
		}
	}
}

// A run on a fake host with exactly the parameters a lease pins yields a
// document that only reaches the caller through the fimscan parser.
func TestFimScanFakeHostRunParses(t *testing.T) {
	for _, mode := range []fimscan.Mode{fimscan.ModeIncremental, fimscan.ModeFull} {
		t.Run(string(mode), func(t *testing.T) {
			a := fimscan.Action()
			raw, err := a.ParametersJSON(map[string]string{"mode": string(mode), "profile": fimscan.DefaultProfileID}, nil)
			if err != nil {
				t.Fatal(err)
			}
			params, hash, err := canonical.CanonicalParameters(raw)
			if err != nil {
				t.Fatal(err)
			}
			want := permit.FimScanIncrementalParametersHash
			if mode == fimscan.ModeFull {
				want = permit.FimScanFullParametersHash
			}
			if hash != want {
				t.Fatalf("parameters hash %s, pinned %s", hash, want)
			}
			out := runFimScanOnFakeHost(t, fakeHostTree(t), params)
			res, err := fimscan.Parse(context.Background(), bytes.NewReader(out), fimscan.Options{
				Profile: fimscan.DefaultProfile(), Mode: mode, HostKey: bytes.Repeat([]byte{0x42}, fimscan.HostKeySize),
			})
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if res.ProfileID != fimscan.DefaultProfileID || res.Mode != mode {
				t.Fatalf("profile %q mode %q", res.ProfileID, res.Mode)
			}
			paths := map[string]bool{}
			for _, r := range res.Records {
				paths[string(r.Path)] = true
			}
			for _, p := range []string{"/etc/hostname", "/usr/bin/ls", "/root/.ssh/authorized_keys"} {
				if !paths[p] {
					t.Errorf("no record for %s", p)
				}
			}
			if paths["/tmp/outside"] {
				t.Error("a path outside the profile was reported")
			}
		})
	}
}

// fakeHostTree builds a minimal host under a temporary root.
func fakeHostTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	file := func(p, content string, mode os.FileMode) {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{"/etc/systemd/system", "/boot", "/usr/sbin", "/usr/lib/systemd/system",
		"/usr/local/bin", "/usr/local/sbin", "/usr/local/lib"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	file("/etc/hostname", "fake\n", 0o644)
	file("/etc/ssh/sshd_config", "Port 22\n", 0o644)
	file("/usr/bin/ls", "ELF-ls", 0o755)
	file("/root/.ssh/authorized_keys", "ssh-ed25519 AAAA root\n", 0o600)
	file("/tmp/outside", "not in profile", 0o644)
	file("/proc/self/mountinfo", "22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n", 0o444)
	for target, link := range map[string]string{"usr/bin": "/bin", "usr/sbin": "/sbin", "usr/lib": "/lib"} {
		if err := os.Symlink(target, filepath.Join(root, link)); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// runFimScanOnFakeHost runs the embedded script the way the executor hands
// it over (script file plus canonical parameters file) against root.
func runFimScanOnFakeHost(t *testing.T, root string, params []byte) []byte {
	t.Helper()
	work := t.TempDir()
	script := filepath.Join(work, "action.sh")
	if err := os.WriteFile(script, fimscan.Script, 0o600); err != nil {
		t.Fatal(err)
	}
	paramsPath := filepath.Join(work, "params.json")
	if err := os.WriteFile(paramsPath, params, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", script)
	cmd.Dir = t.TempDir()
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"NEBULA_PARAMS=" + paramsPath,
		"NEBULA_FIM_TEST_ROOT=" + root,
		"TMPDIR=" + filepath.Join(work, "no-such-dir"),
		"HOME=" + filepath.Join(work, "no-such-home"),
		"NEBULA_FIM_TEST_RACY_SECONDS=-1",
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("script: %v (stderr %d bytes)", err, stderr.Len())
	}
	return stdout.Bytes()
}
