// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

type fakeKey struct {
	pb.ExecutorServiceClient
	line string
}

func (f *fakeKey) GetSSHPublicKey(context.Context, *pb.GetSSHPublicKeyRequest, ...grpc.CallOption) (*pb.GetSSHPublicKeyResponse, error) {
	return &pb.GetSSHPublicKeyResponse{AuthorizedKey: f.line}, nil
}

func newFakeKey(t *testing.T) (*fakeKey, ssh.PublicKey) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, _ := ssh.NewPublicKey(pub)
	return &fakeKey{line: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))}, k
}

func TestEnrollScript(t *testing.T) {
	f, k := newFakeKey(t)
	var out strings.Builder
	if err := hostEnrollScript(context.Background(), f, []string{"--from", "192.168.0.10, 10.8.0.0/24"}, &out); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	for _, want := range []string{
		`from="192.168.0.10,10.8.0.0/24",no-agent-forwarding,no-port-forwarding,no-X11-forwarding ssh-ed25519 `,
		" nebula-nebula-default'",
		"user='nebula'",
		"NOPASSWD: ALL",
		"visudo -cf",
		"/etc/tmpfiles.d/nebula.conf",
		"ssh-keygen -lf",
		ssh.FingerprintSHA256(k),
		// sshd drop-in for AllowUsers/AllowGroups, one pattern per address.
		"want='AllowUsers nebula@192.168.0.10 nebula@10.8.0.0/24'",
		"}AllowGroups $user\"",
		`groupadd --system "$user"`,
		`useradd --system --create-home --shell /bin/sh -g "$user" "$user"`,
		"probe='192.168.0.10 10.8.0.0'",
		`-T -C "user=$user,host=$a,addr=$a"`,
		"/etc/ssh/sshd_config.d/10-nebula.conf",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script missing %q", want)
		}
	}
	// The script is valid POSIX shell.
	if sh, err := exec.LookPath("sh"); err == nil {
		p := filepath.Join(t.TempDir(), "enroll.sh")
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(sh, "-n", p).CombinedOutput(); err != nil {
			t.Fatalf("sh -n: %v %s", err, out)
		}
	}

	out.Reset()
	if err := hostEnrollScript(context.Background(), f, []string{"--from", "10.0.0.1", "--no-sudo", "--user", "ops"}, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "sudoers") || !strings.Contains(out.String(), "user='ops'") {
		t.Fatalf("no-sudo script: %s", out.String())
	}
}

func TestEnrollScriptRejectsUnsafeInput(t *testing.T) {
	f, _ := newFakeKey(t)
	for name, args := range map[string][]string{
		"no from":       {},
		"hostname":      {"--from", "nebula.lan"},
		"quote in from": {"--from", `10.0.0.1"`},
		"root user":     {"--from", "10.0.0.1", "--user", "root"},
		"user quote":    {"--from", "10.0.0.1", "--user", "a'b"},
		"bad key ref":   {"--from", "10.0.0.1", "--key", "../x"},
	} {
		if err := hostEnrollScript(context.Background(), f, args, &strings.Builder{}); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// A key line with options or a hostile comment from the executor is
	// re-encoded: only type and key reach the script.
	f.line = f.line + ` evil'; rm -rf /`
	var out strings.Builder
	if err := hostEnrollScript(context.Background(), f, []string{"--from", "10.0.0.1"}, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "rm -rf") {
		t.Fatal("key comment reached the script")
	}
}
