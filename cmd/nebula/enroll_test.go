// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"

	"github.com/nebula-operation-station/nebula-operation-station/internal/enrollscript"
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

// updateEnrollGolden rewrites the golden scripts. They were generated with
// the enrollScript code from before the extraction into
// internal/enrollscript (EN-04); regenerate only for an intended change of
// the script.
var updateEnrollGolden = flag.Bool("update-enroll-golden", false, "rewrite the enroll-script golden files")

// enrollGoldenDir holds the golden scripts, shared with the
// internal/enrollscript golden test.
const enrollGoldenDir = "../../internal/enrollscript/testdata"

// goldenKeyLine is a fixed ed25519 key (seed 0x01..0x20) so the golden
// scripts are reproducible.
func goldenKeyLine(t *testing.T) string {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	k, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(seed).Public())
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
}

// enrollGoldenCases maps a golden file name to CLI arguments. The same
// names and options are in internal/enrollscript/golden_test.go.
var enrollGoldenCases = []struct {
	name string
	args []string
}{
	{"default", []string{"--from", "192.168.0.10, 10.8.0.0/24"}},
	{"no-sudo-user-ops", []string{"--from", "10.0.0.1", "--no-sudo", "--user", "ops"}},
	{"ipv6-custom-key", []string{"--from", "2001:db8::10,fd00:1:2::/64", "--key", "lab_key-2"}},
	{"mixed-many", []string{"--from", "10.0.0.1,10.0.0.2/32,172.16.0.0/12,::1,fe80::/10,192.0.2.255", "--user", "_svc-nos_1"}},
	{"max-lengths-no-sudo", []string{
		"--from", "203.0.113.7",
		"--user", "a" + strings.Repeat("b", 31),
		"--key", "k" + strings.Repeat("0", 63),
		"--no-sudo",
	}},
}

// TestEnrollScriptGolden: the CLI output is byte-identical to the golden
// scripts generated before the extraction (EN-04).
func TestEnrollScriptGolden(t *testing.T) {
	f := &fakeKey{line: goldenKeyLine(t)}
	for _, tc := range enrollGoldenCases {
		t.Run(tc.name, func(t *testing.T) {
			var out strings.Builder
			if err := hostEnrollScript(context.Background(), f, tc.args, &out); err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(enrollGoldenDir, tc.name+".golden")
			if *updateEnrollGolden {
				if err := os.WriteFile(p, []byte(out.String()), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			if out.String() != string(want) {
				t.Fatalf("script differs from %s:\n%s", p, out.String())
			}
		})
	}
}

// TestEnrollScriptOverLimitWritesNothing: a script over the 64 KiB limit
// (thousands of --from entries) is refused and nothing is printed.
func TestEnrollScriptOverLimitWritesNothing(t *testing.T) {
	f := &fakeKey{line: goldenKeyLine(t)}
	var addrs []string
	for i := 1; i <= 2000; i++ {
		addrs = append(addrs, fmt.Sprintf("2001:db8:%x::/64", i))
	}
	var out strings.Builder
	err := hostEnrollScript(context.Background(), f, []string{"--from", strings.Join(addrs, ",")}, &out)
	if !errors.Is(err, enrollscript.ErrTooLarge) || out.Len() != 0 {
		t.Fatalf("err %v, %d bytes written; want ErrTooLarge and no output", err, out.Len())
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
