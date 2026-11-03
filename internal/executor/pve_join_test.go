// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveapi"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/sshtransport"
)

// fakeAgentFiles is a guest agent file-read stub.
type fakeAgentFiles struct {
	data  []byte
	err   error
	calls []string
	max   int
	token string
}

func (f *fakeAgentFiles) AgentFileRead(ctx context.Context, rm executordb.PveRemote, node string, vmid uint64, path string, maxBytes int, read pveapi.TokenSupplier) ([]byte, error) {
	f.calls = append(f.calls, rm.RemoteID+"|"+node+"|"+uintString(vmid)+"|"+path)
	f.max = maxBytes
	if read != nil {
		f.token, _ = read(ctx)
	}
	return f.data, f.err
}

func uintString(v uint64) string {
	var b [20]byte
	i := len(b)
	for {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
		if v == 0 {
			return string(b[i:])
		}
	}
}

func authorizedLine(k ssh.PublicKey, comment string) []byte {
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
	if comment != "" {
		line += " " + comment
	}
	return []byte(line + "\n")
}

func newEd25519PublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestParseAgentHostKeyValidatesUntrustedOutput(t *testing.T) {
	ed := newEd25519PublicKey(t)
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ssh.NewPublicKey(&ec.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	good := authorizedLine(ed, "root@web1")
	cases := []struct {
		name string
		raw  []byte
		ok   bool
	}{
		{"one line with comment", good, true},
		{"no trailing newline", []byte(strings.TrimSuffix(string(good), "\n")), true},
		{"no comment", authorizedLine(ed, ""), true},
		{"empty", nil, false},
		{"only newline", []byte("\n"), false},
		{"oversize", append(append([]byte{}, good[:len(good)-1]...), []byte(" "+strings.Repeat("a", maxPveAgentHostKeyBytes)+"\n")...), false},
		{"two lines", append(append([]byte{}, good...), good...), false},
		{"carriage return", []byte(strings.TrimSuffix(string(good), "\n") + "\r\n"), false},
		{"NUL byte", []byte(strings.Replace(string(good), "root", "ro\x00ot", 1)), false},
		{"escape sequence in comment", []byte(strings.Replace(string(good), "root", "\x1b[31mroot", 1)), false},
		{"invalid UTF-8", []byte(strings.Replace(string(good), "root", "r\xffoot", 1)), false},
		{"options prefix", append([]byte(`command="/bin/sh" `), good...), false},
		{"not ed25519", authorizedLine(ecKey, "root@web1"), false},
		{"garbage", []byte("ssh-ed25519 AAAA-not-base64 x\n"), false},
		{"private key text", []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			k, err := ParseAgentHostKey(c.raw)
			if c.ok {
				if err != nil {
					t.Fatalf("err = %v", err)
				}
				if string(k.Marshal()) != string(ed.Marshal()) {
					t.Fatal("parsed key differs")
				}
				return
			}
			if !errors.Is(err, ErrPveAgentHostKey) {
				t.Fatalf("err = %v, want ErrPveAgentHostKey", err)
			}
		})
	}
}

// joinEnv is a Service with a loopback SSH "guest" and, optionally, a PVE
// remote whose guest agent the join may read.
type joinEnv struct {
	*reconcileEnv
	ssh   *testSSH
	mut   *pveMutEnv
	agent *fakeAgentFiles
	join  *PveGuestJoin
}

func newJoinEnv(t *testing.T, withAgent bool) *joinEnv {
	t.Helper()
	re := newReconcileEnv(t)
	srv := startTestSSH(t, re.userPub, sshModeNormal)
	e := &joinEnv{reconcileEnv: re, ssh: srv, join: &PveGuestJoin{Service: re.svc}}
	if withAgent {
		e.mut = newPveMutEnv(t, false)
		e.agent = &fakeAgentFiles{data: authorizedLine(srv.hostKey.PublicKey(), "root@web1")}
		e.join.Mutations, e.join.Agent = e.mut.m, e.agent
	}
	return e
}

func (e *joinEnv) request() PveGuestJoinRequest {
	return PveGuestJoinRequest{RemoteID: mutRemote, Node: "pve1", VMID: 101, Generation: 1,
		HostID: "web1", Endpoint: e.ssh.addr, SSHUser: "nos", CredentialRef: "cred"}
}

func (e *joinEnv) pending() int {
	e.t.Helper()
	got, err := e.svc.ListPending(context.Background(), &pb.ListPendingRequest{})
	if err != nil {
		e.t.Fatal(err)
	}
	return len(got.GetPermits())
}

func TestGuestJoinAgentReadBindsTheAgentKey(t *testing.T) {
	e := newJoinEnv(t, true)
	p, err := e.join.Propose(context.Background(), e.request())
	if err != nil {
		t.Fatal(err)
	}
	want := sshtransport.Fingerprint(e.ssh.hostKey.PublicKey())
	if p.Method != PveJoinMethodAgent || p.Fingerprint != want || p.KeyType != ssh.KeyAlgoED25519 {
		t.Fatalf("proposal = %+v, want agent-verified %s", p, want)
	}
	if len(e.agent.calls) != 1 || e.agent.calls[0] != mutRemote+"|pve1|101|"+pveJoinHostKeyPath {
		t.Fatalf("agent calls = %v", e.agent.calls)
	}
	if e.agent.max != maxPveAgentHostKeyBytes {
		t.Fatalf("agent read limit = %d", e.agent.max)
	}
	if !strings.Contains(e.agent.token, mutReadToken) {
		t.Fatal("the agent read must use the remote's read token")
	}
	if p.Host.GetHostId() != "web1" || p.Host.GetFingerprint() != want || p.Host.GetSshUser() != "nos" || p.Host.GetCredentialRef() != "cred" {
		t.Fatalf("host = %+v", p.Host)
	}
	if p.Permit.GetExecutionDigest() == "" || e.pending() != 1 {
		t.Fatal("the join must propose the normal enrollment for approval")
	}
	recs := e.logs.find("guest_join_proposed", "")
	if len(recs) != 1 || recs[0].attrs["method"] != PveJoinMethodAgent || recs[0].attrs["vmid"] != uint64(101) ||
		recs[0].attrs["generation"] != uint64(1) || recs[0].attrs["remote"] != mutRemote || recs[0].attrs["node"] != "pve1" {
		t.Fatalf("audit records = %+v", recs)
	}
}

func TestGuestJoinAgentKeyMismatchStopsJoin(t *testing.T) {
	e := newJoinEnv(t, true)
	e.agent.data = authorizedLine(newEd25519PublicKey(t), "root@web1")
	_, err := e.join.Propose(context.Background(), e.request())
	if !errors.Is(err, ErrPveJoinKeyMismatch) {
		t.Fatalf("err = %v, want ErrPveJoinKeyMismatch", err)
	}
	if e.pending() != 0 {
		t.Fatal("a mismatch must not propose anything")
	}
	if len(e.logs.find("guest_join_key_mismatch", "")) != 1 {
		t.Fatal("a mismatch must be audited")
	}
}

func TestGuestJoinFallsBackToFingerprintReview(t *testing.T) {
	cases := map[string]func(e *joinEnv, r *PveGuestJoinRequest){
		"no agent reader":    func(e *joinEnv, _ *PveGuestJoinRequest) { e.join.Agent, e.join.Mutations = nil, nil },
		"agent unavailable":  func(e *joinEnv, _ *PveGuestJoinRequest) { e.agent.err = errors.New("QEMU guest agent is not running") },
		"agent output junk":  func(e *joinEnv, _ *PveGuestJoinRequest) { e.agent.data = []byte("\x1b]0;pwned\x07\n") },
		"agent output large": func(e *joinEnv, _ *PveGuestJoinRequest) { e.agent.data = []byte(strings.Repeat("A", 1<<20)) },
		"unknown remote":     func(_ *joinEnv, r *PveGuestJoinRequest) { r.RemoteID = "other-pve" },
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			e := newJoinEnv(t, true)
			req := e.request()
			mod(e, &req)
			p, err := e.join.Propose(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			want := sshtransport.Fingerprint(e.ssh.hostKey.PublicKey())
			if p.Method != PveJoinMethodReview || p.Fingerprint != want || p.AgentDetail == "" {
				t.Fatalf("proposal = %+v, want review of %s with a reason", p, want)
			}
			if strings.ContainsAny(p.AgentDetail, "\x1b\x07") || strings.Contains(p.AgentDetail, "QEMU") {
				t.Fatalf("detail %q must be fixed text, not agent output", p.AgentDetail)
			}
			if e.pending() != 1 {
				t.Fatal("review must propose the normal enrollment")
			}
		})
	}
}

func TestGuestJoinRejectsMalformedRequest(t *testing.T) {
	e := newJoinEnv(t, true)
	cases := map[string]func(r *PveGuestJoinRequest){
		"remote":       func(r *PveGuestJoinRequest) { r.RemoteID = "Bad Remote" },
		"node":         func(r *PveGuestJoinRequest) { r.Node = "pve1;rm" },
		"vmid low":     func(r *PveGuestJoinRequest) { r.VMID = 99 },
		"vmid high":    func(r *PveGuestJoinRequest) { r.VMID = 10_000_000_000 },
		"generation":   func(r *PveGuestJoinRequest) { r.Generation = 0 },
		"host":         func(r *PveGuestJoinRequest) { r.HostID = "Web 1" },
		"endpoint":     func(r *PveGuestJoinRequest) { r.Endpoint = "ssh://x" },
		"user":         func(r *PveGuestJoinRequest) { r.SSHUser = "root;id" },
		"credential":   func(r *PveGuestJoinRequest) { r.CredentialRef = "../key" },
		"unknown cred": func(r *PveGuestJoinRequest) { r.CredentialRef = "nope" },
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			req := e.request()
			mod(&req)
			if _, err := e.join.Propose(context.Background(), req); !errors.Is(err, ErrPveJoinInvalid) {
				t.Fatalf("err = %v, want ErrPveJoinInvalid", err)
			}
		})
	}
	if len(e.agent.calls) != 0 || e.ssh.connections() != 0 {
		t.Fatal("a malformed request must not cause I/O")
	}
	if e.pending() != 0 {
		t.Fatal("nothing may be proposed")
	}
}

func TestGuestJoinRefusesPinnedHostOrKey(t *testing.T) {
	t.Run("host already pinned", func(t *testing.T) {
		e := newJoinEnv(t, true)
		e.host = "web1"
		e.pin(e.ssh.hostKey)
		if _, err := e.join.Propose(context.Background(), e.request()); !errors.Is(err, ErrPveJoinRefused) {
			t.Fatalf("err = %v, want ErrPveJoinRefused", err)
		}
	})
	t.Run("key pinned for another host", func(t *testing.T) {
		e := newJoinEnv(t, true)
		e.host = "template-clone"
		e.pin(e.ssh.hostKey)
		_, err := e.join.Propose(context.Background(), e.request())
		if !errors.Is(err, ErrPveJoinRefused) || !strings.Contains(err.Error(), "template-clone") {
			t.Fatalf("err = %v, want ErrPveJoinRefused naming the other host", err)
		}
		if e.pending() != 0 {
			t.Fatal("nothing may be proposed")
		}
	})
	t.Run("guest unreachable", func(t *testing.T) {
		e := newJoinEnv(t, false)
		req := e.request()
		req.Endpoint = "127.0.0.1:1"
		if _, err := e.join.Propose(context.Background(), req); !errors.Is(err, ErrPveJoinUnreachable) {
			t.Fatalf("err = %v, want ErrPveJoinUnreachable", err)
		}
	})
}
