// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/sshtransport"
)

// H05 acceptance: SSH transport, host key pinning and enrollment (spec 08),
// against in-process SSH servers on 127.0.0.1.

// sshd is a minimal SSH server that counts what reaches it.
type sshd struct {
	ln         net.Listener
	authorized ssh.PublicKey
	hostKey    ssh.Signer
	conns      atomic.Int32
	auths      atomic.Int32
	mu         sync.Mutex
	open       []net.Conn
	wg         sync.WaitGroup
}

func newSSHD(t *testing.T, hostKey ssh.Signer, authorized ssh.PublicKey) *sshd {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	d := &sshd{ln: ln, authorized: authorized, hostKey: hostKey}
	d.wg.Add(1)
	go d.serve()
	t.Cleanup(func() {
		ln.Close()
		d.mu.Lock()
		for _, c := range d.open {
			c.Close()
		}
		d.mu.Unlock()
		d.wg.Wait()
	})
	return d
}

func (d *sshd) endpoint() string { return d.ln.Addr().String() }

func (d *sshd) serve() {
	defer d.wg.Done()
	for {
		c, err := d.ln.Accept()
		if err != nil {
			return
		}
		d.conns.Add(1)
		d.mu.Lock()
		d.open = append(d.open, c)
		d.mu.Unlock()
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			defer c.Close()
			cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
				d.auths.Add(1)
				if d.authorized != nil && string(k.Marshal()) == string(d.authorized.Marshal()) {
					return &ssh.Permissions{}, nil
				}
				return nil, errors.New("denied")
			}}
			cfg.AddHostKey(d.hostKey)
			sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
			if err != nil {
				return
			}
			defer sc.Close()
			go ssh.DiscardRequests(reqs)
			for nc := range chans {
				_ = nc.Reject(ssh.Prohibited, "test")
			}
		}()
	}
}

func hostSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func closedPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := ln.Addr().String()
	ln.Close()
	return a
}

func (h *harness) probe(endpoint string) *pb.ProbeHostKeyResponse {
	h.t.Helper()
	p, err := h.client.ProbeHostKey(h.ctx(), &pb.ProbeHostKeyRequest{Endpoint: endpoint})
	if err != nil {
		h.t.Fatalf("probe %s: %v", endpoint, err)
	}
	return p
}

func (h *harness) pin(host string, p *pb.ProbeHostKeyResponse) *pb.HostKeyPin {
	h.t.Helper()
	r, err := h.client.PinHostKey(h.ctx(), &pb.PinHostKeyRequest{
		HostId: host, AuthorizedKey: p.GetAuthorizedKey(), ExpectedFingerprint: p.GetFingerprint(),
		SshUser: "nebula", CredentialRef: credRef, Source: pb.HostKeySource_HOST_KEY_SOURCE_PROBE,
	})
	if err != nil {
		h.t.Fatalf("pin %s: %v", host, err)
	}
	return r.GetPin()
}

func (h *harness) testConn(host string, endpoints ...string) *pb.TestConnectionResponse {
	h.t.Helper()
	r, err := h.client.TestConnection(h.ctx(), &pb.TestConnectionRequest{HostId: host, Endpoints: endpoints})
	if err != nil {
		h.t.Fatalf("test connection %s: %v", host, err)
	}
	return r
}

func TestH05_ProbeShowsFingerprintAndSendsNoCredential(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.unlock()
	hk := hostSigner(t)
	d := newSSHD(t, hk, h.userKey)
	p := h.probe(d.endpoint())
	if p.GetFingerprint() != ssh.FingerprintSHA256(hk.PublicKey()) || p.GetKeyType() != ssh.KeyAlgoED25519 {
		t.Fatalf("probe %+v", p)
	}
	if d.auths.Load() != 0 {
		t.Fatal("probe offered a credential")
	}
}

func TestH05_NoConnectionBeforePin(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.unlock()
	d := newSSHD(t, hostSigner(t), h.userKey)
	_, err := h.client.TestConnection(h.ctx(), &pb.TestConnectionRequest{HostId: "dockerflux", Endpoints: []string{d.endpoint()}})
	wantCode(t, err, codes.NotFound, "no pinned key")
	if d.conns.Load() != 0 {
		t.Fatal("unpinned host contacted")
	}
}

// Milestone 3 acceptance: a host with LAN and VPN endpoints falls back on
// TCP failure.
func TestH05_PinnedHostFallsBackOnTCPFailure(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.unlock()
	hk := hostSigner(t)
	vpn := newSSHD(t, hk, h.userKey)
	h.pin("dockerflux", h.probe(vpn.endpoint()))
	lan := closedPort(t)
	r := h.testConn("dockerflux", lan, vpn.endpoint())
	if !r.GetOk() || r.GetEndpoint() != vpn.endpoint() || len(r.GetAttempts()) != 1 || r.GetAttempts()[0].GetStage() != "tcp" {
		t.Fatalf("result %+v", r)
	}
}

// Milestone 3 acceptance: a changed host key stops the host and is
// reported; nothing is sent to it, and no other endpoint is tried until the
// admin re-pins.
func TestH05_ChangedHostKeyStopsAndBlocksTheHost(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.unlock()
	oldKey, newKey := hostSigner(t), hostSigner(t)
	good := newSSHD(t, oldKey, h.userKey)
	pin := h.pin("dockerflux", h.probe(good.endpoint()))

	replaced := newSSHD(t, newKey, h.userKey)
	r := h.testConn("dockerflux", replaced.endpoint(), good.endpoint())
	if r.GetOk() || r.GetFailureClass() != string(sshtransport.ClassHostKeyMismatch) {
		t.Fatalf("result %+v", r)
	}
	if replaced.auths.Load() != 0 || good.conns.Load() != 1 {
		t.Fatalf("credential sent (%d) or next endpoint tried (%d connections)", replaced.auths.Load(), good.conns.Load())
	}
	if !strings.Contains(h.logs.String(), `"kind":"host_key_mismatch"`) {
		t.Fatal("no security event logged")
	}

	// Blocked: even the correct endpoint is not contacted.
	r = h.testConn("dockerflux", good.endpoint())
	if r.GetOk() || r.GetFailureClass() != "blocked" || good.conns.Load() != 1 {
		t.Fatalf("blocked host contacted: %+v", r)
	}
	list, err := h.client.ListHostKeys(h.ctx(), &pb.ListHostKeysRequest{})
	if err != nil || len(list.GetHosts()) != 1 {
		t.Fatalf("list %v %v", list, err)
	}
	b := list.GetHosts()[0]
	if !b.GetBlocked() || b.GetBlockedFingerprint() != ssh.FingerprintSHA256(newKey.PublicKey()) || b.GetBlockedEndpoint() != replaced.endpoint() {
		t.Fatalf("block record %+v", b)
	}

	// Re-pin: unpin needs the current fingerprint.
	_, err = h.client.UnpinHostKey(h.ctx(), &pb.UnpinHostKeyRequest{HostId: "dockerflux", ExpectedFingerprint: ssh.FingerprintSHA256(newKey.PublicKey())})
	wantCode(t, err, codes.InvalidArgument, "pinned to")
	if _, err := h.client.UnpinHostKey(h.ctx(), &pb.UnpinHostKeyRequest{HostId: "dockerflux", ExpectedFingerprint: pin.GetFingerprint()}); err != nil {
		t.Fatal(err)
	}
	h.pin("dockerflux", h.probe(good.endpoint()))
	if r := h.testConn("dockerflux", good.endpoint()); !r.GetOk() {
		t.Fatalf("after re-pin: %+v", r)
	}
}

func TestH05_BlockSurvivesRestart(t *testing.T) {
	dir := privateDir(t)
	id := newIdentity()
	h1 := newHarness(t, harnessOptions{dataDir: dir, identity: id, untrusted: true})
	h1.unlock()
	good := newSSHD(t, hostSigner(t), h1.userKey)
	h1.pin("dockerflux", h1.probe(good.endpoint()))
	evil := newSSHD(t, hostSigner(t), h1.userKey)
	if r := h1.testConn("dockerflux", evil.endpoint()); r.GetFailureClass() != string(sshtransport.ClassHostKeyMismatch) {
		t.Fatalf("result %+v", r)
	}
	h1.stop()

	h2 := newHarness(t, harnessOptions{dataDir: dir, identity: id, untrusted: true})
	h2.unlock()
	if r := h2.testConn("dockerflux", good.endpoint()); r.GetFailureClass() != "blocked" {
		t.Fatalf("block lost across restart: %+v", r)
	}
}

func TestH05_AuthFailureTriesNoOtherEndpoint(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.unlock()
	hk := hostSigner(t)
	denying := newSSHD(t, hk, hostSigner(t).PublicKey()) // key not authorized
	other := newSSHD(t, hk, h.userKey)
	h.pin("dockerflux", h.probe(denying.endpoint()))
	r := h.testConn("dockerflux", denying.endpoint(), other.endpoint())
	if r.GetOk() || r.GetFailureClass() != string(sshtransport.ClassAuth) || other.conns.Load() != 0 {
		t.Fatalf("result %+v, other endpoint contacted %d times", r, other.conns.Load())
	}
	if denying.auths.Load() != 1 {
		t.Fatalf("%d authentication attempts, want 1 (one key only)", denying.auths.Load())
	}
	// Not a host key problem: the host is not blocked.
	if r := h.testConn("dockerflux", other.endpoint()); !r.GetOk() {
		t.Fatalf("host blocked after an auth failure: %+v", r)
	}
}

func TestH05_LockedKeyringConnectsNowhere(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.unlock()
	d := newSSHD(t, hostSigner(t), h.userKey)
	h.pin("dockerflux", h.probe(d.endpoint()))
	before := d.conns.Load()
	if _, err := h.client.Lock(h.ctx(), &pb.LockRequest{}); err != nil {
		t.Fatal(err)
	}
	_, err := h.client.TestConnection(h.ctx(), &pb.TestConnectionRequest{HostId: "dockerflux", Endpoints: []string{d.endpoint()}})
	wantCode(t, err, codes.FailedPrecondition, "locked")
	if d.conns.Load() != before {
		t.Fatal("host contacted while locked")
	}
}

func TestH05_OnlyTheAdminEnrolls(t *testing.T) {
	uid := uint32(os.Getuid())
	h := newHarness(t, harnessOptions{uidRoles: map[uint32][]peercred.Role{uid: {peercred.RoleServer}}})
	d := newSSHD(t, hostSigner(t), nil)
	key := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(d.hostKey.PublicKey())))
	fp := ssh.FingerprintSHA256(d.hostKey.PublicKey())
	_, err := h.client.ProbeHostKey(h.ctx(), &pb.ProbeHostKeyRequest{Endpoint: d.endpoint()})
	wantCode(t, err, codes.PermissionDenied, "")
	_, err = h.client.PinHostKey(h.ctx(), &pb.PinHostKeyRequest{HostId: "dockerflux", AuthorizedKey: key, ExpectedFingerprint: fp,
		SshUser: "nebula", CredentialRef: credRef, Source: pb.HostKeySource_HOST_KEY_SOURCE_PROBE})
	wantCode(t, err, codes.PermissionDenied, "")
	_, err = h.client.UnpinHostKey(h.ctx(), &pb.UnpinHostKeyRequest{HostId: "dockerflux", ExpectedFingerprint: fp})
	wantCode(t, err, codes.PermissionDenied, "")
	_, err = h.client.TestConnection(h.ctx(), &pb.TestConnectionRequest{HostId: "dockerflux", Endpoints: []string{d.endpoint()}})
	wantCode(t, err, codes.PermissionDenied, "")
	if d.conns.Load() != 0 {
		t.Fatal("server role made the executor connect")
	}
	if _, err := h.client.ListHostKeys(h.ctx(), &pb.ListHostKeysRequest{}); err != nil {
		t.Fatalf("server cannot list pins: %v", err)
	}
}

func TestH05_PinNeedsTheConfirmedFingerprintAndAStrongKey(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	d := newSSHD(t, hostSigner(t), nil)
	p := h.probe(d.endpoint())
	req := func(mut func(*pb.PinHostKeyRequest)) error {
		r := &pb.PinHostKeyRequest{HostId: "dockerflux", AuthorizedKey: p.GetAuthorizedKey(), ExpectedFingerprint: p.GetFingerprint(),
			SshUser: "nebula", CredentialRef: credRef, Source: pb.HostKeySource_HOST_KEY_SOURCE_PROBE}
		mut(r)
		_, err := h.client.PinHostKey(h.ctx(), r)
		return err
	}
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	weakPub, _ := ssh.NewPublicKey(&weak.PublicKey)
	for name, mut := range map[string]func(*pb.PinHostKeyRequest){
		"other fingerprint": func(r *pb.PinHostKeyRequest) {
			r.ExpectedFingerprint = ssh.FingerprintSHA256(hostSigner(t).PublicKey())
		},
		"no fingerprint": func(r *pb.PinHostKeyRequest) { r.ExpectedFingerprint = "" },
		"key options":    func(r *pb.PinHostKeyRequest) { r.AuthorizedKey = `command="id" ` + r.AuthorizedKey },
		"two lines":      func(r *pb.PinHostKeyRequest) { r.AuthorizedKey += "\n" + r.AuthorizedKey },
		"weak RSA": func(r *pb.PinHostKeyRequest) {
			r.AuthorizedKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(weakPub)))
			r.ExpectedFingerprint = ssh.FingerprintSHA256(weakPub)
		},
		"no source":     func(r *pb.PinHostKeyRequest) { r.Source = pb.HostKeySource_HOST_KEY_SOURCE_UNSPECIFIED },
		"root;id user":  func(r *pb.PinHostKeyRequest) { r.SshUser = "root;id" },
		"bad reference": func(r *pb.PinHostKeyRequest) { r.CredentialRef = "../../etc/shadow" },
		"bad host":      func(r *pb.PinHostKeyRequest) { r.HostId = "Docker Flux" },
	} {
		if err := req(mut); err == nil {
			t.Errorf("%s: pinned", name)
		}
	}
	if err := req(func(*pb.PinHostKeyRequest) {}); err != nil {
		t.Fatal(err)
	}
	err = req(func(*pb.PinHostKeyRequest) {})
	wantCode(t, err, codes.AlreadyExists, "unpin it first")
	// A cloned machine with the same host key cannot be pinned as another host.
	err = req(func(r *pb.PinHostKeyRequest) { r.HostId = "strompi" })
	wantCode(t, err, codes.InvalidArgument, "already pinned for host dockerflux")
}

// With a pinned key, host criticality is bound to it (closes the H01 gap
// of a fingerprint typed by hand).
func TestH05_CriticalityFollowsThePin(t *testing.T) {
	h := newHarness(t, harnessOptions{untrusted: true})
	d := newSSHD(t, hostSigner(t), nil)
	p := h.pin("dockerflux", h.probe(d.endpoint()))
	r, err := h.client.SetHostCriticality(h.ctx(), &pb.SetHostCriticalityRequest{HostId: "dockerflux", Criticality: pb.RiskClass_RISK_CLASS_CRITICAL})
	if err != nil || r.GetHostKeyFingerprint() != p.GetFingerprint() {
		t.Fatalf("criticality without fingerprint: %v %v", r, err)
	}
	_, err = h.client.SetHostCriticality(h.ctx(), &pb.SetHostCriticalityRequest{HostId: "dockerflux", Criticality: pb.RiskClass_RISK_CLASS_LOW, HostKeyFingerprint: fpA})
	wantCode(t, err, codes.InvalidArgument, "pinned to")
}

// A connection for a permit target is refused when the target's key is not
// the pinned one, before any traffic.
func TestH05_TargetFingerprintMustMatchThePin(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.unlock()
	d := newSSHD(t, hostSigner(t), h.userKey)
	h.pin("dockerflux", h.probe(d.endpoint()))
	before := d.conns.Load()
	host, portStr, _ := net.SplitHostPort(d.endpoint())
	port, _ := strconv.Atoi(portStr)
	ep := sshtransport.Endpoint{Host: host, Port: uint16(port)}
	_, err := h.svc.Connect(context.Background(), "dockerflux", fpA, []sshtransport.Endpoint{ep})
	if !errors.Is(err, executor.ErrTargetFingerprint) || d.conns.Load() != before {
		t.Fatalf("connect with another fingerprint: %v", err)
	}
	c, err := h.svc.Connect(context.Background(), "dockerflux", ssh.FingerprintSHA256(d.hostKey.PublicKey()), []sshtransport.Endpoint{ep})
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}
