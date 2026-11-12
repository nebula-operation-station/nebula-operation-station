// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pairing"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/sshtransport"
)

// pairSSH is a loopback SSH server whose host keys can be swapped between
// connections. It accepts the executor's credential and nothing else, and
// counts accepted TCP connections so a test can prove nothing was probed.
type pairSSH struct {
	addr  string
	user  ssh.PublicKey
	conns atomic.Int64
	mu    sync.Mutex
	keys  []ssh.Signer
}

func startPairSSH(t *testing.T, user ssh.PublicKey, keys ...ssh.Signer) *pairSSH {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &pairSSH{addr: ln.Addr().String(), user: user, keys: keys}
	var wg sync.WaitGroup
	var open sync.Map
	t.Cleanup(func() {
		_ = ln.Close()
		open.Range(func(k, _ any) bool { _ = k.(net.Conn).Close(); return true })
		wg.Wait()
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.conns.Add(1)
			open.Store(c, true)
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				sc, chans, reqs, err := ssh.NewServerConn(c, s.config())
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					_ = nc.Reject(ssh.Prohibited, "no channels")
				}
				_ = sc.Close()
			}()
		}
	}()
	return s
}

func (s *pairSSH) config() *ssh.ServerConfig {
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if string(k.Marshal()) == string(s.user.Marshal()) {
			return &ssh.Permissions{}, nil
		}
		return nil, errors.New("denied")
	}}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range s.keys {
		cfg.AddHostKey(k)
	}
	return cfg
}

func (s *pairSSH) setKeys(keys ...ssh.Signer) {
	s.mu.Lock()
	s.keys = keys
	s.mu.Unlock()
}

func (s *pairSSH) connections() int64 { return s.conns.Load() }

func newEd25519HostKey(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newECDSAHostKey(t *testing.T) ssh.Signer {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newRSAHostKey(t *testing.T) ssh.Signer {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// pairEnv is an offer environment with one downloaded offer.
type pairEnv struct {
	*offerEnv
	offer *pb.CreateEnrollOfferResponse
}

func newPairEnv(t *testing.T) *pairEnv {
	t.Helper()
	e := newOfferEnv(t)
	resp := e.create(t, false)
	if _, err := e.fetch(resp.GetOfferId()); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	e.wantState(t, resp, executordb.OfferDownloaded)
	return &pairEnv{offerEnv: e, offer: resp}
}

// code returns the pairing code the script would print on a host with key.
func (e *pairEnv) code(t *testing.T, key ssh.Signer) string {
	t.Helper()
	c, err := pairing.Compute(e.stored(t).Salt, key.PublicKey().Marshal())
	if err != nil {
		t.Fatal(err)
	}
	return c.String()
}

func (e *pairEnv) stored(t *testing.T) executordb.Offer {
	t.Helper()
	return e.offerEnv.offer(t, e.offer)
}

func (e *pairEnv) submit(code, endpoint string, session []byte, inventory ...string) (*pb.SubmitPairingCodeResponse, error) {
	return e.svc.SubmitPairingCode(context.Background(), &pb.SubmitPairingCodeRequest{
		OfferIdHash: e.offer.GetOfferIdHash(), SessionBinding: session, Code: code, Endpoint: endpoint,
		InventoryEndpoints: inventory})
}

func (e *pairEnv) commit(digest string, session []byte) (*pb.CommitPairedEnrollResponse, error) {
	return e.svc.CommitPairedEnroll(context.Background(), &pb.CommitPairedEnrollRequest{
		OfferIdHash: e.offer.GetOfferIdHash(), SessionBinding: session, PermitDigest: digest})
}

// matched submits the right code for key at srv and approves the permit
// from the CLI.
func (e *pairEnv) matched(t *testing.T, srv *pairSSH, key ssh.Signer, inventory ...string) *pb.SubmitPairingCodeResponse {
	t.Helper()
	resp, err := e.submit(e.code(t, key), srv.addr, offerSessionA, inventory...)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if resp.GetOutcome() != pb.PairingOutcome_PAIRING_OUTCOME_MATCHED {
		t.Fatalf("outcome %v (%s), want MATCHED", resp.GetOutcome(), resp.GetDetail())
	}
	return resp
}

func (e *pairEnv) approve(t *testing.T, digest string) {
	t.Helper()
	d, err := canonical.ParseDigest(digest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.auth.ApprovePairedCLI(d, "test"); err != nil {
		t.Fatalf("approve: %v", err)
	}
}

func (e *pairEnv) wantNotPinned(t *testing.T) {
	t.Helper()
	if _, ok, err := e.db.HostKey(offerTestHost); err != nil || ok {
		t.Fatalf("host pinned=%v err=%v, want not pinned", ok, err)
	}
}

// A malformed code is counted and rejected before any probe; the third
// one ends the offer.
func TestSubmitPairingCodeMalformedIsCountedWithoutProbe(t *testing.T) {
	e := newPairEnv(t)
	srv := startPairSSH(t, e.userPub, newEd25519HostKey(t))
	for i := 1; i <= executordb.OfferMaxRejectedCodes; i++ {
		resp, err := e.submit("K7QXM-2PD9H-TR4AB-6CJWN-0FE5", srv.addr, offerSessionA)
		if err != nil {
			t.Fatalf("submit %d: %v", i, err)
		}
		if resp.GetOutcome() != pb.PairingOutcome_PAIRING_OUTCOME_CODE_REJECTED || resp.GetRejectedCodes() != int32(i) {
			t.Fatalf("submit %d: outcome %v rejected %d", i, resp.GetOutcome(), resp.GetRejectedCodes())
		}
	}
	if n := srv.connections(); n != 0 {
		t.Fatalf("%d probes for malformed codes, want none", n)
	}
	e.wantState(t, e.offer, executordb.OfferFailed)
	if got := len(e.logs.find("enroll_code_rejected", "")); got != executordb.OfferMaxRejectedCodes {
		t.Fatalf("%d enroll_code_rejected audits, want %d", got, executordb.OfferMaxRejectedCodes)
	}
}

// The probe offers only ssh-ed25519: a host with ECDSA and ed25519 keys is
// paired on its ed25519 key, whatever its own preference.
func TestSubmitPairingCodeProbeNegotiatesEd25519(t *testing.T) {
	e := newPairEnv(t)
	ed := newEd25519HostKey(t)
	srv := startPairSSH(t, e.userPub, newECDSAHostKey(t), ed)
	resp := e.matched(t, srv, ed)
	if resp.GetKeyType() != ssh.KeyAlgoED25519 || resp.GetFingerprint() != sshtransport.Fingerprint(ed.PublicKey()) {
		t.Fatalf("paired on %s %s, want the ed25519 key", resp.GetKeyType(), resp.GetFingerprint())
	}
	if resp.GetPermit().GetDigest() == "" || len(resp.GetPermit().GetChallenge()) == 0 {
		t.Fatal("matched without a paired permit")
	}
	e.wantState(t, e.offer, executordb.OfferPairingProposed)
	if len(e.logs.find("enroll_paired_proposed", "")) != 1 {
		t.Fatal("enroll_paired_proposed not audited")
	}
}

// A host with only ECDSA and RSA keys fails the probe with "no ed25519":
// not a mismatch, the offer stays usable and another endpoint may be tried.
func TestSubmitPairingCodeWithoutEd25519IsProbeFailure(t *testing.T) {
	e := newPairEnv(t)
	noEd := startPairSSH(t, e.userPub, newECDSAHostKey(t), newRSAHostKey(t))
	ed := newEd25519HostKey(t)
	resp, err := e.submit(e.code(t, ed), noEd.addr, offerSessionA)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if resp.GetOutcome() != pb.PairingOutcome_PAIRING_OUTCOME_PROBE_FAILED || !strings.Contains(resp.GetDetail(), "no ed25519") {
		t.Fatalf("outcome %v detail %q, want PROBE_FAILED no ed25519", resp.GetOutcome(), resp.GetDetail())
	}
	if resp.GetNotify() || resp.GetFingerprint() != "" {
		t.Fatal("probe failure treated like a mismatch")
	}
	e.wantState(t, e.offer, executordb.OfferDownloaded)
	if len(e.logs.find("enroll_code_mismatch", "")) != 0 {
		t.Fatal("probe failure audited as mismatch")
	}
	// The operator picks the right endpoint.
	good := startPairSSH(t, e.userPub, ed)
	if r := e.matched(t, good, ed); r.GetProbes() != 2 {
		t.Fatalf("probes %d, want 2", r.GetProbes())
	}
}

// An unreachable endpoint is a probe failure too, and the probe limit ends
// the offer.
func TestSubmitPairingCodeProbeLimit(t *testing.T) {
	e := newPairEnv(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	_ = ln.Close()
	code := e.code(t, newEd25519HostKey(t))
	for i := 1; i <= executordb.OfferMaxProbes; i++ {
		resp, err := e.submit(code, dead, offerSessionA)
		if err != nil || resp.GetOutcome() != pb.PairingOutcome_PAIRING_OUTCOME_PROBE_FAILED {
			t.Fatalf("probe %d: %v %v", i, resp.GetOutcome(), err)
		}
	}
	if _, err := e.submit(code, dead, offerSessionA); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("probe beyond the limit: %v, want ResourceExhausted", err)
	}
	e.wantState(t, e.offer, executordb.OfferFailed)
}

// A well-formed code that does not match ends the offer, audits the
// presented fingerprint and endpoint, and asks for a notification.
func TestSubmitPairingCodeMismatchFailsOffer(t *testing.T) {
	e := newPairEnv(t)
	presented := newEd25519HostKey(t)
	srv := startPairSSH(t, e.userPub, presented)
	other := newEd25519HostKey(t)
	right := e.code(t, presented)
	resp, err := e.submit(e.code(t, other), srv.addr, offerSessionA)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	fp := sshtransport.Fingerprint(presented.PublicKey())
	if resp.GetOutcome() != pb.PairingOutcome_PAIRING_OUTCOME_MISMATCH || !resp.GetNotify() || resp.GetFingerprint() != fp {
		t.Fatalf("outcome %v notify %v fp %s, want MISMATCH with notify and %s", resp.GetOutcome(), resp.GetNotify(), resp.GetFingerprint(), fp)
	}
	if resp.GetPermit() != nil {
		t.Fatal("mismatch proposed a permit")
	}
	e.wantState(t, e.offer, executordb.OfferFailed)
	if e.stored(t).Salt != nil {
		t.Fatal("salt kept after the mismatch")
	}
	recs := e.logs.find("enroll_code_mismatch", "")
	if len(recs) != 1 || recs[0].attrs["presented"] != fp || recs[0].attrs["endpoint"] != srv.addr {
		t.Fatalf("mismatch audit %v", recs)
	}
	e.wantNotPinned(t)
	// There is no second submission, not even with the right code.
	if _, err := e.submit(right, srv.addr, offerSessionA); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("submission after mismatch: %v", err)
	}
}

// A host that is pinned or blocked is refused before any probe.
func TestSubmitPairingCodeRefusesPinnedHost(t *testing.T) {
	e := newPairEnv(t)
	key := newEd25519HostKey(t)
	srv := startPairSSH(t, e.userPub, key)
	if _, err := e.db.PinHostKey(executordb.HostKey{HostID: offerTestHost, PublicKey: newEd25519HostKey(t).PublicKey().Marshal(),
		User: "nebula", CredentialRef: "cred", Source: executordb.SourceProbe, PinnedBy: "test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.submit(e.code(t, key), srv.addr, offerSessionA); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("pinned host: %v, want FailedPrecondition", err)
	}
	if _, err := e.db.BlockHost(offerTestHost, "", srv.addr); err != nil {
		t.Fatal(err)
	}
	if _, err := e.submit(e.code(t, key), srv.addr, offerSessionA); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("blocked host: %v, want FailedPrecondition", err)
	}
	if srv.connections() != 0 {
		t.Fatal("pinned host probed")
	}
}

// Submit and commit are accepted only for the creating web session.
func TestPairingIsBoundToCreatingSession(t *testing.T) {
	e := newPairEnv(t)
	key := newEd25519HostKey(t)
	srv := startPairSSH(t, e.userPub, key)
	for _, s := range [][]byte{offerSessionB, nil, []byte("short")} {
		if _, err := e.submit(e.code(t, key), srv.addr, s); status.Code(err) != codes.NotFound {
			t.Fatalf("submit from session %q: %v, want NotFound", s, err)
		}
	}
	if srv.connections() != 0 {
		t.Fatal("foreign session caused a probe")
	}
	resp := e.matched(t, srv, key)
	e.approve(t, resp.GetPermit().GetDigest())
	if _, err := e.commit(resp.GetPermit().GetDigest(), offerSessionB); status.Code(err) != codes.NotFound {
		t.Fatalf("commit from session B: %v, want NotFound", err)
	}
	e.wantNotPinned(t)
	// The foreign attempt did not spend the permit.
	c, err := e.commit(resp.GetPermit().GetDigest(), offerSessionA)
	if err != nil || !c.GetPinned() {
		t.Fatalf("commit from session A: %v %v", c, err)
	}
}

// Commit re-probes, pins only the approved key with source paired, tests
// the login and only then names the endpoint to add.
func TestCommitPairedEnrollPinsApprovedKey(t *testing.T) {
	e := newPairEnv(t)
	key := newEd25519HostKey(t)
	srv := startPairSSH(t, e.userPub, newECDSAHostKey(t), key)
	resp := e.matched(t, srv, key, "192.0.2.21")
	if !resp.GetEndpointToAdd() {
		t.Fatal("endpoint outside the inventory not marked to add")
	}
	if len(e.logs.find("inventory_endpoint_added", "")) != 0 {
		t.Fatal("endpoint added before the commit")
	}
	e.approve(t, resp.GetPermit().GetDigest())
	c, err := e.commit(resp.GetPermit().GetDigest(), offerSessionA)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	fp := sshtransport.Fingerprint(key.PublicKey())
	if !c.GetPinned() || c.GetFingerprint() != fp || !c.GetLoginOk() || c.GetEndpointAdded() != srv.addr {
		t.Fatalf("commit %+v", c)
	}
	if c.GetState() != string(executordb.OfferEnrolled) {
		t.Fatalf("state %s", c.GetState())
	}
	e.wantState(t, e.offer, executordb.OfferEnrolled)
	hk, ok, err := e.db.HostKey(offerTestHost)
	if err != nil || !ok || hk.Fingerprint != fp || hk.CredentialRef != "cred" || !strings.HasPrefix(hk.PinnedBy, "paired:") {
		t.Fatalf("pin %+v ok=%v err=%v", hk, ok, err)
	}
	for _, kind := range []string{"host_key_pinned", "host_enrolled", "inventory_endpoint_added"} {
		recs := e.logs.find(kind, "")
		if len(recs) != 1 || recs[0].attrs["source"] != "paired" {
			t.Fatalf("%s audit %v, want one with source paired", kind, recs)
		}
	}
	// A permit is used once.
	if _, err := e.commit(resp.GetPermit().GetDigest(), offerSessionA); err == nil {
		t.Fatal("second commit accepted")
	}
}

// An endpoint already in the inventory is not added again.
func TestCommitPairedEnrollInventoryEndpointNotAdded(t *testing.T) {
	e := newPairEnv(t)
	key := newEd25519HostKey(t)
	srv := startPairSSH(t, e.userPub, key)
	resp := e.matched(t, srv, key, "192.0.2.21", srv.addr)
	if resp.GetEndpointToAdd() {
		t.Fatal("inventory endpoint marked to add")
	}
	e.approve(t, resp.GetPermit().GetDigest())
	c, err := e.commit(resp.GetPermit().GetDigest(), offerSessionA)
	if err != nil || !c.GetPinned() || c.GetEndpointAdded() != "" {
		t.Fatalf("commit %+v %v", c, err)
	}
	if len(e.logs.find("inventory_endpoint_added", "")) != 0 {
		t.Fatal("inventory endpoint audited as added")
	}
}

// A key that changed between approval and commit is not pinned; the offer
// fails, nothing is added and the server is asked to notify.
func TestCommitPairedEnrollKeyChangedPinsNothing(t *testing.T) {
	e := newPairEnv(t)
	key := newEd25519HostKey(t)
	srv := startPairSSH(t, e.userPub, key)
	resp := e.matched(t, srv, key, "192.0.2.21")
	e.approve(t, resp.GetPermit().GetDigest())
	srv.setKeys(newEd25519HostKey(t))
	c, err := e.commit(resp.GetPermit().GetDigest(), offerSessionA)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if c.GetPinned() || c.GetEndpointAdded() != "" || !c.GetNotify() || c.GetError() == "" {
		t.Fatalf("commit %+v", c)
	}
	e.wantNotPinned(t)
	e.wantState(t, e.offer, executordb.OfferFailed)
	if len(e.logs.find("inventory_endpoint_added", "")) != 0 || len(e.logs.find("enroll_key_changed", "")) != 1 {
		t.Fatal("wrong audit for a changed key")
	}
}

// Commit needs an approved permit; without one nothing happens and the
// offer can still be committed after approval.
func TestCommitPairedEnrollNeedsApproval(t *testing.T) {
	e := newPairEnv(t)
	key := newEd25519HostKey(t)
	srv := startPairSSH(t, e.userPub, key)
	resp := e.matched(t, srv, key)
	before := srv.connections()
	if _, err := e.commit(resp.GetPermit().GetDigest(), offerSessionA); err == nil {
		t.Fatal("unapproved commit accepted")
	}
	if _, err := e.commit(strings.Repeat("0", 64), offerSessionA); err == nil {
		t.Fatal("commit with a foreign digest accepted")
	}
	if srv.connections() != before {
		t.Fatal("unapproved commit probed")
	}
	e.wantNotPinned(t)
	e.approve(t, resp.GetPermit().GetDigest())
	if c, err := e.commit(resp.GetPermit().GetDigest(), offerSessionA); err != nil || !c.GetPinned() {
		t.Fatalf("commit after approval: %+v %v", c, err)
	}
}

// A revoked or expired offer adds nothing and pins nothing, even with an
// approved permit.
func TestCommitPairedEnrollRevokedOrExpiredAddsNothing(t *testing.T) {
	for _, tc := range []struct {
		name string
		end  func(e *pairEnv)
	}{
		{"revoked", func(e *pairEnv) {
			if _, err := e.svc.RevokeEnrollOffer(context.Background(), &pb.RevokeEnrollOfferRequest{OfferIdHash: e.offer.GetOfferIdHash()}); err != nil {
				e.t.Fatal(err)
			}
		}},
		{"expired", func(e *pairEnv) {
			e.clock.Add(executordb.OfferLifetime + executordb.OfferProposedGrace + time.Second)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newPairEnv(t)
			key := newEd25519HostKey(t)
			srv := startPairSSH(t, e.userPub, key)
			resp := e.matched(t, srv, key, "192.0.2.21")
			e.approve(t, resp.GetPermit().GetDigest())
			tc.end(e)
			c, err := e.commit(resp.GetPermit().GetDigest(), offerSessionA)
			if err == nil && (c.GetPinned() || c.GetEndpointAdded() != "") {
				t.Fatalf("commit %+v", c)
			}
			e.wantNotPinned(t)
			if len(e.logs.find("inventory_endpoint_added", "")) != 0 {
				t.Fatal("endpoint added for an ended offer")
			}
		})
	}
}

// After a paired pin the host key algorithms are restricted to the pinned
// type: a host that now has only an ECDSA key fails the connection in the
// algorithm negotiation, before it can present that key at all. Without
// the restriction the client would read the ECDSA key and report it as
// the presented key of a mismatch instead.
func TestPairedPinRestrictsHostKeyAlgorithms(t *testing.T) {
	e := newPairEnv(t)
	key := newEd25519HostKey(t)
	srv := startPairSSH(t, e.userPub, key)
	resp := e.matched(t, srv, key)
	e.approve(t, resp.GetPermit().GetDigest())
	if c, err := e.commit(resp.GetPermit().GetDigest(), offerSessionA); err != nil || !c.GetLoginOk() {
		t.Fatalf("commit %+v %v", c, err)
	}
	ecdsaKey := newECDSAHostKey(t)
	srv.setKeys(ecdsaKey)
	ep, _ := sshtransport.ParseEndpoint(srv.addr)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Premise: an unrestricted client reads the ECDSA key from this host.
	if k, err := e.svc.transport.Probe(ctx, ep); err != nil || k.Type() != ecdsaKey.PublicKey().Type() {
		t.Fatalf("unrestricted probe: %v %v, want the ECDSA key", k, err)
	}
	c, err := e.svc.Connect(ctx, offerTestHost, "", []sshtransport.Endpoint{ep})
	if err == nil {
		c.Close()
		t.Fatal("connection accepted a host presenting only ECDSA")
	}
	if sshtransport.ClassOf(err) != sshtransport.ClassHostKeyMismatch {
		t.Fatalf("class %s, want host_key_mismatch", sshtransport.ClassOf(err))
	}
	var te *sshtransport.Error
	if !errors.As(err, &te) || te.Presented != nil || !noEd25519Offered(err) {
		t.Fatalf("connect error %v: the ECDSA key was negotiated, HostKeyAlgorithms not restricted to ssh-ed25519", err)
	}
	recs := e.logs.find("host_key_mismatch", "")
	if len(recs) != 1 || recs[0].attrs["presented"] != "" {
		t.Fatalf("mismatch audit %v, want one without a presented key", recs)
	}
}

func (e *pairEnv) idHash(t *testing.T) [32]byte {
	t.Helper()
	h, ok := parseOfferIDHash(e.offer.GetOfferIdHash())
	if !ok {
		t.Fatal("offer ID hash")
	}
	return h
}

// A mismatch observed while a concurrent submission moved the offer to
// pairing_proposed ends that proposal too: the offer fails and the
// proposal cannot be committed.
func TestSubmitPairingCodeMismatchEndsConcurrentProposal(t *testing.T) {
	e := newPairEnv(t)
	h := e.idHash(t)
	presented := newEd25519HostKey(t)
	srv := startPairSSH(t, e.userPub, presented)
	fake, err := canonical.ParseDigest(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	e.svc.pairingHooks = &pairingHooks{afterProbe: func() {
		if err := e.db.ProposeOfferPairing(h); err != nil {
			t.Errorf("concurrent proposal: %v", err)
		}
		e.svc.offers.setPaired(h, pairedProposal{digest: fake})
	}}
	resp, err := e.submit(e.code(t, newEd25519HostKey(t)), srv.addr, offerSessionA)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if resp.GetOutcome() != pb.PairingOutcome_PAIRING_OUTCOME_MISMATCH || !resp.GetNotify() || resp.GetDetail() != "" {
		t.Fatalf("outcome %v notify %v detail %q", resp.GetOutcome(), resp.GetNotify(), resp.GetDetail())
	}
	if resp.GetState() != string(executordb.OfferFailed) {
		t.Fatalf("state %s, want failed", resp.GetState())
	}
	e.wantState(t, e.offer, executordb.OfferFailed)
	if e.svc.offers.paired(h) != nil {
		t.Fatal("proposal survived the mismatch")
	}
	recs := e.logs.find("enroll_offer_failed", "")
	if len(recs) != 1 || recs[0].attrs["reason"] != "proposal ended by an observed mismatch" {
		t.Fatalf("offer failed audit %v", recs)
	}
	if len(e.logs.find("enroll_code_mismatch", "")) != 1 {
		t.Fatal("mismatch not audited")
	}
}

// A mismatch whose store transition fails is not reported as a clean
// mismatch: the response names the failure and the real state, the
// mismatch is still audited with a notification, and the offer accepts
// neither another code nor a commit of a proposal.
func TestSubmitPairingCodeMismatchEndOfferStoreError(t *testing.T) {
	e := newPairEnv(t)
	h := e.idHash(t)
	presented := newEd25519HostKey(t)
	srv := startPairSSH(t, e.userPub, presented)
	fake, err := canonical.ParseDigest(strings.Repeat("cd", 32))
	if err != nil {
		t.Fatal(err)
	}
	var ends atomic.Int64
	e.svc.pairingHooks = &pairingHooks{
		endOffer: func([32]byte, executordb.OfferState, executordb.OfferState) error {
			ends.Add(1)
			return errors.New("injected store error")
		},
		afterProbe: func() {
			// A matched proposal from a concurrent submission.
			if err := e.db.ProposeOfferPairing(h); err != nil {
				t.Errorf("concurrent proposal: %v", err)
			}
			e.svc.offers.setPaired(h, pairedProposal{digest: fake})
		},
	}
	resp, err := e.submit(e.code(t, newEd25519HostKey(t)), srv.addr, offerSessionA)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if resp.GetOutcome() != pb.PairingOutcome_PAIRING_OUTCOME_MISMATCH || !resp.GetNotify() {
		t.Fatalf("outcome %v notify %v", resp.GetOutcome(), resp.GetNotify())
	}
	if !strings.Contains(resp.GetDetail(), "could not be ended") || resp.GetState() != string(executordb.OfferPairingProposed) {
		t.Fatalf("detail %q state %s, want the failure and the real state", resp.GetDetail(), resp.GetState())
	}
	if ends.Load() < 2 {
		t.Fatalf("%d end attempts, want the downloaded and the pairing_proposed one", ends.Load())
	}
	if len(e.logs.find("enroll_code_mismatch", "")) != 1 {
		t.Fatal("mismatch not audited")
	}
	// The surviving store state is not usable: no commit, no submission.
	if e.svc.offers.paired(h) != nil {
		t.Fatal("proposal survived the mismatch")
	}
	if _, err := e.commit(fake.String(), offerSessionA); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("commit after mismatch: %v, want FailedPrecondition", err)
	}
	e.wantNotPinned(t)
	e.svc.pairingHooks = nil
	before := srv.connections()
	if _, err := e.submit(e.code(t, presented), srv.addr, offerSessionA); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("submission after mismatch: %v, want FailedPrecondition", err)
	}
	if srv.connections() != before {
		t.Fatal("submission after mismatch probed")
	}
}

// A mismatch whose store transition fails while the offer is still
// downloaded blocks every later submission of the offer, even one with
// the right code.
func TestSubmitPairingCodeMismatchStoreErrorBlocksRetry(t *testing.T) {
	e := newPairEnv(t)
	presented := newEd25519HostKey(t)
	srv := startPairSSH(t, e.userPub, presented)
	e.svc.pairingHooks = &pairingHooks{endOffer: func([32]byte, executordb.OfferState, executordb.OfferState) error {
		return errors.New("injected store error")
	}}
	wrong := e.code(t, newEd25519HostKey(t))
	resp, err := e.submit(wrong, srv.addr, offerSessionA)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if resp.GetOutcome() != pb.PairingOutcome_PAIRING_OUTCOME_MISMATCH || !resp.GetNotify() || resp.GetDetail() == "" ||
		resp.GetState() != string(executordb.OfferDownloaded) {
		t.Fatalf("response %+v, want MISMATCH naming the failed end", resp)
	}
	before := srv.connections()
	for _, code := range []string{wrong, e.code(t, presented)} {
		if _, err := e.submit(code, srv.addr, offerSessionA); status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("submission after mismatch: %v, want FailedPrecondition", err)
		}
	}
	if srv.connections() != before {
		t.Fatal("submission after mismatch probed")
	}
}

// Submissions of one offer are serialized: while one is probing, another
// one, with whatever code, is refused without a probe and without
// counting.
func TestSubmitPairingCodeConcurrentSubmissionRefused(t *testing.T) {
	e := newPairEnv(t)
	key := newEd25519HostKey(t)
	srv := startPairSSH(t, e.userPub, key)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	e.svc.pairingHooks = &pairingHooks{afterProbe: func() {
		once.Do(func() {
			close(entered)
			<-release
		})
	}}
	type result struct {
		resp *pb.SubmitPairingCodeResponse
		err  error
	}
	first := make(chan result, 1)
	wrong := e.code(t, newEd25519HostKey(t))
	go func() {
		r, err := e.submit(wrong, srv.addr, offerSessionA)
		first <- result{r, err}
	}()
	<-entered
	for _, code := range []string{e.code(t, key), wrong, "malformed"} {
		if _, err := e.submit(code, srv.addr, offerSessionA); status.Code(err) != codes.FailedPrecondition {
			close(release)
			t.Fatalf("concurrent submission %q: %v, want FailedPrecondition", code, err)
		}
	}
	close(release)
	r := <-first
	if r.err != nil || r.resp.GetOutcome() != pb.PairingOutcome_PAIRING_OUTCOME_MISMATCH {
		t.Fatalf("first submission: %+v %v", r.resp, r.err)
	}
	if n := srv.connections(); n != 1 {
		t.Fatalf("%d probes, want only the first submission's", n)
	}
	o := e.stored(t)
	if o.Probes != 1 || o.RejectedCodes != 0 || o.State != executordb.OfferFailed {
		t.Fatalf("offer %s probes %d rejected %d", o.State, o.Probes, o.RejectedCodes)
	}
	if len(e.logs.find("enroll_code_mismatch", "")) != 1 || len(e.logs.find("enroll_paired_proposed", "")) != 0 {
		t.Fatal("more than one code compared")
	}
}

// After a probe failure a retry must carry the code claimed by the first
// well-formed submission: a different code is refused without a probe,
// and a claim the executor no longer knows (restart) refuses every code.
func TestSubmitPairingCodeRetryCarriesClaimedCode(t *testing.T) {
	e := newPairEnv(t)
	key := newEd25519HostKey(t)
	noEd := startPairSSH(t, e.userPub, newECDSAHostKey(t))
	good := startPairSSH(t, e.userPub, key)
	right := e.code(t, key)
	resp, err := e.submit(right, noEd.addr, offerSessionA)
	if err != nil || resp.GetOutcome() != pb.PairingOutcome_PAIRING_OUTCOME_PROBE_FAILED {
		t.Fatalf("first submission: %+v %v", resp, err)
	}
	other := e.code(t, newEd25519HostKey(t))
	if _, err := e.submit(other, good.addr, offerSessionA); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("retry with another code: %v, want FailedPrecondition", err)
	}
	if good.connections() != 0 || e.stored(t).Probes != 1 {
		t.Fatal("retry with another code probed or was counted")
	}
	e.wantState(t, e.offer, executordb.OfferDownloaded)
	e.matched(t, good, key)

	// Restart: the claimed code is gone with the process.
	e2 := newPairEnv(t)
	resp, err = e2.submit(e2.code(t, key), noEd.addr, offerSessionA)
	if err != nil || resp.GetOutcome() != pb.PairingOutcome_PAIRING_OUTCOME_PROBE_FAILED {
		t.Fatalf("first submission: %+v %v", resp, err)
	}
	e2.svc.offers.mu.Lock()
	e2.svc.offers.offers[e2.idHash(t)].claimed = nil
	e2.svc.offers.mu.Unlock()
	before := good.connections()
	if _, err := e2.submit(e2.code(t, key), good.addr, offerSessionA); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("retry with an unknown claim: %v, want FailedPrecondition", err)
	}
	if good.connections() != before {
		t.Fatal("retry with an unknown claim probed")
	}
}

// A matching key that is already pinned for another host is refused: the
// offer fails and nothing is proposed or pinned.
func TestSubmitPairingCodeKeyPinnedForOtherHost(t *testing.T) {
	e := newPairEnv(t)
	key := newEd25519HostKey(t)
	srv := startPairSSH(t, e.userPub, key)
	if _, err := e.db.PinHostKey(executordb.HostKey{HostID: "db-02", PublicKey: key.PublicKey().Marshal(),
		User: "nebula", CredentialRef: "cred", Source: executordb.SourceProbe, PinnedBy: "test"}); err != nil {
		t.Fatal(err)
	}
	_, err := e.submit(e.code(t, key), srv.addr, offerSessionA)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "db-02") {
		t.Fatalf("submit: %v, want FailedPrecondition naming db-02", err)
	}
	e.wantState(t, e.offer, executordb.OfferFailed)
	e.wantNotPinned(t)
	if e.svc.offers.paired(e.idHash(t)) != nil || len(e.logs.find("enroll_paired_proposed", "")) != 0 {
		t.Fatal("proposal for a key pinned for another host")
	}
	recs := e.logs.find("enroll_offer_failed", "")
	if len(recs) != 1 || recs[0].attrs["reason"] != "host key pinned for another host" || recs[0].attrs["other"] != "db-02" {
		t.Fatalf("offer failed audit %v", recs)
	}
}

// An offer that ends between the pin and CompleteOffer gets its pin
// undone: nothing stays pinned, nothing is added, nothing is enrolled.
func TestCommitPairedEnrollUndoesPinWhenOfferEnds(t *testing.T) {
	e := newPairEnv(t)
	h := e.idHash(t)
	key := newEd25519HostKey(t)
	srv := startPairSSH(t, e.userPub, key)
	resp := e.matched(t, srv, key, "192.0.2.21")
	e.approve(t, resp.GetPermit().GetDigest())
	var pinnedAtHook bool
	e.svc.pairingHooks = &pairingHooks{afterPin: func() {
		_, pinnedAtHook, _ = e.db.HostKey(offerTestHost)
		if err := e.db.EndOffer(h, executordb.OfferPairingProposed, executordb.OfferRevoked); err != nil {
			t.Errorf("revoke: %v", err)
		}
	}}
	c, err := e.commit(resp.GetPermit().GetDigest(), offerSessionA)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if !pinnedAtHook {
		t.Fatal("hook did not run between pin and CompleteOffer")
	}
	if c.GetPinned() || c.GetEndpointAdded() != "" || c.GetLoginOk() || !strings.Contains(c.GetError(), "offer ended") {
		t.Fatalf("commit %+v", c)
	}
	if c.GetState() != string(executordb.OfferRevoked) {
		t.Fatalf("state %s, want revoked", c.GetState())
	}
	e.wantNotPinned(t)
	if len(e.logs.find("enroll_pin_undone", "")) != 1 {
		t.Fatal("pin undo not audited")
	}
	for _, kind := range []string{"host_key_pinned", "host_enrolled", "inventory_endpoint_added"} {
		if len(e.logs.find(kind, "")) != 0 {
			t.Fatalf("%s audited for an undone pin", kind)
		}
	}
}

// Malformed requests are refused without counting or probing.
func TestSubmitPairingCodeRefusesMalformedRequests(t *testing.T) {
	e := newPairEnv(t)
	key := newEd25519HostKey(t)
	srv := startPairSSH(t, e.userPub, key)
	code := e.code(t, key)
	for name, req := range map[string]*pb.SubmitPairingCodeRequest{
		"offer hash": {OfferIdHash: "XYZ", SessionBinding: offerSessionA, Code: code, Endpoint: srv.addr},
		"endpoint":   {OfferIdHash: e.offer.GetOfferIdHash(), SessionBinding: offerSessionA, Code: code, Endpoint: "bad host!"},
		"inventory":  {OfferIdHash: e.offer.GetOfferIdHash(), SessionBinding: offerSessionA, Code: code, Endpoint: srv.addr, InventoryEndpoints: []string{"bad host!"}},
		"too many": {OfferIdHash: e.offer.GetOfferIdHash(), SessionBinding: offerSessionA, Code: code, Endpoint: srv.addr,
			InventoryEndpoints: strings.Split("a,b,c,d,e,f,g,h,i", ",")},
	} {
		if _, err := e.svc.SubmitPairingCode(context.Background(), req); status.Code(err) != codes.InvalidArgument && status.Code(err) != codes.NotFound {
			t.Fatalf("%s: %v", name, err)
		}
	}
	o := e.stored(t)
	if o.Probes != 0 || o.RejectedCodes != 0 || srv.connections() != 0 {
		t.Fatalf("malformed requests counted: probes %d rejected %d conns %d", o.Probes, o.RejectedCodes, srv.connections())
	}
}
