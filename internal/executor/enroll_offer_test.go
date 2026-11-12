// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/enrollscript"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

const (
	offerTestSetupKey = "8E5C2F0A-1B3D-4C5E-9F70-A1B2C3D4E5F6"
	offerTestKeyID    = "d0g6k2n4p6r8"
	offerTestHost     = "web-01"
	offerTestClient   = "192.0.2.77"
	offerTestPeer     = "127.0.0.1"
)

var (
	offerSessionA = []byte("session-a-0123456789abcdef")
	offerSessionB = []byte("session-b-0123456789abcdef")
)

// offerEnv is an executor with enrollment configured (NetBird included),
// an unlocked vault and an open privileged session.
type offerEnv struct {
	*reconcileEnv
	sign func([]byte) []byte
}

func newOfferEnv(t *testing.T) *offerEnv {
	t.Helper()
	e, sign := sessionRPCEnv(t, 30*time.Minute)
	if err := e.svc.SetEnrollOffers(EnrollOfferConfig{
		Sources: []string{"192.0.2.10", "2001:db8:5::/64"},
		NetBird: &EnrollOfferNetBird{
			ManagementURL: "https://netbird.example.lan",
			ManagedGroup:  "nos-managed",
			Clients:       []enrollscript.NetBirdClient{{Version: "0.30.0", KeyPassing: enrollscript.KeyPassingEnv}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	e.svc.vault.SetMinParams(testVaultParams)
	pass := []byte(strings.Repeat("correct-horse-battery-staple-", 4))
	if err := e.svc.vault.Init(pass, testVaultParams, "test"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.vault.Unlock(pass); err != nil {
		t.Fatal(err)
	}
	openPrivilegedSession(t, e, sign)
	return &offerEnv{reconcileEnv: e, sign: sign}
}

func (e *offerEnv) create(t *testing.T, netbird bool) *pb.CreateEnrollOfferResponse {
	t.Helper()
	resp, err := e.svc.CreateEnrollOffer(context.Background(), &pb.CreateEnrollOfferRequest{
		HostId: offerTestHost, CredentialRef: "cred", Sudo: true, Netbird: netbird, SessionBinding: offerSessionA})
	if err != nil {
		t.Fatalf("create offer: %v", err)
	}
	return resp
}

func (e *offerEnv) fetch(id string) (*pb.FetchEnrollScriptResponse, error) {
	return e.svc.FetchEnrollScript(context.Background(), &pb.FetchEnrollScriptRequest{
		OfferId: id, ClientAddr: offerTestClient, PeerAddr: offerTestPeer})
}

func (e *offerEnv) download(id string, session []byte) (*pb.DownloadEnrollScriptResponse, error) {
	return e.svc.DownloadEnrollScript(context.Background(), &pb.DownloadEnrollScriptRequest{
		OfferId: id, SessionBinding: session, ClientAddr: offerTestClient, PeerAddr: offerTestPeer})
}

func (e *offerEnv) show(id string, session []byte) (*pb.ShowEnrollScriptResponse, error) {
	return e.svc.ShowEnrollScript(context.Background(), &pb.ShowEnrollScriptRequest{OfferId: id, SessionBinding: session})
}

func (e *offerEnv) offer(t *testing.T, resp *pb.CreateEnrollOfferResponse) executordb.Offer {
	t.Helper()
	h, ok := parseOfferIDHash(resp.GetOfferIdHash())
	if !ok {
		t.Fatalf("malformed offer ID hash %q", resp.GetOfferIdHash())
	}
	o, err := e.db.Offer(h)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func (e *offerEnv) wantState(t *testing.T, resp *pb.CreateEnrollOfferResponse, want executordb.OfferState) {
	t.Helper()
	if got := e.offer(t, resp).State; got != want {
		t.Fatalf("offer state %s, want %s", got, want)
	}
}

// approveNetBird stands in for EN-12: the NetBird offer permit was
// approved and NetBird's create answer carried offerTestSetupKey.
func (e *offerEnv) approveNetBird(t *testing.T, resp *pb.CreateEnrollOfferResponse) {
	t.Helper()
	h, _ := parseOfferIDHash(resp.GetOfferIdHash())
	if _, err := e.db.MarkSetupKeyPending(h, "nos-managed"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.openNetBirdOffer(h, offerTestKeyID, offerTestSetupKey); err != nil {
		t.Fatal(err)
	}
}

func wantUnavailable(t *testing.T, err error) {
	t.Helper()
	if status.Code(err) != codes.NotFound || status.Convert(err).Message() != "enrollment offer not available" {
		t.Fatalf("got %v, want the uniform refusal", err)
	}
}

func TestCreateEnrollOfferNeedsPrivilegedSession(t *testing.T) {
	e, _ := sessionRPCEnv(t, 30*time.Minute)
	if err := e.svc.SetEnrollOffers(EnrollOfferConfig{Sources: []string{"192.0.2.10"}}); err != nil {
		t.Fatal(err)
	}
	_, err := e.svc.CreateEnrollOffer(context.Background(), &pb.CreateEnrollOfferRequest{
		HostId: offerTestHost, CredentialRef: "cred", SessionBinding: offerSessionA})
	wantCode(t, err, codes.FailedPrecondition)
	if !strings.Contains(err.Error(), "privileged session") {
		t.Fatalf("error %v does not name the privileged session", err)
	}
	if got := e.svc.offers.index(); len(got) != 0 {
		t.Fatalf("refused create left %d offers", len(got))
	}
}

func TestCreateEnrollOfferRefusesMalformedAndUnconfigured(t *testing.T) {
	e := newOfferEnv(t)
	long := bytes.Repeat([]byte("x"), EnrollSessionBindingMaxLen+1)
	for _, c := range []struct {
		name string
		req  *pb.CreateEnrollOfferRequest
		code codes.Code
	}{
		{"host", &pb.CreateEnrollOfferRequest{HostId: "Bad Host", CredentialRef: "cred", SessionBinding: offerSessionA}, codes.InvalidArgument},
		{"root user", &pb.CreateEnrollOfferRequest{HostId: offerTestHost, SshUser: "root", CredentialRef: "cred", SessionBinding: offerSessionA}, codes.InvalidArgument},
		{"user", &pb.CreateEnrollOfferRequest{HostId: offerTestHost, SshUser: "a b", CredentialRef: "cred", SessionBinding: offerSessionA}, codes.InvalidArgument},
		{"credential", &pb.CreateEnrollOfferRequest{HostId: offerTestHost, CredentialRef: "Cred!", SessionBinding: offerSessionA}, codes.InvalidArgument},
		{"credential not loaded", &pb.CreateEnrollOfferRequest{HostId: offerTestHost, CredentialRef: "other", SessionBinding: offerSessionA}, codes.FailedPrecondition},
		{"no session binding", &pb.CreateEnrollOfferRequest{HostId: offerTestHost, CredentialRef: "cred"}, codes.InvalidArgument},
		{"short session binding", &pb.CreateEnrollOfferRequest{HostId: offerTestHost, CredentialRef: "cred", SessionBinding: []byte("short")}, codes.InvalidArgument},
		{"long session binding", &pb.CreateEnrollOfferRequest{HostId: offerTestHost, CredentialRef: "cred", SessionBinding: long}, codes.InvalidArgument},
		{"ephemeral without NetBird", &pb.CreateEnrollOfferRequest{HostId: offerTestHost, CredentialRef: "cred", NetbirdEphemeral: true, SessionBinding: offerSessionA}, codes.InvalidArgument},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := e.svc.CreateEnrollOffer(context.Background(), c.req)
			wantCode(t, err, c.code)
		})
	}
	if got := e.svc.offers.index(); len(got) != 0 {
		t.Fatalf("refused creates left %d offers", len(got))
	}

	t.Run("not configured", func(t *testing.T) {
		e2, sign := sessionRPCEnv(t, 30*time.Minute)
		openPrivilegedSession(t, e2, sign)
		_, err := e2.svc.CreateEnrollOffer(context.Background(), &pb.CreateEnrollOfferRequest{
			HostId: offerTestHost, CredentialRef: "cred", SessionBinding: offerSessionA})
		wantCode(t, err, codes.FailedPrecondition)
	})
	t.Run("NetBird not configured", func(t *testing.T) {
		e2, sign := sessionRPCEnv(t, 30*time.Minute)
		if err := e2.svc.SetEnrollOffers(EnrollOfferConfig{Sources: []string{"192.0.2.10"}}); err != nil {
			t.Fatal(err)
		}
		openPrivilegedSession(t, e2, sign)
		_, err := e2.svc.CreateEnrollOffer(context.Background(), &pb.CreateEnrollOfferRequest{
			HostId: offerTestHost, CredentialRef: "cred", Netbird: true, SessionBinding: offerSessionA})
		wantCode(t, err, codes.FailedPrecondition)
	})
}

func TestSetEnrollOffersRejectsInvalidConfig(t *testing.T) {
	e, _ := sessionRPCEnv(t, 30*time.Minute)
	nb := func(url, group string) *EnrollOfferNetBird {
		return &EnrollOfferNetBird{ManagementURL: url, ManagedGroup: group,
			Clients: []enrollscript.NetBirdClient{{Version: "0.30.0", KeyPassing: enrollscript.KeyPassingEnv}}}
	}
	for name, c := range map[string]EnrollOfferConfig{
		"no source":    {},
		"bad source":   {Sources: []string{"example.org"}},
		"http URL":     {Sources: []string{"192.0.2.10"}, NetBird: nb("http://netbird.example.lan", "nos-managed")},
		"bad group":    {Sources: []string{"192.0.2.10"}, NetBird: nb("https://netbird.example.lan", "nos managed")},
		"no client":    {Sources: []string{"192.0.2.10"}, NetBird: &EnrollOfferNetBird{ManagementURL: "https://netbird.example.lan", ManagedGroup: "g"}},
		"empty source": {Sources: []string{""}},
	} {
		if err := e.svc.SetEnrollOffers(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if e.svc.offers.config() != nil {
		t.Fatal("a refused configuration was installed")
	}
}

func TestCreateEnrollOfferRefusesPinnedHost(t *testing.T) {
	e := newOfferEnv(t)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostKey, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	e.host = offerTestHost
	e.pin(hostKey)
	_, err = e.svc.CreateEnrollOffer(context.Background(), &pb.CreateEnrollOfferRequest{
		HostId: offerTestHost, CredentialRef: "cred", SessionBinding: offerSessionA})
	wantCode(t, err, codes.FailedPrecondition)
}

func TestCreateEnrollOfferWithoutNetBirdIsOpenWithHash(t *testing.T) {
	e := newOfferEnv(t)
	resp := e.create(t, false)
	if len(resp.GetOfferId()) != EnrollOfferIDLen {
		t.Fatalf("offer ID length %d, want %d", len(resp.GetOfferId()), EnrollOfferIDLen)
	}
	if !enrollscript.ValidOfferID(resp.GetOfferId()) {
		t.Fatal("offer ID not accepted by the download command")
	}
	if resp.GetOfferIdHash() != sha256Hex([]byte(resp.GetOfferId())) {
		t.Fatal("offer ID hash is not the SHA-256 of the ID")
	}
	if resp.GetState() != string(executordb.OfferOpen) || resp.GetScriptSha256() == "" || resp.GetNetbirdPermit() != nil {
		t.Fatalf("response %v, want open with hash and no permit", resp)
	}
	o := e.offer(t, resp)
	if hex.EncodeToString(o.ScriptSHA256) != resp.GetScriptSha256() {
		t.Fatal("stored hash differs from the returned one")
	}
	if want, ok := sessionDigest(offerSessionA); !ok || o.SessionHash != want {
		t.Fatal("offer is not bound to the creating session")
	}
	if len(e.logs.find("enroll_offer_created", "")) != 1 {
		t.Fatal("enroll_offer_created not audited")
	}
	for _, r := range e.logs.records {
		for _, v := range r.attrs {
			if strings.Contains(fmt.Sprint(v), resp.GetOfferId()) {
				t.Fatalf("offer ID logged in %v", r)
			}
		}
	}
}

func TestFetchEnrollScriptConsumesExactlyOnce(t *testing.T) {
	e := newOfferEnv(t)
	resp := e.create(t, false)
	got, err := e.fetch(resp.GetOfferId())
	if err != nil {
		t.Fatal(err)
	}
	if sha256Hex(got.GetScript()) != resp.GetScriptSha256() || got.GetScriptSha256() != resp.GetScriptSha256() {
		t.Fatal("fetched script does not match the offer's hash")
	}
	if len(got.GetScript()) == 0 || len(got.GetScript()) > enrollscript.MaxScriptBytes {
		t.Fatalf("script size %d", len(got.GetScript()))
	}
	o := e.offer(t, resp)
	if o.State != executordb.OfferDownloaded || o.ClientAddr != offerTestClient || o.PeerAddr != offerTestPeer {
		t.Fatalf("offer after fetch: state %s client %q peer %q", o.State, o.ClientAddr, o.PeerAddr)
	}
	_, err = e.fetch(resp.GetOfferId())
	wantUnavailable(t, err)
	_, err = e.download(resp.GetOfferId(), offerSessionA)
	wantUnavailable(t, err)
	if n := len(e.logs.find("enroll_script_downloaded", "")); n != 1 {
		t.Fatalf("%d download audits, want 1", n)
	}
}

func TestConcurrentFetchAndDownloadReleaseOnce(t *testing.T) {
	e := newOfferEnv(t)
	resp := e.create(t, false)
	const n = 8
	errs := make(chan error, 2*n)
	var wg sync.WaitGroup
	for range n {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, err := e.fetch(resp.GetOfferId())
			errs <- err
		}()
		go func() {
			defer wg.Done()
			_, err := e.download(resp.GetOfferId(), offerSessionA)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	ok := 0
	for err := range errs {
		if err == nil {
			ok++
		} else {
			wantUnavailable(t, err)
		}
	}
	if ok != 1 {
		t.Fatalf("%d concurrent releases succeeded, want exactly 1", ok)
	}
	e.wantState(t, resp, executordb.OfferDownloaded)
}

func TestDownloadEnrollScriptConsumesExactlyOnce(t *testing.T) {
	e := newOfferEnv(t)
	resp := e.create(t, false)
	got, err := e.download(resp.GetOfferId(), offerSessionA)
	if err != nil {
		t.Fatal(err)
	}
	if sha256Hex(got.GetScript()) != resp.GetScriptSha256() {
		t.Fatal("downloaded script does not match the offer's hash")
	}
	e.wantState(t, resp, executordb.OfferDownloaded)
	_, err = e.download(resp.GetOfferId(), offerSessionA)
	wantUnavailable(t, err)
	_, err = e.fetch(resp.GetOfferId())
	wantUnavailable(t, err)
}

func TestShowAndDownloadOnlyForCreatingSession(t *testing.T) {
	e := newOfferEnv(t)
	resp := e.create(t, false)
	for name, s := range map[string][]byte{"other session": offerSessionB, "none": nil, "short": offerSessionA[:8]} {
		_, err := e.show(resp.GetOfferId(), s)
		if err == nil {
			t.Fatalf("%s: show allowed", name)
		}
		wantUnavailable(t, err)
		_, err = e.download(resp.GetOfferId(), s)
		wantUnavailable(t, err)
	}
	// Nothing was consumed: the creating session still downloads.
	e.wantState(t, resp, executordb.OfferOpen)
	if _, err := e.download(resp.GetOfferId(), offerSessionA); err != nil {
		t.Fatal(err)
	}
}

func TestShowEnrollScriptDoesNotConsume(t *testing.T) {
	e := newOfferEnv(t)
	resp := e.create(t, false)
	var first []byte
	for i := range 3 {
		got, err := e.show(resp.GetOfferId(), offerSessionA)
		if err != nil {
			t.Fatalf("show %d: %v", i, err)
		}
		if i == 0 {
			first = got.GetScript()
		} else if !bytes.Equal(first, got.GetScript()) {
			t.Fatal("show is not repeatable")
		}
		if got.GetScriptSha256() != resp.GetScriptSha256() {
			t.Fatal("show does not name the download hash")
		}
		e.wantState(t, resp, executordb.OfferOpen)
	}
	dl, err := e.download(resp.GetOfferId(), offerSessionA)
	if err != nil {
		t.Fatal(err)
	}
	// Without NetBird the placeholder variant is the downloaded script.
	if !bytes.Equal(first, dl.GetScript()) {
		t.Fatal("show differs from the download of an offer without NetBird")
	}
	// Show still works after the download, the offer is not final.
	if _, err := e.show(resp.GetOfferId(), offerSessionA); err != nil {
		t.Fatal(err)
	}
	e.wantState(t, resp, executordb.OfferDownloaded)
}

func TestNetBirdOfferHasNoKeyOrScriptBeforePermit(t *testing.T) {
	e := newOfferEnv(t)
	resp := e.create(t, true)
	if resp.GetState() != string(executordb.OfferAwaitingApproval) || resp.GetScriptSha256() != "" {
		t.Fatalf("NetBird offer %v, want awaiting_approval without hash", resp)
	}
	p := resp.GetNetbirdPermit()
	if p == nil || p.GetDigest() == "" || len(p.GetChallenge()) == 0 || !bytes.Contains(p.GetCanonical(), []byte(resp.GetOfferIdHash())) {
		t.Fatalf("NetBird offer permit %v not proposed for this offer", p)
	}
	if n := len(e.svc.auth.PendingNetBirdOffers()); n != 1 {
		t.Fatalf("%d pending NetBird offer permits, want 1", n)
	}
	o := e.offer(t, resp)
	if o.SetupKey.Status != executordb.SetupKeyNone || o.SetupKey.VaultRef != "" || o.ScriptSHA256 != nil {
		t.Fatalf("offer before approval: record %s vault %q hash %x", o.SetupKey.Status, o.SetupKey.VaultRef, o.ScriptSHA256)
	}
	if secrets, err := e.svc.vault.List(); err != nil || len(secrets) != 0 {
		t.Fatalf("vault holds %d secrets before approval (%v)", len(secrets), err)
	}
	_, err := e.fetch(resp.GetOfferId())
	wantUnavailable(t, err)
	e.wantState(t, resp, executordb.OfferAwaitingApproval)

	// "Show script" renders the placeholder variant without a hash.
	got, err := e.show(resp.GetOfferId(), offerSessionA)
	if err != nil {
		t.Fatal(err)
	}
	if got.GetScriptSha256() != "" || !bytes.Contains(got.GetScript(), []byte(enrollscript.SetupKeyPlaceholder)) {
		t.Fatal("show before approval: want placeholder render without hash")
	}
	e.wantState(t, resp, executordb.OfferAwaitingApproval)
}

func TestNetBirdOfferShowWithholdsSetupKey(t *testing.T) {
	e := newOfferEnv(t)
	resp := e.create(t, true)
	e.approveNetBird(t, resp)
	o := e.offer(t, resp)
	if o.State != executordb.OfferOpen || o.SetupKey.VaultRef == "" {
		t.Fatalf("approved offer: state %s vault %q", o.State, o.SetupKey.VaultRef)
	}

	var shown []byte
	for i := range 3 {
		got, err := e.show(resp.GetOfferId(), offerSessionA)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(got.GetScript(), []byte(offerTestSetupKey)) {
			t.Fatal("show returned the setup key")
		}
		if !bytes.Contains(got.GetScript(), []byte(enrollscript.SetupKeyPlaceholder)) {
			t.Fatal("show lacks the placeholder")
		}
		if got.GetScriptSha256() != hex.EncodeToString(o.ScriptSHA256) {
			t.Fatal("show does not name the download hash")
		}
		if i == 0 {
			shown = got.GetScript()
		}
		e.wantState(t, resp, executordb.OfferOpen)
	}
	// Show never reads the vault: it works with the vault locked.
	e.svc.vault.Lock()
	if _, err := e.show(resp.GetOfferId(), offerSessionA); err != nil {
		t.Fatalf("show with locked vault: %v", err)
	}
	// The fetch needs the setup key: refused without consuming.
	_, err := e.fetch(resp.GetOfferId())
	wantUnavailable(t, err)
	e.wantState(t, resp, executordb.OfferOpen)
	pass := []byte(strings.Repeat("correct-horse-battery-staple-", 4))
	if err := e.svc.vault.Unlock(pass); err != nil {
		t.Fatal(err)
	}

	// The browser download is refused for NetBird offers, without
	// consuming the offer.
	_, err = e.download(resp.GetOfferId(), offerSessionA)
	wantCode(t, err, codes.FailedPrecondition)
	e.wantState(t, resp, executordb.OfferOpen)

	full, err := e.fetch(resp.GetOfferId())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(full.GetScript(), []byte("nb_key='"+offerTestSetupKey+"'")) {
		t.Fatal("fetched script does not carry the setup key")
	}
	if !bytes.Contains(shown, []byte("nb_key='"+enrollscript.SetupKeyPlaceholder+"'")) {
		t.Fatal("show does not carry the placeholder in the setup-key line")
	}
	if sha256Hex(full.GetScript()) != hex.EncodeToString(o.ScriptSHA256) {
		t.Fatal("fetched script does not match the stored hash")
	}
	// Apart from the setup-key line the bytes equal the download.
	if !differInOneLine(shown, full.GetScript()) ||
		!bytes.Equal(bytes.Replace(shown, []byte(enrollscript.SetupKeyPlaceholder), []byte(offerTestSetupKey), 1), full.GetScript()) {
		t.Fatal("show differs from the download in more than the setup-key value")
	}
	_, err = e.fetch(resp.GetOfferId())
	wantUnavailable(t, err)
	_, err = e.download(resp.GetOfferId(), offerSessionA)
	wantCode(t, err, codes.FailedPrecondition)
	for _, r := range e.logs.records {
		for _, v := range r.attrs {
			if strings.Contains(fmt.Sprint(v), offerTestSetupKey) {
				t.Fatalf("setup key logged in %v", r)
			}
		}
	}
}

func TestFetchHashMismatchFailsOffer(t *testing.T) {
	for _, browser := range []bool{false, true} {
		t.Run(fmt.Sprint("browser=", browser), func(t *testing.T) {
			e := newOfferEnv(t)
			resp := e.create(t, false)
			h, _ := parseOfferIDHash(resp.GetOfferIdHash())
			// A render input that changed after creation yields other bytes.
			e.svc.offers.get(h).opts.Sudo = false
			var err error
			if browser {
				_, err = e.download(resp.GetOfferId(), offerSessionA)
			} else {
				_, err = e.fetch(resp.GetOfferId())
			}
			wantUnavailable(t, err)
			e.wantState(t, resp, executordb.OfferFailed)
			if len(e.logs.find("enroll_script_hash_mismatch", "")) != 1 {
				t.Fatal("hash mismatch not audited")
			}
			if o := e.offer(t, resp); o.Salt != nil {
				t.Fatal("failed offer kept its salt")
			}
			_, err = e.fetch(resp.GetOfferId())
			wantUnavailable(t, err)
		})
	}
}

func TestShowHashMismatchRefusesOnlyTheRequest(t *testing.T) {
	e := newOfferEnv(t)
	resp := e.create(t, false)
	h, _ := parseOfferIDHash(resp.GetOfferIdHash())
	r := e.svc.offers.get(h)
	r.opts.Sudo = false
	for range 3 {
		_, err := e.show(resp.GetOfferId(), offerSessionA)
		wantCode(t, err, codes.FailedPrecondition)
		e.wantState(t, resp, executordb.OfferOpen)
	}
	if n := len(e.logs.find("enroll_script_hash_mismatch", "")); n != 1 {
		t.Fatalf("%d show mismatch audits, want exactly 1", n)
	}
	if e.svc.offers.showMismatches(h) != 3 {
		t.Fatalf("show mismatch counter %d, want 3", e.svc.offers.showMismatches(h))
	}
	r.opts.Sudo = true
	if _, err := e.fetch(resp.GetOfferId()); err != nil {
		t.Fatalf("download after show mismatches: %v", err)
	}
}

func TestFetchWithoutRenderInputsFailsOffer(t *testing.T) {
	e := newOfferEnv(t)
	resp := e.create(t, false)
	h, _ := parseOfferIDHash(resp.GetOfferIdHash())
	// A restart loses the process-local render inputs.
	e.svc.offers.remove(h)
	_, err := e.show(resp.GetOfferId(), offerSessionA)
	wantCode(t, err, codes.FailedPrecondition)
	e.wantState(t, resp, executordb.OfferOpen)
	_, err = e.fetch(resp.GetOfferId())
	wantUnavailable(t, err)
	e.wantState(t, resp, executordb.OfferFailed)
	if len(e.logs.find("enroll_offer_render_inputs_lost", "")) != 1 {
		t.Fatal("lost render inputs not audited")
	}
}

func TestFetchRefusesMalformedRequestsWithoutConsuming(t *testing.T) {
	e := newOfferEnv(t)
	resp := e.create(t, false)
	id := resp.GetOfferId()
	for name, req := range map[string]*pb.FetchEnrollScriptRequest{
		"empty":        {ClientAddr: offerTestClient, PeerAddr: offerTestPeer},
		"short":        {OfferId: id[:31], ClientAddr: offerTestClient, PeerAddr: offerTestPeer},
		"long":         {OfferId: id + "a", ClientAddr: offerTestClient, PeerAddr: offerTestPeer},
		"upper":        {OfferId: strings.ToUpper(id), ClientAddr: offerTestClient, PeerAddr: offerTestPeer},
		"unknown":      {OfferId: strings.Repeat("a", EnrollOfferIDLen), ClientAddr: offerTestClient, PeerAddr: offerTestPeer},
		"no client":    {OfferId: id, PeerAddr: offerTestPeer},
		"bad client":   {OfferId: id, ClientAddr: "client.example", PeerAddr: offerTestPeer},
		"zoned peer":   {OfferId: id, ClientAddr: offerTestClient, PeerAddr: "fe80::1%eth0"},
		"long address": {OfferId: id, ClientAddr: strings.Repeat("1", 80), PeerAddr: offerTestPeer},
	} {
		_, err := e.svc.FetchEnrollScript(context.Background(), req)
		if err == nil {
			t.Fatalf("%s: accepted", name)
		}
		wantUnavailable(t, err)
	}
	e.wantState(t, resp, executordb.OfferOpen)
	if _, err := e.fetch(id); err != nil {
		t.Fatal(err)
	}
}

func TestRevokeEnrollOffer(t *testing.T) {
	e := newOfferEnv(t)
	open := e.create(t, false)
	waiting := e.create(t, true)

	// The server revokes from any session: the request carries none.
	if _, err := callAs(t, trustTestServerUID, pb.ExecutorService_RevokeEnrollOffer_FullMethodName,
		&pb.RevokeEnrollOfferRequest{OfferIdHash: open.GetOfferIdHash()}, e.svc.RevokeEnrollOffer); err != nil {
		t.Fatal(err)
	}
	e.wantState(t, open, executordb.OfferRevoked)
	// The admin revokes too, also an offer awaiting approval.
	if _, err := callAs(t, trustTestAdminUID, pb.ExecutorService_RevokeEnrollOffer_FullMethodName,
		&pb.RevokeEnrollOfferRequest{OfferIdHash: waiting.GetOfferIdHash()}, e.svc.RevokeEnrollOffer); err != nil {
		t.Fatal(err)
	}
	e.wantState(t, waiting, executordb.OfferRevoked)
	if n := len(e.logs.find("enroll_offer_revoked", "")); n != 2 {
		t.Fatalf("%d revoke audits, want 2", n)
	}

	_, err := e.svc.RevokeEnrollOffer(context.Background(), &pb.RevokeEnrollOfferRequest{OfferIdHash: open.GetOfferIdHash()})
	wantCode(t, err, codes.FailedPrecondition)
	_, err = e.svc.RevokeEnrollOffer(context.Background(), &pb.RevokeEnrollOfferRequest{OfferIdHash: strings.ToUpper(open.GetOfferIdHash())})
	wantCode(t, err, codes.InvalidArgument)
	_, err = e.svc.RevokeEnrollOffer(context.Background(), &pb.RevokeEnrollOfferRequest{OfferIdHash: strings.Repeat("0", 64)})
	wantCode(t, err, codes.NotFound)

	_, err = e.fetch(open.GetOfferId())
	wantUnavailable(t, err)
	_, err = e.show(open.GetOfferId(), offerSessionA)
	wantUnavailable(t, err)

	// A downloaded offer can still be revoked.
	dl := e.create(t, false)
	if _, err := e.fetch(dl.GetOfferId()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.RevokeEnrollOffer(context.Background(), &pb.RevokeEnrollOfferRequest{OfferIdHash: dl.GetOfferIdHash()}); err != nil {
		t.Fatal(err)
	}
	e.wantState(t, dl, executordb.OfferRevoked)
}

func TestListEnrollOffers(t *testing.T) {
	e := newOfferEnv(t)
	a := e.create(t, false)
	b := e.create(t, true)
	if _, err := e.fetch(a.GetOfferId()); err != nil {
		t.Fatal(err)
	}
	_, err := callAs(t, trustTestServerUID, pb.ExecutorService_ListEnrollOffers_FullMethodName,
		&pb.ListEnrollOffersRequest{}, e.svc.ListEnrollOffers)
	wantCode(t, err, codes.PermissionDenied)
	got, err := callAs(t, trustTestAdminUID, pb.ExecutorService_ListEnrollOffers_FullMethodName,
		&pb.ListEnrollOffersRequest{}, e.svc.ListEnrollOffers)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.GetOffers()) != 2 {
		t.Fatalf("%d offers listed, want 2", len(got.GetOffers()))
	}
	la, lb := got.GetOffers()[0], got.GetOffers()[1]
	if la.GetOfferIdHash() != a.GetOfferIdHash() || la.GetState() != string(executordb.OfferDownloaded) ||
		la.GetClientAddr() != offerTestClient || la.GetDownloadedUnix() == 0 || la.GetScriptSha256() != a.GetScriptSha256() {
		t.Fatalf("listed offer a: %v", la)
	}
	if lb.GetOfferIdHash() != b.GetOfferIdHash() || !lb.GetNetbird() || lb.GetState() != string(executordb.OfferAwaitingApproval) ||
		lb.GetScriptSha256() != "" || lb.GetSetupKeyRecord() != string(executordb.SetupKeyNone) {
		t.Fatalf("listed offer b: %v", lb)
	}
	text := got.String()
	for _, id := range []string{a.GetOfferId(), b.GetOfferId()} {
		if strings.Contains(text, id) {
			t.Fatal("list contains an offer ID")
		}
	}
}

func TestCreateEnrollOfferLimits(t *testing.T) {
	t.Run("live offers", func(t *testing.T) {
		e := newOfferEnv(t)
		for range executordb.OfferMaxLive {
			e.create(t, false)
		}
		_, err := e.svc.CreateEnrollOffer(context.Background(), &pb.CreateEnrollOfferRequest{
			HostId: offerTestHost, CredentialRef: "cred", SessionBinding: offerSessionA})
		wantCode(t, err, codes.ResourceExhausted)
		if n := len(e.svc.offers.index()); n != executordb.OfferMaxLive {
			t.Fatalf("index holds %d offers, want %d", n, executordb.OfferMaxLive)
		}
	})
	t.Run("live NetBird offers", func(t *testing.T) {
		e := newOfferEnv(t)
		for range executordb.OfferMaxLiveNetBird {
			e.create(t, true)
		}
		_, err := e.svc.CreateEnrollOffer(context.Background(), &pb.CreateEnrollOfferRequest{
			HostId: offerTestHost, CredentialRef: "cred", Netbird: true, SessionBinding: offerSessionA})
		wantCode(t, err, codes.ResourceExhausted)
	})
	t.Run("script size", func(t *testing.T) {
		e, sign := sessionRPCEnv(t, 30*time.Minute)
		var many []string
		for i := range 4000 {
			many = append(many, fmt.Sprintf("2001:db8:%x::%x", i, i))
		}
		if err := e.svc.SetEnrollOffers(EnrollOfferConfig{Sources: many}); err != nil {
			t.Fatal(err)
		}
		openPrivilegedSession(t, e, sign)
		_, err := e.svc.CreateEnrollOffer(context.Background(), &pb.CreateEnrollOfferRequest{
			HostId: offerTestHost, CredentialRef: "cred", SessionBinding: offerSessionA})
		wantCode(t, err, codes.InvalidArgument)
		if !strings.Contains(err.Error(), "too large") {
			t.Fatalf("error %v does not name the size limit", err)
		}
	})
}

func TestEnrollOfferIndexIsBounded(t *testing.T) {
	var st enrollOfferState
	for i := range EnrollOfferIndexMax + 10 {
		h := sha256.Sum256([]byte(fmt.Sprint(i)))
		st.put(h, &offerRender{})
		st.final(h)
	}
	if n := len(st.index()); n != EnrollOfferIndexMax {
		t.Fatalf("index holds %d entries, want %d", n, EnrollOfferIndexMax)
	}
	if first := st.index()[0]; first != sha256.Sum256([]byte("10")) {
		t.Fatal("index did not drop the oldest final entries first")
	}
}
