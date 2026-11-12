// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"

	"github.com/nebula-operation-station/nebula-operation-station/internal/enrollscript"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pairing"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/clientaddr"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/enroll"
)

// EN-14 part 1: security acceptance of one-step enrollment without NetBird
// (ADR 0013 D1–D4, D7; docs/implementation/one-step-enrollment.md, rules
// E1–E4). Every attack goes through the real executor RPCs over the Unix
// socket and through the real download route (internal/web/enroll with the
// real client-address resolver and limiter) on a loopback test server; the
// hosts are in-process SSH servers on 127.0.0.1. The NetBird cases
// (setup key, peer delete, rogue peer) follow with EN-11/EN-12.

// en14Origin is the public origin the UI command names.
const en14Origin = "https://nebula.example.org"

// en14SaltRE finds the offer salt in a downloaded script: the host
// computes its pairing code from exactly this salt and its host key.
var en14SaltRE = regexp.MustCompile(`(?m)^pair_salt='([A-Za-z0-9+/=]+)'$`)

// en14 is one operator's one-step enrollment against a harness executor.
type en14 struct {
	t         *testing.T
	h         *harness
	session   []byte // the operator's web-session binding
	routeLogs *syncBuffer
	srv       *httptest.Server // download route, no trusted proxy
	secrets   []string         // values that must appear in no log line
}

func newEN14(t *testing.T) *en14 {
	t.Helper()
	h := newHarness(t, harnessOptions{})
	if err := h.svc.SetEnrollOffers(executor.EnrollOfferConfig{Sources: []string{"127.0.0.1"}}); err != nil {
		t.Fatal(err)
	}
	h.unlock()
	h.openSession() // the dialog requires a privileged session
	e := &en14{t: t, h: h, session: []byte("en14-operator-web-session-binding"), routeLogs: &syncBuffer{}}
	e.secrets = append(e.secrets, passphrase, string(e.session))
	e.srv = e.route(nil, time.Now)
	return e
}

// route mounts the real download handler on a loopback test server.
func (e *en14) route(trusted []string, now func() time.Time) *httptest.Server {
	e.t.Helper()
	log := slog.New(slog.NewJSONHandler(e.routeLogs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	res, err := clientaddr.New(clientaddr.Config{TrustedProxies: trusted}, log)
	if err != nil {
		e.t.Fatal(err)
	}
	hd, err := enroll.New(enroll.Options{Executor: e.h.client, ClientAddr: res, Limiter: enroll.NewLimiter(0, now), Log: log})
	if err != nil {
		e.t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle(enroll.PathPrefix, hd)
	srv := httptest.NewServer(mux) // 127.0.0.1 only
	e.t.Cleanup(srv.Close)
	return srv
}

// offer creates a one-step offer for host from the operator's session.
func (e *en14) offer(host string) *pb.CreateEnrollOfferResponse {
	e.t.Helper()
	o, err := e.h.client.CreateEnrollOffer(e.h.ctx(), &pb.CreateEnrollOfferRequest{HostId: host, SessionBinding: e.session})
	if err != nil {
		e.t.Fatalf("create offer: %v", err)
	}
	if len(o.GetOfferId()) != enroll.OfferIDLen || len(o.GetScriptSha256()) != 64 {
		e.t.Fatalf("offer %v", o)
	}
	e.secrets = append(e.secrets, o.GetOfferId())
	return o
}

// get requests the download route for id, with an optional
// X-Forwarded-For header.
func (e *en14) get(srv *httptest.Server, id, xff string) (*http.Response, []byte) {
	e.t.Helper()
	req, err := http.NewRequestWithContext(e.h.ctx(), http.MethodGet, srv.URL+enroll.PathPrefix+id, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		e.t.Fatal(err)
	}
	return resp, b
}

// download fetches the offer's script through the route as the new host
// does, checks it against the hash the UI command carries and returns the
// script and the salt in it.
func (e *en14) download(o *pb.CreateEnrollOfferResponse) ([]byte, []byte) {
	e.t.Helper()
	resp, b := e.get(e.srv, o.GetOfferId(), "")
	if resp.StatusCode != http.StatusOK {
		e.t.Fatalf("download: %d %q", resp.StatusCode, b)
	}
	if hexSum(b) != o.GetScriptSha256() {
		e.t.Fatal("downloaded script does not match the offer's hash")
	}
	return b, e.salt(b)
}

func (e *en14) salt(script []byte) []byte {
	e.t.Helper()
	m := en14SaltRE.FindSubmatch(script)
	if m == nil {
		e.t.Fatal("no salt in the script")
	}
	salt, err := base64.StdEncoding.DecodeString(string(m[1]))
	if err != nil || len(salt) != pairing.SaltSize {
		e.t.Fatalf("salt: %v", err)
	}
	e.secrets = append(e.secrets, string(m[1]), hex.EncodeToString(salt))
	return salt
}

// code is the pairing code a host with key k prints for salt.
func (e *en14) code(salt []byte, k ssh.PublicKey) string {
	e.t.Helper()
	c, err := pairing.Compute(salt, k.Marshal())
	if err != nil {
		e.t.Fatal(err)
	}
	e.secrets = append(e.secrets, c.String(), strings.ReplaceAll(c.String(), "-", ""))
	return c.String()
}

func (e *en14) submit(o *pb.CreateEnrollOfferResponse, endpoint, code string) *pb.SubmitPairingCodeResponse {
	e.t.Helper()
	r, err := e.h.client.SubmitPairingCode(e.h.ctx(), &pb.SubmitPairingCodeRequest{
		OfferIdHash: o.GetOfferIdHash(), SessionBinding: e.session, Code: code, Endpoint: endpoint,
	})
	if err != nil {
		e.t.Fatalf("submit pairing code: %v", err)
	}
	return r
}

// The operator's HIGH approval of a paired permit has no RPC on main:
// SubmitAssertion answers permit_not_found for a paired digest and
// permit.SubmitPairedAssertion is not called by any handler (reported in
// en14a; the approved-path cases wait for that fix). These tests therefore
// check every refusal up to and including "no pin without approval".

func (e *en14) commit(o *pb.CreateEnrollOfferResponse, digest string) (*pb.CommitPairedEnrollResponse, error) {
	return e.h.client.CommitPairedEnroll(e.h.ctx(), &pb.CommitPairedEnrollRequest{
		OfferIdHash: o.GetOfferIdHash(), SessionBinding: e.session, PermitDigest: digest,
	})
}

// pinned returns the pin of host, if any.
func (e *en14) pinned(host string) (*pb.HostKeyPin, bool) {
	e.t.Helper()
	l, err := e.h.client.ListHostKeys(e.h.ctx(), &pb.ListHostKeysRequest{})
	if err != nil {
		e.t.Fatal(err)
	}
	for _, p := range l.GetHosts() {
		if p.GetHostId() == host {
			return p, true
		}
	}
	return nil, false
}

func (e *en14) requireNoPin(host string) {
	e.t.Helper()
	if p, ok := e.pinned(host); ok {
		e.t.Fatalf("host %s is pinned: %v", host, p)
	}
}

// info is the admin view of an offer (nebula host offers).
func (e *en14) info(o *pb.CreateEnrollOfferResponse) *pb.EnrollOfferInfo {
	e.t.Helper()
	l, err := e.h.client.ListEnrollOffers(e.h.ctx(), &pb.ListEnrollOffersRequest{})
	if err != nil {
		e.t.Fatal(err)
	}
	for _, i := range l.GetOffers() {
		if i.GetOfferIdHash() == o.GetOfferIdHash() {
			return i
		}
	}
	e.t.Fatalf("offer %s not listed", o.GetOfferIdHash())
	return nil
}

// matched runs the legitimate flow up to the proposal: download and the
// code the real host prints. It returns the offer and the proposal.
func (e *en14) matched(host string, real ssh.Signer, endpoint string) (*pb.CreateEnrollOfferResponse, *pb.SubmitPairingCodeResponse) {
	e.t.Helper()
	o := e.offer(host)
	_, salt := e.download(o)
	r := e.submit(o, endpoint, e.code(salt, real.PublicKey()))
	if r.GetOutcome() != pb.PairingOutcome_PAIRING_OUTCOME_MATCHED || r.GetPermit() == nil ||
		r.GetFingerprint() != ssh.FingerprintSHA256(real.PublicKey()) {
		e.t.Fatalf("legitimate submission: %v", r)
	}
	return o, r
}

// requireCommitRefused asserts that committing a proposal that was not
// approved with the security key pins nothing.
func (e *en14) requireCommitRefused(o *pb.CreateEnrollOfferResponse, digest, host string) {
	e.t.Helper()
	if c, err := e.commit(o, digest); err == nil {
		e.t.Fatalf("commit without approval accepted: %v", c)
	}
	e.requireNoPin(host)
}

// requireNoSecretsInLogs scans every executor and route log line for the
// offer IDs, salts, pairing codes, session binding and passphrase (E10).
func (e *en14) requireNoSecretsInLogs() {
	e.t.Helper()
	all := e.h.logs.String() + e.routeLogs.String()
	for _, s := range e.secrets {
		if s != "" && strings.Contains(all, s) {
			e.t.Errorf("a secret (%d bytes) appears in the logs", len(s))
		}
	}
}

func (e *en14) requireNoAudit(kind string) {
	e.t.Helper()
	if strings.Contains(e.h.logs.String(), `"kind":"`+kind+`"`) {
		e.t.Fatalf("unexpected %s audit record; log:\n%s", kind, e.h.logs.String())
	}
}

func ecdsaSigner(t *testing.T) ssh.Signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A machine in the path presents another key than the host that printed
// the code: nothing is pinned, the offer fails, the operator is notified
// and the mismatch is audited with the presented fingerprint. A code
// computed without this offer's salt, also for the attacker's own key
// prepared before the offer existed, never matches.
func TestEN14_MachineInThePathWithAnotherKeyGetsNoPin(t *testing.T) {
	e := newEN14(t)
	real := hostSigner(t)
	realSSHD := newSSHD(t, real, e.h.userKey)

	t.Run("code of the real host, key of the machine in the path", func(t *testing.T) {
		mitm := hostSigner(t)
		mitmSSHD := newSSHD(t, mitm, nil)
		o := e.offer("en14-mitm")
		_, salt := e.download(o)
		r := e.submit(o, mitmSSHD.endpoint(), e.code(salt, real.PublicKey()))
		if r.GetOutcome() != pb.PairingOutcome_PAIRING_OUTCOME_MISMATCH || !r.GetNotify() || r.GetPermit() != nil ||
			r.GetState() != "failed" || r.GetFingerprint() != ssh.FingerprintSHA256(mitm.PublicKey()) {
			t.Fatalf("submission against the machine in the path: %v", r)
		}
		e.requireNoPin("en14-mitm")
		if i := e.info(o); i.GetState() != "failed" {
			t.Fatalf("offer after mismatch: %v", i)
		}
		e.h.requireAudit(`"kind":"enroll_code_mismatch"`, `"host":"en14-mitm"`, ssh.FingerprintSHA256(mitm.PublicKey()))
		// One mismatch ends the offer: not even the real host with the
		// right code can continue it.
		_, err := e.h.client.SubmitPairingCode(e.h.ctx(), &pb.SubmitPairingCodeRequest{
			OfferIdHash: o.GetOfferIdHash(), SessionBinding: e.session,
			Code: e.code(salt, real.PublicKey()), Endpoint: realSSHD.endpoint(),
		})
		wantCode(t, err, codes.FailedPrecondition, "")
		e.requireNoPin("en14-mitm")
		if mitmSSHD.auths.Load() != 0 {
			t.Fatal("the probe offered a credential to the machine in the path")
		}
	})

	t.Run("precomputed code without the offer salt", func(t *testing.T) {
		// The attacker prepared its key and the code over it before the
		// offer existed: unsalted (all-zero salt) and with another offer's
		// salt. Neither matches, although the key is the one presented.
		mitm := hostSigner(t)
		unsalted := e.code(make([]byte, pairing.SaltSize), mitm.PublicKey())
		earlier := e.offer("en14-earlier")
		_, oldSalt := e.download(earlier)
		fromOther := e.code(oldSalt, mitm.PublicKey())
		mitmSSHD := newSSHD(t, mitm, nil)
		for name, code := range map[string]string{"unsalted": unsalted, "salt of another offer": fromOther} {
			o := e.offer("en14-precomputed")
			_, salt := e.download(o)
			if code == e.code(salt, mitm.PublicKey()) {
				t.Fatalf("%s: the precomputed code equals the salted one", name)
			}
			r := e.submit(o, mitmSSHD.endpoint(), code)
			if r.GetOutcome() != pb.PairingOutcome_PAIRING_OUTCOME_MISMATCH || r.GetPermit() != nil || r.GetState() != "failed" {
				t.Fatalf("%s: %v", name, r)
			}
			e.requireNoPin("en14-precomputed")
		}
	})

	// Control: the real host with the code it prints matches a fresh
	// offer; even that pins nothing before the HIGH approval.
	o, r := e.matched("en14-real", real, realSSHD.endpoint())
	e.requireCommitRefused(o, r.GetPermit().GetDigest(), "en14-real")
	e.requireNoSecretsInLogs()
}

// An offer ID that leaked after the download is worth nothing: every later
// request gets the same 404 as an unknown ID, and the executor releases
// nothing. A script altered on the way fails the hash check of the UI
// command, which then runs nothing.
func TestEN14_LeakedOfferIDAndTamperedScript(t *testing.T) {
	e := newEN14(t)
	o := e.offer("en14-leak")
	script, _ := e.download(o)

	unknown, unknownBody := e.get(e.srv, strings.Repeat("a", enroll.OfferIDLen), "")
	for _, xff := range []string{"", "192.0.2.10"} {
		resp, body := e.get(e.srv, o.GetOfferId(), xff)
		if resp.StatusCode != http.StatusNotFound || unknown.StatusCode != http.StatusNotFound || string(body) != string(unknownBody) {
			t.Fatalf("leaked ID: %d %q, unknown ID: %d %q", resp.StatusCode, body, unknown.StatusCode, unknownBody)
		}
		for _, k := range []string{"Content-Type", "Content-Disposition", "Cache-Control", "X-Content-Type-Options",
			"Content-Security-Policy", "X-Accel-Buffering", "Content-Length"} {
			if resp.Header.Get(k) != unknown.Header.Get(k) {
				t.Fatalf("header %s differs: %q vs %q", k, resp.Header.Get(k), unknown.Header.Get(k))
			}
		}
	}
	// The executor itself refuses a second release, also to the server.
	_, err := e.h.client.FetchEnrollScript(e.h.ctx(), &pb.FetchEnrollScriptRequest{OfferId: o.GetOfferId(), ClientAddr: "127.0.0.1", PeerAddr: "127.0.0.1"})
	wantCode(t, err, codes.NotFound, "")
	_, err = e.h.client.DownloadEnrollScript(e.h.ctx(), &pb.DownloadEnrollScriptRequest{OfferId: o.GetOfferId(), SessionBinding: e.session, ClientAddr: "127.0.0.1", PeerAddr: "127.0.0.1"})
	wantCode(t, err, codes.NotFound, "")
	if n := strings.Count(e.h.logs.String(), `"kind":"enroll_script_downloaded"`); n != 1 {
		t.Fatalf("%d downloads audited, want 1", n)
	}

	// The UI command, run on the host with a download client that delivers
	// an altered script: the hash check fails and nothing runs. The same
	// command with the original bytes reaches the run step (control).
	if _, err := exec.LookPath("sha256sum"); err != nil {
		t.Fatalf("sha256sum is required: %v", err)
	}
	cmd, err := enrollscript.RenderCommand(enrollscript.CommandOptions{Origin: en14Origin, OfferID: o.GetOfferId(),
		ScriptSHA256: o.GetScriptSha256(), Downloader: enrollscript.DownloaderCurl})
	if err != nil {
		t.Fatal(err)
	}
	tampered := []byte(strings.Replace(string(script), "\n", "\necho tampered > \"$EN14_MARK\"\n", 1))
	if hexSum(tampered) == o.GetScriptSha256() {
		t.Fatal("tampering did not change the hash")
	}
	runCommand := func(served []byte) (ran bool, err error) {
		dir := t.TempDir()
		bin := filepath.Join(dir, "bin")
		if err := os.Mkdir(bin, 0o700); err != nil {
			t.Fatal(err)
		}
		src := filepath.Join(dir, "served.sh")
		if err := os.WriteFile(src, served, 0o600); err != nil {
			t.Fatal(err)
		}
		mark, sudoMark := filepath.Join(dir, "tampered-ran"), filepath.Join(dir, "sudo-ran")
		stubs := map[string]string{
			// The download client reads its config from stdin and writes
			// the served bytes to the output file in the working directory.
			"curl": "#!/bin/sh\ncat >/dev/null\ncp \"$EN14_SRC\" nos-enroll.sh\n",
			// sudo only records that the script would have run.
			"sudo": "#!/bin/sh\necho ran > \"$EN14_SUDO\"\n",
		}
		for n, body := range stubs {
			if err := os.WriteFile(filepath.Join(bin, n), []byte(body), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		c := exec.Command("sh", "-c", cmd)
		c.Dir = dir
		c.Env = []string{"PATH=" + bin + ":" + os.Getenv("PATH"), "HOME=" + dir, "TMPDIR=" + dir,
			"EN14_SRC=" + src, "EN14_MARK=" + mark, "EN14_SUDO=" + sudoMark}
		out, err := c.CombinedOutput()
		if _, serr := os.Stat(mark); serr == nil {
			t.Fatalf("the altered script ran; output %q", out)
		}
		_, serr := os.Stat(sudoMark)
		return serr == nil, err
	}
	if ran, err := runCommand(tampered); err == nil || ran {
		t.Fatalf("altered script: exit %v, run step reached %v", err, ran)
	}
	if ran, err := runCommand(script); err != nil || !ran {
		t.Fatalf("original script: exit %v, run step reached %v", err, ran)
	}
	e.requireNoSecretsInLogs()
}

// A compromised server holds the operator's web session, an open
// privileged session and the server role. Without the code the host
// printed it gets a mismatch; with a code it computed itself for its own
// key it gets at most a proposal, which pins nothing without the
// operator's HIGH approval with the security key; another offer's permit
// does not fit.
func TestEN14_CompromisedServerCannotPinWithoutCodeAndApproval(t *testing.T) {
	e := newEN14(t)
	real := hostSigner(t)
	realSSHD := newSSHD(t, real, e.h.userKey)
	if st, err := e.h.client.GetSessionState(e.h.ctx(), &pb.GetSessionStateRequest{}); err != nil || !st.GetActive() {
		t.Fatalf("privileged session not open: %v %v", st, err)
	}

	t.Run("guessed code", func(t *testing.T) {
		o := e.offer("en14-guess")
		_, salt := e.download(o)
		// A well-formed code for some other key: the server does not know
		// the real host's code.
		r := e.submit(o, realSSHD.endpoint(), e.code(salt, hostSigner(t).PublicKey()))
		if r.GetOutcome() != pb.PairingOutcome_PAIRING_OUTCOME_MISMATCH || r.GetPermit() != nil || !r.GetNotify() {
			t.Fatalf("guessed code: %v", r)
		}
		e.requireNoPin("en14-guess")
	})

	t.Run("commit without any code", func(t *testing.T) {
		o := e.offer("en14-nocode")
		e.download(o)
		forged := hex.EncodeToString(make([]byte, sha256.Size))
		_, err := e.commit(o, forged)
		wantCode(t, err, codes.FailedPrecondition, "not pairing_proposed")
		e.requireNoPin("en14-nocode")
	})

	t.Run("own key and self-computed code, no approval", func(t *testing.T) {
		// The server fetches the script itself (it holds the server role),
		// reads the salt and computes the code for a key it controls.
		o := e.offer("en14-own")
		f, err := e.h.client.FetchEnrollScript(e.h.ctx(), &pb.FetchEnrollScriptRequest{OfferId: o.GetOfferId(), ClientAddr: "127.0.0.1", PeerAddr: "127.0.0.1"})
		if err != nil {
			t.Fatal(err)
		}
		own := hostSigner(t)
		ownSSHD := newSSHD(t, own, nil)
		r := e.submit(o, ownSSHD.endpoint(), e.code(e.salt(f.GetScript()), own.PublicKey()))
		if r.GetOutcome() != pb.PairingOutcome_PAIRING_OUTCOME_MATCHED || r.GetPermit() == nil {
			t.Fatalf("self-computed code: %v", r)
		}
		// The proposal is HIGH and shows the server's key to the operator.
		if c := string(r.GetPermit().GetCanonical()); !strings.Contains(c, ssh.FingerprintSHA256(own.PublicKey())) ||
			!strings.Contains(c, `"code_matched":true`) {
			t.Fatalf("canonical %s", c)
		}
		// No approval: commit refused, nothing pinned, and a second try
		// does not wear the refusal down.
		e.requireCommitRefused(o, r.GetPermit().GetDigest(), "en14-own")
		e.requireCommitRefused(o, r.GetPermit().GetDigest(), "en14-own")
		if ownSSHD.auths.Load() != 0 {
			t.Fatal("credential offered to an unapproved key")
		}
	})

	t.Run("permit of another offer", func(t *testing.T) {
		// Offer B is legitimately matched; its permit is presented for
		// offer A, the server's own proposal.
		a := e.offer("en14-a")
		own := hostSigner(t)
		ownSSHD := newSSHD(t, own, nil)
		fa, err := e.h.client.FetchEnrollScript(e.h.ctx(), &pb.FetchEnrollScriptRequest{OfferId: a.GetOfferId(), ClientAddr: "127.0.0.1", PeerAddr: "127.0.0.1"})
		if err != nil {
			t.Fatal(err)
		}
		ra := e.submit(a, ownSSHD.endpoint(), e.code(e.salt(fa.GetScript()), own.PublicKey()))
		if ra.GetOutcome() != pb.PairingOutcome_PAIRING_OUTCOME_MATCHED {
			t.Fatalf("offer A: %v", ra)
		}
		b, rb := e.matched("en14-b", real, realSSHD.endpoint())
		_, err = e.commit(a, rb.GetPermit().GetDigest())
		wantCode(t, err, codes.PermissionDenied, "does not belong to this offer")
		e.requireNoPin("en14-a")
		e.requireNoPin("en14-b")
		// A's proposal stays unusable for B's offer as well.
		_, err = e.commit(b, ra.GetPermit().GetDigest())
		wantCode(t, err, codes.PermissionDenied, "does not belong to this offer")
		e.requireNoPin("en14-b")
	})
	e.requireNoSecretsInLogs()
}

// ECDSA, forwarded headers and logs: a machine in the path that offers
// only ECDSA makes the probe fail without a mismatch and without a
// rejected code; a pinned ed25519 host that later answers only with ECDSA
// is refused; a forged X-Forwarded-For from a peer that is not a trusted
// proxy neither evades the rate limit nor changes the audited address.
func TestEN14_ECDSAForwardedHeaderAndLogs(t *testing.T) {
	e := newEN14(t)
	real := hostSigner(t)
	realSSHD := newSSHD(t, real, e.h.userKey)

	t.Run("ECDSA-only machine in the path", func(t *testing.T) {
		ec := newSSHD(t, ecdsaSigner(t), nil)
		o := e.offer("en14-ecdsa")
		_, salt := e.download(o)
		code := e.code(salt, real.PublicKey())
		r := e.submit(o, ec.endpoint(), code)
		if r.GetOutcome() != pb.PairingOutcome_PAIRING_OUTCOME_PROBE_FAILED || r.GetPermit() != nil || r.GetNotify() ||
			r.GetRejectedCodes() != 0 || r.GetState() != "downloaded" || !strings.Contains(r.GetDetail(), "no ed25519") {
			t.Fatalf("ECDSA-only probe: %v", r)
		}
		e.requireNoPin("en14-ecdsa")
		e.requireNoAudit("enroll_code_mismatch")
		if i := e.info(o); i.GetState() != "downloaded" || i.GetRejectedCodes() != 0 {
			t.Fatalf("offer after ECDSA probe: %v", i)
		}
		if ec.auths.Load() != 0 {
			t.Fatal("credential offered to the ECDSA machine")
		}
		// Not counted as a failure: the same code at the real host matches.
		r = e.submit(o, realSSHD.endpoint(), code)
		if r.GetOutcome() != pb.PairingOutcome_PAIRING_OUTCOME_MATCHED || r.GetProbes() != 2 || r.GetRejectedCodes() != 0 {
			t.Fatalf("retry at the real host: %v", r)
		}
		e.requireCommitRefused(o, r.GetPermit().GetDigest(), "en14-ecdsa")
	})

	t.Run("pinned ed25519 host later answers only with ECDSA", func(t *testing.T) {
		// The paired pin needs the approval RPC (see above); the host is
		// pinned through the admin probe-and-pin path, and the connection
		// rule under test (HostKeyAlgorithms restricted to the pinned
		// type) is the same for every pin source.
		pin := e.h.pin("en14-pinned", e.h.probe(realSSHD.endpoint()))
		if pin.GetFingerprint() != ssh.FingerprintSHA256(real.PublicKey()) {
			t.Fatalf("pin %v", pin)
		}
		if r := e.h.testConn("en14-pinned", realSSHD.endpoint()); !r.GetOk() {
			t.Fatalf("control connection: %v", r)
		}
		ec := newSSHD(t, ecdsaSigner(t), e.h.userKey)
		r := e.h.testConn("en14-pinned", ec.endpoint())
		if r.GetOk() || r.GetFailureClass() != "host_key_mismatch" {
			t.Fatalf("ECDSA answer accepted: %v", r)
		}
		if ec.auths.Load() != 0 {
			t.Fatal("credential offered to the ECDSA server")
		}
		if p, _ := e.pinned("en14-pinned"); p.GetFingerprint() != pin.GetFingerprint() {
			t.Fatalf("pin changed: %v", p)
		}
	})

	t.Run("forged X-Forwarded-For from an untrusted peer", func(t *testing.T) {
		// A trusted proxy exists, but the loopback peer is not one.
		now := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
		srv := e.route([]string{"192.0.2.250"}, func() time.Time { return now })
		forged := func(i int) string { return fmt.Sprintf("203.0.113.%d, 192.0.2.250", i+1) }
		for i := range enroll.PerMinute {
			resp, _ := e.get(srv, strings.Repeat("b", enroll.OfferIDLen), forged(i))
			if resp.StatusCode != http.StatusNotFound {
				t.Fatalf("request %d: %d", i, resp.StatusCode)
			}
		}
		// The limit is the peer's: a valid offer with yet another forged
		// address is refused and not consumed.
		o := e.offer("en14-xff")
		if resp, _ := e.get(srv, o.GetOfferId(), "198.51.100.77"); resp.StatusCode != http.StatusNotFound {
			t.Fatalf("rate limit evaded: %d", resp.StatusCode)
		}
		if i := e.info(o); i.GetState() != "open" {
			t.Fatalf("refused request consumed the offer: %v", i)
		}
		// On a fresh route the download succeeds, and the audited address
		// is the peer's, not the forged one.
		srv2 := e.route([]string{"192.0.2.250"}, func() time.Time { return now })
		resp, b := e.get(srv2, o.GetOfferId(), "198.51.100.77")
		if resp.StatusCode != http.StatusOK || hexSum(b) != o.GetScriptSha256() {
			t.Fatalf("download: %d", resp.StatusCode)
		}
		e.salt(b)
		if i := e.info(o); i.GetClientAddr() != "127.0.0.1" || i.GetPeerAddr() != "127.0.0.1" {
			t.Fatalf("recorded addresses %q %q", i.GetClientAddr(), i.GetPeerAddr())
		}
		e.h.requireAudit(`"kind":"enroll_script_downloaded"`, `"client_addr":"127.0.0.1"`, `"peer_addr":"127.0.0.1"`)
		all := e.h.logs.String() + e.routeLogs.String()
		for _, a := range []string{"198.51.100.77", "203.0.113."} {
			if strings.Contains(all, a) {
				t.Fatalf("forged address %s reached the logs", a)
			}
		}
	})

	t.Run("no secret in logs", func(t *testing.T) {
		if len(e.secrets) < 8 {
			t.Fatalf("only %d secrets collected", len(e.secrets))
		}
		e.requireNoSecretsInLogs()
		// The offer appears in logs only as its 8-hex prefix.
		for _, l := range strings.Split(e.h.logs.String(), "\n") {
			if m := regexp.MustCompile(`"offer":"([^"]*)"`).FindStringSubmatch(l); m != nil && len(m[1]) != 8 {
				t.Fatalf("offer logged as %q", m[1])
			}
		}
	})
}
