// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Tests of the one-step enrollment dialog (ADR 0013, EN-10 part 1, without
// NetBird). They run the UI behind the real middleware and login chain:
// the dialog needs the web session that holds the privileged session; the
// command block is the ADR D1 step 3 command; "Show script" never consumes
// and is served with no-store, nosniff and the sandbox CSP; the pairing
// code is checked (check character) before the executor is called; the
// approval page shows the full fingerprint and "code matched"; a mismatch
// shows the ADR D3 text; hostile host names stay text; no page carries an
// inline script.

package ui_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pairing"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/clientaddr"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/middleware"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

const (
	osOrigin  = "https://nos.example.lan"
	osOfferID = "abcdefghijklmnopqrstuvwxyz234567"
	osHostile = `<script>alert(1)</script>'"&`
	osFP      = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
	// osMismatchText is the UI text of ADR 0013 D3 "Failure handling".
	osMismatchText = "The host at this endpoint presents a key that does not match the code from the host. " +
		"Either the endpoint is a different machine, or something is in between. Check the endpoint, then create a new offer."
)

var osScript = []byte("#!/bin/sh\n# nos enrollment\necho '<netbird-setup-key-withheld>'\n")

func osHash(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

var osOfferHash = osHash([]byte(osOfferID))

// osExec is a fake executor for the offer RPCs. It records every call and
// enforces the session binding like the executor does.
type osExec struct {
	mu         sync.Mutex
	calls      []string
	create     *pb.CreateEnrollOfferRequest
	submit     *pb.SubmitPairingCodeRequest
	submitResp *pb.SubmitPairingCodeResponse
	assertion  *pb.SubmitAssertionRequest
	commit     *pb.CommitPairedEnrollRequest
	commitResp *pb.CommitPairedEnrollResponse
	download   *pb.DownloadEnrollScriptRequest
	consumed   bool
	// downloadScript, when set, is returned by DownloadEnrollScript with
	// the stored hash, to simulate a tampered response.
	downloadScript []byte
}

func (x *osExec) record(name string) { x.calls = append(x.calls, name) }

func (x *osExec) count(name string) int {
	x.mu.Lock()
	defer x.mu.Unlock()
	n := 0
	for _, c := range x.calls {
		if c == name {
			n++
		}
	}
	return n
}

func (x *osExec) bound(b []byte) bool {
	return x.create != nil && string(x.create.GetSessionBinding()) == string(b)
}

func (x *osExec) ProposeEnroll(context.Context, *pb.ProposeEnrollRequest, ...grpc.CallOption) (*pb.ProposeEnrollResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not used")
}

func (x *osExec) CommitEnroll(context.Context, *pb.CommitEnrollRequest, ...grpc.CallOption) (*pb.CommitEnrollResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not used")
}

func (x *osExec) SubmitAssertion(_ context.Context, in *pb.SubmitAssertionRequest, _ ...grpc.CallOption) (*pb.SubmitAssertionResponse, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.record("SubmitAssertion")
	x.assertion = in
	return &pb.SubmitAssertionResponse{}, nil
}

func (x *osExec) CreateEnrollOffer(_ context.Context, in *pb.CreateEnrollOfferRequest, _ ...grpc.CallOption) (*pb.CreateEnrollOfferResponse, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.record("CreateEnrollOffer")
	if n := len(in.GetSessionBinding()); n < 16 || n > 64 {
		return nil, status.Error(codes.InvalidArgument, "session binding length")
	}
	x.create = in
	return &pb.CreateEnrollOfferResponse{OfferId: osOfferID, OfferIdHash: osOfferHash, State: "open",
		ExpiresUnix: time.Now().Add(15 * time.Minute).Unix(), ScriptSha256: osHash(osScript)}, nil
}

func (x *osExec) ShowEnrollScript(_ context.Context, in *pb.ShowEnrollScriptRequest, _ ...grpc.CallOption) (*pb.ShowEnrollScriptResponse, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.record("ShowEnrollScript")
	if in.GetOfferId() != osOfferID || !x.bound(in.GetSessionBinding()) {
		return nil, status.Error(codes.NotFound, "no such offer")
	}
	return &pb.ShowEnrollScriptResponse{Script: slices.Clone(osScript), ScriptSha256: osHash(osScript)}, nil
}

func (x *osExec) DownloadEnrollScript(_ context.Context, in *pb.DownloadEnrollScriptRequest, _ ...grpc.CallOption) (*pb.DownloadEnrollScriptResponse, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.record("DownloadEnrollScript")
	x.download = in
	if in.GetOfferId() != osOfferID || !x.bound(in.GetSessionBinding()) || x.consumed {
		return nil, status.Error(codes.NotFound, "no such offer")
	}
	x.consumed = true
	if x.downloadScript != nil {
		return &pb.DownloadEnrollScriptResponse{Script: slices.Clone(x.downloadScript), ScriptSha256: osHash(osScript)}, nil
	}
	return &pb.DownloadEnrollScriptResponse{Script: slices.Clone(osScript), ScriptSha256: osHash(osScript)}, nil
}

func (x *osExec) SubmitPairingCode(_ context.Context, in *pb.SubmitPairingCodeRequest, _ ...grpc.CallOption) (*pb.SubmitPairingCodeResponse, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.record("SubmitPairingCode")
	if in.GetOfferIdHash() != osOfferHash || !x.bound(in.GetSessionBinding()) {
		return nil, status.Error(codes.NotFound, "no such offer")
	}
	x.submit = in
	if x.submitResp != nil {
		return x.submitResp, nil
	}
	return &pb.SubmitPairingCodeResponse{Outcome: pb.PairingOutcome_PAIRING_OUTCOME_MATCHED, State: "pairing_proposed",
		Endpoint: in.GetEndpoint(), Fingerprint: osFP, KeyType: "ssh-ed25519",
		Permit: &pb.PairedPermitInfo{Digest: strings.Repeat("d", 64), Challenge: []byte("challenge-bytes"),
			ApprovalExpiryUnix: time.Now().Add(5 * time.Minute).Unix()}}, nil
}

func (x *osExec) CommitPairedEnroll(_ context.Context, in *pb.CommitPairedEnrollRequest, _ ...grpc.CallOption) (*pb.CommitPairedEnrollResponse, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.record("CommitPairedEnroll")
	if in.GetOfferIdHash() != osOfferHash || !x.bound(in.GetSessionBinding()) {
		return nil, status.Error(codes.NotFound, "no such offer")
	}
	x.commit = in
	if x.commitResp != nil {
		return x.commitResp, nil
	}
	return &pb.CommitPairedEnrollResponse{HostId: "web1", Pinned: true, Fingerprint: osFP, State: "enrolled"}, nil
}

func (x *osExec) RevokeEnrollOffer(_ context.Context, in *pb.RevokeEnrollOfferRequest, _ ...grpc.CallOption) (*pb.RevokeEnrollOfferResponse, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.record("RevokeEnrollOffer")
	return &pb.RevokeEnrollOfferResponse{State: "revoked"}, nil
}

// osEnv is the UI with the one-step dialog behind the real chain.
type osEnv struct {
	t        *testing.T
	srv      *httptest.Server
	inv      *inventory.Store
	sessions *auth.Store
	status   *linkStatus
	exec     *osExec
	logs     *lockedBuffer
	// cookie is the web session holding the privileged session.
	cookie *http.Cookie
}

func newOSEnv(t *testing.T, cfg clientaddr.Config) *osEnv {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatalf("open server DB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	clk := &linkClock{t: time.Now()}
	e := &osEnv{t: t, inv: inventory.New(db), sessions: auth.NewStore(db, clk.now), exec: &osExec{},
		status: &linkStatus{expiry: clk.now().Add(15 * time.Minute).Unix()}, logs: &lockedBuffer{}}
	log := slog.New(slog.NewTextHandler(e.logs, nil))
	resolver, err := clientaddr.New(cfg, log)
	if err != nil {
		t.Fatalf("clientaddr: %v", err)
	}
	u, err := ui.New(ui.Options{
		PublicOrigin:     osOrigin,
		Log:              log,
		Status:           e.status,
		Inventory:        e.inv,
		Hosts:            func(ctx context.Context) ([]inventory.Host, error) { return e.inv.List(ctx) },
		Enroll:           e.exec,
		EnrollClientAddr: resolver,
		SecurityKeys: func(context.Context) ([]*pb.WebAuthnCredential, error) {
			return []*pb.WebAuthnCredential{{CredentialId: "Y3JlZC1h"}}, nil
		},
	})
	if err != nil {
		t.Fatalf("ui.New: %v", err)
	}
	a, err := auth.New(auth.Options{Executor: linkExec{status: e.status}, Sessions: e.sessions, Log: log})
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	e.srv = httptest.NewServer(middleware.Handler(middleware.Options{PublicOrigin: osOrigin}, a.Wrap(u.Handler())))
	t.Cleanup(e.srv.Close)
	e.host("web1", osHostile, "192.0.2.10")
	e.cookie = e.session("cred-alice", "alice")
	if code, _, _ := e.do(http.MethodPost, "/privileged/finish", e.cookie, "application/json", `{"assertion":{"id":"k"}}`, nil); code != http.StatusOK {
		t.Fatalf("privileged finish = %d", code)
	}
	return e
}

func (e *osEnv) host(id, name, addr string) {
	e.t.Helper()
	if _, err := e.inv.Create(context.Background(), inventory.Host{
		ID: id, DisplayName: name, Environment: inventory.EnvProd, Criticality: inventory.CriticalityLow,
		Endpoints: []inventory.Endpoint{{Address: addr}},
	}, inventory.CreateOptions{}); err != nil {
		e.t.Fatalf("create host %s: %v", id, err)
	}
}

func (e *osEnv) session(cred, user string) *http.Cookie {
	e.t.Helper()
	token, _, err := e.sessions.Create(context.Background(), cred, user)
	if err != nil {
		e.t.Fatalf("create session: %v", err)
	}
	return &http.Cookie{Name: auth.CookieName, Value: token}
}

// do sends one request with the right Origin; it does not follow
// redirects.
func (e *osEnv) do(method, path string, c *http.Cookie, ctype, body string, hdr http.Header) (int, string, http.Header) {
	e.t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, e.srv.URL+path, r)
	if err != nil {
		e.t.Fatal(err)
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	req.Header.Set("Origin", osOrigin)
	for k, v := range hdr {
		req.Header[k] = v
	}
	if c != nil {
		req.AddCookie(c)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		e.t.Fatal(err)
	}
	return res.StatusCode, string(b), res.Header
}

func (e *osEnv) form(path string, c *http.Cookie, v url.Values) (int, string, http.Header) {
	e.t.Helper()
	return e.do(http.MethodPost, path, c, "application/x-www-form-urlencoded", v.Encode(), nil)
}

// createOffer creates the offer for web1 from the privileged session and
// returns the offer page path.
func (e *osEnv) createOffer() string {
	e.t.Helper()
	code, body, hdr := e.form("/inventory/enroll/onestep", e.cookie, url.Values{"host": {"web1"}, "ssh_user": {"nebula"},
		"credential": {"nebula-default"}, "sudo": {"1"}})
	if code != http.StatusSeeOther {
		e.t.Fatalf("create = %d: %s", code, body)
	}
	loc := hdr.Get("Location")
	if loc != "/inventory/enroll/onestep/"+osOfferHash {
		e.t.Fatalf("Location = %q", loc)
	}
	if strings.Contains(loc, osOfferID) {
		e.t.Fatal("the offer ID is in a URL")
	}
	return loc
}

// validCode returns a well-formed pairing code.
func validCode(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	c, err := pairing.Compute(make([]byte, pairing.SaltSize), k.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	return c.String()
}

var (
	scriptTagRE = regexp.MustCompile(`(?i)<script\b[^>]*>`)
	onAttrRE    = regexp.MustCompile(`(?i)<[^>]+\son[a-z]+\s*=`)
)

// assertNoInlineScript fails when a page has a script element without a
// /static/ source or an inline event handler attribute.
func assertNoInlineScript(t *testing.T, body string) {
	t.Helper()
	for _, tag := range scriptTagRE.FindAllString(body, -1) {
		if !strings.Contains(tag, `src="/static/`) {
			t.Errorf("inline script element: %s", tag)
		}
	}
	if onAttrRE.MatchString(body) {
		t.Error("inline event handler attribute")
	}
	if strings.Contains(body, "javascript:") {
		t.Error("javascript: URL")
	}
}

func TestOnestepDialogNeedsPrivilegedSession(t *testing.T) {
	e := newOSEnv(t, clientaddr.Config{})
	other := e.session("cred-bob", "bob")

	// The holder sees the form.
	code, body, _ := e.do(http.MethodGet, "/inventory/enroll/onestep", e.cookie, "", "", nil)
	if code != http.StatusOK || !strings.Contains(body, `id="onestep-create"`) {
		t.Fatalf("holder dialog = %d, form missing", code)
	}
	// Another web session (even an authenticated one) gets no form and
	// cannot create.
	code, body, _ = e.do(http.MethodGet, "/inventory/enroll/onestep", other, "", "", nil)
	if code != http.StatusForbidden || strings.Contains(body, `id="onestep-create"`) || !strings.Contains(body, "privileged session") {
		t.Fatalf("other session dialog = %d", code)
	}
	if code, _, _ := e.form("/inventory/enroll/onestep", other, url.Values{"host": {"web1"}, "ssh_user": {"nebula"}, "credential": {"nebula-default"}}); code != http.StatusForbidden {
		t.Errorf("other session create = %d, want 403", code)
	}
	// A closed executor session refuses even the holder.
	e.status.set(false, nil)
	if code, _, _ := e.form("/inventory/enroll/onestep", e.cookie, url.Values{"host": {"web1"}, "ssh_user": {"nebula"}, "credential": {"nebula-default"}}); code != http.StatusForbidden {
		t.Errorf("closed session create = %d, want 403", code)
	}
	// Without login nothing at all.
	if code, _, _ := e.do(http.MethodGet, "/inventory/enroll/onestep", nil, "", "", nil); code == http.StatusOK {
		t.Error("anonymous dialog answered 200")
	}
	if n := e.exec.count("CreateEnrollOffer"); n != 0 {
		t.Errorf("CreateEnrollOffer called %d times without a privileged session", n)
	}
}

func TestOnestepCreateSendsBindingAndShowsCommandBlocks(t *testing.T) {
	e := newOSEnv(t, clientaddr.Config{})
	page := e.createOffer()
	req := e.exec.create
	if req.GetHostId() != "web1" || req.GetSshUser() != "nebula" || req.GetCredentialRef() != "nebula-default" || !req.GetSudo() || req.GetNetbird() {
		t.Errorf("create request = %v", req)
	}
	if strings.Contains(string(req.GetSessionBinding()), e.cookie.Value) {
		t.Error("the session token itself was sent to the executor")
	}
	code, body, hdr := e.do(http.MethodGet, page, e.cookie, "", "", nil)
	if code != http.StatusOK {
		t.Fatalf("offer page = %d", code)
	}
	if hdr.Get("Cache-Control") != "no-store" {
		t.Errorf("offer page Cache-Control = %q, want no-store", hdr.Get("Cache-Control"))
	}
	text := html.UnescapeString(body)
	head := "( umask 077\n" +
		"  for t in /dev/shm \"${XDG_RUNTIME_DIR:-}\" \"${TMPDIR:-/tmp}\"; do\n" +
		"    [ -n \"$t\" ] && [ -d \"$t\" ] && [ -w \"$t\" ] && break; done\n" +
		"  d=$(mktemp -d \"$t/nos-enroll.XXXXXXXX\") || exit 1\n" +
		"  trap 'rm -rf \"$d\"' EXIT; trap 'exit 130' HUP INT TERM\n" +
		"  cd \"$d\" &&\n" +
		"  printf 'url = \"https://nos.example.lan/enroll/%s\"\\noutput = \"nos-enroll.sh\"\\n' \\\n" +
		"    '" + osOfferID + "' |\n" +
		"    curl --proto '=https' --tlsv1.2 -fsS -K - &&\n" +
		"  echo '" + osHash(osScript) + "  nos-enroll.sh' | sha256sum -c - &&\n"
	if !strings.Contains(text, head+"  sudo sh nos-enroll.sh )") {
		t.Errorf("sudo command block missing:\n%s", text)
	}
	if !strings.Contains(text, head+"  sh nos-enroll.sh )") {
		t.Error("root command block missing")
	}
	if !strings.Contains(text, osHash(osScript)) {
		t.Error("SHA-256 not shown")
	}
	// TOFU warning for remote hosts.
	if lower := strings.ToLower(text); !strings.Contains(lower, "trust on first use") || !strings.Contains(lower, "web console") {
		t.Error("TOFU warning missing")
	}
	// Show script link and browser download (no NetBird in part 1).
	if !strings.Contains(body, page+"/script") || !strings.Contains(body, page+"/download") {
		t.Error("show script link or browser download form missing")
	}
	if !strings.Contains(body, `src="/static/enroll-onestep.js"`) {
		t.Error("static script not loaded")
	}
	assertNoInlineScript(t, body)
	// The audit line names the offer by hash prefix only, never the ID.
	if logs := e.logs.String(); strings.Contains(logs, osOfferID) || !strings.Contains(logs, "enroll_offer_created") {
		t.Errorf("audit: ID logged or record missing:\n%s", logs)
	}
	// Another session does not see the offer page.
	if code, body, _ := e.do(http.MethodGet, page, e.session("cred-bob", "bob"), "", "", nil); code != http.StatusNotFound || strings.Contains(body, osOfferID) {
		t.Errorf("other session offer page = %d", code)
	}
}

func TestOnestepCreateValidatesInput(t *testing.T) {
	e := newOSEnv(t, clientaddr.Config{})
	cases := []url.Values{
		{"host": {"nope"}, "ssh_user": {"nebula"}, "credential": {"nebula-default"}},
		{"host": {"../x"}, "ssh_user": {"nebula"}, "credential": {"nebula-default"}},
		{"host": {"web1"}, "ssh_user": {"root"}, "credential": {"nebula-default"}},
		{"host": {"web1"}, "ssh_user": {"ne bula"}, "credential": {"nebula-default"}},
		{"host": {"web1"}, "ssh_user": {"nebula"}, "credential": {"a'b"}},
		{"host": {"web1"}, "ssh_user": {"nebula"}, "credential": {"nebula-default"}, "netbird": {"1"}},
	}
	for i, v := range cases {
		code, body, _ := e.form("/inventory/enroll/onestep", e.cookie, v)
		if code != http.StatusBadRequest {
			t.Errorf("case %d: code = %d, want 400", i, code)
		}
		assertNoInlineScript(t, body)
	}
	if n := e.exec.count("CreateEnrollOffer"); n != 0 {
		t.Errorf("CreateEnrollOffer called %d times for invalid input", n)
	}
}

func TestOnestepShowScriptDoesNotConsumeAndIsSandboxed(t *testing.T) {
	e := newOSEnv(t, clientaddr.Config{})
	page := e.createOffer()
	for i := range 3 {
		code, body, hdr := e.do(http.MethodGet, page+"/script", e.cookie, "", "", nil)
		if code != http.StatusOK || body != string(osScript) {
			t.Fatalf("show %d = %d %q", i, code, body)
		}
		want := map[string]string{
			"Content-Type":            "text/plain; charset=utf-8",
			"Cache-Control":           "no-store",
			"X-Content-Type-Options":  "nosniff",
			"Content-Security-Policy": "default-src 'none'; sandbox",
		}
		for k, v := range want {
			if got := hdr.Get(k); got != v {
				t.Errorf("show %s = %q, want %q", k, got, v)
			}
		}
		if cd := hdr.Get("Content-Disposition"); strings.HasPrefix(cd, "attachment") {
			t.Errorf("show is an attachment: %q", cd)
		}
	}
	if e.exec.count("DownloadEnrollScript") != 0 || e.exec.consumed {
		t.Error("show script consumed the offer")
	}
	// Another session: 404, executor not asked with the ID.
	before := e.exec.count("ShowEnrollScript")
	if code, body, _ := e.do(http.MethodGet, page+"/script", e.session("cred-bob", "bob"), "", "", nil); code != http.StatusNotFound || strings.Contains(body, "nos enrollment") {
		t.Errorf("other session show = %d", code)
	}
	if e.exec.count("ShowEnrollScript") != before {
		t.Error("executor called for another session")
	}
}

func TestOnestepBrowserDownloadHeadersAndHash(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		e := newOSEnv(t, clientaddr.Config{})
		page := e.createOffer()
		code, body, hdr := e.form(page+"/download", e.cookie, url.Values{})
		if code != http.StatusOK || body != string(osScript) {
			t.Fatalf("download = %d %q", code, body)
		}
		for k, v := range map[string]string{
			"Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
			"Content-Security-Policy": "default-src 'none'; sandbox", "X-Accel-Buffering": "no",
		} {
			if got := hdr.Get(k); got != v {
				t.Errorf("download %s = %q, want %q", k, got, v)
			}
		}
		if cd := hdr.Get("Content-Disposition"); cd != `attachment; filename="nos-enroll.sh"` {
			t.Errorf("Content-Disposition = %q", cd)
		}
		if d := e.exec.download; d.GetClientAddr() != "127.0.0.1" || d.GetPeerAddr() != "127.0.0.1" {
			t.Errorf("download addresses = %q %q", d.GetClientAddr(), d.GetPeerAddr())
		}
		// Second download refused by the executor: no script.
		if code, body, _ := e.form(page+"/download", e.cookie, url.Values{}); code == http.StatusOK || strings.Contains(body, "nos enrollment") {
			t.Errorf("second download = %d", code)
		}
	})
	t.Run("hash mismatch", func(t *testing.T) {
		e := newOSEnv(t, clientaddr.Config{})
		e.exec.downloadScript = []byte("#!/bin/sh\nrm -rf /\n")
		page := e.createOffer()
		code, body, _ := e.form(page+"/download", e.cookie, url.Values{})
		if code == http.StatusOK || strings.Contains(body, "rm -rf /\n") {
			t.Fatalf("tampered download = %d %q", code, body)
		}
	})
}

func TestOnestepCodeIsCheckedBeforeTheExecutor(t *testing.T) {
	e := newOSEnv(t, clientaddr.Config{})
	page := e.createOffer()
	good := validCode(t)
	// Flip the check character to another valid symbol.
	last := good[len(good)-1]
	other := byte('0')
	if last == '0' {
		other = '1'
	}
	wrongCheck := good[:len(good)-1] + string(other)
	bad := []string{"", "K7QXM", wrongCheck, good + "0", strings.Replace(good, good[:1], "!", 1), good[:3] + "*" + good[4:], strings.Repeat("0", 70)}
	for _, c := range bad {
		code, body, _ := e.form(page+"/code", e.cookie, url.Values{"code": {c}, "endpoint": {"192.0.2.10:22"}})
		if code != http.StatusBadRequest || !strings.Contains(body, "pairing code") {
			t.Errorf("code %q = %d, want 400 with a message", c, code)
		}
		assertNoInlineScript(t, body)
	}
	if n := e.exec.count("SubmitPairingCode"); n != 0 {
		t.Fatalf("SubmitPairingCode called %d times for malformed codes", n)
	}
	// Folding: lower case, spaces and hyphens are accepted and normalised.
	typed := strings.ToLower(strings.ReplaceAll(good, "-", " "))
	code, body, _ := e.form(page+"/code", e.cookie, url.Values{"code": {typed}, "endpoint": {"192.0.2.10:22"}})
	if code != http.StatusOK {
		t.Fatalf("valid code = %d: %s", code, body)
	}
	if got := e.exec.submit.GetCode(); got != good {
		t.Errorf("code sent = %q, want %q", got, good)
	}
	if got := e.exec.submit.GetInventoryEndpoints(); len(got) != 1 || got[0] != "192.0.2.10:22" {
		t.Errorf("inventory endpoints = %v", got)
	}
}

func TestOnestepMatchShowsFullFingerprintAndCodeMatched(t *testing.T) {
	e := newOSEnv(t, clientaddr.Config{})
	page := e.createOffer()
	e.exec.submitResp = &pb.SubmitPairingCodeResponse{Outcome: pb.PairingOutcome_PAIRING_OUTCOME_MATCHED, State: "pairing_proposed",
		Endpoint: "192.0.2.77:22", Fingerprint: osFP, KeyType: "ssh-ed25519", EndpointToAdd: true,
		Permit: &pb.PairedPermitInfo{Digest: strings.Repeat("d", 64), Challenge: []byte("challenge-bytes"), ApprovalExpiryUnix: time.Now().Add(5 * time.Minute).Unix()}}
	code, body, hdr := e.form(page+"/code", e.cookie, url.Values{"code": {validCode(t)}, "endpoint": {"other"}, "endpoint_other": {"192.0.2.77"}})
	if code != http.StatusOK {
		t.Fatalf("submit = %d: %s", code, body)
	}
	if e.exec.submit.GetEndpoint() != "192.0.2.77" {
		t.Errorf("typed endpoint sent = %q", e.exec.submit.GetEndpoint())
	}
	if hdr.Get("Cache-Control") != "no-store" {
		t.Error("approval page is cacheable")
	}
	text := html.UnescapeString(body)
	for _, want := range []string{osFP, "code matched", "matches the pairing code from the host", "192.0.2.77:22",
		"will be added to the inventory host", "nebula-default", "web1", osHostile} {
		if !strings.Contains(text, want) {
			t.Errorf("approval page lacks %q", want)
		}
	}
	if strings.Contains(body, "<script>alert(1)") {
		t.Error("hostile host name rendered as markup")
	}
	// The WebAuthn options are in a data attribute, not a script.
	if !strings.Contains(body, `data-options="`) {
		t.Error("approval options missing")
	}
	assertNoInlineScript(t, body)

	// Commit: assertion for the stored digest, then the commit; the
	// endpoint to add is appended to the inventory host.
	e.exec.commitResp = &pb.CommitPairedEnrollResponse{HostId: "web1", Pinned: true, Fingerprint: osFP, State: "enrolled", EndpointAdded: "192.0.2.77:22", LoginOk: true}
	code, out, _ := e.do(http.MethodPost, page+"/commit", e.cookie, "application/json", `{"assertion":{"id":"k"}}`, nil)
	if code != http.StatusOK {
		t.Fatalf("commit = %d: %s", code, out)
	}
	if e.exec.assertion.GetExecutionDigest() != strings.Repeat("d", 64) || e.exec.commit.GetPermitDigest() != strings.Repeat("d", 64) {
		t.Error("commit did not use the stored permit digest")
	}
	var res map[string]any
	if err := json.Unmarshal([]byte(out), &res); err != nil || res["pinned"] != true {
		t.Errorf("commit answer = %s", out)
	}
	h, err := e.inv.Get(context.Background(), "web1")
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Endpoints) != 2 || h.Endpoints[0].Address != "192.0.2.10" || h.Endpoints[1].Address != "192.0.2.77" {
		t.Errorf("endpoints after commit = %v", h.Endpoints)
	}
	logs := e.logs.String()
	for _, k := range []string{"enroll_paired_proposed", "host_enrolled", "inventory_endpoint_added"} {
		if !strings.Contains(logs, k) {
			t.Errorf("audit %s missing", k)
		}
	}
}

func TestOnestepMismatchShowsADRText(t *testing.T) {
	e := newOSEnv(t, clientaddr.Config{})
	page := e.createOffer()
	e.exec.submitResp = &pb.SubmitPairingCodeResponse{Outcome: pb.PairingOutcome_PAIRING_OUTCOME_MISMATCH, State: "failed",
		Endpoint: "192.0.2.10:22", Fingerprint: osFP, KeyType: "ssh-ed25519", Notify: true}
	code, body, _ := e.form(page+"/code", e.cookie, url.Values{"code": {validCode(t)}, "endpoint": {"192.0.2.10:22"}})
	if code != http.StatusOK {
		t.Fatalf("submit = %d", code)
	}
	text := html.UnescapeString(body)
	if !strings.Contains(text, osMismatchText) {
		t.Errorf("mismatch text missing:\n%s", text)
	}
	if strings.Contains(text, "code matched") || strings.Contains(body, `id="onestep-approve"`) {
		t.Error("mismatch page offers an approval")
	}
	if !strings.Contains(e.logs.String(), "enroll_code_mismatch") {
		t.Error("audit enroll_code_mismatch missing")
	}
	// The failed offer accepts no further code and no commit.
	if code, _, _ := e.form(page+"/code", e.cookie, url.Values{"code": {validCode(t)}, "endpoint": {"192.0.2.10:22"}}); code == http.StatusOK {
		t.Error("failed offer accepted another code")
	}
	if code, _, _ := e.do(http.MethodPost, page+"/commit", e.cookie, "application/json", `{}`, nil); code == http.StatusOK {
		t.Error("failed offer committed")
	}
	if n := e.exec.count("SubmitPairingCode"); n != 1 {
		t.Errorf("SubmitPairingCode called %d times", n)
	}
}

func TestOnestepHostileHostNamesStayText(t *testing.T) {
	e := newOSEnv(t, clientaddr.Config{})
	code, body, _ := e.do(http.MethodGet, "/inventory/enroll/onestep", e.cookie, "", "", nil)
	if code != http.StatusOK {
		t.Fatalf("dialog = %d", code)
	}
	if strings.Contains(body, "<script>alert(1)") {
		t.Error("hostile name rendered as markup in the dialog")
	}
	if !strings.Contains(html.UnescapeString(body), osHostile) {
		t.Error("hostile name not shown as text")
	}
	assertNoInlineScript(t, body)
	page := e.createOffer()
	_, body, _ = e.do(http.MethodGet, page, e.cookie, "", "", nil)
	if strings.Contains(body, "<script>alert(1)") {
		t.Error("hostile name rendered as markup on the offer page")
	}
	// The address picker lists the inventory endpoints as plain text.
	if !strings.Contains(body, "192.0.2.10:22") {
		t.Error("address picker lacks the inventory endpoint")
	}
}

func TestOnestepTrustedProxyWithoutHeaderIsRefused(t *testing.T) {
	e := newOSEnv(t, clientaddr.Config{TrustedProxies: []string{"127.0.0.1"}})
	code, _, _ := e.form("/inventory/enroll/onestep", e.cookie, url.Values{"host": {"web1"}, "ssh_user": {"nebula"}, "credential": {"nebula-default"}})
	if code != http.StatusBadRequest {
		t.Fatalf("create without X-Forwarded-For = %d, want 400", code)
	}
	if n := e.exec.count("CreateEnrollOffer"); n != 0 {
		t.Fatal("offer created without a usable forwarded header")
	}
	// With a header the forwarded client is audited with the peer.
	hdr := http.Header{"X-Forwarded-For": {"192.0.2.55"}}
	code, body, _ := e.do(http.MethodPost, "/inventory/enroll/onestep", e.cookie, "application/x-www-form-urlencoded",
		url.Values{"host": {"web1"}, "ssh_user": {"nebula"}, "credential": {"nebula-default"}}.Encode(), hdr)
	if code != http.StatusSeeOther {
		t.Fatalf("create with header = %d: %s", code, body)
	}
	logs := e.logs.String()
	if !strings.Contains(logs, "client=192.0.2.55") || !strings.Contains(logs, "peer=127.0.0.1") {
		t.Errorf("audit lacks client and peer:\n%s", logs)
	}
}

func TestOnestepRevoke(t *testing.T) {
	e := newOSEnv(t, clientaddr.Config{})
	page := e.createOffer()
	code, _, hdr := e.form(page+"/revoke", e.cookie, url.Values{})
	if code != http.StatusSeeOther || hdr.Get("Location") != "/inventory/enroll/onestep" {
		t.Fatalf("revoke = %d %q", code, hdr.Get("Location"))
	}
	if e.exec.count("RevokeEnrollOffer") != 1 {
		t.Error("revoke not forwarded")
	}
	if code, _, _ := e.do(http.MethodGet, page+"/script", e.cookie, "", "", nil); code != http.StatusNotFound {
		t.Errorf("show after revoke = %d", code)
	}
}

// TestOnestepScriptChecksTheCheckCharacter binds the static script's
// check alphabet to the pairing package's.
func TestOnestepScriptChecksTheCheckCharacter(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRoot, "web", "static", "enroll-onestep.js"))
	if err != nil {
		t.Fatal(err)
	}
	js := string(b)
	for _, want := range []string{"0123456789ABCDEFGHJKMNPQRSTVWXYZ*~$=U", "% 37", "setCustomValidity"} {
		if !strings.Contains(js, want) {
			t.Errorf("enroll-onestep.js lacks %q", want)
		}
	}
}
