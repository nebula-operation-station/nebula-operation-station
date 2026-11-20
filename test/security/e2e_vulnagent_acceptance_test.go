// SPDX-License-Identifier: AGPL-3.0-or-later

package security

// E2E01: end-to-end acceptance of the vulnerability agent over real HTTP.
//
// Two live bugs of 2026-11-20 passed every unit test because each side was
// tested alone:
//
//   - the agent's bearer-token POSTs were refused with 403 by the browser
//     origin check of the security middleware (fixed by ao01: the token
//     API exemption isTokenAPIRequest in cmd/nebula-server/software.go);
//   - the output of package.list_installed was refused by the executor's
//     hostrun classifier (stdout must be exactly one JSON document; fixed
//     by pli01, package.list_installed 1.1.0).
//
// The tests here put the real parts together:
//
//   - The server is the server's own HTTP chain: webServer of
//     cmd/nebula-server (same mux, middleware.NewServer with the origin
//     check and its OriginExempt rule, the read-only API with the vuln API
//     mounted under api.Prefix, the real session gate for the pages),
//     built from a server.json read by serverconfig.Load with the vuln
//     token "vuln-agent" limited to source_addresses ["127.0.0.1"]. It runs
//     in package main through a go build overlay (e2e01ServerDriver; nothing
//     is written to the source tree), so a change of the real wiring is
//     what the test sees, not a copy of it. TLS is terminated on the
//     server's listener because nosclient talks https only.
//   - The agent side is internal/vulnagent/nosclient (and the agent-config
//     reader of internal/vulnagent/run) with the token file, the pinned CA
//     and no Origin header: every call one agent run makes.
//   - The package list is the registered package.list_installed script,
//     run as an attached run through hostrun.Attached against the
//     in-process SSH server that executes it with /bin/sh on this machine,
//     so the executor's own classifier decides; the result is then parsed
//     as the server parses it.

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/osdebian"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun/hostruntest"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnagent/nosclient"
	vulnrun "github.com/nebula-operation-station/nebula-operation-station/internal/vulnagent/run"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnver"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/api"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
)

const (
	// e2e01Token is the agent's bearer token (test only, never a real one).
	e2e01Token = "nos_e2e01-acceptance-vuln-agent-token"
	// e2e01TokenName is the token's name in server.json.
	e2e01TokenName = "vuln-agent"
	// e2e01Origin is the server's public_origin.
	e2e01Origin = "https://nos.e2e01.test"
	// e2e01StartTimeout bounds building and starting the server (the
	// overlay build of cmd/nebula-server).
	e2e01StartTimeout = 50 * time.Second
	// e2e01CallTimeout bounds every request of the test.
	e2e01CallTimeout = 10 * time.Second
	// e2e01MaxAnswer bounds what the control socket and a raw response are
	// read up to.
	e2e01MaxAnswer = 64 << 10
	// e2e01ForeignSource is a loopback address outside the token's
	// source_addresses (Linux routes all of 127.0.0.0/8 to lo).
	e2e01ForeignSource = "127.0.0.2"
	// e2e01OriginRefusal is the security middleware's 403 body.
	e2e01OriginRefusal = "origin not allowed"
)

// e2e01ServerDriver is added to package main of cmd/nebula-server through a
// go build overlay. It builds the HTTP chain exactly as run in main.go does
// for the vulnerability agent: server.json through serverconfig.Load,
// server.db, the vuln service, the agent settings store, api.New with the
// vuln API (newVulnAPI, vulnInventory) mounted by api.Mount and api.MountOps
// (no ops token configured), the real session gate, and webServer. It
// serves on cfg.Listen with TLS, reports the address over the control
// socket and serves until the test hangs up.
const e2e01ServerDriver = `// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/notify"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/api"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
)

type e2e01Sink struct{}

func (e2e01Sink) Notify(context.Context, notify.Event) int { return 0 }

// e2e01Ops is the read-only API's view of executions (main.go:
// executions.New on the executor); the vuln agent never reaches it.
type e2e01Ops struct{}

func (e2e01Ops) Get(context.Context, string) (executions.Execution, error) {
	return executions.Execution{}, executions.ErrNotFound
}
func (e2e01Ops) List(context.Context, int) ([]executions.Summary, error) { return nil, nil }
func (e2e01Ops) AllUpdates(context.Context) (map[string]executions.HostUpdates, error) {
	return nil, nil
}
func (e2e01Ops) AllOpsStates(context.Context) (map[string]executions.OpsState, error) {
	return nil, nil
}

func TestE2E01OverlayServer(t *testing.T) {
	cfg, err := serverconfig.Load(os.Getenv("E2E01_CONFIG"))
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	db, err := serverdb.Open(filepath.Join(cfg.DataDir, "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	vuln, err := newVulnService(db, e2e01Sink{}, log, nil)
	if err != nil {
		t.Fatal(err)
	}
	agentCfg, err := vulnstore.NewAgentConfigStore(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	hosts := func(context.Context) ([]inventory.Host, error) { return nil, nil }
	a, err := api.New(api.Options{Tokens: cfg.API.Tokens, Hosts: hosts, Operations: e2e01Ops{}, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	vh, err := newVulnAPI(cfg.API, vuln, vulnInventory{now: time.Now}, agentCfg, log)
	if err != nil {
		t.Fatal(err)
	}
	if vh == nil {
		t.Fatal("server.json enables no vuln API")
	}
	apiHandler := api.MountOps(api.Mount(a, vh), nil)
	login, err := auth.New(auth.Options{Executor: &lazyExecutor{}, Sessions: auth.NewStore(db, nil), Log: log})
	if err != nil {
		t.Fatal(err)
	}
	pages := http.NewServeMux()
	pages.Handle("/", http.NotFoundHandler())
	srv, err := webServer(cfg.PublicOrigin, login, pages, apiHandler)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.LoadX509KeyPair(os.Getenv("E2E01_CERT"), os.Getenv("E2E01_KEY"))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})) }()
	defer srv.Close()
	ctl, err := net.Dial("unix", os.Getenv("E2E01_CONTROL"))
	if err != nil {
		t.Fatal(err)
	}
	defer ctl.Close()
	if _, err := fmt.Fprintf(ctl, "%s\n", ln.Addr()); err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, ctl)
}
`

// e2e01Env is a running server and the agent's files.
type e2e01Env struct {
	t         *testing.T
	base      string // https://127.0.0.1:port
	caFile    string // the server certificate, pinned
	tokenFile string // the agent token, mode 0600
	caPool    *x509.CertPool
}

// with returns a copy of e that reports to t (for subtests).
func (e *e2e01Env) with(t *testing.T) *e2e01Env {
	c := *e
	c.t = t
	return &c
}

// e2e01Server writes server.json, the TLS key pair and the token file into
// a private directory, starts the overlay driver and waits for its address
// on the control socket. The server stops when t ends: closing the control
// connection ends the driver.
func e2e01Server(t *testing.T) *e2e01Env {
	t.Helper()
	dir := privateDir(t)
	certPEM, keyPEM, err := e2e01Cert()
	if err != nil {
		t.Fatal(err)
	}
	e, err := e2e01Files(dir, certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	e.t = t
	addr, stop, err := e2e01Run(dir, filepath.Join(dir, "server.json"), e.caFile, filepath.Join(dir, "key.pem"))
	if err != nil {
		t.Fatalf("start the server: %v", err)
	}
	t.Cleanup(stop)
	e.base = "https://" + addr
	return e
}

// e2e01Files writes the server's and the agent's files into dir.
func e2e01Files(dir string, certPEM, keyPEM []byte) (*e2e01Env, error) {
	var err error
	write := func(name string, b []byte) (string, error) {
		p := filepath.Join(dir, name)
		return p, os.WriteFile(p, b, 0o600)
	}
	e := &e2e01Env{caPool: x509.NewCertPool()}
	e.caPool.AppendCertsFromPEM(certPEM)
	if e.caFile, err = write("ca.pem", certPEM); err != nil {
		return nil, err
	}
	if _, err := write("key.pem", keyPEM); err != nil {
		return nil, err
	}
	if e.tokenFile, err = write("agent.token", []byte(e2e01Token+"\n")); err != nil {
		return nil, err
	}
	dataDir := filepath.Join(dir, "data")
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		return nil, err
	}
	// The vuln token as server.json holds it (docs: api.tokens).
	cfg := map[string]any{
		"listen":          "127.0.0.1:0",
		"public_origin":   e2e01Origin,
		"data_dir":        dataDir,
		"executor_socket": filepath.Join(dir, "executor.sock"),
		"executor_user":   "nebula-executor",
		"api": map[string]any{"enabled": true, "tokens": []map[string]any{{
			"name":             e2e01TokenName,
			"sha256":           api.HashToken(e2e01Token),
			"scopes":           []string{serverconfig.ScopeVulnInventoryRead, serverconfig.ScopeVulnFindingsWrite},
			"source_addresses": []string{"127.0.0.1"},
		}}},
	}
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	if _, err := write("server.json", cfgJSON); err != nil {
		return nil, err
	}
	return e, nil
}

// e2e01Run starts e2e01ServerDriver with the go tool (GOPROXY=off, so
// nothing is fetched) and returns the address it serves on and the stop
// function, which ends the driver and waits for it.
func e2e01Run(dir, cfgFile, certFile, keyFile string) (string, func(), error) {
	goTool, err := exec.LookPath("go")
	if err != nil {
		return "", nil, fmt.Errorf("the go tool is needed to build the server: %w", err)
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		return "", nil, err
	}
	driver := filepath.Join(dir, "driver.go")
	if err := os.WriteFile(driver, []byte(e2e01ServerDriver), 0o600); err != nil {
		return "", nil, err
	}
	overlay, err := json.Marshal(map[string]any{"Replace": map[string]string{
		filepath.Join(root, "cmd", "nebula-server", "zz_e2e01_overlay_test.go"): driver}})
	if err != nil {
		return "", nil, err
	}
	overlayFile := filepath.Join(dir, "overlay.json")
	if err := os.WriteFile(overlayFile, overlay, 0o600); err != nil {
		return "", nil, err
	}
	ctlPath := filepath.Join(dir, "ctl.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: ctlPath, Net: "unix"})
	if err != nil {
		return "", nil, err
	}
	cmd := exec.Command(goTool, "test", "-overlay", overlayFile, "-count=1", "-timeout=10m",
		"-run", "^TestE2E01OverlayServer$", "./cmd/nebula-server")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOPROXY=off", "GOFLAGS=-mod=readonly", "E2E01_CONFIG="+cfgFile,
		"E2E01_CERT="+certFile, "E2E01_KEY="+keyFile, "E2E01_CONTROL="+ctlPath)
	out := &syncBuffer{}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		ln.Close()
		return "", nil, err
	}
	// A driver that ends before it reports closes the listener, so the
	// Accept below returns at once instead of waiting for the deadline.
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited); ln.Close() }()
	kill := func() { _ = cmd.Process.Kill(); <-exited }
	if err := ln.SetDeadline(time.Now().Add(e2e01StartTimeout)); err != nil {
		kill()
		return "", nil, err
	}
	conn, err := ln.Accept()
	if err != nil {
		kill()
		return "", nil, fmt.Errorf("server driver did not report (%w):\n%s", err, out.String())
	}
	ln.Close()
	// The driver serves until conn closes.
	stop := func() {
		conn.Close()
		select {
		case <-exited:
		case <-time.After(e2e01CallTimeout):
			kill()
		}
	}
	_ = conn.SetReadDeadline(time.Now().Add(e2e01CallTimeout))
	line, err := bufio.NewReader(io.LimitReader(conn, e2e01MaxAnswer)).ReadString('\n')
	if err != nil {
		stop()
		return "", nil, fmt.Errorf("read server address: %w:\n%s", err, out.String())
	}
	_ = conn.SetReadDeadline(time.Time{})
	addr := strings.TrimSpace(line)
	if host, _, err := net.SplitHostPort(addr); err != nil || host != "127.0.0.1" {
		stop()
		return "", nil, fmt.Errorf("server reported address %q, want 127.0.0.1:port", addr)
	}
	return addr, stop, nil
}

// e2e01Cert returns a fresh self-signed certificate for 127.0.0.1 (it is
// its own CA, the agent pins it) and its key, PEM encoded.
func e2e01Cert() ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "nos-e2e01"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	kd, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), nil
}

// client is the agent's NOS client on tokenFile, one attempt per call so a
// refusal is reported at once.
func (e *e2e01Env) client(tokenFile string) *nosclient.Client {
	e.t.Helper()
	c, err := nosclient.New(nosclient.Config{BaseURL: e.base, TokenFile: tokenFile, CAFile: e.caFile, MaxAttempts: 1})
	if err != nil {
		e.t.Fatal(err)
	}
	return c
}

func (e *e2e01Env) ctx() context.Context {
	ctx, cancel := context.WithTimeout(e.t.Context(), 4*e2e01CallTimeout)
	e.t.Cleanup(cancel)
	return ctx
}

// raw sends one request that is not the agent's: from source (empty: the
// default address), with the headers given and no others. It returns the
// status and the body.
func (e *e2e01Env) raw(method, path, source string, header map[string]string, body string) (int, string) {
	e.t.Helper()
	d := &net.Dialer{Timeout: e2e01CallTimeout}
	if source != "" {
		d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(source)}
	}
	hc := &http.Client{Timeout: e2e01CallTimeout, Transport: &http.Transport{Proxy: nil, DialContext: d.DialContext,
		TLSClientConfig: &tls.Config{RootCAs: e.caPool, MinVersion: tls.VersionTLS12}}}
	defer hc.CloseIdleConnections()
	req, err := http.NewRequestWithContext(e.t.Context(), method, e.base+path, strings.NewReader(body))
	if err != nil {
		e.t.Fatal(err)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := hc.Do(req)
	if err != nil {
		e.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, e2e01MaxAnswer))
	if err != nil {
		e.t.Fatal(err)
	}
	return resp.StatusCode, string(b)
}

// e2e01StartRequest is the start request of one agent run: every source of the
// server's list, dated an hour ago.
func e2e01StartRequest() nosclient.StartRequest {
	req := nosclient.StartRequest{MatcherVersion: "e2e01-1.0.0"}
	at := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	for _, s := range vulnListedSources {
		req.Sources = append(req.Sources, nosclient.SourceSnapshot{SourceID: s.ID, SnapshotID: "snap-" + s.ID,
			Integrity: vulnfinding.IntegrityNone, DateKind: nosclient.DateKindData, ContentDate: at})
	}
	return req
}

// --- the agent's run over the real chain ---

// TestE2E01VulnAgentOverRealHTTP starts the server once (one overlay
// build) and runs the agent's calls and the refusals against it.
func TestE2E01VulnAgentOverRealHTTP(t *testing.T) {
	e := e2e01Server(t)
	t.Run("AgentRunPassesTheRealHTTPChain", func(t *testing.T) { e2e01AgentRun(t, e.with(t)) })
	t.Run("WrongTokenIsUnauthorized", func(t *testing.T) { e2e01WrongToken(t, e.with(t)) })
	t.Run("ForeignSourceAddressIsForbidden", func(t *testing.T) { e2e01ForeignSourceRefused(t, e.with(t)) })
	t.Run("BrowserPostWithoutOriginIsForbidden", func(t *testing.T) { e2e01BrowserPost(t, e.with(t)) })
}

// Every call of one agent run goes through the server's real HTTP chain
// and is answered with its success status: the agent settings read, the
// inventory export (GET), the run start, a findings batch and the run
// completion (POST with the bearer token, no Origin header). Before ao01
// every POST here was refused by the origin check with 403.
func e2e01AgentRun(t *testing.T, e *e2e01Env) {
	ctx := e.ctx()

	settings, err := vulnrun.NewHTTPAgentConfig(vulnrun.AgentConfigOptions{BaseURL: e.base, TokenFile: e.tokenFile, CAFile: e.caFile})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := settings.AgentConfig(ctx); err != nil {
		t.Fatalf("GET agent-config: %v", err)
	}

	c := e.client(e.tokenFile)
	pages := 0
	snap, err := c.Export(ctx, func(nosclient.Page) error { pages++; return nil })
	if err != nil {
		t.Fatalf("GET inventory: %v", err)
	}
	if snap == nil || snap.ID == "" || pages < 1 {
		t.Fatalf("inventory export: snapshot %+v, %d pages", snap, pages)
	}
	run, err := c.StartRun(ctx, snap, e2e01StartRequest())
	if err != nil {
		t.Fatalf("POST start run (bearer, no Origin): %v", err)
	}
	if run.InventorySnapshotID != snap.ID {
		t.Fatalf("run bound to snapshot %q, want %q", run.InventorySnapshotID, snap.ID)
	}
	res, err := run.Submit(ctx, nosclient.Batch{Seq: 1})
	if err != nil {
		t.Fatalf("POST findings batch (bearer, no Origin): %v", err)
	}
	if res.BatchSeq != 1 || res.Rejected != 0 {
		t.Fatalf("batch result %+v", res)
	}
	if _, err := run.Complete(ctx); err != nil {
		t.Fatalf("POST complete run (bearer, no Origin): %v", err)
	}
}

// --- refusals ---

// A wrong token is refused by the API with 401, through nosclient.
func e2e01WrongToken(t *testing.T, e *e2e01Env) {
	wrong := filepath.Join(privateDir(t), "wrong.token")
	if err := os.WriteFile(wrong, []byte("nos_e2e01-not-the-agent-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := e.client(wrong)
	_, err := c.Export(e.ctx(), func(nosclient.Page) error { return nil })
	var se *nosclient.StatusError
	if !errors.Is(err, nosclient.ErrUnauthorized) || !errors.As(err, &se) || se.Status != http.StatusUnauthorized {
		t.Fatalf("GET inventory with a wrong token: %v, want 401", err)
	}
	// The write path too: a wrong token on a POST is the API's 401, not
	// the origin check's 403.
	code, body := e.raw(http.MethodPost, "/api/v1/vuln/runs", "",
		map[string]string{"Authorization": "Bearer nos_e2e01-not-the-agent-token", "Content-Type": "application/json"}, "{}")
	if code != http.StatusUnauthorized {
		t.Fatalf("POST start run with a wrong token: %d %q, want 401", code, body)
	}
}

// The right token from an address outside source_addresses is refused
// with 403 by the API (not by the origin check), for reads and writes.
func e2e01ForeignSourceRefused(t *testing.T, e *e2e01Env) {
	hdr := map[string]string{"Authorization": "Bearer " + e2e01Token, "Content-Type": "application/json"}
	for _, rq := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/v1/vuln/inventory", ""},
		{http.MethodPost, "/api/v1/vuln/runs", "{}"},
	} {
		code, body := e.raw(rq.method, rq.path, e2e01ForeignSource, hdr, rq.body)
		if code != http.StatusForbidden || strings.Contains(body, e2e01OriginRefusal) {
			t.Errorf("%s %s from %s: %d %q, want the API's 403", rq.method, rq.path, e2e01ForeignSource, code, body)
		}
	}
	// The same request from the allowed address passes the source check
	// (it then fails as input, which shows the 403 above is the source).
	if code, body := e.raw(http.MethodPost, "/api/v1/vuln/runs", "", hdr, "{}"); code == http.StatusForbidden || code == http.StatusUnauthorized {
		t.Fatalf("POST start run from 127.0.0.1: %d %q, want past the source check", code, body)
	}
}

// The origin check stays for browsers: a POST without Origin and without a
// token, and a POST that carries the session cookie (with or without a
// bearer header), are refused by the middleware with 403, on the API
// prefix and on the pages. A GET is not state-changing and is not refused
// by it.
func e2e01BrowserPost(t *testing.T, e *e2e01Env) {
	cookie := auth.CookieName + "=e2e01-session"
	cases := []struct {
		name   string
		path   string
		header map[string]string
	}{
		{"api, no token", "/api/v1/vuln/runs", map[string]string{"Content-Type": "application/json"}},
		{"page, no token", "/assistant/ops/questions", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}},
		{"api, session cookie", "/api/v1/vuln/runs", map[string]string{"Cookie": cookie, "Content-Type": "application/json"}},
		{"api, session cookie and bearer", "/api/v1/vuln/runs", map[string]string{"Cookie": cookie,
			"Authorization": "Bearer " + e2e01Token, "Content-Type": "application/json"}},
		{"api, foreign origin", "/api/v1/vuln/runs", map[string]string{"Origin": "https://evil.example", "Content-Type": "application/json"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body := e.with(t).raw(http.MethodPost, tc.path, "", tc.header, "{}")
			if code != http.StatusForbidden || !strings.Contains(body, e2e01OriginRefusal) {
				t.Fatalf("POST %s: %d %q, want the origin check's 403", tc.path, code, body)
			}
		})
	}
	code, body := e.raw(http.MethodGet, "/api/v1/vuln/inventory", "", nil, "")
	if code != http.StatusUnauthorized || strings.Contains(body, e2e01OriginRefusal) {
		t.Fatalf("GET inventory without token: %d %q, want the API's 401", code, body)
	}
}

// --- package.list_installed through the executor's classifier ---

// e2e01Status is a small dpkg status database: two installed binaries
// (one with a source package and version), the kernel image with its
// Built-Using, and a config-files leftover that is not inventory.
const e2e01Status = `Package: openssl
Status: install ok installed
Priority: optional
Section: utils
Installed-Size: 2280
Maintainer: Debian OpenSSL Team <pkg-openssl-devel@alioth-lists.debian.net>
Architecture: amd64
Version: 3.0.15-1~deb12u1
Description: Secure Sockets Layer toolkit - cryptographic utility

Package: libssl3
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 6340
Maintainer: Debian OpenSSL Team <pkg-openssl-devel@alioth-lists.debian.net>
Architecture: amd64
Multi-Arch: same
Source: openssl
Version: 3.0.15-1~deb12u1
Description: Secure Sockets Layer toolkit - shared libraries

Package: linux-image-6.1.0-26-amd64
Status: install ok installed
Priority: optional
Section: kernel
Installed-Size: 400000
Maintainer: Debian Kernel Team <debian-kernel@lists.debian.org>
Architecture: amd64
Source: linux-signed-amd64 (6.1.112+1)
Version: 6.1.112-1
Built-Using: linux (= 6.1.112-1)
Description: Linux 6.1 for 64-bit PCs (signed)

Package: oldtool
Status: deinstall ok config-files
Priority: optional
Section: utils
Installed-Size: 10
Maintainer: Nobody <nobody@example.org>
Architecture: amd64
Version: 1.0-1
Description: removed, configuration kept
`

// e2e01Hostrun runs the registered package.list_installed script as an
// attached run through hostrun.Attached against the in-process SSH server
// (which runs it with /bin/sh on this machine, like a managed host). env is
// put in front of the unchanged script.
func e2e01Hostrun(t *testing.T, env string) hostrun.Result {
	t.Helper()
	a, ok := actions.Lookup("package.list_installed")
	if !ok {
		t.Fatal("package.list_installed is not registered")
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	srv := hostruntest.Start(t, signer.PublicKey())
	c, err := ssh.Dial("tcp", srv.Addr, &ssh.ClientConfig{User: "nebula", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(srv.HostKey.PublicKey()), Timeout: e2e01CallTimeout})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r, err := hostrun.Attached(t.Context(), c, "e2e01000-0000-4000-8000-000000000001", []byte(`{}`), []byte(env+string(a.Script)), a.Timeout)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// The script's output is accepted by the executor's classifier and parses
// into package records, on a fixture dpkg database and, when present, on
// this machine's own. Before pli01 the plain-text output was classified as
// "stdout is not exactly one JSON document".
func TestE2E01PackageListIsAcceptedByHostrun(t *testing.T) {
	if _, err := exec.LookPath("dpkg-query"); err != nil {
		t.Skip("no dpkg-query on this machine: package.list_installed cannot run here")
	}
	admin := privateDir(t)
	if err := os.WriteFile(filepath.Join(admin, "status"), []byte(e2e01Status), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"info", "updates", "triggers"} {
		if err := os.Mkdir(filepath.Join(admin, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name string
		env  string
		want []string // packages that must be in the inventory
	}{
		{"fixture", "DPKG_ADMINDIR='" + admin + "'; export DPKG_ADMINDIR\n", []string{"openssl", "libssl3", "linux-image-6.1.0-26-amd64"}},
	}
	if fi, err := os.Stat("/var/lib/dpkg/status"); err == nil && fi.Size() > 0 {
		cases = append(cases, struct {
			name string
			env  string
			want []string
		}{"this machine", "unset DPKG_ADMINDIR\n", nil})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := e2e01Hostrun(t, tc.env)
			if r.Class != hostrun.ClassSuccess || r.ExitCode != 0 {
				t.Fatalf("hostrun class %s (%s), exit %d, log %q", r.Class, r.Detail, r.ExitCode, r.Log)
			}
			inv := osdebian.ParseInstalledResult(r.Result, osdebian.ReadStatus{ExitCode: r.ExitCode}, vulnver.DistroDebian)
			if len(inv.Packages) < 1 {
				t.Fatalf("no package records (complete=%v reason=%q dropped=%d)", inv.Complete, inv.Reason, inv.Dropped)
			}
			if tc.want == nil {
				return
			}
			if !inv.Complete || inv.Reason != "" || inv.Dropped != 0 || len(inv.Packages) != len(tc.want) {
				t.Fatalf("complete=%v reason=%q dropped=%d packages=%d, want %d complete", inv.Complete, inv.Reason,
					inv.Dropped, len(inv.Packages), len(tc.want))
			}
			got := map[string]bool{}
			for _, p := range inv.Packages {
				got[p.Name] = true
			}
			for _, w := range tc.want {
				if !got[w] {
					t.Errorf("package %s missing from the inventory %+v", w, inv.Packages)
				}
			}
		})
	}
}
