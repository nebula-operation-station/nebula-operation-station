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
//   - The server is the nebula-server binary itself, built once from
//     ./cmd/nebula-server with the go tool and started with -config on a
//     server.json read by its own serverconfig.LoadWithFlags: the whole
//     composition of runServer in main.go (api.New, newVulnAPI, api.Mount,
//     api.MountOps, the session gate, webServer with middleware.NewServer
//     and its origin check and OriginExempt rule) is what answers, so a
//     regression in that wiring fails here. The vuln token "vuln-agent" is
//     limited to source_addresses ["127.0.0.1"]. No executor runs (the
//     server keeps connecting in the background, as after a reboot).
//   - nosclient talks https only and nebula-server serves plain HTTP behind
//     a TLS terminator, so the test puts a byte-level TLS front in front of
//     it (e2e01TLSFront): it decrypts and copies the bytes unchanged, and
//     dials the server from the client's own source address, so the
//     server's source_addresses check sees the real client address.
//   - The agent side is internal/vulnagent/nosclient (and the agent-config
//     reader of internal/vulnagent/run) with the token file, the pinned CA
//     and no Origin header: every call one agent run makes, including a
//     batch with a finding the server must refuse as input. After the
//     server has shut down, the completed run is read back from its
//     server.db, and that the refused finding was not stored.
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
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/osdebian"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun/hostruntest"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnagent/nosclient"
	vulnrun "github.com/nebula-operation-station/nebula-operation-station/internal/vulnagent/run"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
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
	// e2e01BuildTimeout bounds building the server binary. A cold build
	// (empty build cache, started from inside go test ./... beside other
	// packages) can take minutes; the test's own deadline still applies.
	e2e01BuildTimeout = 8 * time.Minute
	// e2e01StartTimeout bounds starting the built binary until it logs
	// "started" (no build in it).
	e2e01StartTimeout = 30 * time.Second
	// e2e01StopTimeout bounds the graceful shutdown after SIGINT.
	e2e01StopTimeout = 20 * time.Second
	// e2e01CallTimeout bounds every request of the test.
	e2e01CallTimeout = 10 * time.Second
	// e2e01MaxAnswer bounds what a raw response is read up to.
	e2e01MaxAnswer = 64 << 10
	// e2e01MaxLogLine bounds one log line of the server read by the test.
	e2e01MaxLogLine = 1 << 20
	// e2e01ForeignSource is a loopback address outside the token's
	// source_addresses (Linux routes all of 127.0.0.0/8 to lo).
	e2e01ForeignSource = "127.0.0.2"
	// e2e01OriginRefusal is the security middleware's 403 body.
	e2e01OriginRefusal = "origin not allowed"
	// e2e01Matcher is the matcher version of the agent run.
	e2e01Matcher = "e2e01-1.0.0"
	// e2e01CVE is the vulnerability of the run's one finding.
	e2e01CVE = "CVE-2026-0101"
	// e2e01Host is the host subject of the run's one finding.
	e2e01Host = "web01"
	// e2e01Assessment is the finding's assessment text.
	e2e01Assessment = "E2E01-ASSESSMENT-TEXT"
)

// e2e01Env is a running server and the agent's files.
type e2e01Env struct {
	t         *testing.T
	base      string // https://127.0.0.1:port (the TLS front)
	caFile    string // the server certificate, pinned
	tokenFile string // the agent token, mode 0600
	dataDir   string // the server's data_dir
	caPool    *x509.CertPool
	srv       *e2e01Process
}

// with returns a copy of e that reports to t (for subtests).
func (e *e2e01Env) with(t *testing.T) *e2e01Env {
	c := *e
	c.t = t
	return &c
}

// e2e01Server builds nebula-server, writes server.json, the TLS key pair
// and the token file into a private directory, starts the binary and puts
// the TLS front in front of it. The server stops when t ends (or earlier
// through e.srv.stop).
func e2e01Server(t *testing.T) *e2e01Env {
	t.Helper()
	dir := privateDir(t)
	bin := e2e01Build(t, dir)
	certPEM, keyPEM, err := e2e01Cert()
	if err != nil {
		t.Fatal(err)
	}
	listen, err := e2e01FreeAddr()
	if err != nil {
		t.Fatal(err)
	}
	e, err := e2e01Files(dir, listen, certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	e.t = t
	e.srv, err = e2e01Start(bin, filepath.Join(dir, "server.json"))
	if err != nil {
		t.Fatalf("start the server: %v", err)
	}
	t.Cleanup(func() {
		if err := e.srv.stop(); err != nil {
			t.Errorf("stop the server: %v", err)
		}
	})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	e.base = "https://" + e2e01TLSFront(t, listen, cert)
	return e
}

// e2e01GoFlags returns GOFLAGS for the nested go build: the caller's flags
// unchanged, plus -mod=readonly and -buildvcs=false where the caller set no
// -mod or -buildvcs (nothing in go.mod or go.sum may change, and the build
// must not depend on running git).
func e2e01GoFlags(caller string) string {
	flags := strings.Fields(caller)
	hasMod, hasVCS := false, false
	for _, f := range flags {
		hasMod = hasMod || strings.HasPrefix(f, "-mod=")
		hasVCS = hasVCS || f == "-buildvcs" || strings.HasPrefix(f, "-buildvcs=")
	}
	if !hasMod {
		flags = append(flags, "-mod=readonly")
	}
	if !hasVCS {
		flags = append(flags, "-buildvcs=false")
	}
	return strings.Join(flags, " ")
}

// e2e01Build builds ./cmd/nebula-server into dir with the go tool
// (GOPROXY=off, so nothing is fetched; CGO_ENABLED=0 like make build) and
// returns the binary's path. As root it builds in a private cache, so a
// privileged run leaves no root-owned files in the caller's cache.
func e2e01Build(t *testing.T, dir string) string {
	t.Helper()
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("the go tool is needed to build the server: %v", err)
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), e2e01BuildTimeout)
	defer cancel()
	if dl, ok := t.Deadline(); ok {
		// Leave the test time to report a build that runs out of time.
		var c2 context.CancelFunc
		ctx, c2 = context.WithDeadline(ctx, dl.Add(-30*time.Second))
		defer c2()
	}
	bin := filepath.Join(dir, "nebula-server")
	cmd := exec.CommandContext(ctx, goTool, "build", "-o", bin, "./cmd/nebula-server")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOPROXY=off", "CGO_ENABLED=0", "GOFLAGS="+e2e01GoFlags(os.Getenv("GOFLAGS")))
	if os.Geteuid() == 0 {
		cmd.Env = append(cmd.Env, "GOCACHE="+filepath.Join(dir, "gocache"))
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build ./cmd/nebula-server: %v\n%s", err, out)
	}
	return bin
}

// e2e01FreeAddr returns a loopback address with a port that was free a
// moment ago (nebula-server logs its config listen value, so the test
// needs a fixed port to configure).
func e2e01FreeAddr() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	addr := ln.Addr().String()
	return addr, ln.Close()
}

// e2e01Files writes the server's and the agent's files into dir.
func e2e01Files(dir, listen string, certPEM, keyPEM []byte) (*e2e01Env, error) {
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
	e.dataDir = filepath.Join(dir, "data")
	for _, d := range []string{e.dataDir, filepath.Join(dir, "discovery"), filepath.Join(dir, "pve")} {
		if err := os.Mkdir(d, 0o700); err != nil {
			return nil, err
		}
	}
	// The vuln token as server.json holds it (docs: api.tokens).
	cfg := map[string]any{
		"listen":          listen,
		"public_origin":   e2e01Origin,
		"data_dir":        e.dataDir,
		"discovery_dir":   filepath.Join(dir, "discovery"),
		"pve_spool_dir":   filepath.Join(dir, "pve"),
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

// e2e01Process is a running nebula-server.
type e2e01Process struct {
	cmd    *exec.Cmd
	log    *syncBuffer
	exited chan struct{}
	err    error // cmd.Wait's result, set before exited closes
	once   sync.Once
	stopEr error
}

// e2e01Start starts bin with -config cfgFile and returns once it has logged
// "started" (it then listens), or with the error and its log when it ends
// or does not start within e2e01StartTimeout.
func e2e01Start(bin, cfgFile string) (*e2e01Process, error) {
	p := &e2e01Process{log: &syncBuffer{}, exited: make(chan struct{})}
	p.cmd = exec.Command(bin, "-config", cfgFile)
	p.cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + filepath.Dir(cfgFile)}
	stderr, err := p.cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	p.cmd.Stdout = p.log
	if err := p.cmd.Start(); err != nil {
		return nil, err
	}
	started := make(chan struct{})
	logDone := make(chan struct{})
	go func() {
		defer close(logDone)
		sc := bufio.NewScanner(stderr)
		sc.Buffer(make([]byte, 64<<10), e2e01MaxLogLine)
		seen := false
		for sc.Scan() {
			line := sc.Bytes()
			_, _ = p.log.Write(append(append([]byte{}, line...), '\n'))
			var rec struct {
				Msg string `json:"msg"`
			}
			if !seen && json.Unmarshal(line, &rec) == nil && rec.Msg == "started" {
				seen = true
				close(started)
			}
		}
		_, _ = io.Copy(io.Discard, stderr)
	}()
	go func() {
		<-logDone
		p.err = p.cmd.Wait()
		close(p.exited)
	}()
	select {
	case <-started:
		return p, nil
	case <-p.exited:
		return nil, fmt.Errorf("nebula-server ended before it started (%v):\n%s", p.err, p.log.String())
	case <-time.After(e2e01StartTimeout):
		_ = p.cmd.Process.Kill()
		<-p.exited
		return nil, fmt.Errorf("nebula-server did not start within %s:\n%s", e2e01StartTimeout, p.log.String())
	}
}

// stop sends SIGINT (main's signal.NotifyContext) and waits for the
// graceful shutdown; it kills the process when that takes too long. It
// returns an error unless the server exited cleanly; later calls return
// the first call's result.
func (p *e2e01Process) stop() error {
	p.once.Do(func() {
		if err := p.cmd.Process.Signal(os.Interrupt); err != nil && !errors.Is(err, os.ErrProcessDone) {
			p.stopEr = err
		}
		select {
		case <-p.exited:
			if p.err != nil && p.stopEr == nil {
				p.stopEr = fmt.Errorf("nebula-server exited with %v:\n%s", p.err, p.log.String())
			}
		case <-time.After(e2e01StopTimeout):
			_ = p.cmd.Process.Kill()
			<-p.exited
			p.stopEr = fmt.Errorf("nebula-server did not shut down within %s:\n%s", e2e01StopTimeout, p.log.String())
		}
	})
	return p.stopEr
}

// e2e01TLSFront listens on 127.0.0.1 with TLS (cert) and copies every
// decrypted connection byte for byte to backend, dialled from the client's
// own source address. It returns its address; it stops when t ends.
func e2e01TLSFront(t *testing.T, backend string, cert tls.Certificate) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var (
		mu    sync.Mutex
		conns = map[net.Conn]struct{}{}
		wg    sync.WaitGroup
	)
	track := func(c net.Conn) bool {
		mu.Lock()
		defer mu.Unlock()
		if conns == nil {
			return false
		}
		conns[c] = struct{}{}
		return true
	}
	tl := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	wg.Go(func() {
		for {
			c, err := tl.Accept()
			if err != nil {
				return
			}
			if !track(c) {
				c.Close()
				return
			}
			wg.Go(func() { e2e01Pipe(c, backend, track) })
		}
	})
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		for c := range conns {
			c.Close()
		}
		conns = nil
		mu.Unlock()
		wg.Wait()
	})
	return ln.Addr().String()
}

// e2e01Pipe copies between the TLS connection c and a new connection to
// backend from c's source address until either side ends.
func e2e01Pipe(c net.Conn, backend string, track func(net.Conn) bool) {
	defer c.Close()
	src, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return
	}
	d := net.Dialer{Timeout: e2e01CallTimeout, LocalAddr: &net.TCPAddr{IP: src.IP}}
	b, err := d.Dial("tcp", backend)
	if err != nil {
		return
	}
	defer b.Close()
	if !track(b) {
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(b, c); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, b); done <- struct{}{} }()
	<-done
	c.Close()
	b.Close()
	<-done
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
	req := nosclient.StartRequest{MatcherVersion: e2e01Matcher}
	at := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	for _, s := range vulnListedSources {
		req.Sources = append(req.Sources, nosclient.SourceSnapshot{SourceID: s.ID, SnapshotID: "snap-" + s.ID,
			Integrity: vulnfinding.IntegrityNone, DateKind: nosclient.DateKindData, ContentDate: at})
	}
	return req
}

// e2e01BatchBody is a findings batch (batch_seq 1) as the agent sends it:
// host web01 complete in one part, with one Debian tracker finding for
// openssl.
func e2e01BatchBody() (string, error) {
	b, err := json.Marshal(map[string]any{
		"batch_seq": 1,
		"subjects":  []any{map[string]any{"subject_kind": "host", "subject_ref": map[string]any{"id": e2e01Host}, "part": 1, "last_part": true}},
		"findings": []any{map[string]any{
			"subject_kind":  "host",
			"subject_ref":   map[string]any{"id": e2e01Host},
			"ecosystem":     "debian:bookworm",
			"component":     map[string]any{"source_package": "openssl", "source_version": "3.0.15-1~deb12u1"},
			"vuln":          map[string]any{"id": e2e01CVE},
			"fix":           map[string]any{"state": "fixed", "version": "3.0.16-1~deb12u1"},
			"tracker_state": "fixed",
			"match_basis":   "distro_tracker",
			"evidence": map[string]any{"matcher_version": e2e01Matcher,
				"basis_sources": []any{map[string]any{"source_id": "debian-tracker", "snapshot_id": "snap-debian-tracker", "integrity": "none"}}},
			"assessment": map[string]any{"text": e2e01Assessment},
		}},
	})
	return string(b), err
}

// --- the agent's run over the real chain ---

// TestE2E01VulnAgentOverRealHTTP starts the server once (one build) and
// runs the agent's calls and the refusals against it, then stops it and
// reads back what the agent's run stored.
func TestE2E01VulnAgentOverRealHTTP(t *testing.T) {
	e := e2e01Server(t)
	ran := t.Run("AgentRunPassesTheRealHTTPChain", func(t *testing.T) { e2e01AgentRun(t, e.with(t)) })
	t.Run("WrongTokenIsUnauthorized", func(t *testing.T) { e2e01WrongToken(t, e.with(t)) })
	t.Run("ForeignSourceAddressIsForbidden", func(t *testing.T) { e2e01ForeignSourceRefused(t, e.with(t)) })
	t.Run("BrowserPostIsForbidden", func(t *testing.T) { e2e01BrowserPost(t, e.with(t)) })
	if err := e.srv.stop(); err != nil {
		t.Fatalf("stop the server: %v", err)
	}
	if !ran {
		t.Fatal("the agent run failed; nothing to read back")
	}
	t.Run("StoredRunReadBack", func(t *testing.T) { e2e01ReadBack(t, e.with(t)) })
}

// Every call of one agent run goes through the server's real HTTP chain
// and is answered by the API, not by the origin check: the agent settings
// read, the inventory export (GET), the run start, a findings batch and
// the run completion (POST with the bearer token, no Origin header).
// Before ao01 every POST here was refused by the origin check with 403.
//
// The inventory export of nebula-server is empty by design for now
// (vulnInventory in cmd/nebula-server/vuln.go: NOS does not store parsed
// package lists yet), so a batch with a finding is refused by the API as
// input (its subject is not in the snapshot) and the batch that covers the
// empty snapshot is accepted. Once the server exports packages, the batch
// with the finding is the one to accept and read back.
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
	// The finding's subject is not in the (empty) snapshot. nosclient
	// would not send such a batch, so it goes out as the agent's request
	// would (bearer, no Origin) and the server must read it and refuse it
	// as input: nothing of it is stored (e2e01ReadBack).
	body, err := e2e01BatchBody()
	if err != nil {
		t.Fatal(err)
	}
	code, answer := e.raw(http.MethodPost, api.VulnPrefix+"runs/"+run.ID+"/findings", "",
		map[string]string{"Authorization": "Bearer " + e2e01Token, "Content-Type": "application/json"}, body)
	if code != http.StatusUnprocessableEntity || !strings.Contains(answer, "not in the run's inventory snapshot") {
		t.Fatalf("POST findings batch on a subject outside the snapshot: %d %q, want the API's 422", code, answer)
	}
	// The batch that covers the snapshot is accepted.
	res, err := run.Submit(ctx, nosclient.Batch{Seq: 2})
	if err != nil {
		t.Fatalf("POST findings batch (bearer, no Origin): %v", err)
	}
	if res.BatchSeq != 2 || res.Rejected != 0 || res.Opened != 0 {
		t.Fatalf("batch result %+v, want seq 2, nothing opened or rejected", res)
	}
	if _, err := run.Complete(ctx); err != nil {
		t.Fatalf("POST complete run (bearer, no Origin): %v", err)
	}
}

// What the agent's run wrote is in the server's database: the run is
// completed just now, and the refused finding was not stored. A completion
// answered 2xx but not stored, or a refused batch stored in part, fails
// here.
func e2e01ReadBack(t *testing.T, e *e2e01Env) {
	db, err := serverdb.Open(filepath.Join(e.dataDir, "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	st, err := vulnstore.New(db, vulnstore.Config{Sources: vulnListedSources, Tier: vulnTierOf,
		Classifier: &viewClassifier{view: map[vulnstore.Subject]map[string]string{}}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := e.ctx()
	done, err := st.LastComplete(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if done.IsZero() || time.Since(done) > time.Hour {
		t.Fatalf("last completed run at %v, want the agent's run of just now", done)
	}
	fs, more, err := st.List(ctx, vulnstore.ListQuery{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 || more {
		t.Fatalf("stored findings %+v (more %v), want none: the only finding was refused", fs, more)
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

// The origin check stays for browsers and for everything outside the
// token API: a POST without Origin and without a token, a POST that
// carries the session cookie (with or without a bearer header), and a
// bearer POST without a cookie to a page or to the traffic-map model
// (which stays on the session chain) are refused by the middleware with
// 403. A GET is not state-changing and is not refused by it.
func e2e01BrowserPost(t *testing.T, e *e2e01Env) {
	cookie := auth.CookieName + "=e2e01-session"
	bearer := "Bearer " + e2e01Token
	cases := []struct {
		name   string
		path   string
		header map[string]string
	}{
		{"api, no token", "/api/v1/vuln/runs", map[string]string{"Content-Type": "application/json"}},
		{"page, no token", "/assistant/ops/questions", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}},
		{"api, session cookie", "/api/v1/vuln/runs", map[string]string{"Cookie": cookie, "Content-Type": "application/json"}},
		{"api, session cookie and bearer", "/api/v1/vuln/runs", map[string]string{"Cookie": cookie,
			"Authorization": bearer, "Content-Type": "application/json"}},
		{"api, foreign origin", "/api/v1/vuln/runs", map[string]string{"Origin": "https://evil.example", "Content-Type": "application/json"}},
		{"page, bearer without cookie", "/assistant/ops/questions", map[string]string{"Authorization": bearer,
			"Content-Type": "application/x-www-form-urlencoded"}},
		{"page outside the api prefix, bearer without cookie", "/api-v1/vuln/runs", map[string]string{"Authorization": bearer,
			"Content-Type": "application/json"}},
		{"traffic-map model, bearer without cookie", "/api/v1/trafficmap", map[string]string{"Authorization": bearer,
			"Content-Type": "application/json"}},
		{"traffic-map model below, bearer without cookie", "/api/v1/trafficmap/model", map[string]string{"Authorization": bearer,
			"Content-Type": "application/json"}},
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

// The nested build keeps the caller's GOFLAGS and only adds what is unset.
func TestE2E01GoFlagsExtendTheCallers(t *testing.T) {
	for in, want := range map[string]string{
		"":                           "-mod=readonly -buildvcs=false",
		"-mod=mod":                   "-mod=mod -buildvcs=false",
		"-mod=vendor -buildvcs=true": "-mod=vendor -buildvcs=true",
		"-trimpath -buildvcs":        "-trimpath -buildvcs -mod=readonly",
		" -race  -tags=x ":           "-race -tags=x -mod=readonly -buildvcs=false",
	} {
		if got := e2e01GoFlags(in); got != want {
			t.Errorf("e2e01GoFlags(%q) = %q, want %q", in, got, want)
		}
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

// e2e01FakeDpkgQuery is a dpkg-query that prints e2e01Status as the
// script's dpkg-query -W --showformat does on it (P records), for machines
// without dpkg.
const e2e01FakeDpkgQuery = `#!/bin/sh
printf 'P\tinstalled\topenssl\tamd64\t3.0.15-1~deb12u1\topenssl\t3.0.15-1~deb12u1\t\t.\n'
printf 'P\tinstalled\tlibssl3\tamd64\t3.0.15-1~deb12u1\topenssl\t3.0.15-1~deb12u1\t\t.\n'
printf 'P\tinstalled\tlinux-image-6.1.0-26-amd64\tamd64\t6.1.112-1\tlinux-signed-amd64\t6.1.112+1\tlinux (= 6.1.112-1)\t.\n'
printf 'P\tconfig-files\toldtool\tamd64\t1.0-1\toldtool\t1.0-1\t\t.\n'
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
// into package records. Before pli01 the plain-text output was classified
// as "stdout is not exactly one JSON document".
//
// The fake dpkg-query case runs everywhere. With dpkg-query on this
// machine the real one also reads the fixture dpkg database and this
// machine's own; in CI (CI set, Debian/Ubuntu runners) a missing
// dpkg-query fails the test instead of narrowing it.
func TestE2E01PackageListIsAcceptedByHostrun(t *testing.T) {
	fixture := []string{"openssl", "libssl3", "linux-image-6.1.0-26-amd64"}
	fakeBin := privateDir(t)
	if err := os.WriteFile(filepath.Join(fakeBin, "dpkg-query"), []byte(e2e01FakeDpkgQuery), 0o700); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		env  string
		want []string // packages that must be in the inventory
	}{
		{"fake dpkg-query", "PATH='" + fakeBin + "':\"$PATH\"; export PATH\n", fixture},
	}
	if _, err := exec.LookPath("dpkg-query"); err == nil {
		admin := privateDir(t)
		if err := os.WriteFile(filepath.Join(admin, "status"), []byte(e2e01Status), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, d := range []string{"info", "updates", "triggers"} {
			if err := os.Mkdir(filepath.Join(admin, d), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		cases = append(cases, struct {
			name string
			env  string
			want []string
		}{"fixture", "DPKG_ADMINDIR='" + admin + "'; export DPKG_ADMINDIR\n", fixture})
		if fi, err := os.Stat("/var/lib/dpkg/status"); err == nil && fi.Size() > 0 {
			cases = append(cases, struct {
				name string
				env  string
				want []string
			}{"this machine", "unset DPKG_ADMINDIR\n", nil})
		}
	} else if os.Getenv("CI") != "" {
		t.Fatalf("no dpkg-query on this CI runner: the real package.list_installed run cannot be checked: %v", err)
	} else {
		t.Logf("no dpkg-query on this machine: only the fake dpkg-query case runs (%v)", err)
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
