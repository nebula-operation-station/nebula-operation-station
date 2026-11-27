// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveapi"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
)

// This file tests re-preparation of a template (ADR 0008 D5, PV-03b part
// 2): only a gone, changed or re-pinned template is prepared again; an
// unreadable template refuses with no proposal and an unchanged record.

// fakeTemplatePVE is a pinned TLS PVE API on loopback that answers the
// template config read with whatever reply is set. It accepts only the
// read token and counts every request and every non-GET request.
type fakeTemplatePVE struct {
	srv *httptest.Server
	ep  pvecontract.Endpoint

	mu     sync.Mutex
	reply  func(w http.ResponseWriter, r *http.Request)
	paths  []string
	writes int
}

func newFakeTemplatePVE(t *testing.T, cert tls.Certificate) *fakeTemplatePVE {
	t.Helper()
	f := &fakeTemplatePVE{}
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	f.srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	host, port, err := net.SplitHostPort(f.srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	f.ep = pvecontract.Endpoint{Host: host, Port: uint16(p)}
	return f
}

func (f *fakeTemplatePVE) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.paths = append(f.paths, r.Method+" "+r.URL.Path)
	if r.Method != http.MethodGet {
		f.writes++
	}
	reply := f.reply
	f.mu.Unlock()
	if r.Method != http.MethodGet || r.Header.Get("Authorization") != "PVEAPIToken="+mutReadToken || reply == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	reply(w, r)
}

func (f *fakeTemplatePVE) set(reply func(w http.ResponseWriter, r *http.Request)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reply = reply
}

func (f *fakeTemplatePVE) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.paths...)
}

func (f *fakeTemplatePVE) writeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.writes
}

// replyStatus answers with code and body (Go's standard reason phrase).
func replyStatus(code int, body string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		w.WriteHeader(code)
		_, _ = io.WriteString(w, body)
	}
}

// replyRaw writes the status line "HTTP/1.1 <status>" and body as they
// are, the way PVE puts its error message into the reason phrase.
func replyRaw(status, body string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			w.WriteHeader(http.StatusTeapot)
			return
		}
		c, buf, err := hj.Hijack()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = fmt.Fprintf(buf, "HTTP/1.1 %s\r\nContent-Type: application/json;charset=UTF-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", status, len(body), body)
		_ = buf.Flush()
	}
}

// replyHang never answers; the request ends when the client gives up.
func replyHang(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }

// templateConfigJSON is the PVE reply of a template config with name.
func templateConfigJSON(name string) string {
	return fmt.Sprintf(`{"data":{"digest":%q,"name":%q,"template":1,"cores":2,"memory":"2048","agent":"1","ide2":"local-lvm:cloudinit,media=cdrom","scsi0":"local-lvm:base-9000-disk-0,size=3584M"}}`,
		strings.Repeat("4b", 20), name)
}

// configDigestOf is the digest a reply to the config read must produce:
// SHA-256 of the "data" object with its members in sorted order, as
// TargetState computes it for the records written before this change.
func configDigestOf(t *testing.T, reply string) string {
	t.Helper()
	var env struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal([]byte(reply), &env); err != nil {
		t.Fatal(err)
	}
	canon, err := json.Marshal(env.Data)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(canon)
	return hex.EncodeToString(sum[:])
}

// loopbackTemplateReader is the production client with the remote's
// endpoints replaced by the loopback fake, so the registered remote of the
// mutation environment is read over the real pinned HTTP path.
type loopbackTemplateReader struct {
	c  *pveMutationClient
	ep pvecontract.Endpoint
}

func (l loopbackTemplateReader) TemplateConfig(ctx context.Context, rm executordb.PveRemote, node string, vmid uint64, read pveapi.TokenSupplier) (PveTemplateConfig, error) {
	rm.Endpoints = []pvecontract.Endpoint{l.ep}
	return l.c.TemplateConfig(ctx, rm, node, vmid, read)
}

func goneMessage(node string, vmid uint64) string {
	return fmt.Sprintf("Configuration file 'nodes/%s/qemu-server/%d.conf' does not exist", node, vmid)
}

// TestTemplateReadTellsGoneFromUnreadable: the template read of the
// production client reports "gone" only for a 404 or a 500 with exactly
// the "does not exist" message of the requested node and VMID; a config
// is found with the TargetState digest; every other reply is a read error,
// never "gone". It never sends anything but a GET.
func TestTemplateReadTellsGoneFromUnreadable(t *testing.T) {
	chain := makeTestChain(t)
	f := newFakeTemplatePVE(t, chain.tls)
	c := testMutClient(chain)
	rm := testMutRemote(f.ep)
	read := tokenOf(mutReadToken)
	cfg := templateConfigJSON("tpl-ubuntu-24-04-amd64")
	msg := goneMessage("pve1", 9000)
	nullBody := `{"data":null}`

	cases := []struct {
		name  string
		reply func(http.ResponseWriter, *http.Request)
		found bool
		gone  bool
	}{
		{"config", replyStatus(http.StatusOK, cfg), true, false},
		{"404", replyStatus(http.StatusNotFound, nullBody), false, true},
		{"404 without body", replyStatus(http.StatusNotFound, ""), false, true},
		{"500 exact reason phrase", replyRaw("500 "+msg, nullBody), false, true},
		{"500 exact message in body", replyStatus(http.StatusInternalServerError, `{"data":null,"message":`+strconv.Quote(msg+"\n")+`}`), false, true},
		{"500 message with surrounding whitespace", replyStatus(http.StatusInternalServerError, `{"data":null,"message":`+strconv.Quote("  "+msg+"\n\t")+`}`), false, true},

		{"500 another vmid", replyRaw("500 "+goneMessage("pve1", 9001), nullBody), false, false},
		{"500 another vmid prefix", replyRaw("500 "+goneMessage("pve1", 90001), nullBody), false, false},
		{"500 another node", replyRaw("500 "+goneMessage("pve2", 9000), nullBody), false, false},
		{"500 text before", replyRaw("500 error: "+msg, nullBody), false, false},
		{"500 text after", replyRaw("500 "+msg+" (retry)", nullBody), false, false},
		{"500 body text after", replyStatus(http.StatusInternalServerError, `{"message":`+strconv.Quote(msg+" on purpose")+`}`), false, false},
		{"500 lxc config message", replyRaw("500 Configuration file 'nodes/pve1/lxc/9000.conf' does not exist", nullBody), false, false},
		{"500 other", replyStatus(http.StatusInternalServerError, nullBody), false, false},
		{"500 message not a string", replyStatus(http.StatusInternalServerError, `{"message":["`+msg+`"]}`), false, false},
		{"500 oversize body with message", replyStatus(http.StatusInternalServerError, `{"message":`+strconv.Quote(msg)+`,"pad":"`+strings.Repeat("x", pveTemplateGoneMaxBody)+`"}`), false, false},
		{"500 malformed body", replyStatus(http.StatusInternalServerError, `{"message":`), false, false},
		{"403 with the message", replyRaw("403 "+msg, nullBody), false, false},
		{"401", replyStatus(http.StatusUnauthorized, nullBody), false, false},
		{"502", replyStatus(http.StatusBadGateway, nullBody), false, false},
		{"200 malformed", replyStatus(http.StatusOK, `{"data":{"digest":`), false, false},
		{"200 data null", replyStatus(http.StatusOK, nullBody), false, false},
		{"200 empty config", replyStatus(http.StatusOK, `{"data":{}}`), false, false},
		{"200 config without digest", replyStatus(http.StatusOK, `{"data":{"name":"tpl"}}`), false, false},
		{"200 invalid utf-8", replyStatus(http.StatusOK, "{\"data\":{\"digest\":\"\xff\"}}"), false, false},
		{"200 oversize", replyStatus(http.StatusOK, `{"data":{"digest":"`+strings.Repeat("a", pveMutationMaxReadBytes)+`"}}`), false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f.set(tc.reply)
			got, err := c.TemplateConfig(context.Background(), rm, "pve1", 9000, read)
			switch {
			case tc.found:
				if err != nil || !got.Found || got.Node != "pve1" || got.ConfigDigest != configDigestOf(t, cfg) {
					t.Fatalf("config read = %+v, %v", got, err)
				}
			case tc.gone:
				if err != nil || got.Found || got.ConfigDigest != "" {
					t.Fatalf("gone read = %+v, %v; want found false", got, err)
				}
			default:
				if !errors.Is(err, errPveMutationRead) || got.Found {
					t.Fatalf("read = %+v, %v; want a read error", got, err)
				}
			}
		})
	}
	if f.writeCount() != 0 {
		t.Fatalf("template read sent %d writes", f.writeCount())
	}
	for _, p := range f.requests() {
		if p != "GET /api2/json/nodes/pve1/qemu/9000/config" {
			t.Fatalf("template read requested %q", p)
		}
	}

	t.Run("digest equals TargetState", func(t *testing.T) {
		// A record written from TargetState before this change keeps
		// binding: both reads compute the same digest of the same config.
		f.set(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/status/current") {
				_, _ = io.WriteString(w, `{"data":{"vmid":9000,"status":"stopped"}}`)
				return
			}
			_, _ = io.WriteString(w, cfg)
		})
		live, err := c.TargetState(context.Background(), rm, "qemu", "pve1", 9000, read)
		if err != nil {
			t.Fatal(err)
		}
		got, err := c.TemplateConfig(context.Background(), rm, "pve1", 9000, read)
		if err != nil || got.ConfigDigest != live.ConfigDigest {
			t.Fatalf("template digest %q (%v), TargetState digest %q", got.ConfigDigest, err, live.ConfigDigest)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		f.set(replyHang)
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		if got, err := c.TemplateConfig(ctx, rm, "pve1", 9000, read); !errors.Is(err, errPveMutationRead) || got.Found {
			t.Fatalf("timed-out read = %+v, %v", got, err)
		}
	})
	t.Run("invalid request sends nothing", func(t *testing.T) {
		before := len(f.requests())
		for _, in := range []struct {
			node string
			vmid uint64
			read pveapi.TokenSupplier
		}{{"pve1", 0, read}, {"pve1", 99, read}, {"../pve1", 9000, read}, {"", 9000, read}, {"pve1", 9000, nil}} {
			if _, err := c.TemplateConfig(context.Background(), rm, in.node, in.vmid, in.read); !errors.Is(err, ErrPveMutationRequest) {
				t.Fatalf("TemplateConfig(%q, %d) = %v", in.node, in.vmid, err)
			}
		}
		if n := len(f.requests()); n != before {
			t.Fatalf("invalid requests reached the remote: %d", n-before)
		}
	})
	t.Run("transport error", func(t *testing.T) {
		gone := newFakeTemplatePVE(t, chain.tls)
		gone.srv.Close()
		if got, err := c.TemplateConfig(context.Background(), testMutRemote(gone.ep), "pve1", 9000, read); !errors.Is(err, errPveMutationRead) || got.Found {
			t.Fatalf("read of a closed endpoint = %+v, %v", got, err)
		}
	})
}

// TestTemplateGoneReplyIsBounded: a reason phrase longer than the named
// limit is never "gone", even if it starts with the exact message.
func TestTemplateGoneReplyIsBounded(t *testing.T) {
	gone := pveTemplateGone("pve1", 9000)
	msg := goneMessage("pve1", 9000)
	resp := func(status string, code int, body string) *http.Response {
		return &http.Response{Status: status, StatusCode: code, Body: io.NopCloser(strings.NewReader(body))}
	}
	if !gone(resp("500 "+msg, 500, "")) || !gone(resp("404 Not Found", 404, "")) {
		t.Fatal("exact 500 or 404 not gone")
	}
	if gone(resp("500 "+msg+strings.Repeat(" ", pveTemplateGoneMaxMessage), 500, "")) {
		t.Fatal("overlong reason phrase counted as gone")
	}
	if gone(resp("500 Internal Server Error", 500, `{"message":"`+msg+"\xff"+`"}`)) {
		t.Fatal("invalid UTF-8 body counted as gone")
	}
	for _, code := range []int{200, 400, 403, 410, 501, 502, 503} {
		if gone(resp(strconv.Itoa(code)+" "+msg, code, `{"message":`+strconv.Quote(msg)+`}`)) {
			t.Fatalf("status %d counted as gone", code)
		}
	}
}

// reprepEnv is the image environment whose template reads go through the
// production client to a loopback PVE fake.
type reprepEnv struct {
	*imagesEnv
	tpl *fakeTemplatePVE
}

func newReprepEnv(t *testing.T) *reprepEnv {
	t.Helper()
	e := newImagesEnv(t)
	chain := makeTestChain(t)
	f := newFakeTemplatePVE(t, chain.tls)
	e.client.setTemplateReader(loopbackTemplateReader{c: testMutClient(chain), ep: f.ep})
	return &reprepEnv{imagesEnv: e, tpl: f}
}

// prepareServing prepares req (proposal, approval, run) and serves cfg as
// the new template's config when Prepare reads it back.
func (e *reprepEnv) prepareServing(req PveImagePrepareRequest, cfg string) PveTemplateRecord {
	e.t.Helper()
	approved := e.approveImage(req)
	e.tpl.set(replyStatus(http.StatusOK, cfg))
	rec, err := e.imgs.Prepare(context.Background(), approved)
	if err != nil {
		e.t.Fatal(err)
	}
	return rec
}

func (e *reprepEnv) proposal(req PveImagePrepareRequest) error {
	return e.proposalCtx(context.Background(), req)
}

func (e *reprepEnv) proposalCtx(ctx context.Context, req PveImagePrepareRequest) error {
	mutExecSeq++
	id := fmt.Sprintf("00000000-0000-4000-b000-%012d", mutExecSeq)
	_, _, err := e.imgs.ProposalRequest(ctx, req, id, canonical.RiskHigh, strings.Repeat("c", 64), time.Now().Add(time.Hour))
	return err
}

func (e *reprepEnv) record(key PveTemplateKey) PveTemplateRecord {
	e.t.Helper()
	rec, ok, err := e.store.PveTemplate(key)
	if err != nil || !ok {
		e.t.Fatalf("record of %+v: %v %v", key, ok, err)
	}
	return rec
}

// TestRePrepareAfterTemplateGone: a template deleted in PVE (404, or 500
// with the exact message) fails the binding with ErrPveTemplateNotPrepared;
// a new proposal is accepted and Prepare writes generation 2 with no
// record removal. The old binding stays refused.
func TestRePrepareAfterTemplateGone(t *testing.T) {
	for name, gone := range map[string]func(http.ResponseWriter, *http.Request){
		"404":         replyStatus(http.StatusNotFound, `{"data":null}`),
		"500 message": replyRaw("500 "+goneMessage("pve1", 9000), `{"data":null}`),
	} {
		t.Run(name, func(t *testing.T) {
			e := newReprepEnv(t)
			cfg1 := templateConfigJSON("tpl-ubuntu-24-04-amd64")
			first := e.prepareServing(prepareReq(imgUbuntuID, 9000), cfg1)
			if first.Generation != 1 || first.ConfigDigest != configDigestOf(t, cfg1) {
				t.Fatalf("first record = %+v", first)
			}
			if _, err := e.imgs.BindTemplate(context.Background(), bindingOf(first)); err != nil {
				t.Fatalf("bind of the prepared template: %v", err)
			}
			if err := e.proposal(prepareReq(imgUbuntuID, 9001)); !errors.Is(err, ErrPveImagePrepared) {
				t.Fatalf("proposal while valid: %v", err)
			}

			e.tpl.set(gone)
			if _, err := e.imgs.BindTemplate(context.Background(), bindingOf(first)); !errors.Is(err, ErrPveTemplateNotPrepared) {
				t.Fatalf("bind of a gone template: %v", err)
			}
			cfg2 := templateConfigJSON("tpl-ubuntu-24-04-amd64-2")
			second := e.prepareServing(prepareReq(imgUbuntuID, 9001), cfg2)
			if second.Generation != 2 || second.VMID != 9001 || second.ConfigDigest != configDigestOf(t, cfg2) {
				t.Fatalf("re-preparation record = %+v", second)
			}
			if _, err := e.imgs.BindTemplate(context.Background(), bindingOf(first)); !errors.Is(err, ErrPveTemplateChanged) {
				t.Fatalf("bind of the replaced generation: %v", err)
			}
			if _, err := e.imgs.BindTemplate(context.Background(), bindingOf(second)); err != nil {
				t.Fatalf("bind of generation 2: %v", err)
			}
		})
	}
}

// TestRePrepareAfterTemplateChanged: a template whose config changed in
// PVE fails the binding with ErrPveTemplateChanged and may be prepared
// again (generation 2).
func TestRePrepareAfterTemplateChanged(t *testing.T) {
	e := newReprepEnv(t)
	first := e.prepareServing(prepareReq(imgUbuntuID, 9000), templateConfigJSON("tpl-ubuntu-24-04-amd64"))
	e.tpl.set(replyStatus(http.StatusOK, templateConfigJSON("edited-outside-nos")))
	if _, err := e.imgs.BindTemplate(context.Background(), bindingOf(first)); !errors.Is(err, ErrPveTemplateChanged) {
		t.Fatalf("bind of a changed template: %v", err)
	}
	second := e.prepareServing(prepareReq(imgUbuntuID, 9001), templateConfigJSON("tpl-ubuntu-24-04-amd64-2"))
	if second.Generation != 2 {
		t.Fatalf("re-preparation record = %+v", second)
	}
}

// TestRePrepareAfterRepinNeedsItsOwnApproval: a re-pin bumps the remote's
// trust generation; the old record fails the binding with
// ErrPveRemoteChanged, a new proposal is accepted but runs only after its
// own approval, and Prepare writes generation 2 with the new trust
// generation.
func TestRePrepareAfterRepinNeedsItsOwnApproval(t *testing.T) {
	e := newReprepEnv(t)
	cfg := templateConfigJSON("tpl-ubuntu-24-04-amd64")
	first := e.prepareServing(prepareReq(imgUbuntuID, 9000), cfg)
	rm, ok, err := e.pe.db.GetRemote(mutRemote)
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	if first.TrustGeneration != rm.TrustGeneration {
		t.Fatalf("record trust generation %d, remote %d", first.TrustGeneration, rm.TrustGeneration)
	}
	repinned, err := e.pe.db.RepinRemote(mutRemote, rm.TrustPin, fpHex(makeTestChain(t).ca), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if repinned.TrustGeneration != rm.TrustGeneration+1 {
		t.Fatalf("repin trust generation %d", repinned.TrustGeneration)
	}
	// The template itself is unchanged; only the remote's trust moved.
	if _, err := e.imgs.BindTemplate(context.Background(), bindingOf(first)); !errors.Is(err, ErrPveRemoteChanged) {
		t.Fatalf("bind after re-pin: %v", err)
	}

	// The new proposal is pending: without its own approval it runs
	// nothing and the record stays.
	req := prepareReq(imgUbuntuID, 9001)
	pending := e.propose(req, canonical.RiskLow)
	steps := len(e.client.dispatched())
	unapproved := req
	unapproved.Digest = pending.Digest
	if _, err := e.imgs.Prepare(context.Background(), unapproved); err == nil {
		t.Fatal("re-preparation ran without its own approval")
	}
	if n := len(e.client.dispatched()); n != steps {
		t.Fatalf("unapproved re-preparation dispatched %d steps", n-steps)
	}
	if got := e.record(first.PveTemplateKey); got != first {
		t.Fatalf("record changed by the unapproved run: %+v", got)
	}
	if _, err := e.auth.ApproveCLI(pending.Digest, 0, "admin"); err != nil {
		t.Fatal(err)
	}
	second, err := e.imgs.Prepare(context.Background(), unapproved)
	if err != nil {
		t.Fatal(err)
	}
	if second.Generation != 2 || second.TrustGeneration != repinned.TrustGeneration {
		t.Fatalf("re-preparation record = %+v", second)
	}
	if _, err := e.imgs.BindTemplate(context.Background(), bindingOf(second)); err != nil {
		t.Fatalf("bind of generation 2: %v", err)
	}
}

// TestUnreadableTemplateRefusesReprepare: a template read that fails with
// a transport error, a timeout, a 500, another error status or a malformed
// body is neither "gone" nor "changed": the proposal is refused with no
// permit, nothing is sent to PVE, and the record and its generation stay.
func TestUnreadableTemplateRefusesReprepare(t *testing.T) {
	cases := []struct {
		name    string
		reply   func(http.ResponseWriter, *http.Request)
		timeout bool
		closed  bool
	}{
		{name: "transport error", closed: true},
		{name: "timeout", reply: replyHang, timeout: true},
		{name: "500", reply: replyStatus(http.StatusInternalServerError, `{"data":null}`)},
		{name: "500 message of another vmid", reply: replyRaw("500 "+goneMessage("pve1", 9001), `{"data":null}`)},
		{name: "500 message of another node", reply: replyRaw("500 "+goneMessage("pve2", 9000), `{"data":null}`)},
		{name: "500 message with extra text", reply: replyRaw("500 "+goneMessage("pve1", 9000)+" (cluster)", `{"data":null}`)},
		{name: "503", reply: replyStatus(http.StatusServiceUnavailable, `{"data":null}`)},
		{name: "malformed body", reply: replyStatus(http.StatusOK, `{"data":{"digest":"`)},
		{name: "oversize body", reply: replyStatus(http.StatusOK, `{"data":{"x":"`+strings.Repeat("a", pveMutationMaxReadBytes)+`"}}`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newReprepEnv(t)
			first := e.prepareServing(prepareReq(imgUbuntuID, 9000), templateConfigJSON("tpl-ubuntu-24-04-amd64"))
			steps := len(e.client.dispatched())
			if tc.closed {
				e.tpl.srv.Close()
			} else {
				e.tpl.set(tc.reply)
			}
			ctx := context.Background()
			if tc.timeout {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 300*time.Millisecond)
				defer cancel()
			}
			err := e.proposalCtx(ctx, prepareReq(imgUbuntuID, 9001))
			if !errors.Is(err, ErrPveTemplateUnreadable) {
				t.Fatalf("proposal with an unreadable template: %v", err)
			}
			for _, fallThrough := range []error{ErrPveTemplateNotPrepared, ErrPveTemplateChanged, ErrPveRemoteChanged} {
				if errors.Is(err, fallThrough) {
					t.Fatalf("read error %v matches %v", err, fallThrough)
				}
			}
			if !strings.Contains(e.logs.String(), "pve_template_unreadable") {
				t.Fatal("unreadable template not audited")
			}
			// Provisioning gets the same refusal, never "changed".
			if _, err := e.imgs.BindTemplate(context.Background(), bindingOf(first)); !errors.Is(err, ErrPveTemplateUnreadable) || errors.Is(err, ErrPveTemplateChanged) {
				t.Fatalf("bind with an unreadable template: %v", err)
			}
			if got := e.record(first.PveTemplateKey); got != first {
				t.Fatalf("record changed: %+v", got)
			}
			if n := len(e.client.dispatched()); n != steps {
				t.Fatalf("refused proposal dispatched %d steps", n-steps)
			}
			if e.tpl.writeCount() != 0 {
				t.Fatal("template read sent a write")
			}
		})
	}
}

// TestTemplateReaderMissingFailsClosed: a client that cannot read
// templates binds nothing and proposes nothing for a recorded key.
func TestTemplateReaderMissingFailsClosed(t *testing.T) {
	e := newImagesEnv(t)
	first := e.prepare(prepareReq(imgUbuntuID, 9000))
	e.m.Client = e.client.fakeMutClient // no TemplateConfig
	if _, err := e.imgs.BindTemplate(context.Background(), bindingOf(first)); !errors.Is(err, ErrPveTemplateUnreadable) {
		t.Fatalf("bind without a template reader: %v", err)
	}
	if _, _, err := e.imgs.ProposalRequest(context.Background(), prepareReq(imgUbuntuID, 9001), "00000000-0000-4000-b000-999999999997", canonical.RiskHigh,
		strings.Repeat("c", 64), time.Now().Add(time.Hour)); !errors.Is(err, ErrPveTemplateUnreadable) {
		t.Fatalf("proposal without a template reader: %v", err)
	}
}

// TestBlockedOrRemovedRemoteRefusesReprepareBeforeAnyPVEChange: with a
// blocked or removed remote the binding falls through with
// ErrPveRemoteChanged, but the proposal is refused by the mutation's
// remote check, and an approved re-preparation is refused by Run before it
// reads or changes anything in PVE (ADR 0008 D5: Run checks the remote
// first). The record stays.
func TestBlockedOrRemovedRemoteRefusesReprepareBeforeAnyPVEChange(t *testing.T) {
	for name, tc := range map[string]struct {
		change func(db *executordb.DB) error
		want   error
	}{
		"blocked": {func(db *executordb.DB) error { _, err := db.BlockRemote(mutRemote, "pin mismatch", "executor"); return err }, ErrPveRemoteChanged},
		"removed": {func(db *executordb.DB) error { _, err := db.RemoveRemote(mutRemote, "admin"); return err }, executordb.ErrRemoteNotFound},
	} {
		t.Run(name, func(t *testing.T) {
			e := newReprepEnv(t)
			first := e.prepareServing(prepareReq(imgUbuntuID, 9000), templateConfigJSON("tpl-ubuntu-24-04-amd64"))
			// The template is gone and a re-preparation was approved
			// while the remote was still active.
			e.tpl.set(replyStatus(http.StatusNotFound, `{"data":null}`))
			approved := e.approveImage(prepareReq(imgUbuntuID, 9001))
			steps := len(e.client.dispatched())
			reads := len(e.tpl.requests())
			if err := tc.change(e.pe.db); err != nil {
				t.Fatal(err)
			}

			if _, err := e.imgs.BindTemplate(context.Background(), bindingOf(first)); !errors.Is(err, ErrPveRemoteChanged) {
				t.Fatalf("bind on a %s remote: %v", name, err)
			}
			if err := e.proposal(prepareReq(imgUbuntuID, 9002)); !errors.Is(err, tc.want) {
				t.Fatalf("proposal on a %s remote: %v", name, err)
			}
			if _, err := e.imgs.Prepare(context.Background(), approved); !errors.Is(err, tc.want) {
				t.Fatalf("approved prepare on a %s remote: %v", name, err)
			}
			if n := len(e.client.dispatched()); n != steps {
				t.Fatalf("%s remote: %d steps dispatched", name, n-steps)
			}
			if n := len(e.tpl.requests()); n != reads {
				t.Fatalf("%s remote: %d template reads", name, n-reads)
			}
			if strings.Contains(e.logs.String(), "pve_template_unrecorded") {
				t.Fatalf("%s remote: refused before Run but audited as built", name)
			}
			if got := e.record(first.PveTemplateKey); got != first {
				t.Fatalf("record changed: %+v", got)
			}
		})
	}
}

// TestPrepareAuditsGoneTemplateAfterRun: when the template Prepare just
// built reads back as gone (404 or 500 with the exact message), Prepare
// writes the template_unreadable audit line and no record; "gone" there is
// never "not prepared".
func TestPrepareAuditsGoneTemplateAfterRun(t *testing.T) {
	for name, gone := range map[string]func(http.ResponseWriter, *http.Request){
		"404":         replyStatus(http.StatusNotFound, `{"data":null}`),
		"500 message": replyRaw("500 "+goneMessage("pve1", 9000), `{"data":null}`),
	} {
		t.Run(name, func(t *testing.T) {
			e := newReprepEnv(t)
			req := e.approveImage(prepareReq(imgUbuntuID, 9000))
			e.tpl.set(gone)
			if _, err := e.imgs.Prepare(context.Background(), req); err == nil {
				t.Fatal("prepare recorded a template that reads back as gone")
			}
			logs := e.logs.String()
			if !strings.Contains(logs, "pve_template_unrecorded") || !strings.Contains(logs, "template_unreadable") {
				t.Fatalf("missing unrecorded audit: %s", logs)
			}
			if _, ok, err := e.store.PveTemplate(req.PveTemplateKey); ok || err != nil {
				t.Fatalf("record written: %v %v", ok, err)
			}
		})
	}
}

// TestGoneTemplateVMIDReusedByAnotherGuest: after the template is deleted
// and its VMID is reused by another guest, the old record never binds that
// guest (its config differs: ErrPveTemplateChanged), re-preparation on a
// free VMID works, and provisioning cannot reserve the reused VMID while
// the guest uses it (ErrPveVMIDTaken).
func TestGoneTemplateVMIDReusedByAnotherGuest(t *testing.T) {
	e := newReprepEnv(t)
	first := e.prepareServing(prepareReq(imgUbuntuID, 9000), templateConfigJSON("tpl-ubuntu-24-04-amd64"))
	e.tpl.set(replyStatus(http.StatusOK, fmt.Sprintf(`{"data":{"digest":%q,"name":"web","cores":4,"memory":"8192","scsi0":"local-lvm:vm-9000-disk-0,size=32G"}}`, strings.Repeat("7d", 20))))
	if _, err := e.imgs.BindTemplate(context.Background(), bindingOf(first)); !errors.Is(err, ErrPveTemplateChanged) {
		t.Fatalf("bind of the reused VMID: %v", err)
	}
	vmids := &FilePveVMIDStore{Path: t.TempDir() + "/pve-vmids.json"}
	now := time.Now()
	if _, err := vmids.ReserveVMID(mutRemote, "00000000-0000-4000-b000-999999999996", first.VMID, map[uint64]bool{first.VMID: true}, now.Add(time.Hour), now); !errors.Is(err, ErrPveVMIDTaken) {
		t.Fatalf("reserve the reused VMID: %v", err)
	}
	second := e.prepareServing(prepareReq(imgUbuntuID, 9001), templateConfigJSON("tpl-ubuntu-24-04-amd64-2"))
	if second.Generation != 2 || second.VMID != 9001 {
		t.Fatalf("re-preparation record = %+v", second)
	}
}

// Compile-time checks: the production client and the test fake read
// templates.
var (
	_ PveTemplateReader = (*pveMutationClient)(nil)
	_ PveTemplateReader = (*imageClient)(nil)
)
