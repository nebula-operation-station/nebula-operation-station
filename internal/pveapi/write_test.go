// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	upidClone    = "UPID:pve1:00001234:00ABCDEF:6900A000:qmclone:9000:nos@pve!action:"
	upidResize   = "UPID:pve1:00001234:00ABCDEF:6900A000:resize:120:nos@pve!action:"
	upidStart    = "UPID:pve1:00001234:00ABCDEF:6900A000:qmstart:120:nos@pve!action:"
	upidTemplate = "UPID:pve1:00001234:00ABCDEF:6900A000:qmtemplate:9000:nos@pve!action:"
	upidConfig   = "UPID:pve1:00001234:00ABCDEF:6900A000:qmconfig:120:nos@pve!action:"
	upidDownload = "UPID:pve1:00001234:00ABCDEF:6900A000:download:jammy.qcow2:nos@pve!action:"
)

// recordedRequest is one request seen by the fake PVE write server.
type recordedRequest struct {
	method string
	path   string
	auth   string
	ctype  string
	form   url.Values
}

// fakeWriteServer answers every request with a fixed status and body and
// records what it received.
type fakeWriteServer struct {
	mu     sync.Mutex
	reqs   []recordedRequest
	status int
	body   string
}

func (f *fakeWriteServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	form, _ := url.ParseQuery(string(raw))
	f.mu.Lock()
	f.reqs = append(f.reqs, recordedRequest{
		method: r.Method, path: r.URL.Path, auth: r.Header.Get("Authorization"),
		ctype: r.Header.Get("Content-Type"), form: form,
	})
	status, body := f.status, f.body
	f.mu.Unlock()
	if status == 0 {
		status = http.StatusOK
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func (f *fakeWriteServer) only(t *testing.T) recordedRequest {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.reqs) != 1 {
		t.Fatalf("requests = %d, want 1", len(f.reqs))
	}
	return f.reqs[0]
}

func (f *fakeWriteServer) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.reqs)
}

func newTestWriter(t *testing.T, f http.Handler) *Writer {
	t.Helper()
	ts := httptest.NewServer(f)
	t.Cleanup(ts.Close)
	w, err := NewWriter(ts.URL, ts.Client(), func(context.Context) (string, error) { return testToken, nil }, 5*time.Second)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	return w
}

func upidBody(upid string) string { return `{"data":"` + upid + `"}` }

func TestNewWriterRejectsBadInput(t *testing.T) {
	tok := func(context.Context) (string, error) { return testToken, nil }
	for _, base := range []string{
		"", "ftp://pve:8006", "pve:8006", "https://pve:8006/api2/json", "https://pve:8006?x=1",
		"https://pve:8006#f", "https://user:pw@pve:8006",
	} {
		if _, err := NewWriter(base, http.DefaultClient, tok, 0); err == nil {
			t.Errorf("NewWriter(%q): want error", base)
		}
	}
	if _, err := NewWriter("https://pve:8006", nil, tok, 0); err == nil {
		t.Error("nil http client: want error")
	}
	if _, err := NewWriter("https://pve:8006", http.DefaultClient, nil, 0); err == nil {
		t.Error("nil token: want error")
	}
	if _, err := NewWriter("https://pve:8006/", http.DefaultClient, tok, 0); err != nil {
		t.Errorf("trailing slash: %v", err)
	}
}

func TestCloneVMSendsFullClone(t *testing.T) {
	f := &fakeWriteServer{body: upidBody(upidClone)}
	w := newTestWriter(t, f)
	got, err := w.CloneVM(context.Background(), CloneRequest{Node: "pve1", SourceVMID: 9000, NewVMID: 120, Name: "web-01.lab", Storage: "local-lvm"})
	if err != nil {
		t.Fatalf("CloneVM: %v", err)
	}
	if got != upidClone {
		t.Errorf("upid = %q", got)
	}
	r := f.only(t)
	if r.method != http.MethodPost || r.path != "/api2/json/nodes/pve1/qemu/9000/clone" {
		t.Errorf("request = %s %s", r.method, r.path)
	}
	if r.auth != testToken || r.ctype != "application/x-www-form-urlencoded" {
		t.Errorf("headers auth=%q ctype=%q", r.auth, r.ctype)
	}
	want := url.Values{"newid": {"120"}, "full": {"1"}, "name": {"web-01.lab"}, "storage": {"local-lvm"}}
	if r.form.Encode() != want.Encode() {
		t.Errorf("form = %v, want %v", r.form, want)
	}
}

func TestCloneVMRejectsInvalidArguments(t *testing.T) {
	ok := CloneRequest{Node: "pve1", SourceVMID: 9000, NewVMID: 120}
	cases := map[string]func(*CloneRequest){
		"node path":      func(r *CloneRequest) { r.Node = "../pve1" },
		"node slash":     func(r *CloneRequest) { r.Node = "pve1/qemu" },
		"node empty":     func(r *CloneRequest) { r.Node = "" },
		"source low":     func(r *CloneRequest) { r.SourceVMID = 99 },
		"newid high":     func(r *CloneRequest) { r.NewVMID = MaxVMID + 1 },
		"newid = source": func(r *CloneRequest) { r.NewVMID = 9000 },
		"name space":     func(r *CloneRequest) { r.Name = "web 01" },
		"name upper":     func(r *CloneRequest) { r.Name = "Web" },
		"name dash":      func(r *CloneRequest) { r.Name = "-web" },
		"name long":      func(r *CloneRequest) { r.Name = strings.Repeat("a", 64) },
		"name comma":     func(r *CloneRequest) { r.Name = "web,full=0" },
		"storage":        func(r *CloneRequest) { r.Storage = "local/../x" },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			f := &fakeWriteServer{body: upidBody(upidClone)}
			w := newTestWriter(t, f)
			r := ok
			mut(&r)
			_, err := w.CloneVM(context.Background(), r)
			if !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("err = %v, want ErrInvalidArgument", err)
			}
			if f.count() != 0 {
				t.Error("invalid request reached the server")
			}
		})
	}
}

func TestResizeDiskSendsAbsoluteSize(t *testing.T) {
	f := &fakeWriteServer{body: upidBody(upidResize)}
	w := newTestWriter(t, f)
	got, err := w.ResizeDisk(context.Background(), ResizeRequest{Node: "pve1", VMID: 120, Disk: "scsi0", SizeGiB: 32})
	if err != nil || got != upidResize {
		t.Fatalf("ResizeDisk = %q, %v", got, err)
	}
	r := f.only(t)
	if r.method != http.MethodPut || r.path != "/api2/json/nodes/pve1/qemu/120/resize" {
		t.Errorf("request = %s %s", r.method, r.path)
	}
	if r.form.Encode() != (url.Values{"disk": {"scsi0"}, "size": {"32G"}}).Encode() {
		t.Errorf("form = %v", r.form)
	}
}

func TestResizeDiskRejectsInvalidArguments(t *testing.T) {
	for name, r := range map[string]ResizeRequest{
		"disk unknown":  {Node: "pve1", VMID: 120, Disk: "efidisk0", SizeGiB: 32},
		"disk suffix":   {Node: "pve1", VMID: 120, Disk: "scsi0,x=1", SizeGiB: 32},
		"disk range":    {Node: "pve1", VMID: 120, Disk: "scsi31", SizeGiB: 32},
		"size zero":     {Node: "pve1", VMID: 120, Disk: "scsi0", SizeGiB: 0},
		"size negative": {Node: "pve1", VMID: 120, Disk: "scsi0", SizeGiB: -1},
		"size huge":     {Node: "pve1", VMID: 120, Disk: "scsi0", SizeGiB: MaxDiskGiB + 1},
		"vmid":          {Node: "pve1", VMID: 0, Disk: "scsi0", SizeGiB: 32},
	} {
		t.Run(name, func(t *testing.T) {
			f := &fakeWriteServer{body: upidBody(upidResize)}
			w := newTestWriter(t, f)
			if _, err := w.ResizeDisk(context.Background(), r); !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("err = %v, want ErrInvalidArgument", err)
			}
			if f.count() != 0 {
				t.Error("invalid request reached the server")
			}
		})
	}
}

func TestStartAndTemplateReturnUPID(t *testing.T) {
	f := &fakeWriteServer{body: upidBody(upidStart)}
	w := newTestWriter(t, f)
	got, err := w.StartVM(context.Background(), "pve1", 120)
	if err != nil || got != upidStart {
		t.Fatalf("StartVM = %q, %v", got, err)
	}
	if r := f.only(t); r.method != http.MethodPost || r.path != "/api2/json/nodes/pve1/qemu/120/status/start" || len(r.form) != 0 {
		t.Errorf("start request = %+v", r)
	}

	f2 := &fakeWriteServer{body: upidBody(upidTemplate)}
	w2 := newTestWriter(t, f2)
	got, err = w2.ConvertToTemplate(context.Background(), "pve1", 9000)
	if err != nil || got != upidTemplate {
		t.Fatalf("ConvertToTemplate = %q, %v", got, err)
	}
	if r := f2.only(t); r.method != http.MethodPost || r.path != "/api2/json/nodes/pve1/qemu/9000/template" {
		t.Errorf("template request = %+v", r)
	}
}

func TestStartRejectsInvalidTarget(t *testing.T) {
	f := &fakeWriteServer{body: upidBody(upidStart)}
	w := newTestWriter(t, f)
	for _, tc := range []struct {
		node string
		vmid int64
	}{{"", 120}, {"pve1?x", 120}, {"pve1", 99}, {"pve1", MaxVMID + 1}} {
		if _, err := w.StartVM(context.Background(), tc.node, tc.vmid); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("StartVM(%q,%d) err = %v", tc.node, tc.vmid, err)
		}
		if _, err := w.ConvertToTemplate(context.Background(), tc.node, tc.vmid); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("ConvertToTemplate(%q,%d) err = %v", tc.node, tc.vmid, err)
		}
	}
	if f.count() != 0 {
		t.Error("invalid request reached the server")
	}
}

// TestWriteRejectsHostileResponses covers UPID validation, size limits,
// encoding and status handling for every dispatching call.
func TestWriteRejectsHostileResponses(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		reason  string
		unknown bool
	}{
		{"oversize", 200, `{"data":"` + strings.Repeat("A", MaxWriteResponseBytes) + `"}`, ReasonOversize, true},
		{"invalid utf8", 200, "{\"data\":\"\xff\"}", ReasonInvalidUTF8, true},
		{"not json", 200, `<html>`, ReasonInvalidJSON, true},
		{"null data", 200, `{"data":null}`, ReasonSchema, true},
		{"missing data", 200, `{}`, ReasonSchema, true},
		{"object data", 200, `{"data":{"upid":"x"}}`, ReasonSchema, true},
		{"not a upid", 200, `{"data":"OK"}`, ReasonSchema, true},
		{"wrong node", 200, upidBody(strings.Replace(upidStart, "pve1", "pve2", 1)), ReasonSchema, true},
		{"wrong type", 200, upidBody(strings.Replace(upidStart, "qmstart", "qmstop", 1)), ReasonSchema, true},
		{"wrong vmid", 200, upidBody(strings.Replace(upidStart, ":120:", ":121:", 1)), ReasonSchema, true},
		{"forbidden", 403, `{"message":"secret-echo"}`, ReasonHTTPError, false},
		{"bad request", 400, `{"errors":{"vmid":"x"}}`, ReasonHTTPError, false},
		{"not found", 404, ``, ReasonHTTPError, false},
		{"redirect", 302, ``, ReasonHTTPError, true},
		{"server error", 500, `{"data":null}`, ReasonHTTPError, true},
		{"bad gateway", 502, ``, ReasonHTTPError, true},
		{"gateway timeout", 504, ``, ReasonHTTPError, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeWriteServer{status: tc.status, body: tc.body}
			w := newTestWriter(t, f)
			_, err := w.StartVM(context.Background(), "pve1", 120)
			var we *WriteError
			if !errors.As(err, &we) || !errors.Is(err, ErrWriteFailed) {
				t.Fatalf("err = %v, want *WriteError", err)
			}
			if we.Reason != tc.reason || we.OutcomeUnknown() != tc.unknown {
				t.Errorf("reason=%q unknown=%v, want %q %v", we.Reason, we.OutcomeUnknown(), tc.reason, tc.unknown)
			}
			if strings.Contains(err.Error(), "secret-echo") || strings.Contains(err.Error(), testToken) {
				t.Errorf("error leaks response or token: %v", err)
			}
		})
	}
}

func TestWriteDoesNotFollowRedirects(t *testing.T) {
	var hits int
	var mu sync.Mutex
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		_, _ = io.WriteString(w, upidBody(upidStart))
	}))
	t.Cleanup(target.Close)
	w := newTestWriter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	if _, err := w.StartVM(context.Background(), "pve1", 120); err == nil {
		t.Fatal("want error on redirect")
	}
	mu.Lock()
	defer mu.Unlock()
	if hits != 0 {
		t.Errorf("redirect target hit %d times", hits)
	}
}

func TestWriteTokenErrorSendsNothing(t *testing.T) {
	f := &fakeWriteServer{body: upidBody(upidStart)}
	ts := httptest.NewServer(f)
	t.Cleanup(ts.Close)
	w, err := NewWriter(ts.URL, ts.Client(), func(context.Context) (string, error) {
		return "", errors.New("vault locked")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = w.StartVM(context.Background(), "pve1", 120)
	var we *WriteError
	if !errors.As(err, &we) || we.Reason != ReasonNoToken || we.OutcomeUnknown() {
		t.Fatalf("err = %v", err)
	}
	if f.count() != 0 {
		t.Error("request sent without token")
	}
}

func TestWriteTimeoutIsOutcomeUnknown(t *testing.T) {
	release := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(ts.Close)
	t.Cleanup(func() { close(release) })
	w, err := NewWriter(ts.URL, ts.Client(), func(context.Context) (string, error) { return testToken, nil }, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	_, err = w.StartVM(context.Background(), "pve1", 120)
	var we *WriteError
	if !errors.As(err, &we) || we.Reason != ReasonTimeout || !we.OutcomeUnknown() {
		t.Fatalf("err = %v, want timeout with unknown outcome", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want DeadlineExceeded in chain", err)
	}
}

func TestWriteCanceledContextSendsNothing(t *testing.T) {
	f := &fakeWriteServer{body: upidBody(upidStart)}
	w := newTestWriter(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := w.StartVM(ctx, "pve1", 120); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if f.count() != 0 {
		t.Error("request sent with canceled context")
	}
}

func TestWriteBadRequestKeepsOnlySentParamNames(t *testing.T) {
	f := &fakeWriteServer{status: 400, body: `{"errors":{"size":"bad value 32G","injected\nline":"x","newid":"no"},"data":null}`}
	w := newTestWriter(t, f)
	_, err := w.ResizeDisk(context.Background(), ResizeRequest{Node: "pve1", VMID: 120, Disk: "scsi0", SizeGiB: 32})
	var we *WriteError
	if !errors.As(err, &we) || we.Status != 400 {
		t.Fatalf("err = %v", err)
	}
	if strings.Join(we.Params, ",") != "size" {
		t.Errorf("params = %q, want [size]", we.Params)
	}
	if strings.Contains(err.Error(), "bad value") || strings.Contains(err.Error(), "injected") {
		t.Errorf("error carries response text: %v", err)
	}
}

// TestWriterMethodSetIsAllowlist pins the Writer API to the ADR 0008
// allowlist; a new write method must be added here deliberately.
func TestWriterMethodSetIsAllowlist(t *testing.T) {
	want := []string{"CloneVM", "ConvertToTemplate", "DownloadURL", "ResizeDisk", "SetConfig", "StartVM", "TaskStatus"}
	typ := reflect.TypeFor[*Writer]()
	var got []string
	for i := range typ.NumMethod() {
		got = append(got, typ.Method(i).Name)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("Writer methods = %v, want %v", got, want)
	}
	// The read client has no write path.
	for _, name := range want {
		if _, ok := reflect.TypeFor[*Client]().MethodByName(name); ok {
			t.Errorf("Client unexpectedly has %s", name)
		}
	}
}

func TestValidDNSName(t *testing.T) {
	for s, want := range map[string]bool{
		"web": true, "web-01": true, "web.lab.example": true, "a1": true,
		"": false, "-a": false, "a-": false, "a..b": false, ".a": false, "a.": false,
		"a_b": false, "A": false, "a b": false, strings.Repeat("a", 63): true,
		strings.Repeat("a", 64): false, strings.Repeat("a.", 126) + "a": true,
		strings.Repeat("a.", 127) + "a": false,
	} {
		if got := validDNSName(s); got != want {
			t.Errorf("validDNSName(%q) = %v, want %v", s, got, want)
		}
	}
}
