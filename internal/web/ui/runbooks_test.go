// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/runbooks"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

func runbookHandler(t *testing.T) (http.Handler, *runbooks.Store, *fakeOps) {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	rb := runbooks.New(db)
	f := &fakeOps{}
	return newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org", Runbooks: rb, Operations: f}).Handler(), rb, f
}

const hostileRunbook = `{"slug":"web_restart","title":"<script>alert(1)</script>","description":"x\" onmouseover=\"y","risk":"MEDIUM",
 "durable":false,"timeout_s":60,"params":[{"name":"unit","label":"<b>Unit</b>","type":"name"}],
 "body":"echo '</pre><script>alert(2)</script>'\nsudo -n reboot\n"}`

func TestRunbookPages(t *testing.T) {
	h, rb, f := runbookHandler(t)
	if page := getBody(t, h, "/runbooks"); !strings.Contains(page, "No runbooks yet.") {
		t.Fatal(page)
	}
	if code, body := postJSON(t, h, "/runbooks/save", hostileRunbook); code != http.StatusOK || !strings.Contains(body, `"version":1`) {
		t.Fatalf("%d %s", code, body)
	}
	list := getBody(t, h, "/runbooks")
	if !strings.Contains(list, `<a href="/runbooks/web_restart">web_restart</a>`) || !strings.Contains(list, "reboot_or_power") ||
		strings.Contains(list, "<script>alert") {
		t.Fatal(list)
	}
	page := getBody(t, h, "/runbooks/web_restart")
	for _, want := range []string{"Runbook web_restart, version 1", "&lt;script&gt;alert(1)&lt;/script&gt;", "&lt;/pre&gt;&lt;script&gt;alert(2)",
		"reboot_or_power at line", "nebula artifact trust --action runbook.web_restart --version 1.0.0 --risk MEDIUM web_restart-1.sh",
		`href="/operations/new?action=runbook.web_restart"`, "$NEBULA_P_UNIT", "&lt;b&gt;Unit&lt;/b&gt;"} {
		if !strings.Contains(page, want) {
			t.Errorf("page misses %q", want)
		}
	}
	if strings.Contains(page, "<script>alert") || strings.Contains(page, `onmouseover="y"`) {
		t.Fatal("unescaped runbook text")
	}

	// The artifact is served as a download, never rendered.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/runbooks/web_restart/1/artifact", nil))
	v, _ := rb.Get(context.Background(), "web_restart", 1)
	if rec.Code != http.StatusOK || rec.Body.String() != string(v.Artifact) || rec.Header().Get("Content-Type") != "application/octet-stream" ||
		!strings.HasPrefix(rec.Header().Get("Content-Disposition"), "attachment;") || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("%d %v", rec.Code, rec.Header())
	}
	for _, p := range []string{"/runbooks/web_restart/2/artifact", "/runbooks/web_restart/x/artifact", "/runbooks/nope", "/runbooks/web_restart?version=0"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: %d", p, rec.Code)
		}
	}

	// Editing starts from the latest version; saving adds version 2.
	if edit := getBody(t, h, "/runbooks/new?from=web_restart"); !strings.Contains(edit, `data-existing="1"`) || !strings.Contains(edit, "web_restart") {
		t.Fatal(edit)
	}
	if code, _ := postJSON(t, h, "/runbooks/save", strings.Replace(hostileRunbook, "sudo -n reboot", "echo two", 1)); code != http.StatusOK {
		t.Fatal(code)
	}
	if page := getBody(t, h, "/runbooks/web_restart"); !strings.Contains(page, "version 2") || strings.Contains(page, "reboot_or_power") {
		t.Fatal("not the latest version")
	}
	if page := getBody(t, h, "/runbooks/web_restart?version=1"); !strings.Contains(page, "reboot_or_power") {
		t.Fatal("old version not shown")
	}

	// The planner lists runbooks and preselects the one asked for.
	v2, _ := rb.Get(context.Background(), "web_restart", 0)
	f.extra = append(f.extra, v2.Action())
	plan := getBody(t, opsHandler(t, f, nil), "/operations/new?action=runbook.web_restart")
	if !strings.Contains(plan, `value="runbook.web_restart" checked`) || strings.Contains(plan, `value="core.facts" checked`) {
		t.Fatal("runbook not preselected")
	}
}

func TestRunbookSaveRefusesBadInput(t *testing.T) {
	h, _, _ := runbookHandler(t)
	for name, body := range map[string]string{
		"bidi":         strings.Replace(hostileRunbook, `sudo -n reboot`, "echo \u202eevil", 1),
		"slug":         strings.Replace(hostileRunbook, `"web_restart"`, `"Web"`, 1),
		"slug new":     strings.Replace(hostileRunbook, `"web_restart"`, `"new"`, 1),
		"unknown":      strings.Replace(hostileRunbook, `"durable":false`, `"durable":false,"x":1`, 1),
		"not json":     "nope",
		"param type":   strings.Replace(hostileRunbook, `"type":"name"`, `"type":"string"`, 1),
		"crlf script":  strings.Replace(hostileRunbook, `\nsudo`, `\r\nsudo`, 1),
		"long timeout": strings.Replace(hostileRunbook, `"timeout_s":60`, `"timeout_s":3600`, 1),
	} {
		if code, _ := postJSON(t, h, "/runbooks/save", body); code != http.StatusBadRequest {
			t.Errorf("%s: %d", name, code)
		}
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/runbooks/save", strings.NewReader(hostileRunbook))
	req.Header.Set("Content-Type", "text/plain")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatal(rec.Code)
	}
	big := strings.Replace(hostileRunbook, `sudo -n reboot`, strings.Repeat("x", 2<<20), 1)
	if code, _ := postJSON(t, h, "/runbooks/save", big); code != http.StatusRequestEntityTooLarge {
		t.Fatal(code)
	}
}

// M7-3: secret slots are shown on the runbook and asked for when planning.
func TestRunbookSecretSlotsAreShown(t *testing.T) {
	h, rb, f := runbookHandler(t)
	body := strings.Replace(hostileRunbook, `"params":[`, `"secrets":["influx_token"],"params":[`, 1)
	if code, msg := postJSON(t, h, "/runbooks/save", body); code != http.StatusOK {
		t.Fatalf("%d %s", code, msg)
	}
	if page := getBody(t, h, "/runbooks/web_restart"); !strings.Contains(page, "$NEBULA_SECRET_INFLUX_TOKEN") || !strings.Contains(page, "at least MEDIUM") {
		t.Fatal(page)
	}
	v, _ := rb.Get(context.Background(), "web_restart", 0)
	f.extra = append(f.extra, v.Action())
	plan := getBody(t, opsHandler(t, f, nil), "/operations/new?action=runbook.web_restart")
	if !strings.Contains(plan, `data-secret="influx_token"`) || !strings.Contains(plan, "Vault secret for slot influx_token") {
		t.Fatal("planner does not ask for the secret")
	}
}

type fakeTrust struct {
	trusted bool
	sum     string // what Begin reports as hashed
	begun   *pb.BeginTrustArtifactRequest
	commits int
}

func (f *fakeTrust) BeginTrustArtifact(_ context.Context, in *pb.BeginTrustArtifactRequest, _ ...grpc.CallOption) (*pb.BeginTrustArtifactResponse, error) {
	f.begun = in
	sum := f.sum
	if sum == "" {
		h := sha256.Sum256(in.GetArtifact())
		sum = hex.EncodeToString(h[:])
	}
	return &pb.BeginTrustArtifactResponse{TrustId: "t1", ArtifactSha256: sum, RequestOptionsJson: []byte(`{"publicKey":{"challenge":"trust"}}`)}, nil
}

func (f *fakeTrust) CommitTrustArtifact(_ context.Context, in *pb.CommitTrustArtifactRequest, _ ...grpc.CallOption) (*pb.CommitTrustArtifactResponse, error) {
	if string(in.GetAssertionJson()) != `"good"` {
		return nil, status.Error(codes.PermissionDenied, "assertion_rejected")
	}
	f.commits++
	f.trusted = true
	return &pb.CommitTrustArtifactResponse{}, nil
}

func (f *fakeTrust) GetArtifactTrust(context.Context, *pb.GetArtifactTrustRequest, ...grpc.CallOption) (*pb.GetArtifactTrustResponse, error) {
	return &pb.GetArtifactTrustResponse{Trusted: f.trusted, RiskClass: pb.RiskClass_RISK_CLASS_MEDIUM}, nil
}

// M7-4: a runbook version can be trusted on the executor with the key.
func TestRunbookTrust(t *testing.T) {
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	rb := runbooks.New(db)
	ft := &fakeTrust{}
	h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org", Runbooks: rb, Trust: ft}).Handler()
	if code, _ := postJSON(t, h, "/runbooks/save", hostileRunbook); code != http.StatusOK {
		t.Fatal(code)
	}
	page := getBody(t, h, "/runbooks/web_restart")
	if !strings.Contains(page, "not trusted: the executor treats this version as at least HIGH") || !strings.Contains(page, `id="runbook-trust"`) {
		t.Fatal(page)
	}
	code, body := postJSON(t, h, "/runbooks/trust/begin", `{"slug":"web_restart","version":1}`)
	v, _ := rb.Get(context.Background(), "web_restart", 1)
	if code != http.StatusOK || !strings.Contains(body, `"trust_id":"t1"`) || string(ft.begun.GetArtifact()) != string(v.Artifact) ||
		ft.begun.GetActionId() != "runbook.web_restart" || ft.begun.GetModuleVersion() != "1.0.0" || ft.begun.GetRiskClass() != pb.RiskClass_RISK_CLASS_MEDIUM {
		t.Fatalf("%d %s %v", code, body, ft.begun)
	}
	if code, _ := postJSON(t, h, "/runbooks/trust/commit", `{"trust_id":"t1","assertion":"bad"}`); code == http.StatusOK {
		t.Fatal("bad assertion accepted")
	}
	if code, _ := postJSON(t, h, "/runbooks/trust/commit", `{"trust_id":"t1","assertion":"good"}`); code != http.StatusOK || ft.commits != 1 {
		t.Fatal(code)
	}
	if page := getBody(t, h, "/runbooks/web_restart"); !strings.Contains(page, "Executor: trusted as MEDIUM") || strings.Contains(page, `id="runbook-trust"`) {
		t.Fatal(page)
	}
	// The executor hashing other bytes than the version's is an error.
	ft.sum = strings.Repeat("0", 64)
	if code, _ := postJSON(t, h, "/runbooks/trust/begin", `{"slug":"web_restart","version":1}`); code != http.StatusBadGateway {
		t.Fatal(code)
	}
	for _, b := range []string{`{"slug":"web_restart","version":0}`, `{"slug":"nope","version":1}`} {
		if code, _ := postJSON(t, h, "/runbooks/trust/begin", b); code != http.StatusNotFound {
			t.Errorf("%s: %d", b, code)
		}
	}
}
