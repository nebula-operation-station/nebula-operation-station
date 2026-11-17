// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/opsconfig"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// fakeOpsAgent is the backend of the ops agent settings. Its challenge is
// bound to the change digest: the assertion must be "ok:<digest>" for the
// digest of the change the challenge was begun for.
type fakeOpsAgent struct {
	mu         sync.Mutex
	row        opsconfig.Row
	core       string
	maintainer bool
	saveErr    error
	bound      map[string]string // challenge ID -> change digest (hex)
	begun      []ui.OpsAgentChange
	committed  []ui.OpsAgentChange
	writes     int
}

func (f *fakeOpsAgent) OpsAgentConfig(context.Context) (opsconfig.Row, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.row, nil
}

func (f *fakeOpsAgent) OpsAgentCorePrompt() string { return f.core }

func (f *fakeOpsAgent) OpsAgentMaintainer(context.Context, string) (bool, error) {
	return f.maintainer, nil
}

func (f *fakeOpsAgent) BeginOpsAgentChange(_ context.Context, _ string, c ui.OpsAgentChange) (ui.VulnChallenge, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, err := c.Digest()
	if err != nil {
		return ui.VulnChallenge{}, err
	}
	id := fmt.Sprintf("ops-challenge-%06d", len(f.bound)+1)
	if f.bound == nil {
		f.bound = map[string]string{}
	}
	f.bound[id] = hex.EncodeToString(d[:])
	f.begun = append(f.begun, c)
	f.writes++
	return ui.VulnChallenge{ID: id, Options: []byte(`{"publicKey":{"challenge":"AAAA"}}`)}, nil
}

func (f *fakeOpsAgent) CommitOpsAgentChange(_ context.Context, _ string, id string, c ui.OpsAgentChange, assertion []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes++
	var a struct {
		Sig string `json:"sig"`
	}
	if err := json.Unmarshal(assertion, &a); err != nil {
		return ui.ErrOpsAgentAssertionRefused
	}
	d, err := c.Digest()
	if err != nil {
		return err
	}
	if f.bound[id] == "" || a.Sig != "ok:"+hex.EncodeToString(d[:]) || f.bound[id] != hex.EncodeToString(d[:]) {
		return ui.ErrOpsAgentAssertionRefused
	}
	if f.saveErr != nil {
		return f.saveErr
	}
	f.committed = append(f.committed, c)
	return nil
}

func (f *fakeOpsAgent) writeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.writes
}

// opsFixture: enabled, lab, plain HTTP allowed, version 4.
func opsAgentFixture(maintainer bool) *fakeOpsAgent {
	return &fakeOpsAgent{maintainer: maintainer, core: "Assess findings. <script>alert('core')</script>",
		row: opsconfig.Row{Settings: opsconfig.Settings{Enabled: true, BaseURL: "http://10.0.0.20:11434/v1", Model: "qwen3.5-9b",
			AllowPlainHTTP: true, DataClass: opsconfig.DataClassLab, Language: opsconfig.LanguageDE,
			Instructions: "Prefer <b>Debian</b> trackers."},
			Version: 4, UpdatedBy: "admin", UpdatedAt: vulnNow.Add(-time.Hour)}}
}

// opsAgentClock is an injected clock for the pending challenges.
type opsAgentClock struct{ t time.Time }

func (c *opsAgentClock) now() time.Time { return c.t }

// opsHandler builds the handler with the ops fake, the vuln fake and a
// TOTP status (recovery pending when recovery is true).
func opsAgentHandler(t *testing.T, ops *fakeOpsAgent, vuln *fakeVulnAgent, clock *opsAgentClock, recovery bool) http.Handler {
	t.Helper()
	totp := func(context.Context) (*pb.GetTOTPStatusResponse, error) {
		return &pb.GetTOTPStatusResponse{Configured: true, Activated: true, RecoveryPending: recovery}, nil
	}
	o := ui.Options{PublicOrigin: leaseOrigin, OpsAgent: ops, TOTPStatus: totp,
		Now: func() time.Time { return clock.now() }}
	if vuln != nil {
		o.VulnAgent = vuln
	}
	return newTestHandler(t, o).Handler()
}

// opsBody is a begin body for the stored settings with optional changes.
func opsAgentBody(mod func(m map[string]any)) string {
	m := map[string]any{"enabled": true, "base_url": "http://10.0.0.20:11434/v1", "model": "qwen3.5-9b",
		"allow_plain_http": true, "data_class": "lab", "operator_instructions": "Prefer Debian trackers.",
		"language": "de", "base_version": 4, "confirm_url_change": false}
	if mod != nil {
		mod(m)
	}
	b, _ := json.Marshal(m)
	return string(b)
}

const (
	opsBegin  = "/settings/ops-agent/begin"
	opsCommit = "/settings/ops-agent/commit"
)

// opsAssertion is the assertion JSON for a change, as the browser would
// send it after the security key signed the challenge of that change.
func opsAgentAssertion(t *testing.T, body string) string {
	t.Helper()
	c := opsAgentChangeFrom(t, body)
	d, err := c.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return `{"sig":"ok:` + hex.EncodeToString(d[:]) + `"}`
}

// opsChangeFrom computes the change a begin body describes, the same way
// the handler reads it, for building assertions in tests.
func opsAgentChangeFrom(t *testing.T, body string) ui.OpsAgentChange {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatal(err)
	}
	s := opsconfig.Settings{Enabled: m["enabled"].(bool), BaseURL: m["base_url"].(string), Model: m["model"].(string),
		AllowPlainHTTP: m["allow_plain_http"].(bool), DataClass: m["data_class"].(string),
		Instructions: m["operator_instructions"].(string), Language: m["language"].(string)}
	return ui.OpsAgentChange{Settings: s, BaseVersion: int64(m["base_version"].(float64)),
		URLChanged: s.BaseURL != "http://10.0.0.20:11434/v1"}
}

// beginOps posts a begin and returns the challenge ID.
func beginOpsAgent(t *testing.T, h http.Handler, body string) string {
	t.Helper()
	code, out := vulnPost(t, h, opsBegin, body)
	if code != http.StatusOK {
		t.Fatalf("begin = %d (%v), want 200", code, out)
	}
	id, _ := out["id"].(string)
	if id == "" {
		t.Fatalf("begin returned no id: %v", out)
	}
	return id
}

func TestOpsAgentSettingsHiddenWithoutBackend(t *testing.T) {
	h := newTestHandler(t, ui.Options{PublicOrigin: leaseOrigin}).Handler()
	if body := getBody(t, h, "/settings"); strings.Contains(body, "ops-agent-form") {
		t.Fatal("settings page shows the ops agent section without a backend")
	}
	for _, p := range []string{opsBegin, opsCommit} {
		if code, _ := vulnPost(t, h, p, `{}`); code != http.StatusNotFound {
			t.Errorf("POST %s without backend = %d, want 404", p, code)
		}
	}
}

func TestOpsAgentSectionShowsDataClassTextAndReadOnlyCorePrompt(t *testing.T) {
	ops := opsAgentFixture(true)
	body := getBody(t, opsAgentHandler(t, ops, nil, &opsAgentClock{t: vulnNow}, false), "/settings")
	for _, want := range []string{
		"Ops-Agent", `id="ops-agent-form"`, `value="http://10.0.0.20:11434/v1"`, `value="qwen3.5-9b"`,
		"lab: Hostnamen und CVE-IDs gehen an das LLM, nur über den Lab-only-Dialer",
		"external: nur Zähler je Tier",
		"Prefer &lt;b&gt;Debian&lt;/b&gt; trackers.",
		"Assess findings. &lt;script&gt;alert(&#39;core&#39;)&lt;/script&gt;",
		`<option value="de" selected>`, `id="ops-agent-submit"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("settings page lacks %q", want)
		}
	}
	// The LLM credential is never a field and never shown.
	for _, bad := range []string{`type="password"`, `name="api_key"`, `name="credential"`, "<script>alert("} {
		if strings.Contains(body, bad) {
			t.Errorf("settings page contains %q", bad)
		}
	}
}

func TestOpsAgentFormDisabledForOthers(t *testing.T) {
	body := getBody(t, opsAgentHandler(t, opsAgentFixture(false), nil, &opsAgentClock{t: vulnNow}, false), "/settings")
	if !strings.Contains(body, "Only the maintainer (admin) can change these settings") {
		t.Error("non-admin sees no hint that the ops agent section is read-only")
	}
	if strings.Contains(body, `id="ops-agent-submit"`) {
		t.Error("non-admin sees the save button")
	}
}

func TestOpsAgentCopyButtonCarriesVulnAgentValuesAndSavesNothing(t *testing.T) {
	ops := opsAgentFixture(true)
	vuln := agentFixture(true)
	h := opsAgentHandler(t, ops, vuln, &opsAgentClock{t: vulnNow}, false)
	body := getBody(t, h, "/settings")
	for _, want := range []string{`id="ops-agent-copy"`, `data-copy-url="http://llm.lab:11434/v1"`, `data-copy-model="qwen3.5-9b-64k"`} {
		if !strings.Contains(body, want) {
			t.Errorf("settings page lacks %q", want)
		}
	}
	if ops.writeCount() != 0 || len(vuln.begun) != 0 || len(vuln.committed) != 0 {
		t.Fatalf("rendering the copy button wrote something: ops writes %d, vuln begun %d", ops.writeCount(), len(vuln.begun))
	}
}

func TestOpsAgentCopyButtonHiddenWithoutVulnAgent(t *testing.T) {
	body := getBody(t, opsAgentHandler(t, opsAgentFixture(true), nil, &opsAgentClock{t: vulnNow}, false), "/settings")
	if strings.Contains(body, `id="ops-agent-copy"`) {
		t.Error("copy button shown without a vulnerability agent")
	}
}

func TestOpsAgentChangeNeedsFreshAssertion(t *testing.T) {
	ops := opsAgentFixture(true)
	h := opsAgentHandler(t, ops, nil, &opsAgentClock{t: vulnNow}, false)
	id := beginOpsAgent(t, h, opsAgentBody(func(m map[string]any) { m["model"] = "llama3.1-8b" }))
	for _, assertion := range []string{``, `null`} {
		body := `{"id":"` + id + `"`
		if assertion != "" {
			body += `,"assertion":` + assertion
		}
		body += `}`
		if code, _ := vulnPost(t, h, opsCommit, body); code != http.StatusForbidden {
			t.Errorf("commit with assertion %q = %d, want 403", assertion, code)
		}
	}
	if len(ops.committed) != 0 {
		t.Fatalf("a change without a fresh assertion was stored")
	}
}

func TestOpsAgentChangeWithAssertionForOtherDigestRejected(t *testing.T) {
	ops := opsAgentFixture(true)
	h := opsAgentHandler(t, ops, nil, &opsAgentClock{t: vulnNow}, false)
	bodyA := opsAgentBody(func(m map[string]any) { m["model"] = "llama3.1-8b" })
	bodyB := opsAgentBody(func(m map[string]any) { m["model"] = "mistral-7b" })
	id := beginOpsAgent(t, h, bodyA)
	// The security key signed the digest of change B, not of change A.
	bad := `{"id":"` + id + `","assertion":` + opsAgentAssertion(t, bodyB) + `}`
	if code, _ := vulnPost(t, h, opsCommit, bad); code != http.StatusForbidden {
		t.Fatalf("commit with another change's assertion = %d, want 403", code)
	}
	if len(ops.committed) != 0 {
		t.Fatal("a change was stored with another digest's assertion")
	}
	// A rejected assertion ends the challenge: the same ID cannot be retried.
	retry := `{"id":"` + id + `","assertion":` + opsAgentAssertion(t, bodyA) + `}`
	if code, _ := vulnPost(t, h, opsCommit, retry); code != http.StatusNotFound {
		t.Fatalf("retry on a consumed challenge = %d, want 404", code)
	}
	id = beginOpsAgent(t, h, bodyA)
	good := `{"id":"` + id + `","assertion":` + opsAgentAssertion(t, bodyA) + `}`
	if code, out := vulnPost(t, h, opsCommit, good); code != http.StatusOK || out["done"] != true {
		t.Fatalf("commit with the bound assertion = %d (%v), want 200", code, out)
	}
	if len(ops.committed) != 1 || ops.committed[0].Settings.Model != "llama3.1-8b" {
		t.Fatalf("committed = %+v", ops.committed)
	}
}

func TestOpsAgentChangeWithStaleBaseVersionRejected(t *testing.T) {
	ops := opsAgentFixture(true)
	h := opsAgentHandler(t, ops, nil, &opsAgentClock{t: vulnNow}, false)
	body := opsAgentBody(func(m map[string]any) { m["base_version"] = 3 })
	if code, _ := vulnPost(t, h, opsBegin, body); code != http.StatusConflict {
		t.Fatalf("begin with stale base version = %d, want 409", code)
	}
	if len(ops.begun) != 0 {
		t.Fatal("a stale change reached the backend")
	}
}

func TestOpsAgentURLChangeNeedsConfirmation(t *testing.T) {
	ops := opsAgentFixture(true)
	h := opsAgentHandler(t, ops, nil, &opsAgentClock{t: vulnNow}, false)
	url := func(confirm bool) string {
		return opsAgentBody(func(m map[string]any) {
			m["base_url"] = "http://10.0.0.21:11434/v1"
			m["confirm_url_change"] = confirm
		})
	}
	if code, _ := vulnPost(t, h, opsBegin, url(false)); code != http.StatusBadRequest {
		t.Fatalf("URL change without confirmation = %d, want 400", code)
	}
	if len(ops.begun) != 0 {
		t.Fatal("unconfirmed URL change reached the backend")
	}
	if code, _ := vulnPost(t, h, opsBegin, url(true)); code != http.StatusOK {
		t.Fatalf("confirmed URL change = %d, want 200", code)
	}
}

func TestOpsAgentRejectsInvalidSettings(t *testing.T) {
	ops := opsAgentFixture(true)
	h := opsAgentHandler(t, ops, nil, &opsAgentClock{t: vulnNow}, false)
	for name, mod := range map[string]func(m map[string]any){
		"plain http without allow_plain_http": func(m map[string]any) {
			m["base_url"] = "http://10.0.0.20:11434/v1"
			m["allow_plain_http"] = false
		},
		"unknown data class":   func(m map[string]any) { m["data_class"] = "public" },
		"unknown language":     func(m map[string]any) { m["language"] = "fr" },
		"missing field":        func(m map[string]any) { delete(m, "model") },
		"control character":    func(m map[string]any) { m["operator_instructions"] = "a\x01b" },
		"lab with public host": func(m map[string]any) { m["base_url"] = "https://example.com/v1" },
	} {
		if code, _ := vulnPost(t, h, opsBegin, opsAgentBody(mod)); code != http.StatusBadRequest {
			t.Errorf("%s: begin = %d, want 400", name, code)
		}
	}
	if len(ops.begun) != 0 {
		t.Fatal("an invalid change reached the backend")
	}
}

func TestOpsAgentChangeRefusedInRecovery(t *testing.T) {
	ops := opsAgentFixture(true)
	h := opsAgentHandler(t, ops, nil, &opsAgentClock{t: vulnNow}, true)
	if code, _ := vulnPost(t, h, opsBegin, opsAgentBody(nil)); code != http.StatusForbidden {
		t.Fatalf("begin during recovery = %d, want 403", code)
	}
	if len(ops.begun) != 0 {
		t.Fatal("a change during recovery reached the backend")
	}
	if body := getBody(t, h, "/settings"); !strings.Contains(body, "recovery login is pending") {
		t.Error("settings page does not say why the ops agent cannot change")
	}
}

func TestOpsAgentChangeRefusedWhenRecoveryStatusUnknown(t *testing.T) {
	ops := opsAgentFixture(true)
	h := newTestHandler(t, ui.Options{PublicOrigin: leaseOrigin, OpsAgent: ops,
		TOTPStatus: func(context.Context) (*pb.GetTOTPStatusResponse, error) { return nil, errors.New("executor down") }}).Handler()
	if code, _ := vulnPost(t, h, opsBegin, opsAgentBody(nil)); code != http.StatusServiceUnavailable {
		t.Fatalf("begin with unknown recovery status = %d, want 503", code)
	}
	if len(ops.begun) != 0 {
		t.Fatal("a change with unknown recovery status reached the backend")
	}
}

func TestOpsAgentDataClassChangeReachesCommit(t *testing.T) {
	ops := opsAgentFixture(true)
	h := opsAgentHandler(t, ops, nil, &opsAgentClock{t: vulnNow}, false)
	body := opsAgentBody(func(m map[string]any) {
		m["data_class"] = "external"
		m["base_url"] = "https://llm.example.org/v1"
		m["confirm_url_change"] = true
	})
	id := beginOpsAgent(t, h, body)
	if code, _ := vulnPost(t, h, opsCommit, `{"id":"`+id+`","assertion":`+opsAgentAssertion(t, body)+`}`); code != http.StatusOK {
		t.Fatalf("commit = %d, want 200", code)
	}
	if len(ops.committed) != 1 {
		t.Fatalf("committed = %d, want 1", len(ops.committed))
	}
	if got := ops.committed[0].Settings.DataClass; got != opsconfig.DataClassExternal {
		t.Errorf("committed data class %q, want external", got)
	}
}

func TestOpsAgentCommitFailureIsReportedNotStored(t *testing.T) {
	ops := opsAgentFixture(true)
	ops.saveErr = errors.New("db locked")
	h := opsAgentHandler(t, ops, nil, &opsAgentClock{t: vulnNow}, false)
	body := opsAgentBody(func(m map[string]any) { m["model"] = "llama3.1-8b" })
	id := beginOpsAgent(t, h, body)
	if code, _ := vulnPost(t, h, opsCommit, `{"id":"`+id+`","assertion":`+opsAgentAssertion(t, body)+`}`); code != http.StatusBadGateway {
		t.Fatalf("commit with backend failure = %d, want 502", code)
	}
	if len(ops.committed) != 0 {
		t.Fatal("failed commit was stored")
	}
}

func TestOpsAgentLeavesVulnAgentAndHelpAlone(t *testing.T) {
	ops := opsAgentFixture(true)
	vuln := agentFixture(true)
	h := opsAgentHandler(t, ops, vuln, &opsAgentClock{t: vulnNow}, false)
	body := opsAgentBody(func(m map[string]any) { m["model"] = "llama3.1-8b" })
	id := beginOpsAgent(t, h, body)
	if code, _ := vulnPost(t, h, opsCommit, `{"id":"`+id+`","assertion":`+opsAgentAssertion(t, body)+`}`); code != http.StatusOK {
		t.Fatalf("commit = %d, want 200", code)
	}
	if len(vuln.begun) != 0 || len(vuln.committed) != 0 || vuln.cfg.LLMModel != "qwen3.5-9b-64k" {
		t.Fatalf("ops change touched the vulnerability agent: begun %d committed %d model %q",
			len(vuln.begun), len(vuln.committed), vuln.cfg.LLMModel)
	}
}

func TestOpsAgentChallengesAreLimitedAndExpire(t *testing.T) {
	ops := opsAgentFixture(true)
	clock := &opsAgentClock{t: vulnNow}
	h := opsAgentHandler(t, ops, nil, clock, false)
	// maxOpsAgentPending open challenges are allowed; the next begin waits.
	const maxOpen = 16
	ids := make([]string, 0, maxOpen)
	for i := 0; i < maxOpen; i++ {
		ids = append(ids, beginOpsAgent(t, h, opsAgentBody(func(m map[string]any) { m["model"] = fmt.Sprintf("m%d", i) })))
	}
	if code, _ := vulnPost(t, h, opsBegin, opsAgentBody(func(m map[string]any) { m["model"] = "overflow" })); code != http.StatusTooManyRequests {
		t.Fatalf("begin beyond the limit = %d, want 429", code)
	}
	// After the TTL a challenge is gone.
	clock.t = vulnNow.Add(6 * time.Minute)
	body := opsAgentBody(func(m map[string]any) { m["model"] = "m0" })
	if code, _ := vulnPost(t, h, opsCommit, `{"id":"`+ids[0]+`","assertion":`+opsAgentAssertion(t, body)+`}`); code != http.StatusNotFound {
		t.Fatalf("commit after the TTL = %d, want 404", code)
	}
}

func TestOpsAgentRejectsMalformedChallengeID(t *testing.T) {
	h := opsAgentHandler(t, opsAgentFixture(true), nil, &opsAgentClock{t: vulnNow}, false)
	if code, _ := vulnPost(t, h, opsCommit, `{"id":"../etc","assertion":{"sig":"x"}}`); code != http.StatusNotFound {
		t.Fatalf("malformed challenge ID = %d, want 404", code)
	}
}
