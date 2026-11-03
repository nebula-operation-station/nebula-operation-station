// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
)

const testBatchID = "11111111-2222-4333-8444-555555555555"

type fakeBatchPlanner struct {
	view       executions.BatchView
	viewErr    error
	list       []executions.BatchSummary
	proposed   []executions.BatchRequest
	proposeErr error
	approved   []string
	approveErr error
	refreshed  []string
	skipped    []string
	skipErr    error
}

func (f *fakeBatchPlanner) ListBatches(context.Context) ([]executions.BatchSummary, error) {
	return f.list, nil
}

func (f *fakeBatchPlanner) Batch(_ context.Context, id string) (executions.BatchView, error) {
	if f.viewErr != nil {
		return executions.BatchView{}, f.viewErr
	}
	if id != f.view.ID {
		return executions.BatchView{}, executions.ErrBatchNotFound
	}
	return f.view, nil
}

func (f *fakeBatchPlanner) ProposeBatch(_ context.Context, _ string, req executions.BatchRequest) (executions.BatchCreated, error) {
	f.proposed = append(f.proposed, req)
	if f.proposeErr != nil {
		return executions.BatchCreated{}, f.proposeErr
	}
	return executions.BatchCreated{ID: testBatchID}, nil
}

func (f *fakeBatchPlanner) ApproveBatch(_ context.Context, _, id string, assertion []byte) error {
	f.approved = append(f.approved, id+" "+string(assertion))
	return f.approveErr
}

func (f *fakeBatchPlanner) RefreshBatch(_ context.Context, id string) error {
	f.refreshed = append(f.refreshed, id)
	return nil
}

func (f *fakeBatchPlanner) SkipMember(_ context.Context, _, id, member string) error {
	f.skipped = append(f.skipped, id+"/"+member)
	return f.skipErr
}

func batchServer(t *testing.T, f *fakeBatchPlanner) *http.ServeMux {
	t.Helper()
	p, err := NewBatchPages(f, nil)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	p.Register(mux)
	return mux
}

// fifteenMemberView is the stored ADR example: 12 updates in stage 1 and
// 3 container restarts in stage 2.
func fifteenMemberView(state string) executions.BatchView {
	v := executions.BatchView{ID: testBatchID, Digest: strings.Repeat("d", 64), State: state, Risk: "MEDIUM", Requirement: "assertion_presence",
		Options: []byte(`{"challenge":"abc"}`), Expiry: time.Unix(1_800_000_000, 0), CreatedBy: "axel", CreatedAt: time.Unix(1_799_990_000, 0),
		Stages: []executions.BatchStageView{{Number: 1, StageID: "s1", Gate: "manual", Members: 12}, {Number: 2, StageID: "s2", Gate: "manual", Members: 3}}}
	for i := 1; i <= 15; i++ {
		m := executions.BatchMemberView{Index: i, MemberID: fmt.Sprintf("m-%03d", i), ExecutionID: fmt.Sprintf("00000000-0000-4000-8000-%012d", i),
			Stage: 1, ActionID: "package.install_all", ActionTitle: "Install all updates", ModuleVersion: "1.0.0",
			ArtifactSHA256: strings.Repeat("a", 63) + fmt.Sprintf("%x", i%16), ParametersHash: strings.Repeat("b", 64), Params: "{}", Risk: "MEDIUM",
			HostID: fmt.Sprintf("host-%02d", i), Fingerprint: "SHA256:fp" + fmt.Sprint(i), CredentialRef: "nebula-default", Outcome: executions.OutcomePlanned}
		if i > 12 {
			m.Stage, m.ActionID, m.ActionTitle = 2, "docker.restart", "Restart container"
			m.ContainerID = fmt.Sprintf("%064x", i)
			m.Params = `{"container":"` + m.ContainerID + `"}`
		}
		v.Members = append(v.Members, m)
		v.Counts.Total++
		v.Counts.Planned++
	}
	v.Summary = executions.BatchSummaryText(v.State, v.Counts)
	return v
}

func get(t *testing.T, mux http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestBatchPageListsAllFifteenMembersBeforeApproval(t *testing.T) {
	f := &fakeBatchPlanner{view: fifteenMemberView("pending")}
	rec := get(t, batchServer(t, f), "/batches/"+testBatchID)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	body := rec.Body.String()
	for _, m := range f.view.Members {
		for _, want := range []string{m.MemberID, m.HostID, m.ExecutionID, m.ArtifactSHA256, m.Fingerprint} {
			if !strings.Contains(body, want) {
				t.Errorf("member %d: %q not shown", m.Index, want)
			}
		}
		if m.ContainerID != "" && strings.Count(body, m.ContainerID) < 2 {
			t.Errorf("member %d: container binding or parameters not shown", m.Index)
		}
	}
	for _, want := range []string{"All 15 members", "15 members in 2 stages", strings.Repeat("d", 64), "Install all updates", "Restart container",
		`data-commit="/batches/approve"`, "Approve all 15 members", "waiting for approval", "s1", "s2"} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if strings.Count(body, `class="batch-member `) != 15 {
		t.Errorf("member rows: %d", strings.Count(body, `class="batch-member `))
	}
}

func TestBatchPageEscapesUntrustedText(t *testing.T) {
	v := fifteenMemberView("approved")
	v.Detail = `<script>alert("batch")</script>`
	v.CreatedBy = `"><img src=x onerror=alert(1)>`
	v.Members[0].Outcome = executions.OutcomeFailed
	v.Members[0].Detail = `</td><script>alert("host")</script>`
	v.Members[1].Params = `{"x":"<img src=x onerror=alert(2)>"}`
	v.Members[2].HostID = `<b>host</b>`
	v.Members[3].ActionTitle = `<iframe src="javascript:alert(3)">`
	v.Options = []byte(`{"a":"\"><script>alert(4)</script>"}`)
	v.State, v.Requirement = "pending", "assertion_presence"
	f := &fakeBatchPlanner{view: v}
	body := get(t, batchServer(t, f), "/batches/"+testBatchID).Body.String()
	for _, raw := range []string{`<script>alert`, `<img src=x`, `<b>host</b>`, `<iframe`, `</td><script>`} {
		if strings.Contains(body, raw) {
			t.Errorf("unescaped %q in page", raw)
		}
	}
	for _, escaped := range []string{`&lt;script&gt;alert(&#34;batch&#34;)&lt;/script&gt;`, `&lt;b&gt;host&lt;/b&gt;`, `&lt;iframe`} {
		if !strings.Contains(body, escaped) {
			t.Errorf("escaped %q missing", escaped)
		}
	}
}

func TestBatchPageShowsPartialFailureWithoutRetryOrRollback(t *testing.T) {
	v := fifteenMemberView("approved")
	v.Counts = executions.BatchCounts{Total: 15}
	outcomes := []string{executions.OutcomeSuccess, executions.OutcomeSuccess, executions.OutcomeFailed, executions.OutcomeUnknown, executions.OutcomeSkipped}
	for i := range v.Members {
		o := executions.OutcomeNotExecuted
		if i < len(outcomes) {
			o = outcomes[i]
		}
		v.Members[i].Outcome = o
	}
	v.Members[2].Unreachable = true
	v.Counts = executions.BatchCounts{Total: 15, Success: 2, Failed: 1, Unknown: 1, Skipped: 1, NotExecuted: 10}
	v.Summary = executions.BatchSummaryText(v.State, v.Counts)
	f := &fakeBatchPlanner{view: v}
	body := get(t, batchServer(t, f), "/batches/"+testBatchID).Body.String()
	for _, want := range []string{"partially failed", "2 success, 1 failed, 1 unknown, 1 skipped, 10 not executed", ">success<", ">failed<",
		">unknown<", ">skipped<", ">not executed<", "(unreachable)", "nothing is retried, redispatched or rolled back automatically"} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	lower := strings.ToLower(body)
	for _, forbidden := range []string{">retry", "rollback<", "/batches/retry", "/batches/rollback", `name="member"`} {
		if strings.Contains(lower, forbidden) {
			t.Errorf("page offers %q", forbidden)
		}
	}
	if strings.Contains(body, "schedule-approve") {
		t.Error("approved batch shows an approve button")
	}
}

func TestBatchPageHardenedShowsCLICommandOnly(t *testing.T) {
	v := fifteenMemberView("pending")
	v.Requirement, v.Options = "cli_only", nil
	body := get(t, batchServer(t, &fakeBatchPlanner{view: v}), "/batches/"+testBatchID).Body.String()
	if !strings.Contains(body, "nebula approve "+strings.Repeat("d", 64)) || strings.Contains(body, "schedule-approve") {
		t.Fatal("hardened page must show the CLI command and no browser approval")
	}
}

func TestBatchPageUnknownOrMalformedID(t *testing.T) {
	mux := batchServer(t, &fakeBatchPlanner{view: fifteenMemberView("pending")})
	for _, p := range []string{"/batches/" + strings.Repeat("0", 8) + "-0000-4000-8000-000000000000", "/batches/..%2f", "/batches/%3Cscript%3E"} {
		if rec := get(t, mux, p); rec.Code != http.StatusNotFound {
			t.Errorf("%s: %d", p, rec.Code)
		}
	}
}

func TestBatchListShowsOutcomeCounts(t *testing.T) {
	f := &fakeBatchPlanner{list: []executions.BatchSummary{{ID: testBatchID, State: "approved", Risk: "HIGH", CreatedBy: "<i>x</i>",
		Counts: executions.BatchCounts{Total: 15, Success: 3, Failed: 1, NotExecuted: 11}, Summary: "partially failed"}}}
	body := get(t, batchServer(t, f), "/batches").Body.String()
	for _, want := range []string{testBatchID, "15 (3 success, 1 failed", "11 not executed", "partially failed", "&lt;i&gt;x&lt;/i&gt;"} {
		if !strings.Contains(body, want) {
			t.Errorf("list lacks %q", want)
		}
	}
	if rec := get(t, batchServer(t, f), "/batches/new"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `action="/batches/create"`) {
		t.Errorf("new page %d", rec.Code)
	}
}

func postForm(t *testing.T, mux http.Handler, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestBatchCreateKeepsEveryListedMemberInOrder(t *testing.T) {
	var plan strings.Builder
	plan.WriteString("# updates first\nstage manual failures=1 unreachable=2\n")
	for i := 1; i <= 12; i++ {
		fmt.Fprintf(&plan, "package.install_all host-%02d\r\n", i)
	}
	plan.WriteString("\nstage automatic\n")
	for i := 13; i <= 15; i++ {
		fmt.Fprintf(&plan, "docker.restart host-%02d container=%064x\n", i, i)
	}
	f := &fakeBatchPlanner{}
	rec := postForm(t, batchServer(t, f), "/batches/create", url.Values{"plan": {plan.String()}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/batches/"+testBatchID {
		t.Fatalf("status %d location %q body %q", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	req := f.proposed[0]
	if len(req.Stages) != 2 || len(req.Stages[0].Members) != 12 || len(req.Stages[1].Members) != 3 {
		t.Fatalf("stages %+v", req.Stages)
	}
	if s := req.Stages[0]; s.Gate != "manual" || s.FailureThreshold != 1 || s.UnreachableThreshold != 2 {
		t.Errorf("stage 1 %+v", s)
	}
	if req.Stages[1].Gate != "automatic" || req.Stages[1].FailureThreshold != 0 {
		t.Errorf("stage 2 %+v", req.Stages[1])
	}
	for i, m := range req.Stages[0].Members {
		if m.ActionID != "package.install_all" || m.HostID != fmt.Sprintf("host-%02d", i+1) || len(m.Params) != 0 {
			t.Errorf("update %d: %+v", i+1, m)
		}
	}
	for i, m := range req.Stages[1].Members {
		if m.ActionID != "docker.restart" || m.HostID != fmt.Sprintf("host-%02d", i+13) || m.Params["container"] != fmt.Sprintf("%064x", i+13) {
			t.Errorf("restart %d: %+v", i+1, m)
		}
	}
}

func TestParseBatchPlanRejectsMalformedPlans(t *testing.T) {
	cases := map[string]string{
		"empty":           "",
		"comments only":   "# nothing\n\n",
		"no host":         "core.facts\n",
		"bad param":       "core.facts web unit\n",
		"bad param name":  "core.facts web Unit=x\n",
		"duplicate param": "service.restart web unit=a unit=b\n",
		"empty stage":     "stage\nstage\ncore.facts web\n",
		"trailing stage":  "core.facts web\nstage\n",
		"stage option":    "stage fast\ncore.facts web\n",
		"negative":        "stage failures=-1\ncore.facts web\n",
		"huge threshold":  "stage unreachable=1000\ncore.facts web\n",
		"invalid UTF-8":   "core.facts w\xffb\n",
		"too many lines":  strings.Repeat("\n", maxBatchPlanLines+1),
		"line too long":   "core.facts " + strings.Repeat("a", maxBatchLineBytes) + "\n",
		"too many params": "core.facts web a=1 b=2 c=3 d=4 e=5 f=6 g=7 h=8 i=9\n",
		"plan too large":  strings.Repeat("core.facts web\n", maxBatchPlanBytes/15+1),
	}
	for name, text := range cases {
		if _, err := parseBatchPlan(text); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestBatchCreateReportsErrorsAsText(t *testing.T) {
	crit := &executions.BatchCriticalError{Members: []executions.BatchMemberView{
		{MemberID: "m-003", ActionID: "system.reboot", HostID: "<b>db</b>", Params: "{}"}}}
	cases := []struct {
		err  error
		code int
		want string
	}{
		{crit, http.StatusUnprocessableEntity, "m-003: system.reboot on <b>db</b>"},
		{&executions.BatchInputError{Reason: "member 2 repeats member 1"}, http.StatusBadRequest, "member 2 repeats member 1"},
		{&executions.HostError{Host: "web", Reason: "blocked after a host key mismatch"}, http.StatusBadRequest, "blocked"},
		{executions.ErrBatchCredentials, http.StatusBadGateway, "credential versions"},
		{errors.New("rpc error: secret detail"), http.StatusBadGateway, "could not be proposed"},
	}
	for _, c := range cases {
		f := &fakeBatchPlanner{proposeErr: c.err}
		rec := postForm(t, batchServer(t, f), "/batches/create", url.Values{"plan": {"core.facts web\n"}})
		if rec.Code != c.code || !strings.Contains(rec.Body.String(), c.want) || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain") {
			t.Errorf("%v: %d %q %q", c.err, rec.Code, rec.Body.String(), rec.Header().Get("Content-Type"))
		}
		if strings.Contains(rec.Body.String(), "secret detail") {
			t.Error("internal error detail leaked")
		}
	}
}

func TestBatchApproveRelaysAssertionJSON(t *testing.T) {
	f := &fakeBatchPlanner{}
	mux := batchServer(t, f)
	post := func(ct, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/batches/approve", strings.NewReader(body))
		req.Header.Set("Content-Type", ct)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}
	if rec := post("application/x-www-form-urlencoded", "id=x"); rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("form post: %d", rec.Code)
	}
	if rec := post("application/json", `{"id":"../x","assertion":{}}`); rec.Code != http.StatusNotFound {
		t.Errorf("bad id: %d", rec.Code)
	}
	if rec := post("application/json", `{"id":"`+testBatchID+`","assertion":{"ok":true}}`); rec.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
	}
	if len(f.approved) != 1 || f.approved[0] != testBatchID+` {"ok":true}` {
		t.Fatalf("relayed %v", f.approved)
	}
	f.approveErr = executions.ErrBatchNotPending
	if rec := post("application/json", `{"id":"`+testBatchID+`","assertion":{}}`); rec.Code != http.StatusConflict {
		t.Errorf("not pending: %d", rec.Code)
	}
}

func TestBatchSkipAndRefreshValidateInput(t *testing.T) {
	f := &fakeBatchPlanner{}
	mux := batchServer(t, f)
	if rec := postForm(t, mux, "/batches/skip", url.Values{"id": {testBatchID}, "member": {"m-004"}}); rec.Code != http.StatusSeeOther || f.skipped[0] != testBatchID+"/m-004" {
		t.Fatalf("skip: %d %v", rec.Code, f.skipped)
	}
	if rec := postForm(t, mux, "/batches/skip", url.Values{"id": {testBatchID}, "member": {"m-4; drop"}}); rec.Code != http.StatusNotFound {
		t.Errorf("bad member: %d", rec.Code)
	}
	f.skipErr = executions.ErrBatchMemberFinal
	if rec := postForm(t, mux, "/batches/skip", url.Values{"id": {testBatchID}, "member": {"m-001"}}); rec.Code != http.StatusConflict {
		t.Errorf("final member: %d", rec.Code)
	}
	if rec := postForm(t, mux, "/batches/refresh", url.Values{"id": {testBatchID}}); rec.Code != http.StatusSeeOther || len(f.refreshed) != 1 {
		t.Errorf("refresh: %d", rec.Code)
	}
	if rec := postForm(t, mux, "/batches/refresh", url.Values{"id": {"nope"}}); rec.Code != http.StatusNotFound {
		t.Errorf("bad refresh id: %d", rec.Code)
	}
}
