// SPDX-License-Identifier: AGPL-3.0-or-later
package ui_test

import (
	"context"
	"errors"
	"html"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// Staged OS update from the chart, review ou02: the confirmation page
// shows the staged plan that is proposed, and enrolled hosts without an
// environment are neither selectable nor accepted.

// stagedEnv is the inventory environment of the stagedHosts.
func stagedEnv() map[string]inventory.Environment {
	out := map[string]inventory.Environment{}
	for _, h := range stagedHosts() {
		out[h.ID] = h.Environment
	}
	return out
}

// renderedStage is one stage as the confirmation page shows it.
type renderedStage struct {
	Name  string
	Hosts []string
	Gate  bool
}

var (
	stageItemRe = regexp.MustCompile(`(?s)<li class="staged-confirm__stage">(.*?)</ul>(.*?)</li>`)
	stageHeadRe = regexp.MustCompile(`<h3>Stage (\d+): ([^<]*)</h3>`)
	stageHostRe = regexp.MustCompile(`<li>([^<]*)</li>`)
	hiddenRe    = regexp.MustCompile(`<input type="hidden" name="([^"]*)" value="([^"]*)">`)
)

// renderedStages parses the stages of a confirmation page, mapping the
// shown host names back to ids with names.
func renderedStages(t *testing.T, body string, idOf map[string]string) []renderedStage {
	t.Helper()
	var out []renderedStage
	for i, m := range stageItemRe.FindAllStringSubmatch(body, -1) {
		head := stageHeadRe.FindStringSubmatch(m[1])
		if head == nil {
			t.Fatalf("stage %d has no heading: %q", i+1, m[1])
		}
		if head[1] != string(rune('1'+i)) {
			t.Errorf("stage %d is numbered %s", i+1, head[1])
		}
		st := renderedStage{Name: head[2], Gate: strings.Contains(m[2], "staged-confirm__gate")}
		for _, hm := range stageHostRe.FindAllStringSubmatch(m[1], -1) {
			id, ok := idOf[html.UnescapeString(hm[1])]
			if !ok {
				t.Fatalf("stage %s shows unknown host %q", st.Name, hm[1])
			}
			st.Hosts = append(st.Hosts, id)
		}
		out = append(out, st)
	}
	return out
}

// confirmFormBody is the body the confirmation page's form submits.
func confirmFormBody(t *testing.T, body string) string {
	t.Helper()
	_, form, ok := strings.Cut(body, `<section class="panel staged-confirm"`)
	if !ok {
		t.Fatal("no confirmation section")
	}
	v := url.Values{}
	for _, m := range hiddenRe.FindAllStringSubmatch(form, -1) {
		v.Add(m[1], html.UnescapeString(m[2]))
	}
	return v.Encode()
}

func TestChartStagedConfirmShowsTheProposedPlan(t *testing.T) {
	h, ops := stagedChartHandler(t, false)
	// Submitted PROD, DEV, QA: the plan regroups them DEV, QA, PROD.
	rec := httptest.NewRecorder()
	h.Handler().ServeHTTP(rec, formPost("/inventory/chart/staged", "host=web-01&host=ci-01&host=db-01&action=package.install_all"))
	if rec.Code != http.StatusOK {
		t.Fatalf("confirmation: status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "in the order shown") {
		t.Error("confirmation still promises the submitted order")
	}
	idOf := map[string]string{"CI runner": "ci-01", "DB server": "db-01", "web-01": "web-01"}
	shown := renderedStages(t, body, idOf)
	want := []renderedStage{
		{Name: "dev", Hosts: []string{"ci-01"}, Gate: true},
		{Name: "qa", Hosts: []string{"db-01"}, Gate: true},
		{Name: "prod", Hosts: []string{"web-01"}, Gate: false},
	}
	if !reflect.DeepEqual(shown, want) {
		t.Fatalf("shown stages = %+v, want %+v", shown, want)
	}
	if n := strings.Count(body, "staged-confirm__gate"); n != 2 {
		t.Errorf("gates shown = %d, want 2 (between the three stages)", n)
	}

	// Submit the confirmation form as a browser would: the plan that
	// reaches the proposal lays out exactly as shown.
	rec = httptest.NewRecorder()
	h.Handler().ServeHTTP(rec, formPost("/inventory/chart/staged", confirmFormBody(t, body)))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("confirm: status = %d, want 303: %s", rec.Code, rec.Body.String())
	}
	if len(ops.createdCalls) != 1 {
		t.Fatalf("CreateStaged calls = %v, want 1", ops.createdCalls)
	}
	proposed, err := executions.PlanStages(ops.plan, ops.createdCalls[0][2:], stagedEnv())
	if err != nil {
		t.Fatalf("PlanStages of the proposal: %v", err)
	}
	var got []renderedStage
	for i, st := range proposed {
		got = append(got, renderedStage{Name: st.Name, Hosts: st.Hosts, Gate: i < len(proposed)-1 && st.Continue == "manual"})
	}
	if !reflect.DeepEqual(got, shown) {
		t.Errorf("proposed plan %+v differs from the shown plan %+v", got, shown)
	}
}

// noEnvHandler serves web-01 (PROD) and noenv-01 (no environment), both
// enrolled.
func noEnvHandler(t *testing.T) (*ui.Handler, *fakeOps) {
	t.Helper()
	ops := &fakeOps{}
	h := newTestHandler(t, ui.Options{
		Hosts: func(context.Context) ([]inventory.Host, error) {
			return []inventory.Host{
				{ID: "web-01", Environment: inventory.EnvProd},
				{ID: "noenv-01", DisplayName: "No env"},
			}, nil
		},
		HostKeys: func(context.Context) ([]*pb.HostKeyPin, error) {
			return []*pb.HostKeyPin{
				{HostId: "web-01", KeyType: "ssh-ed25519", Fingerprint: "SHA256:AAAA"},
				{HostId: "noenv-01", KeyType: "ssh-ed25519", Fingerprint: "SHA256:BBBB"},
			}, nil
		},
		Operations:   ops,
		Log:          slog.New(slog.NewTextHandler(&strings.Builder{}, nil)),
		PublicOrigin: "https://nebula.example",
	})
	return h, ops
}

func TestChartStagedHostWithoutEnvironmentNotSelectable(t *testing.T) {
	h, _ := noEnvHandler(t)
	body := getBody(t, h.Handler(), "/inventory/chart")
	if got := hostCheckboxes(t, body); !reflect.DeepEqual(got, []string{"web-01"}) {
		t.Errorf("selectable hosts = %v, want [web-01]", got)
	}
	if !strings.Contains(body, `<input type="checkbox" value="noenv-01" disabled>`) {
		t.Error("no disabled checkbox for the host without environment")
	}
	if !strings.Contains(body, "not selectable: no environment (DEV, QA or PROD)") {
		t.Error("the reason is not shown")
	}
}

func TestChartStagedRefusesHostWithoutEnvironment(t *testing.T) {
	h, ops := noEnvHandler(t)
	for _, form := range []string{
		"host=noenv-01&action=package.install_security",
		"host=web-01&host=noenv-01&action=package.install_security",
		"confirm=1&host=web-01&host=noenv-01&action=package.install_security",
	} {
		rec := httptest.NewRecorder()
		h.Handler().ServeHTTP(rec, formPost("/inventory/chart/staged", form))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", form, rec.Code)
		}
		if msg := rec.Body.String(); !strings.Contains(msg, `"noenv-01"`) || !strings.Contains(msg, "no environment (DEV, QA or PROD)") {
			t.Errorf("%s: unclear error %q", form, msg)
		}
		if strings.Contains(rec.Body.String(), "Confirm staged OS update") {
			t.Errorf("%s: confirmation page shown", form)
		}
	}
	if len(ops.createdCalls) != 0 {
		t.Errorf("a proposal was made: %v", ops.createdCalls)
	}
}

func TestChartStagedRefusals(t *testing.T) {
	log := slog.New(slog.NewTextHandler(&strings.Builder{}, nil))
	post := func(h *ui.Handler, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.Handler().ServeHTTP(rec, formPost("/inventory/chart/staged", body))
		return rec
	}
	t.Run("blocked host", func(t *testing.T) {
		ops := &fakeOps{}
		h := newTestHandler(t, ui.Options{
			Hosts: func(context.Context) ([]inventory.Host, error) {
				return []inventory.Host{{ID: "web-01", Environment: inventory.EnvProd}}, nil
			},
			HostKeys: hostKeysFor("web-01", keyBlocked), Operations: ops, Log: log, PublicOrigin: "https://nebula.example",
		})
		for _, form := range []string{"host=web-01&action=package.install_all", "confirm=1&host=web-01&action=package.install_all"} {
			if rec := post(h, form); rec.Code != http.StatusBadRequest {
				t.Errorf("%s: status = %d, want 400", form, rec.Code)
			}
		}
		if len(ops.createdCalls) != 0 {
			t.Error("a proposal was made for a blocked host")
		}
	})
	t.Run("pins unavailable", func(t *testing.T) {
		ops := &fakeOps{}
		h := newTestHandler(t, ui.Options{
			Hosts: func(context.Context) ([]inventory.Host, error) {
				return []inventory.Host{{ID: "web-01", Environment: inventory.EnvProd}}, nil
			},
			HostKeys: hostKeysFor("web-01", keyUnavailable), Operations: ops, Log: log, PublicOrigin: "https://nebula.example",
		})
		if rec := post(h, "confirm=1&host=web-01&action=package.install_all"); rec.Code != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want 503", rec.Code)
		}
		if len(ops.createdCalls) != 0 {
			t.Error("a proposal was made without known enrollment")
		}
	})
	t.Run("too many hosts", func(t *testing.T) {
		h, ops := stagedChartHandler(t, false)
		v := url.Values{"action": {"package.install_all"}, "confirm": {"1"}}
		for range 1001 {
			v.Add("host", "web-01")
		}
		if rec := post(h, v.Encode()); rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", rec.Code)
		}
		if len(ops.createdCalls) != 0 {
			t.Error("a proposal was made for too many hosts")
		}
	})
	t.Run("oversized body", func(t *testing.T) {
		h, ops := stagedChartHandler(t, false)
		body := "action=package.install_all&confirm=1&host=web-01&pad=" + strings.Repeat("a", 2<<20)
		if rec := post(h, body); rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", rec.Code)
		}
		if len(ops.createdCalls) != 0 {
			t.Error("a proposal was made for an oversized body")
		}
	})
	t.Run("long unknown id is not echoed in full", func(t *testing.T) {
		h, _ := stagedChartHandler(t, false)
		long := strings.Repeat("x", 5000)
		rec := post(h, "action=package.install_all&host="+long)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
		if len(rec.Body.String()) > 200 {
			t.Errorf("error echoes %d bytes", len(rec.Body.String()))
		}
	})
	for _, c := range []struct {
		name string
		err  error
		code int
		text string
	}{
		{"executor refusal", status.Error(codes.FailedPrecondition, "executor locked"), http.StatusConflict, "the executor refused: executor locked"},
		{"executor unavailable", status.Error(codes.Unavailable, "down"), http.StatusBadGateway, "executor unavailable"},
		{"operations unavailable", errors.New("db closed"), http.StatusServiceUnavailable, "operations unavailable"},
	} {
		t.Run(c.name, func(t *testing.T) {
			h, ops := stagedChartHandler(t, false)
			ops.createErr = c.err
			rec := post(h, "confirm=1&host=web-01&action=package.install_all")
			if rec.Code != c.code {
				t.Errorf("status = %d, want %d", rec.Code, c.code)
			}
			if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
				t.Errorf("Content-Type = %q, want text/plain (a no-JavaScript form)", ct)
			}
			if !strings.Contains(rec.Body.String(), c.text) {
				t.Errorf("body = %q, want %q", rec.Body.String(), c.text)
			}
		})
	}
}
