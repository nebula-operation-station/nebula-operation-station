// SPDX-License-Identifier: AGPL-3.0-or-later

package paths_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/attackpath"
	"github.com/nebula-operation-station/nebula-operation-station/internal/attackpath/sources"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui/paths"
)

const origin = "https://nebula.example.org"

const (
	hashA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hashB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// eB is ap-v1's e of the assumed step of path B: 0.3 × 2.835 / 3.9 × 0.5.
const eB = 0.3 * 2.835 / 3.9 * 0.5

const hostile = `<script>alert(1)</script>"><img src=x onerror=alert(2)>`

type fakeSource struct {
	snap paths.Snapshot
	err  error
}

func (f *fakeSource) Snapshot(context.Context) (paths.Snapshot, error) { return f.snap, f.err }

// fixture is one target (the executor host, impact 10) with one path:
// internet -(tcp/443, KEV finding)-> host:web -(credential)-> host:exec,
// and a second target without any path.
func fixture() paths.Snapshot {
	web := attackpath.Step{
		Kind: attackpath.StepNetwork, From: attackpath.InternetID, To: "host:web",
		Edge:    attackpath.Edge{From: attackpath.InternetID, To: "host:web", Kind: attackpath.EdgeNetworkPolicy, Proto: attackpath.ProtoTCP, Port: 443},
		Finding: "fk-web", Owns: true,
		Terms: attackpath.Terms{KEV: true, EPSS: 0.42, EPSSKnown: true, Exploitability: 3.887, Vector: attackpath.AVNetwork, E: 0.9},
	}
	cred := attackpath.Step{
		Kind: attackpath.StepCredential, From: "host:web", To: "host:exec",
		Edge:  attackpath.Edge{From: "host:web", To: "host:exec", Kind: attackpath.EdgeCredential},
		Owns:  true,
		Terms: attackpath.Terms{E: 1},
	}
	l2 := attackpath.Step{
		Kind: attackpath.StepNetwork, From: attackpath.NetBirdID, To: "host:exec",
		Edge:    attackpath.Edge{From: attackpath.NetBirdID, To: "host:exec", Kind: attackpath.EdgeNetworkObserved, Proto: attackpath.ProtoTCP, Port: 22},
		Finding: "fk-ssh", Possible: true, Owns: true,
		Terms: attackpath.Terms{EPSSKnown: false, Exploitability: 2.835, Vector: attackpath.AVNetwork, Assumed: true, E: eB},
	}
	res := &attackpath.Result{
		FormulaVersion: attackpath.FormulaVersion,
		GraphHash:      strings.Repeat("c", 64),
		Targets: []attackpath.TargetPaths{
			{Node: "host:exec", Impact: 10, Complete: true, Paths: []attackpath.Path{
				{Hash: hashA, Entry: attackpath.InternetID, Steps: []attackpath.Step{web, cred}, Likelihood: 0.9, Risk: 9},
				{Hash: hashB, Entry: attackpath.NetBirdID, Steps: []attackpath.Step{l2}, Likelihood: eB, Risk: 10 * eB, Possible: true, Assumed: true},
			}},
			{Node: "host:nas", Impact: 8, Complete: true},
		},
		ChokePoints: []attackpath.ChokePoint{
			{Kind: attackpath.FixFinding, Node: "host:web", Finding: "fk-web", Risk: 9, Paths: 1},
			{Kind: attackpath.FixEdge, Edge: l2.Edge, Risk: 1.09, Paths: 1},
		},
		UnscoredFindings: 2,
	}
	return paths.Snapshot{
		Result:     res,
		ComputedAt: time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC),
		Labels:     map[string]string{"host:web": "web01", "host:exec": "executor", "host:nas": "nas"},
		Findings: map[paths.FindingRef]paths.FindingInfo{
			{Node: "host:web", Key: "fk-web"}: {VulnID: "CVE-2026-1111", Package: "nginx",
				Fix: paths.FixLink{Href: "/inventory/hosts/web/updates?pkg=nginx", Text: "Update nginx", Verified: true}},
			{Node: "host:exec", Key: "fk-ssh"}: {VulnID: "CVE-2026-2222", Package: "openssh-server",
				Fix: paths.FixLink{Href: "javascript:alert(1)", Text: "evil"}},
		},
	}
}

type env struct {
	h     http.Handler
	admin bool
	src   *fakeSource
}

func newEnv(t *testing.T, snap paths.Snapshot) *env {
	t.Helper()
	e := &env{admin: true, src: &fakeSource{snap: snap}}
	h, err := paths.New(paths.Options{
		Source:       e.src,
		Authorize:    func(*http.Request) bool { return e.admin },
		PublicOrigin: origin,
		MapNode: func(id string) (string, bool) {
			if strings.HasPrefix(id, "host:") {
				return "m-" + strings.TrimPrefix(id, "host:"), true
			}
			return "", false
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	e.h = h.Handler()
	return e
}

func (e *env) get(t *testing.T, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	return rec
}

func mustOK(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %q", rec.Code, rec.Body.String())
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	return rec.Body.String()
}

// text strips tags and unescapes entities, so assertions read like the page.
func text(body string) string {
	s := regexp.MustCompile(`(?s)<[^>]*>`).ReplaceAllString(body, " ")
	s = html.UnescapeString(s)
	return strings.Join(strings.Fields(s), " ")
}

var allRoutes = []string{
	"/vuln/paths",
	"/vuln/paths/p/" + hashA,
	"/vuln/paths/map",
	"/vuln/paths/map/frame",
	"/vuln/paths/map?path=" + hashA,
	"/vuln/paths/map/frame?target=host:exec",
}

func TestNonAdminIsRefusedOnEveryRoute(t *testing.T) {
	e := newEnv(t, fixture())
	e.admin = false
	for _, r := range allRoutes {
		rec := e.get(t, r)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403", r, rec.Code)
		}
		for _, leak := range []string{"web01", "executor", "CVE-2026", "m-web", "host:web"} {
			if strings.Contains(rec.Body.String(), leak) {
				t.Errorf("%s: forbidden response leaks %q", r, leak)
			}
		}
	}
}

func TestNewRequiresAuthorizeSourceAndOrigin(t *testing.T) {
	ok := paths.Options{Source: &fakeSource{}, Authorize: func(*http.Request) bool { return true }, PublicOrigin: origin}
	cases := map[string]func(o *paths.Options){
		"no source":     func(o *paths.Options) { o.Source = nil },
		"no authorize":  func(o *paths.Options) { o.Authorize = nil },
		"no origin":     func(o *paths.Options) { o.PublicOrigin = "" },
		"origin path":   func(o *paths.Options) { o.PublicOrigin = origin + "/x" },
		"origin inject": func(o *paths.Options) { o.PublicOrigin = "https://a.example; script-src *" },
		"bad window":    func(o *paths.Options) { o.Window = "99d" },
	}
	for name, mod := range cases {
		o := ok
		mod(&o)
		if _, err := paths.New(o); err == nil {
			t.Errorf("%s: New succeeded", name)
		}
	}
	if _, err := paths.New(ok); err != nil {
		t.Fatalf("valid options: %v", err)
	}
}

func TestListShowsPathsPerTargetAndChokePoints(t *testing.T) {
	e := newEnv(t, fixture())
	body := mustOK(t, e.get(t, "/vuln/paths"))
	txt := text(body)
	for _, want := range []string{
		"executor", "impact 10", "web01", "Internet", "NetBird",
		"0.900", "9.00", // L and R of the top path
		"CVE-2026-1111", "Update nginx",
		"assumed", "possible",
		"/vuln/paths/p/" + hashA,
	} {
		if !strings.Contains(txt, want) && !strings.Contains(body, want) {
			t.Errorf("list lacks %q", want)
		}
	}
	// Choke points: finding fix with its link, edge removal as a rule change.
	if !strings.Contains(body, `href="/inventory/hosts/web/updates?pkg=nginx"`) {
		t.Error("choke point lacks the fix link")
	}
	if !strings.Contains(txt, "tcp/22") || !strings.Contains(txt, "firewall rule change") {
		t.Error("edge choke point is not explained as a rule change")
	}
	if !strings.Contains(txt, "2 findings without a CVSS v3 vector") {
		t.Error("unscored findings are not shown as uncertainty")
	}
}

// panelText returns the text of the list page's panel for the target with
// the given label, so an assertion cannot be satisfied by another panel.
func panelText(t *testing.T, body, label string) string {
	t.Helper()
	open := `<section class="panel" aria-label="Paths to ` + label + `">`
	if strings.Count(body, open) != 1 {
		t.Fatalf("want exactly one panel for %q", label)
	}
	rest := body[strings.Index(body, open):]
	end := strings.Index(rest, "</section>")
	if end < 0 {
		t.Fatalf("panel for %q is not closed", label)
	}
	return text(rest[:end])
}

// completeReport is a data-source report with every required source complete.
func completeReport(t *testing.T) *sources.Report {
	t.Helper()
	var srcs []sources.SourceReport
	for _, name := range sources.RequiredSources() {
		srcs = append(srcs, sources.SourceReport{Source: name, Status: sources.StatusComplete, Coverage: sources.Coverage{Covered: 1, Total: 1}})
	}
	r := &sources.Report{Sources: srcs}
	if !r.Complete() {
		t.Fatal("fixture report is not complete")
	}
	return r
}

func TestNoPathIsNeverShownAsSafe(t *testing.T) {
	cases := map[string]func(t *testing.T, s *paths.Snapshot){
		"coverage unknown": func(_ *testing.T, s *paths.Snapshot) { s.Report = nil },
		"coverage partial": func(_ *testing.T, s *paths.Snapshot) {
			s.Report = &sources.Report{Missing: []string{sources.SourceFirewall}}
		},
		"search incomplete": func(t *testing.T, s *paths.Snapshot) {
			s.Report = completeReport(t)
			s.Result.UnscoredFindings = 0
			s.Result.Targets[1].Complete = false
		},
		"computation truncated": func(t *testing.T, s *paths.Snapshot) {
			s.Report = completeReport(t)
			s.Result.UnscoredFindings = 0
			s.Result.Truncated = true
			s.Result.Limits.Budget = true
		},
		"unscored findings": func(t *testing.T, s *paths.Snapshot) {
			s.Report = completeReport(t)
		},
		"unattached findings": func(t *testing.T, s *paths.Snapshot) {
			s.Report = completeReport(t)
			s.Result.UnscoredFindings = 0
			s.Result.UnattachedFindings = 1
		},
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			s := fixture()
			mod(t, &s)
			// Only the host:nas panel: path B ("port mapping unknown") and
			// the coverage panel also say "unknown" elsewhere on the page.
			nas := panelText(t, mustOK(t, newEnv(t, s).get(t, "/vuln/paths")), "nas")
			if !strings.Contains(nas, "Unknown:") {
				t.Errorf("target without paths is not labelled unknown in its panel: %q", nas)
			}
			lower := strings.ToLower(nas)
			if strings.Contains(lower, "no path found") && !strings.Contains(lower, "unknown") {
				t.Errorf("panel says no path found without unknown: %q", nas)
			}
			if strings.Contains(lower, "no path found within the limits") {
				t.Errorf("panel uses the complete-coverage wording: %q", nas)
			}
			for _, bad := range []string{"safe", "no risk", "secure", "clean"} {
				if strings.Contains(lower, bad) {
					t.Errorf("panel says %q", bad)
				}
			}
		})
	}
}

func TestNoPathWithCompleteCoverageIsNoGuarantee(t *testing.T) {
	s := fixture()
	s.Result.UnscoredFindings = 0
	s.Report = completeReport(t)
	nas := strings.ToLower(panelText(t, mustOK(t, newEnv(t, s).get(t, "/vuln/paths")), "nas"))
	if !strings.Contains(nas, "no path found within the limits") || !strings.Contains(nas, "not a guarantee") {
		t.Errorf("complete coverage wording: %s", nas)
	}
	if strings.Contains(nas, "safe") {
		t.Error("panel says safe")
	}
}

func TestStoredValueMismatchIsFlagged(t *testing.T) {
	s := fixture()
	s.Result.Targets[0].Paths[0].Steps[0].Terms.E = 0.5
	txt := text(mustOK(t, newEnv(t, s).get(t, "/vuln/paths/p/"+hashA)))
	if !strings.Contains(txt, "differs from this recomputation") {
		t.Error("mismatch between stored e and its inputs not flagged")
	}
	txt = text(mustOK(t, newEnv(t, fixture()).get(t, "/vuln/paths/p/"+hashA)))
	if strings.Contains(txt, "differs from this recomputation") {
		t.Error("consistent values flagged as mismatch")
	}
}

func TestStepWithoutFindingShowsStoredValue(t *testing.T) {
	s := fixture()
	s.Result.Targets[0].Paths[0].Steps[1].Terms.E = 0.7
	txt := text(mustOK(t, newEnv(t, s).get(t, "/vuln/paths/p/"+hashA)))
	if !strings.Contains(txt, "stored e = 0.700") || !strings.Contains(txt, "The stored value e = 0.700 differs from this recomputation") {
		t.Errorf("stored e of a step without a finding is not shown and flagged:\n%s", txt)
	}
	if strings.Contains(txt, "e = 1: no vulnerability needed") {
		t.Error("step without a finding still claims e = 1")
	}
	// Consistent: e = 1, no flag.
	txt = text(mustOK(t, newEnv(t, fixture()).get(t, "/vuln/paths/p/"+hashA)))
	if !strings.Contains(txt, "e = 1: no vulnerability needed") || strings.Contains(txt, "differs from this recomputation") {
		t.Errorf("consistent credential step:\n%s", txt)
	}
}

func TestCoverageLimitTextsUseTheComputationCaps(t *testing.T) {
	s := fixture()
	s.Result.Truncated = true
	s.Result.Limits = attackpath.Limits{Graph: true, Findings: true, Targets: true, ChokePoints: true}
	txt := text(mustOK(t, newEnv(t, s).get(t, "/vuln/paths")))
	for _, want := range []string{
		"5,000 nodes", "50,000 edges", "100,000 findings", "crown-jewel target cap (50)", "choke-point cap (500)",
	} {
		if !strings.Contains(txt, want) {
			t.Errorf("limits lack %q:\n%s", want, txt)
		}
	}
}

// TestOverlayIsBoundedByTheRendererByteLimit: an overlay at the beam and
// mark caps with the longest map IDs exceeds the renderer's byte limit; it
// is truncated to fit and flagged, never sent too large (the renderer would
// reject it whole).
func TestOverlayIsBoundedByTheRendererByteLimit(t *testing.T) {
	var targets []attackpath.TargetPaths
	for i := range paths.MaxBeams + 10 {
		from, to := fmt.Sprintf("host:a%d", i), fmt.Sprintf("host:b%d", i)
		h := fmt.Sprintf("%064x", i+1)
		targets = append(targets, attackpath.TargetPaths{Node: to, Impact: 5, Complete: true, Paths: []attackpath.Path{{
			Hash: h, Entry: from, Likelihood: 1, Risk: 5,
			Steps: []attackpath.Step{{Kind: attackpath.StepCredential, From: from, To: to, Owns: true, Terms: attackpath.Terms{E: 1},
				Edge: attackpath.Edge{From: from, To: to, Kind: attackpath.EdgeCredential}}},
		}}})
	}
	snap := paths.Snapshot{Result: &attackpath.Result{FormulaVersion: attackpath.FormulaVersion, Targets: targets}}
	src := &fakeSource{snap: snap}
	h, err := paths.New(paths.Options{
		Source: src, Authorize: func(*http.Request) bool { return true }, PublicOrigin: origin,
		MapNode: func(id string) (string, bool) {
			id = strings.TrimPrefix(id, "host:")
			return id + strings.Repeat("x", 128-len(id)), true
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/vuln/paths/map/frame", nil))
	body := mustOK(t, rec)
	m := regexp.MustCompile(`data-paths="([^"]*)"`).FindStringSubmatch(body)
	if m == nil {
		t.Fatal("frame lacks data-paths")
	}
	raw := html.UnescapeString(m[1])
	if len(raw) > paths.MaxOverlayBytes {
		t.Fatalf("overlay is %d bytes, renderer limit %d", len(raw), paths.MaxOverlayBytes)
	}
	var o struct {
		overlay
		Truncated bool `json:"truncated"`
	}
	if err := json.Unmarshal([]byte(raw), &o); err != nil {
		t.Fatalf("overlay JSON: %v", err)
	}
	if !o.Truncated || len(o.Beams) == 0 || len(o.Marks) == 0 {
		t.Errorf("truncated %v, %d beams, %d marks", o.Truncated, len(o.Beams), len(o.Marks))
	}
	if len(raw) < paths.MaxOverlayBytes/2 {
		t.Errorf("overlay cut far below the limit: %d bytes", len(raw))
	}
}

func TestMissingTargetAndTruncationAreShown(t *testing.T) {
	s := fixture()
	s.Result.MissingTargets = []string{"host:gone"}
	s.Result.Truncated = true
	s.Result.Limits.Budget = true
	txt := text(mustOK(t, newEnv(t, s).get(t, "/vuln/paths")))
	if !strings.Contains(txt, "host:gone") || !strings.Contains(txt, "not in the graph") {
		t.Error("missing target not shown")
	}
	if !strings.Contains(txt, "truncated") || !strings.Contains(txt, "time budget") {
		t.Error("truncation not shown with its limit")
	}
}

func TestNotComputedYetIsUnknown(t *testing.T) {
	txt := strings.ToLower(text(mustOK(t, newEnv(t, paths.Snapshot{}).get(t, "/vuln/paths"))))
	if !strings.Contains(txt, "not computed yet") || !strings.Contains(txt, "unknown") {
		t.Errorf("empty snapshot: %q", txt)
	}
}

func TestUnknownFormulaVersionShowsNoExplanation(t *testing.T) {
	s := fixture()
	s.Result.FormulaVersion = "ap-v9"
	txt := text(mustOK(t, newEnv(t, s).get(t, "/vuln/paths/p/"+hashA)))
	if !strings.Contains(txt, "formula ap-v9 is not known") {
		t.Error("unknown formula not flagged")
	}
}

func TestDetailExplainsEveryStep(t *testing.T) {
	e := newEnv(t, fixture())
	body := mustOK(t, e.get(t, "/vuln/paths/p/"+hashA))
	txt := text(body)
	for _, want := range []string{
		// network step: every input of e and which term won
		"CVE-2026-1111", "nginx", "KEV listed: 0.900", "EPSS 0.420", "0.3 × 3.887 / 3.9 = 0.299",
		"e = max(0.900, 0.420, 0.299) = 0.900", "AV:N", "tcp/443", "firewall or NAT rule",
		"grants code execution",
		// credential step
		"e = 1", "executor's SSH credentials",
		// path totals
		"L = 0.900 × 1 = 0.900", "R = L × impact = 0.900 × 10 = 9.00",
		"independent",
		// fix link per step
		"Update nginx", "fix verified",
	} {
		if !strings.Contains(txt, want) {
			t.Errorf("detail lacks %q\n%s", want, txt)
		}
	}
	if !strings.Contains(body, `href="/inventory/hosts/web/updates?pkg=nginx"`) {
		t.Error("detail lacks the fix link")
	}
	if !strings.Contains(txt, "no vulnerability needed") {
		t.Error("credential step lacks the 'no fix needed' note")
	}
}

func TestDetailUnknownEPSSAssumedAndPossible(t *testing.T) {
	e := newEnv(t, fixture())
	body := mustOK(t, e.get(t, "/vuln/paths/p/"+hashB))
	txt := text(body)
	for _, want := range []string{
		"EPSS unknown", "KEV not listed: 0", "× 0.5", "assumed",
		"port mapping unknown", "possible", "traffic flow",
	} {
		if !strings.Contains(txt, want) {
			t.Errorf("detail lacks %q\n%s", want, txt)
		}
	}
	// A fix link that is not a NOS path is dropped, never rendered.
	if strings.Contains(body, "javascript:") || strings.Contains(txt, "evil") {
		t.Error("non-NOS fix link rendered")
	}
	if !strings.Contains(txt, "no fix link") {
		t.Error("step without a usable fix link does not say so")
	}
}

func TestDetailRejectsBadOrUnknownHash(t *testing.T) {
	e := newEnv(t, fixture())
	for _, h := range []string{"zz", strings.ToUpper(hashA), hashA + "a", "..%2f..%2fetc"} {
		if rec := e.get(t, "/vuln/paths/p/"+h); rec.Code != http.StatusBadRequest && rec.Code != http.StatusNotFound {
			t.Errorf("%q: status %d", h, rec.Code)
		}
	}
	if rec := e.get(t, "/vuln/paths/p/"+strings.Repeat("d", 64)); rec.Code != http.StatusNotFound {
		t.Errorf("unknown hash: status %d", rec.Code)
	}
}

func TestHostileTextIsEscapedEverywhere(t *testing.T) {
	s := fixture()
	s.Labels["host:web"] = hostile
	s.Labels["host:exec"] = hostile
	fi := s.Findings[paths.FindingRef{Node: "host:web", Key: "fk-web"}]
	fi.VulnID = hostile
	fi.Package = hostile
	fi.Fix.Text = hostile
	s.Findings[paths.FindingRef{Node: "host:web", Key: "fk-web"}] = fi
	e := newEnv(t, s)
	for _, r := range []string{"/vuln/paths", "/vuln/paths/p/" + hashA, "/vuln/paths/map", "/vuln/paths/map/frame"} {
		body := mustOK(t, e.get(t, r))
		if strings.Contains(body, "<script>alert") || strings.Contains(body, "<img") {
			t.Errorf("%s: hostile text rendered as HTML", r)
		}
	}
}

func TestPagesCarryNoInlineScriptOrHandlers(t *testing.T) {
	e := newEnv(t, fixture())
	scriptTag := regexp.MustCompile(`(?i)<script\b[^>]*>`)
	handler := regexp.MustCompile(`(?i)\son[a-z]+\s*=`)
	for _, r := range allRoutes {
		body := mustOK(t, e.get(t, r))
		for _, tag := range scriptTag.FindAllString(body, -1) {
			if !strings.Contains(tag, `src="/static/`) {
				t.Errorf("%s: inline script %q", r, tag)
			}
		}
		if handler.MatchString(body) {
			t.Errorf("%s: inline event handler", r)
		}
		if regexp.MustCompile(`(?i)\sstyle\s*=`).MatchString(body) {
			t.Errorf("%s: inline style attribute", r)
		}
	}
}

func TestMapPageEmbedsSandboxedFrameOfItsOwn(t *testing.T) {
	e := newEnv(t, fixture())
	body := mustOK(t, e.get(t, "/vuln/paths/map?path="+hashA))
	if !strings.Contains(body, `src="/vuln/paths/map/frame?path=`+hashA+`"`) {
		t.Error("map page does not frame the paths overlay document")
	}
	if strings.Contains(body, `src="/traffic/frame"`) {
		t.Error("map page frames the normal traffic map document")
	}
	if !strings.Contains(body, `sandbox="allow-scripts"`) || strings.Contains(body, "allow-same-origin") {
		t.Error("frame is not sandboxed to scripts only")
	}
	if !strings.Contains(body, `data-window="24h"`) {
		t.Error("map page lacks the traffic window for the bridge")
	}
	if !strings.Contains(body, `<script src="/static/trafficmap-bridge.js">`) {
		t.Error("map page does not load the traffic map bridge")
	}
	// The parent page carries no overlay data: it is only in the framed document.
	if strings.Contains(body, "data-paths") {
		t.Error("parent page carries the overlay data")
	}
	if !strings.Contains(text(body), "1 step is not on the traffic map") {
		t.Errorf("unmapped steps not counted: %s", text(body))
	}
}

type overlay struct {
	Version int `json:"version"`
	Beams   []struct {
		From     string `json:"from"`
		To       string `json:"to"`
		Rank     int    `json:"rank"`
		Assumed  bool   `json:"assumed"`
		Possible bool   `json:"possible"`
	} `json:"beams"`
	Marks []struct {
		ID   string `json:"id"`
		Role string `json:"role"`
	} `json:"marks"`
}

func frameOverlay(t *testing.T, body string) overlay {
	t.Helper()
	m := regexp.MustCompile(`data-paths="([^"]*)"`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("frame lacks data-paths: %s", body)
	}
	var o overlay
	if err := json.Unmarshal([]byte(html.UnescapeString(m[1])), &o); err != nil {
		t.Fatalf("overlay JSON: %v", err)
	}
	return o
}

func TestFrameCarriesOnlyMappedIDsAndRanks(t *testing.T) {
	s := fixture()
	s.Labels["host:web"] = "secret-label-web"
	e := newEnv(t, s)
	rec := e.get(t, "/vuln/paths/map/frame")
	body := mustOK(t, rec)
	for _, leak := range []string{"secret-label-web", "CVE-2026", "nginx", "host:web", "fk-web", "Update"} {
		if strings.Contains(body, leak) {
			t.Errorf("frame leaks %q", leak)
		}
	}
	o := frameOverlay(t, body)
	if o.Version != 1 {
		t.Errorf("version %d", o.Version)
	}
	// Default: the top path of each target. internet is not on the map,
	// so only the credential step web → exec is a beam.
	if len(o.Beams) != 1 || o.Beams[0].From != "m-web" || o.Beams[0].To != "m-exec" || o.Beams[0].Rank != 1 {
		t.Errorf("beams %+v", o.Beams)
	}
	roles := map[string]string{}
	for _, m := range o.Marks {
		roles[m.ID] = m.Role
	}
	if roles["m-exec"] != "target" || roles["m-nas"] != "target" || roles["m-web"] != "step" {
		t.Errorf("marks %+v", o.Marks)
	}
}

func TestFrameSelectsPathOrTarget(t *testing.T) {
	e := newEnv(t, fixture())
	o := frameOverlay(t, mustOK(t, e.get(t, "/vuln/paths/map/frame?path="+hashB)))
	if len(o.Beams) != 0 {
		t.Errorf("netbird path has no mapped beam, got %+v", o.Beams)
	}
	o = frameOverlay(t, mustOK(t, e.get(t, "/vuln/paths/map/frame?target=host:exec")))
	if len(o.Beams) != 1 {
		t.Errorf("target selection beams %+v", o.Beams)
	}
	for _, q := range []string{"?path=zz", "?target=%3Cx%3E", "?path=" + hashA + "&path=" + hashA, "?other=1"} {
		if rec := e.get(t, "/vuln/paths/map/frame"+q); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d", q, rec.Code)
		}
		if rec := e.get(t, "/vuln/paths/map"+q); rec.Code != http.StatusBadRequest {
			t.Errorf("page %s: status %d", q, rec.Code)
		}
	}
	if rec := e.get(t, "/vuln/paths/map/frame?path="+strings.Repeat("e", 64)); rec.Code != http.StatusNotFound {
		t.Errorf("unknown path: status %d", rec.Code)
	}
}

func TestFrameHasStrictSandboxCSP(t *testing.T) {
	e := newEnv(t, fixture())
	rec := e.get(t, "/vuln/paths/map/frame")
	body := mustOK(t, rec)
	csp := rec.Header().Get("Content-Security-Policy")
	for _, want := range []string{
		"default-src 'none'", "script-src " + origin + "/static/trafficmap/", "connect-src 'none'",
		"frame-ancestors " + origin, "sandbox allow-scripts", "form-action 'none'", "base-uri 'none'",
	} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP lacks %q: %s", want, csp)
		}
	}
	m := regexp.MustCompile(`(?s)<style>(.*?)</style>`).FindStringSubmatch(body)
	if m == nil {
		t.Fatal("frame has no style element")
	}
	sum := sha256.Sum256([]byte(m[1]))
	if !strings.Contains(csp, "'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'") {
		t.Error("CSP style hash does not match the rendered style")
	}
	if !strings.Contains(body, `<script type="module" src="/static/trafficmap/paths-boot.js"></script>`) {
		t.Error("frame does not boot the paths renderer")
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("frame lacks nosniff")
	}
}

func TestSourceErrorIsGeneric(t *testing.T) {
	e := newEnv(t, fixture())
	e.src.err = errors.New("db path /var/lib/secret")
	for _, r := range allRoutes {
		rec := e.get(t, r)
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("%s: status %d", r, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "secret") {
			t.Errorf("%s: error leaks detail", r)
		}
	}
}
