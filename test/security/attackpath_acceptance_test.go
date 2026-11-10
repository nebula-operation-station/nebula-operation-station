// SPDX-License-Identifier: AGPL-3.0-or-later

// Acceptance tests for attack paths (ADR 0011 D10, Q6, threat model
// "Attack paths as a map for an attacker"; plan VU-26):
//
//   - attack-path topology, steps and scores are not reachable with the
//     vulnerability agent token (Hermes) or a read-only API token, on any
//     route, and the agent API's own answers carry none of it (Q6, the most
//     restrictive option);
//   - the attack-path pages are admin-only: a signed-in non-admin gets 403
//     and nothing of the data, a bearer token without a session is sent to
//     the login;
//   - hostile node labels and finding texts are stored verbatim (or refused
//     at the builder when they carry control or bidi characters) and reach
//     the browser only as escaped text; the overlay frame carries no label
//     at all;
//   - the graph, target, depth, paths-per-target and overlay caps hold and
//     whatever hits one is flagged truncated, never shown as safe.
//
// The tests drive the real packages cmd/nebula-server mounts: the attack-
// path builder and computation (internal/attackpath), the pages
// (internal/web/ui/paths), the session gate (internal/web/auth), the
// read-only API and the vuln agent API (internal/web/api) behind the real
// security middleware, wired as webServer and mountAttackPaths do, and
// served over loopback. The admin rule is a stand-in for vulnAdmin (the
// session user "admin"); the server's own tests cover vulnAdmin.
package security

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/attackpath"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/api"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/middleware"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui/paths"

	"google.golang.org/grpc"
)

// Synthetic test data only: invented tokens, IDs and labels. Every hostile
// label carries the marker apMarker, so a leak of any of them is found by
// one search.
const (
	apOrigin     = "https://nebula.test"
	apAgentToken = "nos_vu26-acceptance-agent-token"
	apROToken    = "nos_vu26-acceptance-readonly-token"
	apMarker     = "APC-VU26"

	apWebLabel  = `<script>window.__pwned='web'</script>` + apMarker + `-web`
	apExecLabel = `"><img src=x onerror="window.__pwned='exec'">` + apMarker + `-exec`
	apVulnID    = `CVE-2026-<svg onload=alert(1)>` + apMarker
	apPackage   = `nginx"><iframe srcdoc='<script>alert(2)</script>'>` + apMarker
	apNoFix     = `</td><script>alert(3)</script>` + apMarker
)

var apT0 = time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)

// apFrozen is the computation clock: frozen, so the result is a pure
// function of the input (attackpath.Options).
func apFrozen() time.Time { return apT0 }

// apNode builds a host node.
func apNode(id, label string) attackpath.Node {
	return attackpath.Node{ID: id, Kind: attackpath.NodeHost, Label: label}
}

// apFinding is a KEV-listed, network-vector finding with code execution on
// tcp/443 of node.
func apFinding(node, key string) attackpath.Finding {
	return attackpath.Finding{Node: node, Key: key, Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		KEV: true, Ports: []attackpath.Port{{Proto: attackpath.ProtoTCP, Number: 443}}, State: attackpath.FindingOpen}
}

// apWebEdge is internet -(tcp/443, allowed by policy)-> to.
func apWebEdge(to string) attackpath.Edge {
	return attackpath.Edge{From: attackpath.InternetID, To: to, Kind: attackpath.EdgeNetworkPolicy, Proto: attackpath.ProtoTCP, Port: 443}
}

// apHostileSnapshot computes, with the real builder and ap-v1, one path
// internet -(tcp/443, KEV finding)-> host:web -(credential)-> host:exec,
// both nodes with hostile labels, and the finding with hostile texts.
func apHostileSnapshot(t *testing.T, webLabel, execLabel, vulnID, pkg, noFix string) paths.Snapshot {
	t.Helper()
	b := attackpath.NewBuilder()
	for _, n := range []attackpath.Node{apNode("host:web", webLabel), apNode("host:exec", execLabel)} {
		if err := b.AddNode(n); err != nil {
			t.Fatalf("add node %s: %v", n.ID, err)
		}
	}
	for _, e := range []attackpath.Edge{apWebEdge("host:web"),
		{From: "host:web", To: "host:exec", Kind: attackpath.EdgeCredential}} {
		if err := b.AddEdge(e); err != nil {
			t.Fatalf("add edge %s -> %s: %v", e.From, e.To, err)
		}
	}
	g := b.Build()
	res, err := attackpath.Compute(g, []attackpath.Finding{apFinding("host:web", "fk-web")},
		[]attackpath.Target{{Node: "host:exec", Impact: 10}}, attackpath.Options{Now: apFrozen})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Targets) != 1 || len(res.Targets[0].Paths) != 1 || res.Truncated {
		t.Fatalf("fixture: want one untruncated path, got %+v", res)
	}
	labels := map[string]string{}
	for _, n := range g.Nodes() {
		labels[n.ID] = n.Label
	}
	return paths.Snapshot{
		Result:     res,
		ComputedAt: apT0,
		Labels:     labels,
		Findings: map[paths.FindingRef]paths.FindingInfo{
			{Node: "host:web", Key: "fk-web"}: {VulnID: vulnID, Package: pkg, NoFix: noFix,
				Fix: paths.FixLink{Href: "javascript:window.__pwned='fix'", Text: "Update " + pkg}},
		},
	}
}

func apHostile(t *testing.T) paths.Snapshot {
	return apHostileSnapshot(t, apWebLabel, apExecLabel, apVulnID, apPackage, apNoFix)
}

// apBenign is the same computation with harmless texts: the baseline of
// the markup a page has without any hostile input.
func apBenign(t *testing.T) paths.Snapshot {
	return apHostileSnapshot(t, "web01", "executor", "CVE-2026-1111", "nginx", "no fix in the configured repositories")
}

// apSource serves a fixed snapshot.
type apSource struct{ snap paths.Snapshot }

func (s apSource) Snapshot(context.Context) (paths.Snapshot, error) { return s.snap, nil }

// apMapNode is cmd/nebula-server's attackPathMapNode: a host node maps to
// its inventory host ID, nothing else is on the map.
func apMapNode(id string) (string, bool) {
	h, ok := strings.CutPrefix(id, "host:")
	if !ok || h == "" || strings.Contains(h, ":") {
		return "", false
	}
	return h, true
}

// apIsAdmin stands in for vulnAdmin: only the session user "admin".
func apIsAdmin(ctx context.Context) bool {
	s, ok := auth.SessionFrom(ctx)
	return ok && s.UserName == "admin"
}

// apPages returns the attack-path pages as the server mounts them
// (mountAttackPaths), without the session gate.
func apPages(t *testing.T, snap paths.Snapshot, authorize func(*http.Request) bool) *http.ServeMux {
	t.Helper()
	h, err := paths.New(paths.Options{Source: apSource{snap}, Authorize: authorize, PublicOrigin: apOrigin,
		MapNode: apMapNode, Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/", http.NotFoundHandler())
	h.Register(mux)
	return mux
}

// apExecutor is the login's executor: the stack under test never logs in,
// it only checks existing sessions. CheckCredential fails, which keeps the
// session (internal/web/auth: an unreachable executor revokes nothing).
type apExecutor struct{ auth.Executor }

func (apExecutor) CheckCredential(context.Context, *pb.CheckCredentialRequest, ...grpc.CallOption) (*pb.CheckCredentialResponse, error) {
	return nil, errors.New("executor not reachable in this test")
}

// apOps is an empty operations store for the read-only API.
type apOps struct{}

func (apOps) Get(context.Context, string) (executions.Execution, error) {
	return executions.Execution{}, errors.New("no such operation")
}
func (apOps) List(context.Context, int) ([]executions.Summary, error) { return nil, nil }
func (apOps) AllUpdates(context.Context) (map[string]executions.HostUpdates, error) {
	return nil, nil
}
func (apOps) AllOpsStates(context.Context) (map[string]executions.OpsState, error) {
	return nil, nil
}

// apServer is the server's HTTP chain with the attack-path pages, the
// read-only API and the vuln agent API.
type apServer struct {
	srv         *httptest.Server
	admin, user string // session tokens
	pathHash    string
	graphHash   string
}

// newAPServer wires the chain like cmd/nebula-server's webServer: "/" goes
// through the session gate to the pages, /api/v1/ to api.Mount(read-only
// API, vuln API), everything behind the security middleware.
func newAPServer(t *testing.T) *apServer {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	log := slog.New(slog.DiscardHandler)
	snap := apHostile(t)
	pages := apPages(t, snap, func(r *http.Request) bool { return apIsAdmin(r.Context()) })

	sessions := auth.NewStore(db, nil)
	login, err := auth.New(auth.Options{Executor: apExecutor{}, Sessions: sessions, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	s := &apServer{pathHash: snap.Result.Targets[0].Paths[0].Hash, graphHash: snap.Result.GraphHash}
	if s.admin, _, err = sessions.Create(t.Context(), "cred-admin", "admin"); err != nil {
		t.Fatal(err)
	}
	if s.user, _, err = sessions.Create(t.Context(), "cred-bob", "bob"); err != nil {
		t.Fatal(err)
	}

	// The read-only API token holds every read-only scope; the vuln token
	// both vuln scopes, from loopback only (as newVulnEnv).
	tokens := []serverconfig.APIToken{
		{Name: "status-page", SHA256: api.HashToken(apROToken),
			Scopes: []string{serverconfig.ScopeInventoryRead, serverconfig.ScopeOperationsRead, serverconfig.ScopeExecutionLogsRead}},
		{Name: serverconfig.DefaultVulnTokenName, SHA256: api.HashToken(apAgentToken),
			Scopes:          []string{serverconfig.ScopeVulnInventoryRead, serverconfig.ScopeVulnFindingsWrite},
			SourceAddresses: []string{"127.0.0.1"}},
	}
	ro, err := api.New(api.Options{Tokens: tokens, Operations: apOps{}, Log: log,
		Hosts: func(context.Context) ([]inventory.Host, error) {
			return []inventory.Host{{ID: "web", DisplayName: "web01"}, {ID: "exec", DisplayName: "executor"}}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	st, err := vulnstore.New(db, vulnstore.Config{Sources: vulnListedSources, Tier: vulnTierOf,
		Classifier: &viewClassifier{view: map[vulnstore.Subject]map[string]string{}}, Now: apFrozen})
	if err != nil {
		t.Fatal(err)
	}
	inv := &vulnInventory{snaps: map[string]api.VulnSnapshot{}}
	inv.setSubjects(hostWeb01())
	inv.take(apT0)
	vh, err := api.NewVuln(api.VulnOptions{Tokens: tokens, Inventory: inv, Store: st, Sources: vulnListedSources, Log: log, Now: apFrozen})
	if err != nil {
		t.Fatal(err)
	}

	root := http.NewServeMux()
	root.Handle("/", login.Wrap(pages))
	root.Handle(api.Prefix, api.Mount(ro, vh))
	s.srv = httptest.NewServer(middleware.Handler(middleware.Options{PublicOrigin: apOrigin}, root))
	t.Cleanup(s.srv.Close)
	return s
}

// do sends one request with an optional bearer token and session cookie;
// redirects are not followed.
func (s *apServer) do(t *testing.T, method, path, bearer, session string) (int, http.Header, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, s.srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if session != "" {
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: session})
	}
	if method != http.MethodGet && method != http.MethodHead {
		// Same-origin, so the middleware's origin check is not what refuses.
		req.Header.Set("Origin", apOrigin)
		req.Header.Set("Content-Type", "application/json")
	}
	c := s.srv.Client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, resp.Header, string(b)
}

// leaks names the attack-path data found in body, or "".
func (s *apServer) leaks(body string) string {
	u := html.UnescapeString(body)
	for _, c := range []string{apMarker, s.pathHash, s.graphHash, s.pathHash[:12], attackpath.FormulaVersion, "fk-web", "host:exec", "host:web"} {
		if strings.Contains(body, c) || strings.Contains(u, c) {
			return c
		}
	}
	return ""
}

// apAttackPathPages are the admin-only routes; detail and selection use the
// real path hash.
func (s *apServer) apAttackPathPages() []string {
	return []string{
		paths.ListPath,
		paths.DetailPrefix + s.pathHash,
		paths.MapPath,
		paths.MapPath + "?path=" + s.pathHash,
		paths.MapPath + "?target=host:exec",
		paths.FramePath,
		paths.FramePath + "?path=" + s.pathHash,
		paths.FramePath + "?target=host:exec",
	}
}

// apAPIGuesses are API routes an attack-path endpoint could live under.
// None may serve attack-path data to any token.
func (s *apServer) apAPIGuesses() []string {
	var out []string
	for _, base := range []string{"/api/v1/", api.VulnPrefix} {
		for _, p := range []string{"paths", "attack-paths", "attackpaths", "attack_paths", "paths/" + s.pathHash,
			"attack-paths/" + s.pathHash, "graph", "topology", "chokepoints", "choke-points", "crown-jewels", "jewels",
			"paths/map", "paths/map/frame", "vuln/paths", "export?include=paths", "findings?include=paths"} {
			out = append(out, base+p)
		}
	}
	return append(out, "/api/v1/vuln", "/api/v1/vuln/inventory", "/api/v1/vuln/inventory?include=paths",
		"/api/v1/hosts", "/api/v1/hosts/exec", "/api/v1/hosts?include=paths", "/api/v1/operations",
		"/api/v1/"+strings.TrimPrefix(paths.ListPath, "/"), "/api/v1/"+strings.TrimPrefix(paths.FramePath, "/"))
}

// TestAttackPathsNotReachableWithAgentOrReadOnlyToken: Q6 (most
// restrictive) and D10: neither the vuln agent token (Hermes) nor a
// read-only API token reaches attack-path topology, steps or scores, on
// any API route or page route; the answers both tokens legitimately get
// (inventory export, host list) carry none of it either. An admin session
// is the control: it sees the data on the pages, but not through the API.
func TestAttackPathsNotReachableWithAgentOrReadOnlyToken(t *testing.T) {
	s := newAPServer(t)

	// Control: the data is there, and the canaries would be found.
	code, _, body := s.do(t, http.MethodGet, paths.ListPath, "", s.admin)
	if code != http.StatusOK || s.leaks(body) == "" {
		t.Fatalf("admin list page: status %d, canary found %q; the test needs the data on the page", code, s.leaks(body))
	}
	// Control: both tokens are accepted where they are meant to be.
	if code, _, body := s.do(t, http.MethodGet, "/api/v1/vuln/inventory", apAgentToken, ""); code != http.StatusOK {
		t.Fatalf("agent token not accepted for the inventory export: %d %s", code, body)
	} else if c := s.leaks(body); c != "" {
		t.Errorf("the inventory export carries attack-path data (%q)", c)
	}
	if code, _, body := s.do(t, http.MethodGet, "/api/v1/hosts", apROToken, ""); code != http.StatusOK {
		t.Fatalf("read-only token not accepted for /api/v1/hosts: %d %s", code, body)
	} else if c := s.leaks(body); c != "" {
		t.Errorf("the host list carries attack-path data (%q)", c)
	}

	tokens := map[string]string{"agent": apAgentToken, "read-only": apROToken}
	for name, tok := range tokens {
		for _, p := range s.apAPIGuesses() {
			for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodPost} {
				code, _, body := s.do(t, m, p, tok, "")
				if c := s.leaks(body); c != "" {
					t.Errorf("%s token: %s %s: status %d leaks %q", name, m, p, code, c)
				}
				if code == http.StatusOK && p != "/api/v1/vuln/inventory" && !strings.HasPrefix(p, "/api/v1/hosts") && p != "/api/v1/operations" {
					t.Errorf("%s token: %s %s: status 200 on a route that is no API endpoint", name, m, p)
				}
			}
		}
		// The page routes need a session; a bearer token is no session,
		// alone or with a forged cookie.
		for _, p := range s.apAttackPathPages() {
			for _, cookie := range []string{"", tok, "not-a-session"} {
				code, h, body := s.do(t, http.MethodGet, p, tok, cookie)
				if code != http.StatusSeeOther || h.Get("Location") != "/login" {
					t.Errorf("%s token, cookie %q: GET %s: status %d location %q, want 303 to /login", name, cookie, p, code, h.Get("Location"))
				}
				if c := s.leaks(body); c != "" {
					t.Errorf("%s token: GET %s leaks %q", name, p, c)
				}
			}
		}
	}

	// Not through the API for an admin session either: the API takes
	// tokens only, and attack paths are in no API (D10).
	for _, p := range s.apAPIGuesses() {
		code, _, body := s.do(t, http.MethodGet, p, "", s.admin)
		if code != http.StatusUnauthorized {
			t.Errorf("admin session without token: GET %s: status %d, want 401", p, code)
		}
		if c := s.leaks(body); c != "" {
			t.Errorf("admin session: GET %s leaks %q through the API", p, c)
		}
	}
}

// TestAttackPathPagesEnforceAdminRole: every attack-path route, including
// the detail of a real path and the overlay frame with a real selection,
// refuses a signed-in non-admin with 403 and shows nothing of the data;
// no method other than GET serves anything; an admin gets every route.
func TestAttackPathPagesEnforceAdminRole(t *testing.T) {
	s := newAPServer(t)
	for _, p := range s.apAttackPathPages() {
		code, _, _ := s.do(t, http.MethodGet, p, "", s.admin)
		if code != http.StatusOK {
			t.Errorf("admin: GET %s: status %d", p, code)
		}
		code, _, body = s.do(t, http.MethodGet, p, "", s.user)
		if code != http.StatusForbidden {
			t.Errorf("non-admin: GET %s: status %d, want 403", p, code)
		}
		if c := s.leaks(body); c != "" {
			t.Errorf("non-admin: GET %s leaks %q", p, c)
		}
		if strings.Contains(body, "data-paths") || strings.Contains(body, "<iframe") || strings.Contains(body, "Attack paths") {
			t.Errorf("non-admin: GET %s shows page content", p)
		}
		for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
			for _, sess := range []string{s.admin, s.user} {
				code, _, body := s.do(t, m, p, "", sess)
				if code < 400 {
					t.Errorf("%s %s: status %d, want refused", m, p, code)
				}
				if sess == s.user {
					if c := s.leaks(body); c != "" {
						t.Errorf("non-admin: %s %s leaks %q", m, p, c)
					}
				}
			}
		}
	}

	// The handler checks the role itself, also when mounted outside the
	// session chain (paths.Handler.Register).
	h := apPages(t, apHostile(t), func(*http.Request) bool { return false })
	for _, p := range s.apAttackPathPages() {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, apOrigin+p, nil))
		if w.Code != http.StatusForbidden || s.leaks(w.Body.String()) != "" {
			t.Errorf("without the session chain: GET %s: status %d, leak %q", p, w.Code, s.leaks(w.Body.String()))
		}
	}
}

// TestAttackPathHostileLabelsAreStoredVerbatimOrRefused: the builder keeps
// a markup label byte for byte (it is data, not something to "clean"),
// the graph snapshot carries it only JSON-escaped, and labels with control
// or bidi characters, invalid UTF-8 or over the limit are refused and not
// stored.
func TestAttackPathHostileLabelsAreStoredVerbatimOrRefused(t *testing.T) {
	b := attackpath.NewBuilder()
	stored := map[string]string{"host:web": apWebLabel, "host:exec": apExecLabel,
		"host:tpl": `{{template "layout" .}}` + apMarker, "host:url": `javascript:alert(1)//` + apMarker}
	for id, l := range stored {
		if err := b.AddNode(apNode(id, l)); err != nil {
			t.Fatalf("label %q refused: %v", l, err)
		}
	}
	refused := map[string]string{
		"host:rlo":  "web" + string(rune(0x202e)) + apMarker, // RIGHT-TO-LEFT OVERRIDE
		"host:fsi":  "web" + string(rune(0x2068)) + apMarker, // FIRST STRONG ISOLATE
		"host:nul":  "web\x00" + apMarker,
		"host:esc":  "web\x1b[31m" + apMarker,
		"host:nl":   "web\n<script>" + apMarker,
		"host:utf8": "web\xff\xfe" + apMarker,
		"host:long": strings.Repeat("<b>", attackpath.MaxLabelBytes/3+1),
	}
	for id, l := range refused {
		if err := b.AddNode(apNode(id, l)); !errors.Is(err, attackpath.ErrInvalidNode) {
			t.Errorf("label of %s: err %v, want ErrInvalidNode", id, err)
		}
	}
	g := b.Build()
	for id, l := range stored {
		n, ok := g.Node(id)
		if !ok || n.Label != l {
			t.Errorf("node %s: label %q (present %v), want it verbatim", id, n.Label, ok)
		}
	}
	for id := range refused {
		if _, ok := g.Node(id); ok {
			t.Errorf("node %s with a refused label is in the graph", id)
		}
	}
	snap := g.Snapshot()
	if i := strings.IndexAny(string(snap), "<>&"); i >= 0 {
		t.Errorf("graph snapshot has a raw markup character at %d", i)
	}
	var doc struct {
		Nodes []struct{ ID, Label string } `json:"nodes"`
	}
	if err := json.Unmarshal(snap, &doc); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, n := range doc.Nodes {
		got[n.ID] = n.Label
	}
	for id, l := range stored {
		if got[id] != l {
			t.Errorf("snapshot: node %s label %q, want %q", id, got[id], l)
		}
	}
}

var (
	apTagRE      = regexp.MustCompile(`<[^>]*>`)
	apDataPathRE = regexp.MustCompile(`data-paths="([^"]*)"`)
	apQuotedRE   = regexp.MustCompile(`"[^"]*"|'[^']*'`)
)

// apText is what a reader sees: tags removed, entities decoded.
func apText(body string) string { return html.UnescapeString(apTagRE.ReplaceAllString(body, " ")) }

// apMarkup counts, inside real tags and outside quoted attribute values,
// the elements and handlers hostile text could create. Escaped text has no
// "<", so it is never a tag; an escaped label in an attribute value stays
// inside its quotes, so only a breakout is counted.
func apMarkup(body string) map[string]int {
	tags := apTagRE.FindAllString(body, -1)
	for i, tag := range tags {
		tags[i] = apQuotedRE.ReplaceAllString(tag, `""`)
	}
	l := strings.ToLower(strings.Join(tags, "\n"))
	out := map[string]int{}
	for _, k := range []string{"<script", "<img", "<svg", "<iframe", "<object", "<embed", "onerror", "onload", "javascript:", "srcdoc"} {
		out[k] = strings.Count(l, k)
	}
	return out
}

// TestAttackPathHostileLabelsRenderAsText: hostile node labels and finding
// texts on the list, detail and map pages reach the browser as escaped
// text (readable as given, but not one element or handler more than with
// harmless texts); the hostile fix link is dropped; the overlay frame
// carries no label or finding text at all, only map IDs, ranks and flags.
func TestAttackPathHostileLabelsRenderAsText(t *testing.T) {
	admin := func(*http.Request) bool { return true }
	hostile := apHostile(t)
	hash := hostile.Result.Targets[0].Paths[0].Hash
	hh := apPages(t, hostile, admin)
	bh := apPages(t, apBenign(t), admin)
	get := func(h http.Handler, p string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, apOrigin+p, nil))
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s: status %d: %s", p, w.Code, w.Body.String())
		}
		return w
	}
	pages := map[string][]string{
		paths.ListPath:                      {apWebLabel, apExecLabel, apVulnID, apPackage},
		paths.DetailPrefix + hash:           {apWebLabel, apExecLabel, apVulnID, apPackage, apNoFix},
		paths.MapPath + "?target=host:exec": {apExecLabel},
		paths.MapPath + "?path=" + hash:     {apExecLabel},
	}
	for p, want := range pages {
		body := get(hh, p).Body.String()
		text := apText(body)
		for _, l := range want {
			if !strings.Contains(text, l) {
				t.Errorf("GET %s: the text does not show %q as given", p, l)
			}
			if strings.Contains(body, l) {
				t.Errorf("GET %s: %q appears unescaped in the markup", p, l)
			}
		}
		if strings.Contains(body, "window.__pwned='fix'") {
			t.Errorf("GET %s: the javascript: fix link was rendered", p)
		}
		got, base := apMarkup(body), apMarkup(get(bh, p).Body.String())
		for k, n := range got {
			if n != base[k] {
				t.Errorf("GET %s: %d %q with hostile texts, %d without", p, n, k, base[k])
			}
		}
	}

	for _, p := range []string{paths.FramePath, paths.FramePath + "?target=host:exec", paths.FramePath + "?path=" + hash} {
		body := get(hh, p).Body.String()
		if strings.Contains(html.UnescapeString(body), apMarker) {
			t.Errorf("GET %s: the overlay frame carries label or finding text", p)
		}
		m := apDataPathRE.FindStringSubmatch(body)
		if m == nil {
			t.Fatalf("GET %s: no overlay attribute", p)
		}
		var o struct {
			Version int `json:"version"`
			Beams   []struct {
				From, To          string
				Rank              int
				Assumed, Possible bool
			} `json:"beams"`
			Marks []struct {
				ID, Role string
			} `json:"marks"`
			Truncated bool `json:"truncated"`
		}
		dec := json.NewDecoder(strings.NewReader(html.UnescapeString(m[1])))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&o); err != nil {
			t.Fatalf("GET %s: overlay is not the label-free schema: %v", p, err)
		}
		if len(o.Beams) != 1 || o.Beams[0].From != "web" || o.Beams[0].To != "exec" || o.Truncated {
			t.Errorf("GET %s: overlay %+v, want the one beam web -> exec", p, o)
		}
	}
}

// apChainSnapshot is a synthetic result for the overlay limits: one target
// with nPaths paths of steps steps each, every step a distinct pair of
// mapped hosts with IDs of idLen bytes.
func apChainSnapshot(nPaths, steps, idLen int) paths.Snapshot {
	id := func(p, s int) string {
		base := fmt.Sprintf("host:p%04ds%04d-", p, s)
		return base + strings.Repeat("x", idLen-len(base)+len("host:"))
	}
	tp := attackpath.TargetPaths{Node: "host:target", Impact: 10, Complete: true}
	for p := range nPaths {
		path := attackpath.Path{Hash: fmt.Sprintf("%064x", p+1), Entry: attackpath.InternetID, Likelihood: 0.5, Risk: 5}
		for s := range steps {
			from, to := id(p, s), id(p, s+1)
			path.Steps = append(path.Steps, attackpath.Step{Kind: attackpath.StepCredential, From: from, To: to,
				Edge: attackpath.Edge{From: from, To: to, Kind: attackpath.EdgeCredential}, Owns: true, Terms: attackpath.Terms{E: 1}})
		}
		tp.Paths = append(tp.Paths, path)
	}
	return paths.Snapshot{Result: &attackpath.Result{FormulaVersion: attackpath.FormulaVersion, GraphHash: strings.Repeat("c", 64),
		Targets: []attackpath.TargetPaths{tp}}, ComputedAt: apT0}
}

// TestAttackPathCapsAndTruncationFlag: the graph node and edge caps, the
// crown-jewel target cap, the depth cap and the paths-per-target cap hold;
// whatever hits a limit is flagged truncated and the list page names the
// limit; a crown jewel lost to a cap reads "unknown", never safe; the
// overlay keeps its beam and byte caps and says it was truncated.
func TestAttackPathCapsAndTruncationFlag(t *testing.T) {
	list := func(t *testing.T, res *attackpath.Result) string {
		t.Helper()
		w := httptest.NewRecorder()
		apPages(t, paths.Snapshot{Result: res, ComputedAt: apT0}, func(*http.Request) bool { return true }).
			ServeHTTP(w, httptest.NewRequest(http.MethodGet, apOrigin+paths.ListPath, nil))
		if w.Code != http.StatusOK {
			t.Fatalf("list: status %d", w.Code)
		}
		return apText(w.Body.String())
	}
	safe := regexp.MustCompile(`(?i)\bsafe\b|no path exists|not exposed`)

	t.Run("node cap", func(t *testing.T) {
		b := attackpath.NewBuilder()
		for i := range attackpath.MaxNodes + 25 {
			if err := b.AddNode(apNode(fmt.Sprintf("host:n%05d", i), "n")); err != nil {
				t.Fatal(err)
			}
		}
		if err := b.AddNode(apNode("host:zz-jewel", "jewel")); err != nil {
			t.Fatal(err)
		}
		g := b.Build()
		dn, _ := g.Dropped()
		if !g.Truncated() || dn == 0 || len(g.Nodes()) > attackpath.MaxNodes {
			t.Fatalf("graph: %d nodes, %d dropped, truncated %v; want at most %d and flagged", len(g.Nodes()), dn, g.Truncated(), attackpath.MaxNodes)
		}
		res, err := attackpath.Compute(g, nil, []attackpath.Target{{Node: "host:zz-jewel", Impact: 10}, {Node: "host:n00000", Impact: 8}},
			attackpath.Options{Now: apFrozen})
		if err != nil {
			t.Fatal(err)
		}
		if !res.Truncated || !res.Limits.Graph {
			t.Fatalf("result not flagged: truncated %v, limits %+v", res.Truncated, res.Limits)
		}
		if len(res.MissingTargets) != 1 || res.MissingTargets[0] != "host:zz-jewel" {
			t.Fatalf("missing targets %v, want the dropped crown jewel", res.MissingTargets)
		}
		text := list(t, res)
		for _, w := range []string{"The computation was truncated by", "graph node or edge cap",
			"Unknown: crown jewel host:zz-jewel is not in the graph", "Unknown: no path found"} {
			if !strings.Contains(text, w) {
				t.Errorf("list page does not say %q", w)
			}
		}
		if strings.Contains(text, "No path found within the limits") || safe.MatchString(text) {
			t.Error("a truncated result reads as safe")
		}
	})

	t.Run("edge cap", func(t *testing.T) {
		b := attackpath.NewBuilder()
		const hosts = 1000
		ports := attackpath.MaxEdges/hosts + 1
		for h := range hosts {
			id := fmt.Sprintf("host:e%04d", h)
			if err := b.AddNode(apNode(id, "e")); err != nil {
				t.Fatal(err)
			}
			for p := range ports {
				e := apWebEdge(id)
				e.Port = uint16(1000 + p)
				if err := b.AddEdge(e); err != nil {
					t.Fatal(err)
				}
			}
		}
		g := b.Build()
		_, de := g.Dropped()
		if !g.Truncated() || de == 0 || len(g.Edges()) > attackpath.MaxEdges {
			t.Fatalf("graph: %d edges, %d dropped, truncated %v; want at most %d and flagged", len(g.Edges()), de, g.Truncated(), attackpath.MaxEdges)
		}
		res, err := attackpath.Compute(g, nil, []attackpath.Target{{Node: "host:e0000", Impact: 5}}, attackpath.Options{Now: apFrozen})
		if err != nil {
			t.Fatal(err)
		}
		if !res.Truncated || !res.Limits.Graph {
			t.Fatalf("result not flagged: truncated %v, limits %+v", res.Truncated, res.Limits)
		}
		if text := list(t, res); !strings.Contains(text, "graph node or edge cap") || safe.MatchString(text) {
			t.Error("list page does not name the edge cap, or reads as safe")
		}
	})

	t.Run("target, depth and paths-per-target caps", func(t *testing.T) {
		b := attackpath.NewBuilder()
		var findings []attackpath.Finding
		add := func(id string) {
			t.Helper()
			if err := b.AddNode(apNode(id, id)); err != nil {
				t.Fatal(err)
			}
		}
		edge := func(e attackpath.Edge) {
			t.Helper()
			if err := b.AddEdge(e); err != nil {
				t.Fatal(err)
			}
		}
		add("host:a-exec")
		// 30 exposed hosts, each one credential step from the jewel.
		for i := range 30 {
			id := fmt.Sprintf("host:b%02d", i)
			add(id)
			edge(apWebEdge(id))
			edge(attackpath.Edge{From: id, To: "host:a-exec", Kind: attackpath.EdgeCredential})
			findings = append(findings, apFinding(id, "fk"))
		}
		// A chain one step longer than MaxDepth to a second jewel.
		chain := make([]string, attackpath.MaxDepth+1)
		for i := range chain {
			chain[i] = fmt.Sprintf("host:c%02d", i)
			add(chain[i])
			if i > 0 {
				edge(attackpath.Edge{From: chain[i-1], To: chain[i], Kind: attackpath.EdgeCredential})
			}
		}
		edge(apWebEdge(chain[0]))
		findings = append(findings, apFinding(chain[0], "fk"))
		// Filler crown jewels, so more targets are in the graph than the
		// target cap allows.
		for i := range attackpath.MaxTargets - 30 {
			add(fmt.Sprintf("host:f%02d", i))
		}
		g := b.Build()

		// Two impact-10 jewels and MaxTargets impact-1 ones: the cap keeps
		// the highest impact first.
		targets := []attackpath.Target{{Node: "host:a-exec", Impact: 10}, {Node: chain[len(chain)-1], Impact: 10}}
		for i := range 30 {
			targets = append(targets, attackpath.Target{Node: fmt.Sprintf("host:b%02d", i), Impact: 1})
		}
		for i := range attackpath.MaxTargets - 30 {
			targets = append(targets, attackpath.Target{Node: fmt.Sprintf("host:f%02d", i), Impact: 1})
		}
		res, err := attackpath.Compute(g, findings, targets, attackpath.Options{Now: apFrozen})
		if err != nil {
			t.Fatal(err)
		}
		if !res.Truncated || !res.Limits.Targets || len(res.Targets) > attackpath.MaxTargets {
			t.Fatalf("targets: %d kept, truncated %v, limits %+v; want at most %d and flagged", len(res.Targets), res.Truncated, res.Limits, attackpath.MaxTargets)
		}
		var exec, deep *attackpath.TargetPaths
		for i := range res.Targets {
			switch res.Targets[i].Node {
			case "host:a-exec":
				exec = &res.Targets[i]
			case chain[len(chain)-1]:
				deep = &res.Targets[i]
			}
		}
		if exec == nil || deep == nil {
			t.Fatalf("the impact-10 jewels were dropped by the target cap: %+v", res.Targets)
		}
		if len(exec.Paths) != attackpath.PathsPerTarget {
			t.Errorf("host:a-exec: %d paths, want the cap %d of 30", len(exec.Paths), attackpath.PathsPerTarget)
		}
		for _, tp := range res.Targets {
			for _, p := range tp.Paths {
				if len(p.Steps) > attackpath.MaxDepth {
					t.Errorf("%s: a path of %d steps, over the depth cap %d", tp.Node, len(p.Steps), attackpath.MaxDepth)
				}
			}
		}
		if len(deep.Paths) != 0 {
			t.Errorf("%s: %d paths over a chain longer than the depth cap", deep.Node, len(deep.Paths))
		}
		text := list(t, res)
		if !strings.Contains(text, "crown-jewel target cap (50)") || !strings.Contains(text, "Unknown: no path found") || safe.MatchString(text) {
			t.Error("list page does not name the target cap or reads the deep jewel as safe")
		}
	})

	t.Run("overlay beam and byte caps", func(t *testing.T) {
		for _, c := range []struct {
			name                 string
			nPaths, steps, idLen int
		}{
			{"beams", 60, 20, 16},  // 1,200 short beams: the beam cap
			{"bytes", 40, 20, 120}, // 800 long beams: the byte cap
		} {
			snap := apChainSnapshot(c.nPaths, c.steps, c.idLen)
			h := apPages(t, snap, func(*http.Request) bool { return true })
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, apOrigin+paths.FramePath+"?target=host:target", nil))
			if w.Code != http.StatusOK {
				t.Fatalf("%s: frame status %d", c.name, w.Code)
			}
			m := apDataPathRE.FindStringSubmatch(w.Body.String())
			if m == nil {
				t.Fatalf("%s: no overlay", c.name)
			}
			raw := html.UnescapeString(m[1])
			var o struct {
				Beams     []json.RawMessage `json:"beams"`
				Marks     []json.RawMessage `json:"marks"`
				Truncated bool              `json:"truncated"`
			}
			if err := json.Unmarshal([]byte(raw), &o); err != nil {
				t.Fatal(err)
			}
			if !o.Truncated || len(o.Beams) > paths.MaxBeams || len(o.Marks) > paths.MaxMarks || len(raw) > paths.MaxOverlayBytes {
				t.Errorf("%s: %d beams, %d marks, %d bytes, truncated %v; want within %d/%d/%d and flagged",
					c.name, len(o.Beams), len(o.Marks), len(raw), o.Truncated, paths.MaxBeams, paths.MaxMarks, paths.MaxOverlayBytes)
			}
			w = httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, apOrigin+paths.MapPath+"?target=host:target", nil))
			if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "The overlay was truncated") {
				t.Errorf("%s: map page status %d does not say the overlay was truncated", c.name, w.Code)
			}
		}
	})
}
