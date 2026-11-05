// SPDX-License-Identifier: AGPL-3.0-or-later

// Acceptance tests for the traffic map's threat analysis (ADR 0009 D4, D6,
// "Threat analysis and consequences", TM21): hostile host data never
// becomes markup, the renderer iframe is isolated, icon URLs cannot reach
// internal addresses, polyglot icons are re-encoded and /icons/ serves
// inert PNGs only. They drive the real packages the server mounts
// (internal/web/api/trafficmap, internal/web/ui/trafficmap,
// internal/web/ui/icons, internal/iconfetch, internal/iconstore) behind
// the real security middleware. No network: the icon fetcher only ever
// sees a fake resolver whose answers it must refuse before dialing.
package security

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/flowagg"
	"github.com/nebula-operation-station/nebula-operation-station/internal/iconfetch"
	"github.com/nebula-operation-station/nebula-operation-station/internal/iconstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/softwarecat"
	tmapi "github.com/nebula-operation-station/nebula-operation-station/internal/web/api/trafficmap"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/middleware"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui/icons"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui/icons/iconjob"
	tmui "github.com/nebula-operation-station/nebula-operation-station/internal/web/ui/trafficmap"
)

// tmOrigin is the deployment origin of these tests.
const tmOrigin = "https://nebula.test"

// catalogKeyRE is the catalog key syntax (ADR 0009 D5); sha256RE an icon
// hash as /icons/ serves it.
var (
	catalogKeyRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	sha256RE     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// noFlows is a traffic store without flows: the hostile-name tests are
// about nodes and zones.
type noFlows struct{}

func (noFlows) TopN(context.Context, netip.Addr, flowagg.Window, int) ([]flowagg.FlowTotal, error) {
	return nil, nil
}

func (noFlows) OverviewUnion(context.Context, []netip.Addr, flowagg.Window, int) ([]flowagg.FlowTotal, error) {
	return nil, nil
}

// hostileLabels are names a compromised host, an mDNS responder or a
// container runtime can report. Each must reach the browser as inert,
// printable text.
var hostileLabels = map[string]string{
	"web":   `<img src=x onerror=alert(1)>`,
	"mdns":  "printer.local\u202e\u200b<script>alert(1)</script>\x00\x1b[31m\u2066",
	"utf8":  "caf\xff\xfe</script><svg/onload=alert(1)>",
	"long":  strings.Repeat("<b>", 1000),
	"ctr":   "db-<iframe srcdoc='<script>parent.alert(1)</script>'>",
	"quote": `"'><script>alert(document.cookie)</script>`,
}

// hostileInventory is an inventory whose names, kinds, IDs, software keys
// and icon references were all chosen by an attacker.
func hostileInventory(context.Context) (tmapi.Inventory, error) {
	inv := tmapi.Inventory{Zones: []tmapi.ZoneInput{
		{ID: "lan", Name: `<iframe src="//evil.example/">`, VLAN: 10},
		{ID: `"><svg onload=alert(1)>`, Name: "bad zone id"},
	}}
	for id, label := range hostileLabels {
		inv.Nodes = append(inv.Nodes, tmapi.NodeInput{ID: id, Label: label, Kind: tmapi.KindHost, Zone: "lan"})
	}
	inv.Nodes = append(inv.Nodes,
		tmapi.NodeInput{ID: `"><script>alert(1)</script>`, Label: "bad id", Kind: tmapi.KindHost},
		tmapi.NodeInput{ID: "kind", Label: "kind", Kind: `<b onmouseover=alert(1)>host</b>`},
		tmapi.NodeInput{ID: "soft", Label: "software", Kind: tmapi.KindHost, Software: []tmapi.Software{
			{Key: "<script>alert(1)</script>", Count: 1},
			{Key: "nginx", Count: 1, Icon: "https://evil.example/x.png"},
			{Key: "redis", Count: 1, Icon: "../../../../etc/passwd"},
			{Key: "grafana", Count: 1, Icon: "javascript:alert(1)"},
			{Key: "postgres", Count: 1, Icon: strings.Repeat("ab", 32)},
		}},
	)
	return inv, nil
}

// trafficStack returns the traffic map routes behind the security
// middleware, like cmd/nebula-server mounts them (without the session
// check, which is covered by the server's own tests).
func trafficStack(t *testing.T) http.Handler {
	t.Helper()
	api, err := tmapi.New(tmapi.Options{Inventory: hostileInventory, Flows: noFlows{},
		Authorize: func(*http.Request) bool { return true }, Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	page, err := tmui.New(tmui.Options{PublicOrigin: tmOrigin, Windows: func() []string { return []string{"1h", "24h", "7d", "21d"} }})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	page.RegisterPages(mux)
	page.RegisterModules(mux)
	mux.Handle("/api/v1/trafficmap", api)
	return middleware.Handler(middleware.Options{PublicOrigin: tmOrigin}, mux)
}

func tmGet(h http.Handler, target string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, tmOrigin+target, nil)
	r.Header.Set("Cookie", "nebula_session=not-a-real-session")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// safeText reports why s is not inert printable text, or "".
func safeText(s string, max int) string {
	if !utf8.ValidString(s) {
		return "invalid UTF-8"
	}
	if len(s) > max {
		return fmt.Sprintf("%d bytes, limit %d", len(s), max)
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || !unicode.IsPrint(r) {
			return fmt.Sprintf("contains %U", r)
		}
	}
	return ""
}

// TestTrafficMapHostileNamesNeverBecomeMarkup: hostnames, mDNS names,
// zone names and container names from managed hosts reach the browser
// only as bounded, printable, JSON-escaped text; hostile IDs, kinds,
// software keys and icon references are dropped or replaced.
func TestTrafficMapHostileNamesNeverBecomeMarkup(t *testing.T) {
	h := trafficStack(t)
	for _, target := range []string{"/api/v1/trafficmap", "/api/v1/trafficmap?window=1h&focus=mdns"} {
		w := tmGet(h, target)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status %d: %s", target, w.Code, w.Body.String())
		}
		if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			t.Errorf("%s: Content-Type %q", target, ct)
		}
		if w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: no nosniff", target)
		}
		body := w.Body.Bytes()
		// encoding/json escapes <, > and & as < etc.: even a browser
		// that sniffed the body as HTML would find no tag in it.
		if i := bytes.IndexAny(body, "<>&"); i >= 0 {
			t.Fatalf("%s: raw markup character in the model at %d: %q", target, i, body[max(0, i-20):min(len(body), i+20)])
		}
		for _, bad := range []string{"\u202e", "\u200b", "\u2066", "\x1b"} {
			if bytes.Contains(body, []byte(bad)) {
				t.Errorf("%s: model contains %q", target, bad)
			}
		}
		var m tmapi.Model
		if err := json.Unmarshal(body, &m); err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		seen := map[string]tmapi.Node{}
		for _, n := range m.Nodes {
			seen[n.ID] = n
			if why := safeText(n.Label, tmapi.MaxLabelBytes); why != "" {
				t.Errorf("%s: node %s label %q: %s", target, n.ID, n.Label, why)
			}
			switch n.Kind {
			case tmapi.KindHost, tmapi.KindGuest, tmapi.KindContainer, tmapi.KindAsset,
				tmapi.KindEndpoint, tmapi.KindRouter, tmapi.KindUnknown:
			default:
				t.Errorf("%s: node %s kind %q is not one of the fixed kinds", target, n.ID, n.Kind)
			}
			if n.ID == "kind" && n.Kind != tmapi.KindUnknown {
				t.Errorf("%s: hostile kind became %q, want %q", target, n.Kind, tmapi.KindUnknown)
			}
			for _, s := range n.Software {
				if !catalogKeyRE.MatchString(s.Key) {
					t.Errorf("%s: node %s software key %q", target, n.ID, s.Key)
				}
				if s.Icon != "" && !sha256RE.MatchString(s.Icon) {
					t.Errorf("%s: node %s icon reference %q", target, n.ID, s.Icon)
				}
			}
		}
		for _, z := range m.Zones {
			if strings.ContainsAny(z.ID, `<>"' `) {
				t.Errorf("%s: zone id %q", target, z.ID)
			}
			if why := safeText(z.Name, tmapi.MaxLabelBytes); why != "" {
				t.Errorf("%s: zone %s name %q: %s", target, z.ID, z.Name, why)
			}
		}
		for id := range seen {
			if strings.ContainsAny(id, `<>"' `) {
				t.Errorf("%s: hostile node id %q reached the model", target, id)
			}
		}
		if m.Focus == "" {
			// The overview has every valid node; a hostile name is kept as
			// text (the renderer draws it with fillText), not dropped.
			if got := seen["web"].Label; got != hostileLabels["web"] {
				t.Errorf("label of web = %q, want the literal text %q", got, hostileLabels["web"])
			}
			if !m.Truncated || m.Omitted.Nodes == 0 || m.Omitted.Zones == 0 || m.Omitted.Software == 0 {
				t.Errorf("dropped hostile input is not reported: truncated=%v omitted=%+v", m.Truncated, m.Omitted)
			}
			if !seen["long"].LabelCut {
				t.Error("an oversized label is not marked as cut")
			}
			icons := map[string]string{}
			for _, s := range seen["soft"].Software {
				icons[s.Key] = s.Icon
			}
			for _, k := range []string{"nginx", "redis", "grafana"} {
				if icons[k] != "" {
					t.Errorf("software %s kept icon reference %q", k, icons[k])
				}
			}
			if icons["postgres"] != strings.Repeat("ab", 32) {
				t.Errorf("a valid icon hash was dropped: %q", icons["postgres"])
			}
		}
	}
}

// TestContainerAndServiceNamesWithMarkupAreNoCatalogKeys: an observed
// identifier that carries markup can never become a catalog key, the
// only software name the map shows next to an icon.
func TestContainerAndServiceNamesWithMarkupAreNoCatalogKeys(t *testing.T) {
	for _, name := range []string{
		"<script>alert(1)</script>", `evil"onload="x`, "redis\u202e", "a b", "../../etc", "", strings.Repeat("a", 65),
		"Nginx", "nginx\x00", "javascript:alert(1)",
	} {
		if k, err := softwarecat.NewKey(name); err == nil {
			t.Errorf("NewKey(%q) = %q, want an error", name, k)
		}
	}
}

// crossHostFlows is a traffic store with flows of two hosts, an unrelated
// pair and an address two nodes claim. With leaky set, TopN returns every
// flow of the store whatever node is asked for, as a buggy or compromised
// store would: the focus view must still show only the focus's own flows.
type crossHostFlows struct {
	leaky bool
}

var (
	chHostA = netip.MustParseAddr("10.0.0.1")
	chPeerA = netip.MustParseAddr("10.0.0.10")
	chPeerB = netip.MustParseAddr("10.0.0.5")
	chHostB = netip.MustParseAddr("10.0.0.12")
	chX1    = netip.MustParseAddr("10.0.0.30")
	chX2    = netip.MustParseAddr("10.0.0.31")
	chAmb   = netip.MustParseAddr("10.0.0.99")
)

func chFlow(a, b netip.Addr, ab, ba, conns uint64) flowagg.FlowTotal {
	return flowagg.FlowTotal{Key: flowagg.FlowKey{A: a, B: b, Proto: flowagg.TCP, ServerPort: 443, Server: flowagg.SideB},
		BytesAB: ab, BytesBA: ba, Connections: conns, Confirmed: true}
}

// chAll is every flow of the store. Keys are canonical (A < B by address),
// so host-b's flow has peer-b on side A.
var chAll = []flowagg.FlowTotal{
	chFlow(chHostA, chPeerA, 600, 400, 3),
	chFlow(chPeerB, chHostB, 50, 1950, 5),
	chFlow(chX1, chX2, 3000, 1, 7),
	chFlow(chPeerB, chAmb, 500, 0, 1),
	chFlow(chHostA, chAmb, 400, 0, 1),
}

func chTouching(addrs ...netip.Addr) []flowagg.FlowTotal {
	var out []flowagg.FlowTotal
	for _, f := range chAll {
		for _, a := range addrs {
			if f.Key.A == a || f.Key.B == a {
				out = append(out, f)
				break
			}
		}
	}
	return out
}

func (s crossHostFlows) TopN(_ context.Context, node netip.Addr, _ flowagg.Window, _ int) ([]flowagg.FlowTotal, error) {
	if s.leaky {
		return slices.Clone(chAll), nil
	}
	return chTouching(node), nil
}

func (crossHostFlows) OverviewUnion(_ context.Context, nodes []netip.Addr, _ flowagg.Window, _ int) ([]flowagg.FlowTotal, error) {
	return chTouching(nodes...), nil
}

// crossHostInventory: host-a talks to peer-a, host-b to peer-b, x-1 to x-2;
// amb-1 and amb-2 both claim 10.0.0.99, so flows to it belong to nobody.
func crossHostInventory(context.Context) (tmapi.Inventory, error) {
	n := func(id string, a netip.Addr) tmapi.NodeInput {
		return tmapi.NodeInput{ID: id, Label: "label-of-" + id, Kind: tmapi.KindHost, Addrs: []netip.Addr{a}}
	}
	return tmapi.Inventory{Nodes: []tmapi.NodeInput{
		n("host-a", chHostA), n("peer-a", chPeerA), n("host-b", chHostB), n("peer-b", chPeerB),
		n("x-1", chX1), n("x-2", chX2), n("amb-1", chAmb), n("amb-2", chAmb),
	}}, nil
}

var chNodeIDs = []string{"host-a", "peer-a", "host-b", "peer-b", "x-1", "x-2", "amb-1", "amb-2"}

func crossHostModel(t *testing.T, flows tmapi.Flows, focus string) (tmapi.Model, []byte) {
	t.Helper()
	api, err := tmapi.New(tmapi.Options{Inventory: crossHostInventory, Flows: flows,
		Authorize: func(*http.Request) bool { return true }, Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	h := middleware.Handler(middleware.Options{PublicOrigin: tmOrigin}, api)
	target := "/?window=24h"
	if focus != "" {
		target += "&focus=" + focus
	}
	w := tmGet(h, target)
	if w.Code != http.StatusOK {
		t.Fatalf("focus %q: status %d: %s", focus, w.Code, w.Body.String())
	}
	var m tmapi.Model
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	return m, w.Body.Bytes()
}

// edgeSummary renders edges as "a-b ab/ba conns", sorted.
func edgeSummary(es []tmapi.Edge) []string {
	out := make([]string, 0, len(es))
	for _, e := range es {
		out = append(out, fmt.Sprintf("%s-%s %d/%d %d", e.A, e.B, e.BytesAB, e.BytesBA, e.Connections))
	}
	slices.Sort(out)
	return out
}

func nodeIDs(ns []tmapi.Node) []string {
	out := make([]string, 0, len(ns))
	for _, n := range ns {
		out = append(out, n.ID)
	}
	slices.Sort(out)
	return out
}

// TestTrafficMapFocusShowsNoCrossHostData: the focus view of a host holds
// only that host, its peers and the flows between them, never another
// host's nodes or flows, even when the store hands back more than the
// focus's flows. The overview attributes each flow to the right pair and
// direction and leaves flows to an ambiguous address unresolved.
func TestTrafficMapFocusShowsNoCrossHostData(t *testing.T) {
	want := map[string]struct {
		nodes []string
		edges []string
	}{
		"host-a": {[]string{"host-a", "peer-a"}, []string{"host-a-peer-a 600/400 3"}},
		// Edge ends are ordered by ID: host-b < peer-b, so the bytes swap.
		"host-b": {[]string{"host-b", "peer-b"}, []string{"host-b-peer-b 1950/50 5"}},
	}
	for _, leaky := range []bool{false, true} {
		for focus, w := range want {
			name := fmt.Sprintf("focus=%s/leaky=%v", focus, leaky)
			m, body := crossHostModel(t, crossHostFlows{leaky: leaky}, focus)
			if m.Focus != focus {
				t.Errorf("%s: model focus %q", name, m.Focus)
			}
			if got := nodeIDs(m.Nodes); !slices.Equal(got, w.nodes) {
				t.Errorf("%s: nodes %v, want %v", name, got, w.nodes)
			}
			if got := edgeSummary(m.Edges); !slices.Equal(got, w.edges) {
				t.Errorf("%s: edges %v, want %v", name, got, w.edges)
			}
			if len(m.ZoneLinks) != 0 {
				t.Errorf("%s: zone links %+v", name, m.ZoneLinks)
			}
			// Nothing of another node may reach the response, not even as
			// a label or an ID in an edge.
			for _, id := range chNodeIDs {
				if slices.Contains(w.nodes, id) {
					continue
				}
				if bytes.Contains(body, []byte(`"`+id+`"`)) || bytes.Contains(body, []byte("label-of-"+id)) {
					t.Errorf("%s: response mentions node %s", name, id)
				}
			}
		}
	}

	m, _ := crossHostModel(t, crossHostFlows{}, "")
	if got := nodeIDs(m.Nodes); !slices.Equal(got, slices.Sorted(slices.Values(chNodeIDs))) {
		t.Errorf("overview nodes %v", got)
	}
	wantEdges := []string{"host-a-peer-a 600/400 3", "host-b-peer-b 1950/50 5", "x-1-x-2 3000/1 7"}
	if got := edgeSummary(m.Edges); !slices.Equal(got, wantEdges) {
		t.Errorf("overview edges %v, want %v", got, wantEdges)
	}
	for _, e := range m.Edges {
		if strings.HasPrefix(e.A, "amb-") || strings.HasPrefix(e.B, "amb-") {
			t.Errorf("a flow to the ambiguous address was attributed: %+v", e)
		}
	}
	if m.UnmappedFlows != 2 {
		t.Errorf("overview unmapped flows = %d, want 2 (both flows to the ambiguous address)", m.UnmappedFlows)
	}
	if m.Omitted.Addresses < 1 {
		t.Errorf("the ambiguous address is not reported as omitted: %+v", m.Omitted)
	}
}

// TestTrafficMapPageRejectsHostileFocus: the page's focus parameter must
// be a node ID; anything else is refused before any template runs, and
// the error does not echo the input.
func TestTrafficMapPageRejectsHostileFocus(t *testing.T) {
	h := trafficStack(t)
	for _, focus := range []string{
		`"><script>alert(1)</script>`, "javascript:alert(1)", "web onmouseover=alert(1)", "../hosts/x", "%00", strings.Repeat("a", 200),
	} {
		w := tmGet(h, "/traffic?window=24h&focus="+urlQueryEscape(focus))
		if w.Code != http.StatusBadRequest {
			t.Errorf("focus %q: status %d, want 400", focus, w.Code)
		}
		if strings.Contains(w.Body.String(), "<script") || strings.Contains(w.Body.String(), "alert(") {
			t.Errorf("focus %q: error body echoes the input: %q", focus, w.Body.String())
		}
		if w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("focus %q: no nosniff on the error", focus)
		}
	}
}

func urlQueryEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		fmt.Fprintf(&b, "%%%02X", s[i])
	}
	return b.String()
}

// scriptTag matches an opening script tag.
var scriptTag = regexp.MustCompile(`(?i)<script\b[^>]*>`)

// cspDirectives splits a CSP into directive name → value.
func cspDirectives(t *testing.T, csp string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, d := range strings.Split(csp, ";") {
		f := strings.Fields(d)
		if len(f) == 0 {
			continue
		}
		if _, dup := out[f[0]]; dup {
			t.Errorf("CSP repeats %s", f[0])
		}
		out[f[0]] = strings.Join(f[1:], " ")
	}
	return out
}

// TestTrafficMapIframeIsIsolated: the parent page embeds the renderer only
// in an iframe with sandbox="allow-scripts" (no allow-same-origin, so an
// opaque origin without cookies or parent DOM access), carries no inline
// script, and the renderer document repeats the sandbox in its own CSP,
// forbids every network use but its modules and can be framed only by
// this deployment.
func TestTrafficMapIframeIsIsolated(t *testing.T) {
	h := trafficStack(t)

	w := tmGet(h, "/traffic?window=24h&focus=web")
	if w.Code != http.StatusOK {
		t.Fatalf("page: status %d", w.Code)
	}
	body := w.Body.String()
	frames := regexp.MustCompile(`<iframe\b[^>]*>`).FindAllString(body, -1)
	if len(frames) != 1 {
		t.Fatalf("page has %d iframes, want 1: %q", len(frames), frames)
	}
	if !strings.Contains(frames[0], `sandbox="allow-scripts"`) || !strings.Contains(frames[0], `src="/traffic/frame"`) {
		t.Errorf("renderer iframe is not sandboxed to scripts only: %s", frames[0])
	}
	for _, bad := range []string{"allow-same-origin", "allow-top-navigation", "allow-popups", "allow-forms", "srcdoc"} {
		if strings.Contains(body, bad) {
			t.Errorf("page contains %q", bad)
		}
	}
	for _, tag := range scriptTag.FindAllString(body, -1) {
		if !strings.Contains(tag, "src=") {
			t.Errorf("page has an inline script: %s", tag)
		}
	}
	// The page's CSP is the server default; any widening (a frame-src,
	// connect-src or script source beyond 'self') must show up here.
	pageCSP := cspDirectives(t, w.Header().Get("Content-Security-Policy"))
	wantPage := map[string]string{
		"default-src":     "'self'",
		"script-src":      "'self'",
		"style-src":       "'self'",
		"img-src":         "'self' data:",
		"object-src":      "'none'",
		"base-uri":        "'none'",
		"frame-ancestors": "'none'",
		"form-action":     "'self'",
	}
	if !maps.Equal(pageCSP, wantPage) {
		t.Errorf("page CSP = %v, want exactly %v", pageCSP, wantPage)
	}

	f := tmGet(h, "/traffic/frame")
	if f.Code != http.StatusOK {
		t.Fatalf("frame: status %d", f.Code)
	}
	if n := len(f.Header().Values("Content-Security-Policy")); n != 1 {
		t.Fatalf("frame has %d CSP headers, want exactly its own", n)
	}
	if f.Header().Get("Set-Cookie") != "" {
		t.Error("frame response sets a cookie")
	}
	csp := cspDirectives(t, f.Header().Get("Content-Security-Policy"))
	want := map[string]string{
		"sandbox":         "allow-scripts",
		"default-src":     "'none'",
		"script-src":      tmOrigin + "/static/trafficmap/",
		"connect-src":     "'none'",
		"img-src":         "'none'",
		"frame-src":       "'none'",
		"child-src":       "'none'",
		"worker-src":      "'none'",
		"object-src":      "'none'",
		"base-uri":        "'none'",
		"form-action":     "'none'",
		"frame-ancestors": tmOrigin,
	}
	for k, v := range want {
		if csp[k] != v {
			t.Errorf("frame CSP %s = %q, want %q", k, csp[k], v)
		}
	}
	for k, v := range csp {
		if strings.Contains(v, "unsafe-") || strings.Contains(v, "*") || strings.Contains(v, "data:") || strings.Contains(v, "allow-same-origin") {
			t.Errorf("frame CSP %s = %q is too wide", k, v)
		}
	}
	if !strings.HasPrefix(csp["style-src"], "'sha256-") {
		t.Errorf("frame style-src = %q, want a hash", csp["style-src"])
	}
	for _, tag := range scriptTag.FindAllString(f.Body.String(), -1) {
		if !strings.Contains(tag, `src="/static/trafficmap/`) {
			t.Errorf("frame loads a script from elsewhere or inline: %s", tag)
		}
	}

	m := tmGet(h, "/static/trafficmap/boot.js")
	if m.Code != http.StatusOK {
		t.Fatalf("module: status %d", m.Code)
	}
	if m.Header().Get("Access-Control-Allow-Origin") != "*" || m.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Errorf("module CORS: ACAO %q, ACAC %q", m.Header().Get("Access-Control-Allow-Origin"), m.Header().Get("Access-Control-Allow-Credentials"))
	}
	if m.Header().Get("X-Content-Type-Options") != "nosniff" || !strings.HasPrefix(m.Header().Get("Content-Type"), "text/javascript") {
		t.Errorf("module headers: %v", m.Header())
	}
	for _, p := range []string{"/static/trafficmap/../trafficmap-bridge.js", "/static/trafficmap/boot.test.mjs", "/static/trafficmap/%2e%2e%2fapp.js"} {
		if w := tmGet(h, p); w.Code == http.StatusOK && w.Header().Get("Access-Control-Allow-Origin") == "*" {
			t.Errorf("%s served with ACAO *", p)
		}
	}
}

// jsWithoutComments strips // line comments that start a line and /* */
// blocks, so the doc comments that say "no innerHTML" do not match.
func jsWithoutComments(src string) string {
	src = regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(src, "")
	var out []string
	for _, l := range strings.Split(src, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(l), "//") {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

// TestTrafficMapScriptsHaveNoMarkupSinks: the parent bridge and the
// renderer modules set text only (textContent, fillText). The renderer,
// which receives host data, has no network, storage, cookie or parent
// access in its code either.
func TestTrafficMapScriptsHaveNoMarkupSinks(t *testing.T) {
	root := filepath.Join("..", "..", "web", "static")
	markup := regexp.MustCompile(`\.innerHTML\b|\.outerHTML\b|insertAdjacentHTML|document\.write|\beval\s*\(|new\s+Function\b|\bFunction\s*\(|DOMParser|createContextualFragment|\bsrcdoc\b|setTimeout\s*\(\s*["'\x60]|setInterval\s*\(\s*["'\x60]`)
	renderer := regexp.MustCompile(`\bfetch\s*\(|XMLHttpRequest|WebSocket|EventSource|sendBeacon|importScripts|new\s+Image\b|\.src\s*=|window\.open|document\.cookie|localStorage|sessionStorage|indexedDB|parent\.document|top\.document|opener|postMessage\([^;\n]*["']\*["']`)
	files, err := filepath.Glob(filepath.Join(root, "trafficmap", "*.js"))
	if err != nil || len(files) < 5 {
		t.Fatalf("renderer modules: %v %v", files, err)
	}
	all := append([]string{filepath.Join(root, "trafficmap-bridge.js")}, files...)
	for _, p := range all {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		src := jsWithoutComments(string(b))
		if m := markup.FindString(src); m != "" {
			t.Errorf("%s: markup sink %q", p, m)
		}
		if filepath.Base(filepath.Dir(p)) == "trafficmap" {
			if m := renderer.FindString(src); m != "" {
				t.Errorf("%s: renderer uses %q", p, m)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Icon URLs: SSRF and DNS rebinding.

// TestIconURLPolicyRefusesSSRFTargets: every way to name an internal or
// non-allowlisted target in an icon URL is refused before any DNS lookup.
func TestIconURLPolicyRefusesSSRFTargets(t *testing.T) {
	for _, raw := range []string{
		"http://avatars.githubusercontent.com/u/1",
		"https://127.0.0.1/x.png",
		"https://127.1/x.png",
		"https://2130706433/x.png",
		"https://0x7f000001/x.png",
		"https://017700000001/x.png",
		"https://0.0.0.0/x.png",
		"https://10.0.0.1/x.png",
		"https://192.168.1.1/x.png",
		"https://169.254.169.254/latest/meta-data/",
		"https://[::1]/x.png",
		"https://[::ffff:127.0.0.1]/x.png",
		"https://[fe80::1%25eth0]/x.png",
		"https://[fd00::1]/x.png",
		"https://localhost/x.png",
		"https://metadata.google.internal/computeMetadata/v1/",
		"https://avatars.githubusercontent.com@127.0.0.1/x.png",
		"https://user:pw@avatars.githubusercontent.com/x.png",
		"https://avatars.githubusercontent.com\\@127.0.0.1/x.png",
		"https://avatars.githubusercontent.com:8443/x.png",
		"https://avatars.githubusercontent.com:80/x.png",
		"https://avatars.githubusercontent.com./x.png",
		"https://avatars.githubusercontent.com.evil.example/x.png",
		"https://x.avatars.githubusercontent.com/x.png",
		"https://evilavatars.githubusercontent.com/x.png",
		"https://avatars%2egithubusercontent%2ecom/x.png",
		"https://avatars.githubusercontent.com%00.evil.example/x.png",
		"https://аvatars.githubusercontent.com/x.png",
		"https://avatars.githubusercontent.com/x.png#@127.0.0.1",
		"https://avatars.githubusercontent.com/x.png\r\nHost: 127.0.0.1",
		" https://avatars.githubusercontent.com/x.png",
		"//avatars.githubusercontent.com/x.png",
		"file:///etc/passwd",
		"gopher://127.0.0.1:6379/_FLUSHALL",
		"data:image/png;base64,iVBORw0KGgo=",
		"javascript:alert(1)",
		"https:avatars.githubusercontent.com/x.png",
		"https://" + strings.Repeat("a", iconfetch.MaxURLLen),
	} {
		if u, err := iconfetch.ValidateURL(raw, nil); !errors.Is(err, iconfetch.ErrURL) {
			t.Errorf("ValidateURL(%q) = %v, %v; want ErrURL", raw, u, err)
		}
	}
	// The allowlist is exact; a literal IP is refused even when listed.
	if _, err := iconfetch.ValidateURL("https://10.0.0.1/x.png", []string{"10.0.0.1"}); !errors.Is(err, iconfetch.ErrURL) {
		t.Errorf("allowlisted IP literal: %v", err)
	}
	u, err := iconfetch.ValidateURL("https://AVATARS.githubusercontent.com:443/u/1?v=4", nil)
	if err != nil || u.Hostname() != "avatars.githubusercontent.com" || u.Scheme != "https" {
		t.Errorf("allowlisted URL: %v, %v", u, err)
	}
}

// rebindingResolver answers every lookup for an allowlisted name with the
// next internal address, as a rebinding DNS server would after the URL
// check passed. It records the lookups.
type rebindingResolver struct {
	mu      sync.Mutex
	answers [][]netip.Addr
	hosts   []string
}

func (r *rebindingResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hosts = append(r.hosts, host)
	if len(r.answers) == 0 {
		return nil, errors.New("no more answers")
	}
	a := r.answers[0]
	r.answers = r.answers[1:]
	return a, nil
}

// TestIconFetchRefusesInternalAndRebindingAnswers: an allowlisted name
// whose DNS answer is internal (loopback, private, link-local and cloud
// metadata, CGNAT, unspecified, multicast, broadcast, reserved, mapped
// IPv6) is refused at dial time, on every fetch, so a name that rebinds
// between the URL check and the connection cannot reach an internal
// service. No connection is attempted.
func TestIconFetchRefusesInternalAndRebindingAnswers(t *testing.T) {
	var answers [][]netip.Addr
	for _, a := range []string{
		"127.0.0.1", "127.53.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1",
		"0.0.0.0", "224.0.0.1", "255.255.255.255", "240.0.0.1", "198.18.0.1", "192.0.2.1", "::ffff:127.0.0.1", "::ffff:10.0.0.1",
	} {
		answers = append(answers, []netip.Addr{netip.MustParseAddr(a)})
	}
	// A multi-address answer that contains only internal addresses of
	// different classes is refused as a whole.
	answers = append(answers, []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("169.254.169.254")})
	n := len(answers)
	res := &rebindingResolver{answers: answers}
	c := iconfetch.New(iconfetch.Config{Resolver: res})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for i := 0; i < n; i++ {
		body, err := c.Fetch(ctx, "https://avatars.githubusercontent.com/u/1?v=4")
		if !errors.Is(err, iconfetch.ErrAddress) || body != nil {
			t.Errorf("answer %d: Fetch = %d bytes, %v; want ErrAddress", i, len(body), err)
		}
	}
	if len(res.hosts) != n {
		t.Fatalf("resolver asked %d times for %d fetches: the address check must run at dial time, every time", len(res.hosts), n)
	}
	for _, h := range res.hosts {
		if h != "avatars.githubusercontent.com" {
			t.Errorf("resolver asked for %q", h)
		}
	}
}

// ---------------------------------------------------------------------------
// Polyglot icons and /icons/.

const polyglotMarker = "<script>alert('polyglot')</script>"

func testImage(w, h int) *image.RGBA {
	m := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			m.Set(x, y, color.RGBA{R: uint8(x * 16), G: uint8(y * 16), B: 0x80, A: 0xff})
		}
	}
	return m
}

func encodePNG(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := png.Encode(&b, testImage(16, 16)); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// pngChunk builds one PNG chunk with a valid CRC.
func pngChunk(typ string, data []byte) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.BigEndian, uint32(len(data)))
	b.WriteString(typ)
	b.Write(data)
	crc := crc32.NewIEEE()
	crc.Write([]byte(typ))
	crc.Write(data)
	_ = binary.Write(&b, binary.BigEndian, crc.Sum32())
	return b.Bytes()
}

// polyglots returns valid images that also carry an HTML/JS (or ZIP)
// payload in places decoders skip.
func polyglots(t *testing.T) map[string][]byte {
	t.Helper()
	p := encodePNG(t)
	const ihdrEnd = 8 + 25 // signature + IHDR chunk
	withText := append(append(append([]byte{}, p[:ihdrEnd]...), pngChunk("tEXt", []byte("Comment\x00"+polyglotMarker))...), p[ihdrEnd:]...)
	withPrivate := append(append(append([]byte{}, p[:ihdrEnd]...), pngChunk("htMl", []byte(polyglotMarker))...), p[ihdrEnd:]...)

	var g bytes.Buffer
	pal := image.NewPaletted(image.Rect(0, 0, 16, 16), []color.Color{color.Black, color.White})
	if err := gif.Encode(&g, pal, nil); err != nil {
		t.Fatal(err)
	}
	gb := g.Bytes()
	comment := append([]byte{0x21, 0xFE, byte(len(polyglotMarker))}, polyglotMarker...)
	comment = append(comment, 0x00)
	gifComment := append(append(append([]byte{}, gb[:len(gb)-1]...), comment...), 0x3B)

	var j bytes.Buffer
	if err := jpeg.Encode(&j, testImage(16, 16), nil); err != nil {
		t.Fatal(err)
	}
	jb := j.Bytes()
	com := []byte{0xFF, 0xFE, 0, 0}
	binary.BigEndian.PutUint16(com[2:], uint16(len(polyglotMarker)+2))
	com = append(com, polyglotMarker...)
	jpegComment := append(append(append([]byte{}, jb[:2]...), com...), jb[2:]...)

	return map[string][]byte{
		"png trailing html": append(append([]byte{}, p...), "<html><body>"+polyglotMarker+"</body></html>"...),
		"png trailing zip":  append(append([]byte{}, p...), "PK\x03\x04"+polyglotMarker...),
		"png tEXt":          withText,
		"png private chunk": withPrivate,
		"gif comment":       gifComment,
		"gif trailing js":   append(append([]byte{}, gb...), "*/="+polyglotMarker...),
		"jpeg COM":          jpegComment,
		"jpeg trailing":     append(append([]byte{}, jb...), polyglotMarker...),
	}
}

// pngChunkTypes lists the chunk types of a PNG stream.
func pngChunkTypes(t *testing.T, b []byte) []string {
	t.Helper()
	if !bytes.HasPrefix(b, []byte("\x89PNG\r\n\x1a\n")) {
		t.Fatalf("not a PNG stream")
	}
	var types []string
	for i := 8; i < len(b); {
		if i+12 > len(b) {
			t.Fatalf("truncated chunk at %d", i)
		}
		n := int(binary.BigEndian.Uint32(b[i:]))
		types = append(types, string(b[i+4:i+8]))
		i += 12 + n
		if i > len(b) {
			t.Fatalf("chunk runs past the end")
		}
		if types[len(types)-1] == "IEND" && i != len(b) {
			t.Fatalf("%d bytes after IEND", len(b)-i)
		}
	}
	return types
}

// checkCleanPNG asserts that b is a fresh PNG of size×size with only
// IHDR, IDAT and IEND and none of the payload.
func checkCleanPNG(t *testing.T, name string, b []byte, size int) {
	t.Helper()
	for _, typ := range pngChunkTypes(t, b) {
		if typ != "IHDR" && typ != "IDAT" && typ != "IEND" {
			t.Errorf("%s: output keeps chunk %q", name, typ)
		}
	}
	for _, bad := range []string{polyglotMarker, "script", "alert", "PK\x03\x04", "<html"} {
		if bytes.Contains(b, []byte(bad)) {
			t.Errorf("%s: output still contains %q", name, bad)
		}
	}
	cfg, err := png.DecodeConfig(bytes.NewReader(b))
	if err != nil || cfg.Width != size || cfg.Height != size {
		t.Errorf("%s: output %dx%d, %v; want %dx%d", name, cfg.Width, cfg.Height, err, size, size)
	}
}

// TestPolyglotIconsAreReencoded: an image that is also HTML, JavaScript or
// a ZIP is accepted only as pixels; the stored icons are new PNG streams
// with nothing of the input but the picture.
func TestPolyglotIconsAreReencoded(t *testing.T) {
	for name, in := range polyglots(t) {
		if !bytes.Contains(in, []byte(polyglotMarker)) {
			t.Fatalf("%s: fixture lost its payload", name)
		}
		ic, err := iconstore.Sanitize(in)
		if err != nil {
			t.Errorf("%s: Sanitize: %v", name, err)
			continue
		}
		checkCleanPNG(t, name+" 128", ic.PNG128, iconstore.LargeSize)
		checkCleanPNG(t, name+" 64", ic.PNG64, iconstore.SmallSize)
		if !sha256RE.MatchString(ic.SHA256) {
			t.Errorf("%s: hash %q", name, ic.SHA256)
		}
	}
}

// TestActiveImageFormatsAreRefused: SVG (script-capable), HTML with an
// image after it, WebP, ICO and BMP are rejected by magic bytes.
func TestActiveImageFormatsAreRefused(t *testing.T) {
	p := encodePNG(t)
	for name, in := range map[string][]byte{
		"svg":              []byte(`<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><rect width="1" height="1"/></svg>`),
		"svg with xml":     []byte(`<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`),
		"svg with bom":     append([]byte("\xef\xbb\xbf"), `<svg xmlns="http://www.w3.org/2000/svg"/>`...),
		"html then png":    append([]byte("<!DOCTYPE html><html>"+polyglotMarker+"</html>"), p...),
		"whitespace + png": append([]byte(" \n"), p...),
		"webp":             append([]byte("RIFF\x24\x00\x00\x00WEBPVP8 "), make([]byte, 32)...),
		"ico":              append([]byte{0, 0, 1, 0, 1, 0}, p...),
		"bmp":              append([]byte("BM"), make([]byte, 64)...),
		"png magic only":   []byte("\x89PNG\r\n\x1a\n" + polyglotMarker),
	} {
		if _, err := iconstore.Sanitize(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// iconFixture is the server's icon service on a temporary database.
type iconFixture struct {
	svc   *icons.Service
	store *iconstore.Store
	spool iconjob.Spool
}

func newIconFixture(t *testing.T) *iconFixture {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	cat, err := softwarecat.NewStore(db, softwarecat.Options{})
	if err != nil {
		t.Fatal(err)
	}
	units := base64.StdEncoding.EncodeToString([]byte("widgetd.service loaded active running Some unit"))
	if _, err := cat.IngestServiceList(context.Background(), softwarecat.Target{Kind: softwarecat.TargetHost, HostID: "h1"},
		[]byte(`{"format":"systemd-units-v1","units":"`+units+`"}`), time.Now()); err != nil {
		t.Fatal(err)
	}
	st, err := iconstore.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sp := iconjob.Spool{Dir: t.TempDir()}
	for _, d := range []string{sp.JobsDir(), sp.ResultsDir()} {
		if err := os.Mkdir(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	svc, err := icons.New(icons.Config{Spool: sp, Store: st, Catalog: cat})
	if err != nil {
		t.Fatal(err)
	}
	return &iconFixture{svc: svc, store: st, spool: sp}
}

func serveIcon(h http.Handler, method, path string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, tmOrigin+path, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// iconSafetyHeaders are on every /icons/ response, found or not.
var iconSafetyHeaders = map[string]string{
	"Content-Security-Policy": "default-src 'none'",
	"X-Content-Type-Options":  "nosniff",
}

// TestIconsServeOnlyInertPNGs: an uploaded polyglot is served under
// /icons/<sha256>.png as the re-encoded PNG with Content-Type image/png,
// nosniff, CSP default-src 'none' and Content-Disposition inline; every
// other path or method fails with the same safety headers.
func TestIconsServeOnlyInertPNGs(t *testing.T) {
	f := newIconFixture(t)
	in := polyglots(t)["png trailing html"]
	sha, err := f.svc.Upload(context.Background(), "alice", softwarecat.IconSubject{Kind: softwarecat.SubjectCatalog, ID: "widgetd"}, in)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := f.store.Path(sha, iconstore.LargeSize)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(stored)
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		w := serveIcon(f.svc, method, "/icons/"+sha+".png")
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status %d", method, w.Code)
		}
		for k, v := range iconSafetyHeaders {
			if got := w.Header().Get(k); got != v {
				t.Errorf("%s: %s = %q, want %q", method, k, got, v)
			}
		}
		if w.Header().Get("Content-Type") != "image/png" || w.Header().Get("Content-Disposition") != "inline" {
			t.Errorf("%s: Content-Type %q, Content-Disposition %q", method, w.Header().Get("Content-Type"), w.Header().Get("Content-Disposition"))
		}
		if method == http.MethodGet {
			if !bytes.Equal(w.Body.Bytes(), want) {
				t.Error("served body is not the stored re-encoded icon")
			}
			checkCleanPNG(t, "served", w.Body.Bytes(), iconstore.LargeSize)
		}
	}

	for _, p := range []string{
		"/icons/" + strings.ToUpper(sha) + ".png",
		"/icons/" + sha + ".svg",
		"/icons/" + sha + ".png/x",
		"/icons/" + sha,
		"/icons/" + sha[:63] + ".png",
		"/icons/../../../../etc/passwd",
		"/icons/%2e%2e/%2e%2e/etc/passwd",
		"/icons/" + strings.Repeat("0", 64) + ".png",
		"/icons/",
	} {
		w := serveIcon(f.svc, http.MethodGet, p)
		if w.Code != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", p, w.Code)
		}
		if w.Header().Get("Content-Type") == "image/png" {
			t.Errorf("%s: served as an image", p)
		}
		for k, v := range iconSafetyHeaders {
			if got := w.Header().Get(k); got != v {
				t.Errorf("%s: %s = %q, want %q", p, k, got, v)
			}
		}
	}
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		w := serveIcon(f.svc, m, "/icons/"+sha+".png")
		if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Content-Security-Policy") != "default-src 'none'" {
			t.Errorf("%s: status %d, CSP %q", m, w.Code, w.Header().Get("Content-Security-Policy"))
		}
	}
}

// TestIconFetchJobsRefuseInternalURLs: the admin's "fetch icon from URL"
// refuses internal and non-allowlisted targets before a job reaches the
// fetcher's spool.
func TestIconFetchJobsRefuseInternalURLs(t *testing.T) {
	f := newIconFixture(t)
	for _, raw := range []string{
		"https://169.254.169.254/latest/meta-data/iam/",
		"https://127.0.0.1:443/x.png",
		"https://[::1]/x.png",
		"https://localhost/x.png",
		"http://upload.wikimedia.org/x.png",
		"https://upload.wikimedia.org@10.0.0.1/x.png",
		"https://upload.wikimedia.org.evil.example/x.png",
	} {
		if id, err := f.svc.QueueFetch(context.Background(), "alice", "widgetd", raw); !errors.Is(err, icons.ErrRejected) {
			t.Errorf("QueueFetch(%q) = %q, %v; want ErrRejected", raw, id, err)
		}
	}
	jobs, err := os.ReadDir(f.spool.JobsDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 0 {
		t.Errorf("%d jobs queued for refused URLs", len(jobs))
	}
	if _, err := f.svc.QueueFetch(context.Background(), "alice", "widgetd", "https://upload.wikimedia.org/w/x.png"); err != nil {
		t.Errorf("allowlisted URL refused: %v", err)
	}
}
