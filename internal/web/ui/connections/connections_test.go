// SPDX-License-Identifier: AGPL-3.0-or-later

package connections

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/flowagg"
	"github.com/nebula-operation-station/nebula-operation-station/web/templates"
)

var testNow = time.Date(2026, 11, 5, 12, 30, 0, 0, time.UTC)

// windows are the windows offered under the full retention.
var windows = windowsFor(flowagg.Retention)

// allow is an Authorize that approves every request.
func allow(*http.Request) bool { return true }

var (
	hostAddr  = netip.MustParseAddr("10.0.0.10")
	hostAddr6 = netip.MustParseAddr("fd00::10")
	dnsAddr   = netip.MustParseAddr("10.0.0.53")
	nasAddr   = netip.MustParseAddr("10.0.0.20")
	webAddr   = netip.MustParseAddr("203.0.113.7")
	assetAddr = netip.MustParseAddr("10.0.0.99")
)

// fakeFlows records the last query and returns fixed records.
type fakeFlows struct {
	recs   []Record
	err    error
	calls  int
	nodes  []netip.Addr
	window flowagg.Window
	limit  int
}

func (f *fakeFlows) Flows(_ context.Context, nodes []netip.Addr, w flowagg.Window, limit int) ([]Record, error) {
	f.calls++
	f.nodes, f.window, f.limit = append([]netip.Addr(nil), nodes...), w, limit
	if f.err != nil {
		return nil, f.err
	}
	if len(f.recs) > limit {
		return f.recs[:limit], nil
	}
	return f.recs, nil
}

// fakeDir is a fixed directory: host "web1" at hostAddr/hostAddr6,
// asset "a1" at assetAddr, peers nas (host) and dns (asset).
type fakeDir struct {
	hostErr error
}

func (d *fakeDir) Host(_ context.Context, id string) (Subject, error) {
	if d.hostErr != nil {
		return Subject{}, d.hostErr
	}
	if id != "web1" {
		return Subject{}, ErrNotFound
	}
	return Subject{Name: "web1.lab", Addrs: []netip.Addr{hostAddr, hostAddr6}}, nil
}

func (d *fakeDir) Asset(_ context.Context, id string) (Subject, error) {
	if id != "a1" {
		return Subject{}, ErrNotFound
	}
	return Subject{Name: "printer", Addrs: []netip.Addr{assetAddr}}, nil
}

func (d *fakeDir) Peers(_ context.Context, addrs []netip.Addr) (map[netip.Addr]Peer, error) {
	out := map[netip.Addr]Peer{}
	for _, a := range addrs {
		switch a {
		case nasAddr:
			out[a] = Peer{Kind: PeerHost, ID: "nas", Name: "nas.lab"}
		case dnsAddr:
			out[a] = Peer{Kind: PeerAsset, ID: "as-7", Name: "pihole"}
		}
	}
	return out, nil
}

// rec builds a record between a and b with the server at server.
func rec(a, b, server netip.Addr, port uint16, tier string, ab, ba uint64) Record {
	k := flowagg.FlowKey{A: a, B: b, Proto: flowagg.TCP, ServerPort: port, Tier: tier}
	if a.Compare(b) > 0 {
		k.A, k.B = b, a
		ab, ba = ba, ab
	}
	k.Server = flowagg.SideA
	if server == k.B {
		k.Server = flowagg.SideB
	}
	return Record{FlowTotal: flowagg.FlowTotal{
		Key: k, BytesAB: ab, BytesBA: ba, Connections: 1,
		FirstSeen: testNow.Add(-3 * time.Hour).Truncate(time.Hour),
		LastSeen:  testNow.Truncate(time.Hour),
	}, Reporters: []string{"web1"}}
}

func newTestHandler(t *testing.T, f *fakeFlows) *Handler {
	t.Helper()
	h, err := New(Options{Flows: f, Directory: &fakeDir{}, Authorize: allow, Now: func() time.Time { return testNow }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return h
}

func get(t *testing.T, h *Handler, target string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, target, nil))
	return rr
}

func TestNewRequiresSources(t *testing.T) {
	if _, err := New(Options{Directory: &fakeDir{}}); err == nil {
		t.Fatal("New without Flows: want error")
	}
	if _, err := New(Options{Flows: &fakeFlows{}, Authorize: allow}); err == nil {
		t.Fatal("New without Directory: want error")
	}
	if _, err := New(Options{Flows: &fakeFlows{}, Directory: &fakeDir{}}); err == nil {
		t.Fatal("New without Authorize: want error")
	}
	for _, r := range []time.Duration{-time.Hour, 30 * time.Minute, flowagg.Retention + time.Hour} {
		if _, err := New(Options{Flows: &fakeFlows{}, Directory: &fakeDir{}, Authorize: allow, Retention: r}); err == nil {
			t.Errorf("retention %s accepted", r)
		}
	}
}

// TestUnauthorizedRequestIsRefused checks that the handler fails closed:
// a request Authorize does not approve gets 403 and reads nothing.
func TestUnauthorizedRequestIsRefused(t *testing.T) {
	f := &fakeFlows{recs: []Record{rec(hostAddr, dnsAddr, dnsAddr, 53, flowagg.TierSocket, 1, 1)}}
	var seen []string
	h, err := New(Options{Flows: f, Directory: &fakeDir{}, Now: func() time.Time { return testNow },
		Authorize: func(r *http.Request) bool { seen = append(seen, r.PathValue("id")); return false }})
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"/hosts/web1/connections", "/network/a/a1/connections", "/hosts/web1/connections?window=1h"} {
		rr := get(t, h, target)
		if rr.Code != http.StatusForbidden || strings.Contains(rr.Body.String(), "web1.lab") {
			t.Errorf("%s: status %d body %q, want 403 without data", target, rr.Code, rr.Body)
		}
	}
	if f.calls != 0 {
		t.Errorf("flow source queried %d times for refused requests", f.calls)
	}
	if strings.Join(seen, ",") != "web1,a1,web1" {
		t.Errorf("Authorize saw path IDs %v", seen)
	}
}

// retentionFlows is a FlowSource that reports a shortened retention,
// like SQLFlows over a store an admin configured lower.
type retentionFlows struct {
	*fakeFlows
	retention time.Duration
}

func (r retentionFlows) Retention() time.Duration { return r.retention }

// TestWindowsRespectTheRetention checks that windows longer than the
// store's retention are neither offered nor accepted (ADR 0009 D3), from
// the configured retention and from the source's own.
func TestWindowsRespectTheRetention(t *testing.T) {
	cases := []struct {
		name     string
		opts     func(f *fakeFlows) Options
		offered  []string
		refused  []string
		fallback time.Duration // default window
	}{
		{"configured 7d", func(f *fakeFlows) Options {
			return Options{Flows: f, Retention: 7 * 24 * time.Hour}
		}, []string{"1h", "24h", "7d"}, []string{"21d"}, 24 * time.Hour},
		{"source 12h", func(f *fakeFlows) Options {
			return Options{Flows: retentionFlows{f, 12 * time.Hour}}
		}, []string{"1h"}, []string{"24h", "7d", "21d"}, time.Hour},
		{"configured 21d, source 3d", func(f *fakeFlows) Options {
			return Options{Flows: retentionFlows{f, 3 * 24 * time.Hour}, Retention: flowagg.Retention}
		}, []string{"1h", "24h"}, []string{"7d", "21d"}, 24 * time.Hour},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &fakeFlows{}
			o := c.opts(f)
			o.Directory, o.Authorize, o.Now = &fakeDir{}, allow, func() time.Time { return testNow }
			h, err := New(o)
			if err != nil {
				t.Fatal(err)
			}
			rr := get(t, h, "/hosts/web1/connections")
			if rr.Code != http.StatusOK {
				t.Fatalf("default: status %d", rr.Code)
			}
			if got := f.window.To.Sub(f.window.From); got != c.fallback {
				t.Errorf("default window %s, want %s", got, c.fallback)
			}
			body := rr.Body.String()
			for _, id := range c.offered {
				if !strings.Contains(body, "window="+id+"&") {
					t.Errorf("window %s not offered", id)
				}
				if rr := get(t, h, "/hosts/web1/connections?window="+id); rr.Code != http.StatusOK {
					t.Errorf("window %s: status %d, want 200", id, rr.Code)
				}
			}
			calls := f.calls
			for _, id := range c.refused {
				if strings.Contains(body, "window="+id+"&") {
					t.Errorf("window %s offered beyond the retention", id)
				}
				if rr := get(t, h, "/hosts/web1/connections?window="+id); rr.Code != http.StatusBadRequest {
					t.Errorf("window %s: status %d, want 400", id, rr.Code)
				}
			}
			if f.calls != calls {
				t.Errorf("refused windows reached the flow source")
			}
		})
	}
}

func TestWindowSwitchQueriesSelectedWindow(t *testing.T) {
	cases := []struct {
		query string
		want  time.Duration
	}{
		{"", 24 * time.Hour},
		{"?window=1h", time.Hour},
		{"?window=24h", 24 * time.Hour},
		{"?window=7d", 7 * 24 * time.Hour},
		{"?window=21d", 21 * 24 * time.Hour},
	}
	for _, c := range cases {
		t.Run(c.query, func(t *testing.T) {
			f := &fakeFlows{}
			rr := get(t, newTestHandler(t, f), "/hosts/web1/connections"+c.query)
			if rr.Code != http.StatusOK {
				t.Fatalf("status %d: %s", rr.Code, rr.Body)
			}
			if !f.window.To.Equal(testNow) || f.window.To.Sub(f.window.From) != c.want {
				t.Fatalf("window %v..%v, want %s ending now", f.window.From, f.window.To, c.want)
			}
			if f.limit != MaxRows+1 {
				t.Fatalf("limit %d, want %d", f.limit, MaxRows+1)
			}
			// Every window is offered, the selected one marked current.
			body := rr.Body.String()
			for _, id := range []string{"1h", "24h", "7d", "21d"} {
				if !strings.Contains(body, "window="+id) {
					t.Errorf("window link %s missing", id)
				}
			}
			if strings.Count(body, `aria-current="true"`) != 1 {
				t.Errorf("want exactly one current window")
			}
		})
	}
}

func TestInvalidQueryRejected(t *testing.T) {
	for _, q := range []string{"?window=30d", "?window=", "?sort=evil", "?order=sideways", "?window=1h&window=7d"} {
		f := &fakeFlows{}
		rr := get(t, newTestHandler(t, f), "/hosts/web1/connections"+q)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", q, rr.Code)
		}
		if f.calls != 0 {
			t.Errorf("%s: flow source queried for an invalid request", q)
		}
	}
}

func TestUnknownSubjectIsNotFound(t *testing.T) {
	for _, target := range []string{
		"/hosts/nope/connections",
		"/network/a/nope/connections",
		"/hosts/" + strings.Repeat("x", maxIDLen+1) + "/connections",
		"/hosts/a%01b/connections",
	} {
		f := &fakeFlows{}
		rr := get(t, newTestHandler(t, f), target)
		if rr.Code != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", target, rr.Code)
		}
		if f.calls != 0 {
			t.Errorf("%s: flow source queried", target)
		}
	}
}

func TestDirectoryErrorIsInternalAndGeneric(t *testing.T) {
	h, err := New(Options{Flows: &fakeFlows{}, Directory: &fakeDir{hostErr: errors.New("db path /secret")}, Authorize: allow, Now: func() time.Time { return testNow }})
	if err != nil {
		t.Fatal(err)
	}
	rr := get(t, h, "/hosts/web1/connections")
	if rr.Code != http.StatusInternalServerError || strings.Contains(rr.Body.String(), "/secret") {
		t.Fatalf("status %d body %q", rr.Code, rr.Body)
	}
}

func TestFlowErrorIsInternalAndGeneric(t *testing.T) {
	f := &fakeFlows{err: errors.New("sqlite: /var/lib/x")}
	rr := get(t, newTestHandler(t, f), "/hosts/web1/connections")
	if rr.Code != http.StatusInternalServerError || strings.Contains(rr.Body.String(), "/var/lib") {
		t.Fatalf("status %d body %q", rr.Code, rr.Body)
	}
}

func TestSubjectAddressesNormalizedAndQueried(t *testing.T) {
	f := &fakeFlows{}
	get(t, newTestHandler(t, f), "/hosts/web1/connections")
	if len(f.nodes) != 2 || f.nodes[0] != hostAddr || f.nodes[1] != hostAddr6 {
		t.Fatalf("nodes %v", f.nodes)
	}
	got := subjectAddrs([]netip.Addr{
		netip.MustParseAddr("::ffff:10.0.0.1"),
		netip.MustParseAddr("fe80::1%eth0"),
		netip.MustParseAddr("127.0.0.1"),
		netip.MustParseAddr("0.0.0.0"),
		{},
		netip.MustParseAddr("10.0.0.1"),
	})
	want := []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("fe80::1")}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("subjectAddrs = %v, want %v", got, want)
	}
}

func TestSubjectWithoutAddressesSkipsQuery(t *testing.T) {
	v := buildView(viewInput{subject: Subject{Name: "x"}, kind: kindHost, id: "x", window: windows[1], sort: sortBytes, desc: true})
	if len(v.Notices) == 0 {
		t.Fatal("want a notice for a subject without addresses")
	}
}

func TestRowsShowPeerDirectionServiceAndBytesFromLocalView(t *testing.T) {
	recs := []Record{
		// web1 → dns:53 (outbound); web1 sent 100, received 900.
		rec(hostAddr, dnsAddr, dnsAddr, 53, flowagg.TierSensor, 100, 900),
		// nas → web1:443 (inbound); nas sent 50, web1 sent 5000.
		rec(nasAddr, hostAddr, hostAddr, 443, flowagg.TierSensor, 50, 5000),
	}
	recs[0].Process = "systemd-resolve"
	v := buildView(viewInput{subject: Subject{Name: "web1.lab", Addrs: []netip.Addr{hostAddr}}, kind: kindHost, id: "web1",
		recs: recs, peers: mustPeers(t), window: windows[1], sort: sortBytes, desc: true})
	if len(v.Rows) != 2 {
		t.Fatalf("rows %d", len(v.Rows))
	}
	in := v.Rows[0] // 5050 bytes total, largest first
	if in.PeerAddr != nasAddr.String() || in.Direction != "inbound" || in.Service != "tcp/443" ||
		in.BytesInExact != 50 || in.BytesOutExact != 5000 || in.PeerHref != "/hosts/nas" || in.PeerName != "nas.lab" {
		t.Errorf("inbound row %+v", in)
	}
	out := v.Rows[1]
	if out.PeerAddr != dnsAddr.String() || out.Direction != "outbound" || out.Service != "tcp/53" ||
		out.BytesInExact != 900 || out.BytesOutExact != 100 || out.PeerHref != "/network/a/as-7" || out.Process != "systemd-resolve" {
		t.Errorf("outbound row %+v", out)
	}
	if out.FirstSeen != "2026-11-05 09:00 UTC" || out.LastSeen != "2026-11-05 12:00 UTC" {
		t.Errorf("seen %q %q", out.FirstSeen, out.LastSeen)
	}
}

func TestUnknownPeerIsUnlinkedAndLabeled(t *testing.T) {
	recs := []Record{rec(hostAddr, webAddr, webAddr, 443, flowagg.TierSensor, 1, 2)}
	v := buildView(viewInput{subject: Subject{Addrs: []netip.Addr{hostAddr}}, kind: kindHost, id: "web1",
		recs: recs, peers: mustPeers(t), window: windows[1], sort: sortBytes, desc: true})
	r := v.Rows[0]
	if r.PeerHref != "" || r.PeerKind != "unknown" || r.PeerAddr != webAddr.String() {
		t.Fatalf("row %+v", r)
	}
}

func TestBothEndsLocalIsInternal(t *testing.T) {
	recs := []Record{rec(hostAddr, hostAddr6, hostAddr6, 22, flowagg.TierSensor, 1, 2)}
	v := buildView(viewInput{subject: Subject{Addrs: []netip.Addr{hostAddr, hostAddr6}}, kind: kindHost, id: "web1",
		recs: recs, window: windows[1], sort: sortBytes, desc: true})
	if len(v.Rows) != 1 || v.Rows[0].Direction != "internal" {
		t.Fatalf("rows %+v", v.Rows)
	}
}

func TestRecordNotTouchingSubjectIsDropped(t *testing.T) {
	recs := []Record{rec(nasAddr, dnsAddr, dnsAddr, 53, flowagg.TierSensor, 1, 2)}
	v := buildView(viewInput{subject: Subject{Addrs: []netip.Addr{hostAddr}}, kind: kindHost, id: "web1",
		recs: recs, window: windows[1], sort: sortBytes, desc: true})
	if len(v.Rows) != 0 {
		t.Fatalf("rows %+v", v.Rows)
	}
}

func mustPeers(t *testing.T) map[netip.Addr]Peer {
	t.Helper()
	p, err := (&fakeDir{}).Peers(context.Background(), []netip.Addr{nasAddr, dnsAddr, webAddr})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSortingByColumn(t *testing.T) {
	a := rec(hostAddr, dnsAddr, dnsAddr, 53, flowagg.TierSensor, 10, 1000) // in 1000 out 10
	a.LastSeen = testNow.Add(-5 * time.Hour).Truncate(time.Hour)
	a.FirstSeen = testNow.Add(-6 * time.Hour).Truncate(time.Hour)
	b := rec(hostAddr, nasAddr, nasAddr, 2049, flowagg.TierSensor, 500, 20) // in 20 out 500
	c := rec(webAddr, hostAddr, hostAddr, 443, flowagg.TierSensor, 1, 1)    // tiny, latest first seen
	c.FirstSeen = testNow.Add(-time.Hour).Truncate(time.Hour)
	recs := []Record{a, b, c}
	cases := []struct {
		sort sortKey
		desc bool
		want []string // peer addresses in order
	}{
		{sortBytes, true, []string{"10.0.0.53", "10.0.0.20", "203.0.113.7"}},
		{sortBytes, false, []string{"203.0.113.7", "10.0.0.20", "10.0.0.53"}},
		{sortIn, true, []string{"10.0.0.53", "10.0.0.20", "203.0.113.7"}},
		{sortOut, true, []string{"10.0.0.20", "10.0.0.53", "203.0.113.7"}},
		{sortPeer, false, []string{"10.0.0.20", "10.0.0.53", "203.0.113.7"}},
		{sortPeer, true, []string{"203.0.113.7", "10.0.0.53", "10.0.0.20"}},
		{sortService, false, []string{"10.0.0.53", "203.0.113.7", "10.0.0.20"}},
		{sortLast, true, []string{"10.0.0.20", "203.0.113.7", "10.0.0.53"}},
		{sortFirst, false, []string{"10.0.0.53", "10.0.0.20", "203.0.113.7"}},
		{sortDirection, false, []string{"203.0.113.7", "10.0.0.53", "10.0.0.20"}},
	}
	for _, c := range cases {
		v := buildView(viewInput{subject: Subject{Addrs: []netip.Addr{hostAddr}}, kind: kindHost, id: "web1",
			recs: recs, window: windows[1], sort: c.sort, desc: c.desc})
		var got []string
		for _, r := range v.Rows {
			got = append(got, r.PeerAddr)
		}
		if strings.Join(got, " ") != strings.Join(c.want, " ") {
			t.Errorf("sort %s desc=%v: %v, want %v", c.sort, c.desc, got, c.want)
		}
	}
}

func TestSortHeaderLinksToggleOrderAndKeepWindow(t *testing.T) {
	f := &fakeFlows{recs: []Record{rec(hostAddr, dnsAddr, dnsAddr, 53, flowagg.TierSensor, 1, 2)}}
	rr := get(t, newTestHandler(t, f), "/hosts/web1/connections?window=7d&sort=peer&order=asc")
	body := rr.Body.String()
	if !strings.Contains(body, `href="/hosts/web1/connections?window=7d&amp;sort=peer&amp;order=desc"`) {
		t.Errorf("active column does not toggle to desc:\n%s", body)
	}
	if !strings.Contains(body, `href="/hosts/web1/connections?window=7d&amp;sort=bytes&amp;order=desc"`) {
		t.Errorf("bytes column does not default to desc")
	}
	if !strings.Contains(body, `aria-sort="ascending"`) {
		t.Errorf("active column lacks aria-sort")
	}
	// The window links keep the sort.
	if !strings.Contains(body, `href="/hosts/web1/connections?window=1h&amp;sort=peer&amp;order=asc"`) {
		t.Errorf("window link drops the sort")
	}
}

func TestTierLabelsAndLowerBoundMarker(t *testing.T) {
	sock := rec(hostAddr, dnsAddr, dnsAddr, 53, flowagg.TierSocket, 1, 2)
	ct := rec(hostAddr, nasAddr, nasAddr, 2049, flowagg.TierConntrack, 1, 2)
	sensor := rec(hostAddr, webAddr, webAddr, 443, flowagg.TierSensor, 1, 2)
	sensorLB := rec(hostAddr, webAddr, webAddr, 80, flowagg.TierSensor, 1, 2)
	sensorLB.LowerBound = true
	odd := rec(hostAddr, webAddr, webAddr, 8080, "weird<b>", 1, 2)
	v := buildView(viewInput{subject: Subject{Addrs: []netip.Addr{hostAddr}}, kind: kindHost, id: "web1",
		recs: []Record{sock, ct, sensor, sensorLB, odd}, window: windows[1], sort: sortService, desc: false})
	want := map[string]struct {
		tier string
		lb   bool
	}{
		"tcp/53":   {"snapshot (socket table)", true},
		"tcp/2049": {"snapshot (conntrack)", true},
		"tcp/443":  {"sensor", false},
		"tcp/80":   {"sensor", true},
		"tcp/8080": {"unknown tier", true},
	}
	for _, r := range v.Rows {
		w, ok := want[r.Service]
		if !ok {
			t.Fatalf("unexpected row %s", r.Service)
		}
		if r.Tier != w.tier || r.LowerBound != w.lb {
			t.Errorf("%s: tier %q lb %v, want %q %v", r.Service, r.Tier, r.LowerBound, w.tier, w.lb)
		}
	}
	rr := get(t, newTestHandler(t, &fakeFlows{recs: []Record{sock}}), "/hosts/web1/connections")
	if !strings.Contains(rr.Body.String(), `<abbr title="lower bound">≥</abbr>`) {
		t.Errorf("lower-bound marker not rendered")
	}
}

func TestReporterLabels(t *testing.T) {
	self := rec(hostAddr, dnsAddr, dnsAddr, 53, flowagg.TierSocket, 1, 2)
	self.Reporters = []string{"web1"}
	peerOnly := rec(nasAddr, hostAddr, hostAddr, 443, flowagg.TierSocket, 1, 2)
	peerOnly.Reporters = []string{"nas"}
	peerOnly.ServerReported = false
	both := rec(hostAddr, webAddr, webAddr, 8443, flowagg.TierSocket, 1, 2)
	both.Reporters = []string{"web1", "gw"}
	both.Confirmed, both.ServerReported = true, true
	many := rec(hostAddr, webAddr, webAddr, 80, flowagg.TierSensor, 1, 2)
	many.Reporters = []string{"r1", "r2", "r3", "r4", "r5", "r6"}
	none := rec(hostAddr, webAddr, webAddr, 81, flowagg.TierSensor, 1, 2)
	none.Reporters = nil
	// The source cut the list to 16 of 30 reporters; the count still
	// covers all 30.
	cut := rec(hostAddr, webAddr, webAddr, 82, flowagg.TierSensor, 1, 2)
	for i := range maxRecordReporters {
		cut.Reporters = append(cut.Reporters, fmt.Sprintf("c%02d", i))
	}
	cut.ReporterCount = 30
	v := buildView(viewInput{subject: Subject{Addrs: []netip.Addr{hostAddr}}, kind: kindHost, id: "web1",
		recs: []Record{self, peerOnly, both, many, none, cut}, window: windows[1], sort: sortService, desc: false})
	byService := map[string]rowView{}
	for _, r := range v.Rows {
		byService[r.Service] = r
	}
	if r := byService["tcp/53"]; len(r.Reporters) != 1 || r.Reporters[0].Label != "this host" || r.Reporters[0].Href != "" || r.Evidence != "client end only" {
		t.Errorf("self row %+v", r)
	}
	if r := byService["tcp/8443"]; len(r.Reporters) != 2 || r.Reporters[1].Label != "gw" || r.Reporters[1].Href != "/hosts/gw" || r.Evidence != "both ends" {
		t.Errorf("both row %+v", r)
	}
	if r := byService["tcp/80"]; len(r.Reporters) != MaxReportersShown || r.MoreReporters != 6-MaxReportersShown {
		t.Errorf("many row %+v", r)
	}
	if r := byService["tcp/81"]; len(r.Reporters) != 1 || r.Reporters[0].Label != "unknown" {
		t.Errorf("none row %+v", r)
	}
	if r := byService["tcp/82"]; len(r.Reporters) != MaxReportersShown || r.MoreReporters != 30-MaxReportersShown {
		t.Errorf("cut row: shown %d, more %d", len(r.Reporters), r.MoreReporters)
	}
	// An asset page never labels a reporter "this host".
	v = buildView(viewInput{subject: Subject{Addrs: []netip.Addr{hostAddr}}, kind: kindAsset, id: "web1",
		recs: []Record{self}, window: windows[1], sort: sortBytes, desc: true})
	if v.Rows[0].Reporters[0].Label != "web1" {
		t.Errorf("asset reporter %+v", v.Rows[0].Reporters)
	}
}

func TestPeerOnlyReportIsLabeled(t *testing.T) {
	r := rec(nasAddr, hostAddr, hostAddr, 443, flowagg.TierSocket, 1, 2)
	r.Reporters = []string{"nas"}
	r.ServerReported = false
	v := buildView(viewInput{subject: Subject{Addrs: []netip.Addr{hostAddr}}, kind: kindHost, id: "web1",
		recs: []Record{r}, window: windows[1], sort: sortBytes, desc: true})
	if v.Rows[0].Evidence != "client end only" || v.Rows[0].Reporters[0].Href != "/hosts/nas" {
		t.Fatalf("row %+v", v.Rows[0])
	}
}

func TestHostileTextIsSanitizedAndEscaped(t *testing.T) {
	r := rec(hostAddr, dnsAddr, dnsAddr, 53, flowagg.TierSocket, 1, 2)
	r.Process = "<script>alert(1)</script>\x1b[31m" + strings.Repeat("p", 200)
	r.Reporters = []string{"<img src=x>", "bad\xff", "ok\nline"}
	f := &fakeFlows{recs: []Record{r}}
	rr := get(t, newTestHandler(t, f), "/hosts/web1/connections")
	body := rr.Body.String()
	if strings.Contains(body, "<script>alert") || strings.Contains(body, "<img src=x>") || strings.Contains(body, "\x1b") {
		t.Fatalf("hostile text rendered raw")
	}
	if got := cleanText(r.Process, maxTextLen); len([]rune(got)) > maxTextLen || strings.ContainsRune(got, 0x1b) {
		t.Errorf("cleanText = %q", got)
	}
	if got := cleanText("bad\xff", maxTextLen); got != "bad�" {
		t.Errorf("cleanText invalid UTF-8 = %q", got)
	}
	if got := cleanText("ok\nline", maxTextLen); got != "ok line" {
		t.Errorf("cleanText newline = %q", got)
	}
}

func TestTruncationNotice(t *testing.T) {
	recs := make([]Record, MaxRows+1)
	for i := range recs {
		recs[i] = rec(hostAddr, webAddr, webAddr, uint16(i+1), flowagg.TierSensor, uint64(i), 0)
	}
	f := &fakeFlows{recs: recs}
	rr := get(t, newTestHandler(t, f), "/hosts/web1/connections")
	body := rr.Body.String()
	if !strings.Contains(body, "largest") {
		t.Errorf("no truncation notice")
	}
	if n := len(regexp.MustCompile(`<tr>`).FindAllString(body, -1)); n != MaxRows+1 { // +1 header row
		t.Errorf("rendered %d rows, want %d", n-1, MaxRows)
	}
}

func TestAssetPageRendersWithLinks(t *testing.T) {
	f := &fakeFlows{recs: []Record{rec(assetAddr, nasAddr, nasAddr, 9100, flowagg.TierConntrack, 1, 2)}}
	rr := get(t, newTestHandler(t, f), "/network/a/a1/connections?window=21d")
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{"printer", `href="/network/a/a1"`, `href="/hosts/nas"`, "outbound", "tcp/9100", "snapshot (conntrack)"} {
		if !strings.Contains(body, want) {
			t.Errorf("asset page lacks %q", want)
		}
	}
	if len(f.nodes) != 1 || f.nodes[0] != assetAddr {
		t.Errorf("nodes %v", f.nodes)
	}
	if rr.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control %q", rr.Header().Get("Cache-Control"))
	}
}

func TestHostPageRendersTableHeaders(t *testing.T) {
	f := &fakeFlows{recs: []Record{rec(hostAddr, dnsAddr, dnsAddr, 53, flowagg.TierSensor, 1, 2)}}
	rr := get(t, newTestHandler(t, f), "/hosts/web1/connections")
	body := rr.Body.String()
	for _, want := range []string{"Peer", "Direction", "Protocol/port", "Process", "Bytes in", "Bytes out", "First seen", "Last seen", "Source tier", "Reported by", "pihole", "web1.lab", `href="/hosts/web1"`, "not known"} {
		if !strings.Contains(body, want) {
			t.Errorf("host page lacks %q", want)
		}
	}
}

func TestOtherMethodsRejected(t *testing.T) {
	h := newTestHandler(t, &fakeFlows{})
	rr := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/hosts/web1/connections", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status %d", rr.Code)
	}
}

// TestHostAndAssetPagesLinkTheTab checks that the host and asset page
// templates link the routes this package registers.
func TestHostAndAssetPagesLinkTheTab(t *testing.T) {
	for file, want := range map[string]string{
		"host.html":  `href="/hosts/{{$hid}}/connections"`,
		"asset.html": `href="/network/a/{{.ID}}/connections"`,
	} {
		b, err := fs.ReadFile(templates.FS, file)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), want) {
			t.Errorf("%s lacks %s", file, want)
		}
	}
}

func TestFormatBytes(t *testing.T) {
	cases := map[uint64]string{0: "0 B", 1023: "1023 B", 1024: "1.0 KiB", 1536: "1.5 KiB", 5 << 20: "5.0 MiB", 3 << 30: "3.0 GiB", 2 << 40: "2.0 TiB", 1 << 62: "4194304.0 TiB"}
	for in, want := range cases {
		if got := formatBytes(in); got != want {
			t.Errorf("formatBytes(%d) = %q, want %q", in, got, want)
		}
	}
}
