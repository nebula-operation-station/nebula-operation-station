// SPDX-License-Identifier: AGPL-3.0-or-later

// Package connections serves the connections tab of the host and asset
// pages (ADR 0009 D3, ticket TM20):
//
//   - GET /hosts/{id}/connections: every flow of a managed host;
//   - GET /network/a/{id}/connections: every flow of an IPAM asset.
//
// Each row is one aggregated flow from the subject's point of view:
// peer (linked when it is a managed host or an IPAM asset by the
// server's own records), direction, protocol and server port, process
// when known, bytes in and out, first and last seen, the source tier
// and who reported it. Snapshot volumes are lower bounds and are marked
// so (D3). The window is 1 h, 24 h, 7 d or 21 d (?window=); the table
// sorts by any column (?sort=, ?order=) on the server.
//
// Flow data comes from managed hosts and is untrusted (spec 09): a host
// can lie about its connections, so every row names its reporters and
// tier, and every text from a report is bounded, made valid UTF-8 and
// printable, and rendered by html/template as text. Pages carry no
// inline script or style (strict CSP).
package connections

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/flowagg"
	"github.com/nebula-operation-station/nebula-operation-station/web/templates"
	conntpl "github.com/nebula-operation-station/nebula-operation-station/web/templates/connections"
)

// Limits, next to the code that enforces them.
const (
	// MaxRows bounds the flows shown on one page. The source returns the
	// largest flows first; the page reads MaxRows+1 to detect a cut-off.
	MaxRows = 1000
	// MaxSubjectAddrs bounds the addresses of a host or asset queried.
	MaxSubjectAddrs = 64
	// MaxReportersShown bounds the reporters named in one row.
	MaxReportersShown = 4
	// maxIDLen bounds a host or asset ID in the path.
	maxIDLen = 128
	// maxTextLen bounds process names, reporter IDs and peer names, in
	// runes.
	maxTextLen = 64
	// callTimeout bounds the directory and flow calls of one request.
	callTimeout = 10 * time.Second
)

// ErrNotFound is returned by a Directory for an unknown host or asset.
var ErrNotFound = errors.New("connections: not found")

// Record is one aggregated flow as a FlowSource returns it.
type Record struct {
	flowagg.FlowTotal
	// Reporters are the hosts whose reports were stored for this flow in
	// the window, sorted. They are server-assigned host IDs but rendered
	// as untrusted text.
	Reporters []string
	// Process is the local process name, "" when not collected. It comes
	// from a host and is untrusted.
	Process string
}

// FlowSource returns the flows that have one end in nodes and overlap
// w, at most limit of them, largest (bytes in both directions) first.
type FlowSource interface {
	Flows(ctx context.Context, nodes []netip.Addr, w flowagg.Window, limit int) ([]Record, error)
}

// Subject is a host or asset as the server records it.
type Subject struct {
	// Name is the display name.
	Name string
	// Addrs are the addresses the server attributes to the subject (its
	// own records, never a report).
	Addrs []netip.Addr
}

// PeerKind says what a peer address resolves to.
type PeerKind int

// Peer kinds.
const (
	// PeerUnknown is an address that matches no host or asset.
	PeerUnknown PeerKind = iota
	// PeerHost is a managed host; Peer.ID is the host ID.
	PeerHost
	// PeerAsset is an IPAM asset; Peer.ID is the asset ID.
	PeerAsset
)

// Peer is what the server's own records say about a peer address.
type Peer struct {
	Kind PeerKind
	ID   string
	Name string
}

// Directory resolves hosts, assets and peer addresses from the server's
// records (inventory and IPAM), never from flow reports.
type Directory interface {
	// Host returns a managed host, or ErrNotFound.
	Host(ctx context.Context, id string) (Subject, error)
	// Asset returns an IPAM asset, or ErrNotFound.
	Asset(ctx context.Context, id string) (Subject, error)
	// Peers resolves addresses; unknown addresses are left out.
	Peers(ctx context.Context, addrs []netip.Addr) (map[netip.Addr]Peer, error)
}

// Chrome is the per-request data of the shared page layout.
type Chrome struct {
	// Theme is "system", "light" or "dark".
	Theme string
	// NavCollapsed, PVENav and DeployEnabled drive the navigation.
	NavCollapsed  bool
	PVENav        bool
	DeployEnabled bool
}

// Options configure a Handler.
type Options struct {
	// Flows returns the flows. Required; SQLFlows(db) reads the server
	// database.
	Flows FlowSource
	// Directory resolves hosts, assets and peers. Required.
	Directory Directory
	// Now returns the current time; nil uses time.Now.
	Now func() time.Time
	// Chrome returns the layout data; nil uses the defaults.
	Chrome func(r *http.Request) Chrome
	// Log receives errors; nil discards them.
	Log *slog.Logger
}

// Handler serves the connections pages.
type Handler struct {
	flows  FlowSource
	dir    Directory
	now    func() time.Time
	chrome func(r *http.Request) Chrome
	log    *slog.Logger
	page   *template.Template
}

// New parses the template and returns a Handler.
func New(o Options) (*Handler, error) {
	if o.Flows == nil || o.Directory == nil {
		return nil, errors.New("connections: flows and directory are required")
	}
	h := &Handler{flows: o.Flows, dir: o.Directory, now: o.Now, chrome: o.Chrome, log: o.Log}
	if h.now == nil {
		h.now = time.Now
	}
	if h.chrome == nil {
		h.chrome = func(*http.Request) Chrome { return Chrome{Theme: "system"} }
	}
	if h.log == nil {
		h.log = slog.New(slog.DiscardHandler)
	}
	t, err := template.New("").ParseFS(templates.FS, "layout.html")
	if err != nil {
		return nil, fmt.Errorf("connections: parse layout: %w", err)
	}
	if t, err = t.ParseFS(conntpl.FS, "connections.html"); err != nil {
		return nil, fmt.Errorf("connections: parse template: %w", err)
	}
	h.page = t
	return h, nil
}

// Handler returns the routes. Authentication and the Origin check are
// the job of the surrounding chain (internal/web/auth, middleware).
func (h *Handler) Handler() http.Handler {
	mux := http.NewServeMux()
	h.Register(mux)
	return mux
}

// Register adds the routes to mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /hosts/{id}/connections", func(w http.ResponseWriter, r *http.Request) {
		h.serve(w, r, kindHost)
	})
	mux.HandleFunc("GET /network/a/{id}/connections", func(w http.ResponseWriter, r *http.Request) {
		h.serve(w, r, kindAsset)
	})
}

// --- request -------------------------------------------------------------

type subjectKind int

const (
	kindHost subjectKind = iota
	kindAsset
)

// window is one selectable query window (D3).
type window struct {
	ID, Label string
	Dur       time.Duration
}

var windows = []window{
	{"1h", "1 h", time.Hour},
	{"24h", "24 h", 24 * time.Hour},
	{"7d", "7 d", 7 * 24 * time.Hour},
	{"21d", "21 d", 21 * 24 * time.Hour},
}

const defaultWindow = 1 // 24 h

// sortKey names a sortable column.
type sortKey string

// Sortable columns.
const (
	sortPeer      sortKey = "peer"
	sortDirection sortKey = "direction"
	sortService   sortKey = "service"
	sortProcess   sortKey = "process"
	sortIn        sortKey = "in"
	sortOut       sortKey = "out"
	sortBytes     sortKey = "bytes"
	sortFirst     sortKey = "first"
	sortLast      sortKey = "last"
	sortTier      sortKey = "tier"
)

// defaultDesc says whether a column sorts descending when first
// clicked: volumes and times largest/latest first, text A to Z.
var defaultDesc = map[sortKey]bool{
	sortPeer: false, sortDirection: false, sortService: false, sortProcess: false,
	sortIn: true, sortOut: true, sortBytes: true, sortFirst: true, sortLast: true, sortTier: false,
}

// query is a validated request query.
type query struct {
	window window
	sort   sortKey
	desc   bool
}

// errBadQuery marks an invalid query parameter.
var errBadQuery = errors.New("invalid query")

// one returns the single value of key, "" when absent; a repeated or
// empty parameter is invalid.
func one(v url.Values, key string) (string, error) {
	vals, ok := v[key]
	if !ok {
		return "", nil
	}
	if len(vals) != 1 || vals[0] == "" {
		return "", fmt.Errorf("%w: %s", errBadQuery, key)
	}
	return vals[0], nil
}

func parseQuery(v url.Values) (query, error) {
	q := query{window: windows[defaultWindow], sort: sortBytes, desc: true}
	ws, err := one(v, "window")
	if err != nil {
		return q, err
	}
	if ws != "" {
		i := slices.IndexFunc(windows, func(w window) bool { return w.ID == ws })
		if i < 0 {
			return q, fmt.Errorf("%w: window", errBadQuery)
		}
		q.window = windows[i]
	}
	ss, err := one(v, "sort")
	if err != nil {
		return q, err
	}
	if ss != "" {
		d, ok := defaultDesc[sortKey(ss)]
		if !ok {
			return q, fmt.Errorf("%w: sort", errBadQuery)
		}
		q.sort, q.desc = sortKey(ss), d
	}
	ord, err := one(v, "order")
	if err != nil {
		return q, err
	}
	switch ord {
	case "":
	case "asc":
		q.desc = false
	case "desc":
		q.desc = true
	default:
		return q, fmt.Errorf("%w: order", errBadQuery)
	}
	return q, nil
}

// validID accepts a bounded, printable path ID without '/'.
func validID(id string) bool {
	if id == "" || len(id) > maxIDLen || !utf8.ValidString(id) {
		return false
	}
	for _, r := range id {
		if !unicode.IsPrint(r) || r == '/' {
			return false
		}
	}
	return true
}

func (h *Handler) serve(w http.ResponseWriter, r *http.Request, kind subjectKind) {
	id := r.PathValue("id")
	if !validID(id) {
		http.NotFound(w, r)
		return
	}
	q, err := parseQuery(r.URL.Query())
	if err != nil {
		http.Error(w, "Invalid query.", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), callTimeout)
	defer cancel()
	var subj Subject
	if kind == kindHost {
		subj, err = h.dir.Host(ctx, id)
	} else {
		subj, err = h.dir.Asset(ctx, id)
	}
	if errors.Is(err, ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		h.fail(w, r, "load subject", err)
		return
	}
	in := viewInput{subject: subj, kind: kind, id: id, window: q.window, sort: q.sort, desc: q.desc}
	nodes := subjectAddrs(subj.Addrs)
	if len(nodes) > MaxSubjectAddrs {
		nodes, in.addrsCut = nodes[:MaxSubjectAddrs], true
	}
	if len(nodes) > 0 {
		now := h.now().UTC()
		recs, err := h.flows.Flows(ctx, nodes, flowagg.Window{From: now.Add(-q.window.Dur), To: now}, MaxRows+1)
		if err != nil {
			h.fail(w, r, "load flows", err)
			return
		}
		if len(recs) > MaxRows {
			recs, in.truncated = recs[:MaxRows], true
		}
		in.recs = recs
		in.peers, err = h.dir.Peers(ctx, peerAddrs(recs, nodes))
		if err != nil {
			h.fail(w, r, "resolve peers", err)
			return
		}
	}
	// The subject's addresses as queried (normalized, capped).
	in.subject.Addrs = nodes
	h.render(w, r, buildView(in), kind)
}

func (h *Handler) fail(w http.ResponseWriter, r *http.Request, what string, err error) {
	h.log.ErrorContext(r.Context(), "connections page", "step", what, "error", err.Error())
	http.Error(w, "Internal error.", http.StatusInternalServerError)
}

// subjectAddrs normalizes addresses as the flow store keeps them
// (unmapped, no zone), drops invalid, unspecified and loopback ones
// (never part of a flow) and sorts and deduplicates the rest.
func subjectAddrs(in []netip.Addr) []netip.Addr {
	out := make([]netip.Addr, 0, len(in))
	for _, a := range in {
		a = a.Unmap().WithZone("")
		if !a.IsValid() || a.IsUnspecified() || a.IsLoopback() {
			continue
		}
		out = append(out, a)
	}
	slices.SortFunc(out, netip.Addr.Compare)
	return slices.Compact(out)
}

// peerAddrs returns the distinct non-local ends of recs.
func peerAddrs(recs []Record, nodes []netip.Addr) []netip.Addr {
	var out []netip.Addr
	for _, r := range recs {
		for _, a := range []netip.Addr{r.Key.A, r.Key.B} {
			if _, local := slices.BinarySearchFunc(nodes, a, netip.Addr.Compare); !local {
				out = append(out, a)
			}
		}
	}
	slices.SortFunc(out, netip.Addr.Compare)
	return slices.Compact(out)
}

// --- view ----------------------------------------------------------------

// page is the data of the layout template (web/templates/layout.html)
// plus the data of this package's page.
type page struct {
	Title         string
	Active        string
	Theme         string
	NavCollapsed  bool
	Bare          bool
	PVENav        bool
	DeployEnabled bool
	Search        any // the layout's search box state; none here
	BuiltinTrust  any // the layout's trust banner; none here
	Scripts       []string

	Conn *view
}

type view struct {
	SubjectName string
	KindLabel   string
	BackHref    string
	BackLabel   string
	SelfHref    string
	WindowLabel string
	Windows     []windowLink
	Columns     []column
	Notices     []string
	Rows        []rowView
}

type windowLink struct {
	Label, Href string
	Active      bool
}

type column struct {
	Label string
	Href  string // "" when the column does not sort
	Sort  string // aria-sort value of the active column
}

type reporterView struct {
	Label string
	Href  string
}

type rowView struct {
	PeerAddr      string
	PeerName      string
	PeerKind      string
	PeerHref      string
	Direction     string
	Service       string
	Process       string
	BytesIn       string
	BytesOut      string
	BytesInExact  uint64
	BytesOutExact uint64
	Total         string
	TotalExact    uint64
	FirstSeen     string
	LastSeen      string
	Tier          string
	LowerBound    bool
	Reporters     []reporterView
	MoreReporters int
	Evidence      string

	// sort keys
	peer    netip.Addr
	proto   flowagg.Proto
	port    uint16
	first   time.Time
	last    time.Time
	tierRaw string
}

type viewInput struct {
	subject   Subject // Addrs normalized and sorted (subjectAddrs)
	kind      subjectKind
	id        string
	recs      []Record
	peers     map[netip.Addr]Peer
	window    window
	sort      sortKey
	desc      bool
	truncated bool
	addrsCut  bool
}

// columns lists the table columns in order with their sort keys.
var columns = []struct {
	label string
	key   sortKey
}{
	{"Peer", sortPeer},
	{"Direction", sortDirection},
	{"Protocol/port", sortService},
	{"Process", sortProcess},
	{"Bytes in", sortIn},
	{"Bytes out", sortOut},
	{"Total", sortBytes},
	{"First seen", sortFirst},
	{"Last seen", sortLast},
	{"Source tier", sortTier},
	{"Reported by", ""},
}

func buildView(in viewInput) *view {
	v := &view{SubjectName: cleanText(in.subject.Name, maxTextLen), WindowLabel: in.window.Label}
	esc := url.PathEscape(in.id)
	if in.kind == kindHost {
		v.KindLabel, v.BackLabel, v.BackHref = "Host", "Host", "/hosts/"+esc
	} else {
		v.KindLabel, v.BackLabel, v.BackHref = "Asset", "Asset", "/network/a/"+esc
	}
	v.SelfHref = v.BackHref + "/connections"
	if v.SubjectName == "" {
		v.SubjectName = cleanText(in.id, maxTextLen)
	}
	href := func(w window, s sortKey, desc bool) string {
		order := "asc"
		if desc {
			order = "desc"
		}
		return v.SelfHref + "?window=" + w.ID + "&sort=" + string(s) + "&order=" + order
	}
	for _, w := range windows {
		v.Windows = append(v.Windows, windowLink{Label: w.Label, Href: href(w, in.sort, in.desc), Active: w.ID == in.window.ID})
	}
	for _, c := range columns {
		col := column{Label: c.label}
		if c.key != "" {
			desc := defaultDesc[c.key]
			if c.key == in.sort {
				desc = !in.desc
				col.Sort = "ascending"
				if in.desc {
					col.Sort = "descending"
				}
			}
			col.Href = href(in.window, c.key, desc)
		}
		v.Columns = append(v.Columns, col)
	}
	if len(in.subject.Addrs) == 0 {
		v.Notices = append(v.Notices, "No addresses are recorded for this "+strings.ToLower(v.KindLabel)+", so no connections can be matched.")
	}
	if in.addrsCut {
		v.Notices = append(v.Notices, fmt.Sprintf("Only the first %d addresses are queried.", MaxSubjectAddrs))
	}
	if in.truncated {
		v.Notices = append(v.Notices, fmt.Sprintf("Only the %d largest flows are shown; sorting applies to these.", MaxRows))
	}
	for _, r := range in.recs {
		if row, ok := buildRow(in, r); ok {
			v.Rows = append(v.Rows, row)
		}
	}
	sortRows(v.Rows, in.sort, in.desc)
	return v
}

// buildRow turns a record into a row from the subject's point of view.
// A record with no end in the subject's addresses is dropped.
func buildRow(in viewInput, r Record) (rowView, bool) {
	local := func(a netip.Addr) bool {
		_, ok := slices.BinarySearchFunc(in.subject.Addrs, a, netip.Addr.Compare)
		return ok
	}
	k := r.Key
	aLocal, bLocal := local(k.A), local(k.B)
	if !aLocal && !bLocal {
		return rowView{}, false
	}
	// From the local end: out is local→peer, in is peer→local.
	localAddr, peer := k.A, k.B
	out, inb := r.BytesAB, r.BytesBA
	if !aLocal {
		localAddr, peer = k.B, k.A
		out, inb = r.BytesBA, r.BytesAB
	}
	row := rowView{
		PeerAddr:      peer.String(),
		Service:       k.Proto.String() + "/" + strconv.Itoa(int(k.ServerPort)),
		Process:       cleanText(r.Process, maxTextLen),
		BytesIn:       formatBytes(inb),
		BytesOut:      formatBytes(out),
		BytesInExact:  inb,
		BytesOutExact: out,
		Total:         formatBytes(r.Total()),
		TotalExact:    r.Total(),
		FirstSeen:     formatTime(r.FirstSeen),
		LastSeen:      formatTime(r.LastSeen),
		peer:          peer,
		proto:         k.Proto,
		port:          k.ServerPort,
		first:         r.FirstSeen,
		last:          r.LastSeen,
		tierRaw:       k.Tier,
	}
	switch {
	case aLocal && bLocal:
		row.Direction = "internal"
	case k.ServerAddr() == localAddr:
		row.Direction = "inbound"
	default:
		row.Direction = "outbound"
	}
	row.PeerKind = "unknown"
	if p, ok := in.peers[peer]; ok && validID(p.ID) {
		switch p.Kind {
		case PeerHost:
			row.PeerKind, row.PeerHref = "host", "/hosts/"+url.PathEscape(p.ID)
		case PeerAsset:
			row.PeerKind, row.PeerHref = "asset", "/network/a/"+url.PathEscape(p.ID)
		}
		if row.PeerHref != "" {
			row.PeerName = cleanText(p.Name, maxTextLen)
			if row.PeerName == "" {
				row.PeerName = cleanText(p.ID, maxTextLen)
			}
		}
	}
	if aLocal && bLocal {
		row.PeerKind = "this " + strings.ToLower(kindLabel(in.kind))
	}
	row.Tier, row.LowerBound = tierLabel(k.Tier, r.LowerBound)
	row.Reporters, row.MoreReporters = reporterViews(in, r.Reporters)
	switch {
	case r.Confirmed:
		row.Evidence = "both ends"
	case r.ServerReported:
		row.Evidence = "server end only"
	default:
		row.Evidence = "client end only"
	}
	return row, true
}

func kindLabel(k subjectKind) string {
	if k == kindHost {
		return "Host"
	}
	return "Asset"
}

// tierLabel names a source tier and says whether its volumes are a lower
// bound: snapshot tiers always are (D3), the sensor tier when the flow
// says so, an unknown tier always.
func tierLabel(tier string, lowerBound bool) (string, bool) {
	switch tier {
	case flowagg.TierSocket:
		return "snapshot (socket table)", true
	case flowagg.TierConntrack:
		return "snapshot (conntrack)", true
	case flowagg.TierSensor:
		return "sensor", lowerBound
	}
	return "unknown tier", true
}

// reporterViews labels the reporters of a row: the subject host itself
// as "this host", other hosts linked to their page, at most
// MaxReportersShown, the rest counted.
func reporterViews(in viewInput, reps []string) ([]reporterView, int) {
	if len(reps) == 0 {
		return []reporterView{{Label: "unknown"}}, 0
	}
	more := 0
	if len(reps) > MaxReportersShown {
		reps, more = reps[:MaxReportersShown], len(reps)-MaxReportersShown
	}
	out := make([]reporterView, 0, len(reps))
	for _, rep := range reps {
		if in.kind == kindHost && rep == in.id {
			out = append(out, reporterView{Label: "this host"})
			continue
		}
		rv := reporterView{Label: cleanText(rep, maxTextLen)}
		if validID(rep) {
			rv.Href = "/hosts/" + url.PathEscape(rep)
		}
		if rv.Label == "" {
			rv.Label = "unknown"
		}
		out = append(out, rv)
	}
	return out, more
}

// sortRows orders rows by key; ties fall back to total bytes (largest
// first), then peer, service, tier and direction, so the order is
// deterministic.
func sortRows(rows []rowView, key sortKey, desc bool) {
	slices.SortStableFunc(rows, func(a, b rowView) int {
		c := 0
		switch key {
		case sortPeer:
			c = a.peer.Compare(b.peer)
		case sortDirection:
			c = strings.Compare(a.Direction, b.Direction)
		case sortService:
			c = cmp.Or(cmp.Compare(a.proto, b.proto), cmp.Compare(a.port, b.port))
		case sortProcess:
			c = strings.Compare(a.Process, b.Process)
		case sortIn:
			c = cmp.Compare(a.BytesInExact, b.BytesInExact)
		case sortOut:
			c = cmp.Compare(a.BytesOutExact, b.BytesOutExact)
		case sortBytes:
			c = cmp.Compare(a.TotalExact, b.TotalExact)
		case sortFirst:
			c = a.first.Compare(b.first)
		case sortLast:
			c = a.last.Compare(b.last)
		case sortTier:
			c = strings.Compare(a.Tier, b.Tier)
		}
		if desc {
			c = -c
		}
		return cmp.Or(c,
			cmp.Compare(b.TotalExact, a.TotalExact),
			a.peer.Compare(b.peer),
			cmp.Compare(a.proto, b.proto),
			cmp.Compare(a.port, b.port),
			strings.Compare(a.tierRaw, b.tierRaw),
			strings.Compare(a.Direction, b.Direction))
	})
}

// cleanText makes untrusted text displayable: valid UTF-8 (invalid
// bytes become U+FFFD), control and other non-printable characters
// replaced by a space, trimmed and cut to limit runes.
func cleanText(s string, limit int) string {
	s = strings.ToValidUTF8(s, "�")
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n == limit {
			break
		}
		if !unicode.IsPrint(r) {
			r = ' '
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}

// formatBytes renders a byte count in binary units.
func formatBytes(n uint64) string {
	if n < 1024 {
		return strconv.FormatUint(n, 10) + " B"
	}
	units := []string{"KiB", "MiB", "GiB", "TiB"}
	f := float64(n) / 1024
	i := 0
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	return strconv.FormatFloat(f, 'f', 1, 64) + " " + units[i]
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.UTC().Format("2006-01-02 15:04 UTC")
}

func (h *Handler) render(w http.ResponseWriter, r *http.Request, v *view, kind subjectKind) {
	c := h.chrome(r)
	active := "inventory"
	if kind == kindAsset {
		active = "network"
	}
	p := &page{
		Title:         "Connections · " + v.SubjectName,
		Active:        active,
		Theme:         c.Theme,
		NavCollapsed:  c.NavCollapsed,
		PVENav:        c.PVENav,
		DeployEnabled: c.DeployEnabled,
		Conn:          v,
	}
	var b strings.Builder
	if err := h.page.ExecuteTemplate(&b, "layout", p); err != nil {
		h.fail(w, r, "render", err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, b.String())
}
