// SPDX-License-Identifier: AGPL-3.0-or-later

package paths

import (
	"errors"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/attackpath"
)

// --- shared --------------------------------------------------------------------

// labeler names nodes for the page.
type labeler struct{ labels map[string]string }

func (l labeler) name(id string) string {
	switch id {
	case attackpath.InternetID:
		return "Internet"
	case attackpath.NetBirdID:
		return "NetBird peers"
	}
	if s := clip(l.labels[id]); s != "" {
		return s
	}
	return id
}

// fixView is a fix link as shown, or the reason there is none.
type fixView struct {
	Href, Text, Note, None string
	Verified               bool
}

func fixFor(s Snapshot, node, finding string) fixView {
	info, ok := s.Findings[FindingRef{Node: node, Key: finding}]
	if !ok {
		return fixView{None: "no fix link: finding details unavailable"}
	}
	href := safeFixHref(info.Fix.Href)
	if href == "" {
		none := clip(info.NoFix)
		if none == "" {
			none = "no fix link available"
		}
		return fixView{None: "no fix link: " + none}
	}
	text := clip(info.Fix.Text)
	if text == "" {
		text = "Fix"
	}
	return fixView{Href: href, Text: text, Note: clip(info.Fix.Note), Verified: info.Fix.Verified}
}

func findingName(s Snapshot, node, key string) (vuln, pkg string, stale bool) {
	info, ok := s.Findings[FindingRef{Node: node, Key: key}]
	if !ok || clip(info.VulnID) == "" {
		return "finding " + key, "", false
	}
	return clip(info.VulnID), clip(info.Package), info.Stale
}

func edgeText(e attackpath.Edge) string {
	if e.Kind.Network() {
		return e.Proto.String() + "/" + strconv.Itoa(int(e.Port))
	}
	return ""
}

func basisText(e attackpath.Edge) string {
	switch e.Kind.Basis() {
	case attackpath.BasisPolicy:
		return "allowed by a firewall or NAT rule"
	case attackpath.BasisObserved:
		return "seen in a traffic flow"
	case attackpath.BasisAssumed:
		return "assumed: same VLAN (L2 adjacency), all ports"
	case attackpath.BasisInventory:
		return "proven by NOS inventory data"
	}
	return "no edge (local step)"
}

// coverageView summarises how far "no path" can be trusted.
type coverageView struct {
	Known            bool
	Complete         bool
	Covered, Total   int
	Missing          []string
	Uncertain        int
	GraphTruncated   bool
	UnscoredFindings int
	Unattached       int
	Limits           []string
	Truncated        bool
}

func coverageOf(s Snapshot) coverageView {
	var c coverageView
	if s.Report != nil {
		c.Known = true
		cov := s.Report.Coverage()
		c.Covered, c.Total = cov.Covered, cov.Total
		c.Complete = s.Report.Complete()
		for _, m := range s.Report.Missing {
			c.Missing = append(c.Missing, clip(m))
		}
		c.Uncertain = len(s.Report.Uncertain) + s.Report.Overflow
		c.GraphTruncated = s.Report.GraphTruncated
	}
	if r := s.Result; r != nil {
		c.UnscoredFindings = r.UnscoredFindings
		c.Unattached = r.UnattachedFindings
		c.Truncated = r.Truncated
		if r.Limits.Graph {
			c.Limits = append(c.Limits, "graph node or edge cap ("+grouped(attackpath.MaxNodes)+" nodes, "+
				grouped(attackpath.MaxEdges)+" edges)")
		}
		if r.Limits.Findings {
			c.Limits = append(c.Limits, "findings cap ("+grouped(attackpath.MaxFindings)+" findings)")
		}
		if r.Limits.Targets {
			c.Limits = append(c.Limits, "crown-jewel target cap ("+grouped(attackpath.MaxTargets)+")")
		}
		if r.Limits.ChokePoints {
			c.Limits = append(c.Limits, "choke-point cap ("+grouped(attackpath.MaxChokePoints)+")")
		}
		if r.Limits.Budget {
			c.Limits = append(c.Limits, "time budget")
		}
	}
	return c
}

// grouped formats a non-negative count with thousands separators: 50,000.
func grouped(n int) string {
	s := strconv.Itoa(n)
	for i := len(s) - 3; i > 0 && s[i-1] != '-'; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

// trusted reports whether "no path found" may be stated without "unknown".
func (c coverageView) trusted() bool {
	return c.Known && c.Complete && !c.Truncated && c.UnscoredFindings == 0 && c.Unattached == 0
}

// --- list ----------------------------------------------------------------------

type pathRow struct {
	Rank              int
	Entry, Route      string
	L, R              string
	Possible, Assumed bool
	Href, MapHref     string
	Steps             int
}

type targetView struct {
	Node, Label string
	Impact      int
	Paths       []pathRow
	Incomplete  bool
	NoPath      string
	Unknown     bool
	MapHref     string
}

type chokeView struct {
	Kind              string
	What, Where       string
	Risk              string
	Paths             int
	Fix               fixView
	Rule              bool
	Stale             bool
	VulnID, Package   string
	EdgeFrom, EdgeTo  string
	EdgeProto, EdgeBs string
}

type listView struct {
	Computed       bool
	ComputedAt     string
	Formula        string
	GraphHash      string
	Coverage       coverageView
	Targets        []targetView
	Missing        []string
	Chokes         []chokeView
	ChokesCut      int
	MapHref        string
	MaxDepth       int
	PathsPerTarget int
}

func routeText(lb labeler, p attackpath.Path) string {
	parts := []string{lb.name(p.Entry)}
	for _, st := range p.Steps {
		if st.To != st.From {
			parts = append(parts, lb.name(st.To))
		}
	}
	return strings.Join(parts, " → ")
}

func detailHref(hash string) string { return DetailPrefix + hash }

func mapHref(key, value string) string {
	if key == "" {
		return MapPath
	}
	return MapPath + "?" + url.Values{key: {value}}.Encode()
}

func (h *Handler) serveList(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		http.Error(w, "Invalid query.", http.StatusBadRequest)
		return
	}
	s, err := h.snapshot(r)
	if err != nil {
		h.fail(w, r, "snapshot", err)
		return
	}
	lb := labeler{s.Labels}
	v := &listView{MapHref: MapPath, MaxDepth: attackpath.MaxDepth, PathsPerTarget: attackpath.PathsPerTarget,
		Coverage: coverageOf(s)}
	if s.Result == nil {
		h.render(w, r, h.list, "Attack paths", nil, v)
		return
	}
	res := s.Result
	v.Computed = true
	if !s.ComputedAt.IsZero() {
		v.ComputedAt = s.ComputedAt.UTC().Format("2006-01-02 15:04 UTC")
	}
	v.Formula, v.GraphHash = clip(res.FormulaVersion), clip(res.GraphHash)
	for _, tp := range res.Targets {
		t := targetView{Node: tp.Node, Label: lb.name(tp.Node), Impact: tp.Impact, Incomplete: !tp.Complete,
			MapHref: mapHref("target", tp.Node)}
		for i, p := range tp.Paths {
			t.Paths = append(t.Paths, pathRow{
				Rank: i + 1, Entry: lb.name(p.Entry), Route: routeText(lb, p), L: f3(p.Likelihood), R: f2(p.Risk),
				Possible: p.Possible, Assumed: p.Assumed, Href: detailHref(p.Hash), MapHref: mapHref("path", p.Hash),
				Steps: len(p.Steps),
			})
		}
		if len(tp.Paths) == 0 {
			if v.Coverage.trusted() && tp.Complete {
				t.NoPath = "No path found within the limits (depth " + strconv.Itoa(attackpath.MaxDepth) +
					", complete coverage). This is not a guarantee that none exists."
			} else {
				t.Unknown = true
				t.NoPath = "Unknown: no path found, but the data is incomplete (see coverage), so a path may exist."
			}
		}
		v.Targets = append(v.Targets, t)
	}
	for _, m := range res.MissingTargets {
		v.Missing = append(v.Missing, clip(m))
	}
	for i, c := range res.ChokePoints {
		if i == MaxChokePointsShown {
			v.ChokesCut = len(res.ChokePoints) - i
			break
		}
		cv := chokeView{Kind: c.Kind.String(), Risk: f2(c.Risk), Paths: c.Paths}
		switch c.Kind {
		case attackpath.FixFinding:
			cv.VulnID, cv.Package, cv.Stale = findingName(s, c.Node, c.Finding)
			cv.Where = lb.name(c.Node)
			cv.Fix = fixFor(s, c.Node, c.Finding)
		case attackpath.FixEdge:
			cv.Rule = true
			cv.EdgeFrom, cv.EdgeTo = lb.name(c.Edge.From), lb.name(c.Edge.To)
			cv.EdgeProto, cv.EdgeBs = edgeText(c.Edge), basisText(c.Edge)
		}
		v.Chokes = append(v.Chokes, cv)
	}
	h.render(w, r, h.list, "Attack paths", nil, v)
}

// --- detail --------------------------------------------------------------------

type stepView struct {
	N           int
	Kind        string
	What        string
	From, To    string
	Edge, Basis string
	VulnID, Pkg string
	Stale       bool
	Vector      string
	Terms       []string
	Formula     string
	Assumed     string
	E           string
	Possible    bool
	Grants      string
	NoFinding   bool
	Fix         fixView
	Mismatch    bool
}

type detailView struct {
	Target, TargetNode string
	Impact             int
	Rank               int
	Hash               string
	Entry              string
	Formula            string
	Known              bool
	Steps              []stepView
	LFormula, RFormula string
	Possible, Assumed  bool
	Incomplete         bool
	ListHref, MapHref  string
	Coverage           coverageView
}

// findPath returns the path with hash and its target.
func findPath(res *attackpath.Result, hash string) (attackpath.TargetPaths, int, bool) {
	for _, tp := range res.Targets {
		for i, p := range tp.Paths {
			if p.Hash == hash {
				return tp, i, true
			}
		}
	}
	return attackpath.TargetPaths{}, 0, false
}

func (h *Handler) serveDetail(w http.ResponseWriter, r *http.Request) {
	hash := r.PathValue("hash")
	if !validHash(hash) || r.URL.RawQuery != "" {
		http.Error(w, "Invalid path.", http.StatusBadRequest)
		return
	}
	s, err := h.snapshot(r)
	if err != nil {
		h.fail(w, r, "snapshot", err)
		return
	}
	if s.Result == nil {
		http.Error(w, "No attack-path computation yet.", http.StatusNotFound)
		return
	}
	tp, idx, ok := findPath(s.Result, hash)
	if !ok {
		http.Error(w, "Path not found; it may have changed since the last computation.", http.StatusNotFound)
		return
	}
	p := tp.Paths[idx]
	lb := labeler{s.Labels}
	known := s.Result.FormulaVersion == attackpath.FormulaVersion
	v := &detailView{
		Target: lb.name(tp.Node), TargetNode: tp.Node, Impact: tp.Impact, Rank: idx + 1, Hash: hash,
		Entry: lb.name(p.Entry), Formula: clip(s.Result.FormulaVersion), Known: known,
		Possible: p.Possible, Assumed: p.Assumed, Incomplete: !tp.Complete,
		ListHref: ListPath, MapHref: mapHref("path", hash), Coverage: coverageOf(s),
	}
	es := make([]string, 0, len(p.Steps))
	for i, st := range p.Steps {
		v.Steps = append(v.Steps, explainStep(s, lb, i+1, st, known))
		es = append(es, fe(st.Terms.E))
	}
	v.LFormula = "L = " + strings.Join(es, " × ") + " = " + f3(p.Likelihood)
	v.RFormula = "R = L × impact = " + f3(p.Likelihood) + " × " + strconv.Itoa(tp.Impact) + " = " + f2(p.Risk)
	h.render(w, r, h.detail, "Attack path", nil, v)
}

func explainStep(s Snapshot, lb labeler, n int, st attackpath.Step, known bool) stepView {
	sv := stepView{N: n, Kind: st.Kind.String(), From: lb.name(st.From), To: lb.name(st.To),
		E: fe(st.Terms.E), Possible: st.Possible}
	if st.Kind != attackpath.StepLocal {
		sv.Edge, sv.Basis = edgeText(st.Edge), basisText(st.Edge)
	}
	switch st.Kind {
	case attackpath.StepNetwork:
		sv.What = "Exploit over the network on " + sv.To
	case attackpath.StepLocal:
		sv.What = "Local privilege escalation on " + sv.To
	case attackpath.StepControl:
		sv.What = "Control: owning " + sv.From + " owns " + sv.To + " (PVE node → guest or Docker host → container)"
	case attackpath.StepCredential:
		sv.What = "Credential: " + sv.From + " holds the executor's SSH credentials for " + sv.To
	case attackpath.StepEscape:
		sv.What = "Container escape from " + sv.From + " to " + sv.To + " (" + escapeText(st.Edge.Escape) + ")"
	default:
		sv.What = "Unknown step kind"
	}
	if st.Owns {
		sv.Grants = "grants code execution: the attacker owns " + sv.To
	} else {
		sv.Grants = "only reaches " + sv.To + " (the finding grants no code execution)"
	}
	if st.Finding == "" {
		sv.NoFinding = true
		sv.Fix = fixView{None: "no vulnerability needed; this step is cut only by removing the relationship itself"}
		// The stored e is what L uses; show it, and flag it when it is not
		// the 1 a step without a finding has.
		if st.Terms.E == 1 {
			sv.Formula = "e = 1: no vulnerability needed for a " + sv.Kind + " step"
		} else {
			sv.Formula = "stored e = " + fe(st.Terms.E) + "; a " + sv.Kind + " step without a finding has e = 1"
			sv.Mismatch = known
		}
		return sv
	}
	sv.VulnID, sv.Pkg, sv.Stale = findingName(s, st.To, st.Finding)
	sv.Fix = fixFor(s, st.To, st.Finding)
	t := st.Terms
	if v := t.Vector.String(); v != "" {
		sv.Vector = "AV:" + v
	}
	if !known {
		sv.Formula = "e = " + fe(t.E) + " (inputs shown, but the formula " + clip(s.Result.FormulaVersion) +
			" is not known to this page)"
		return sv
	}
	kev := 0.0
	if t.KEV {
		kev = kevTerm
		sv.Terms = append(sv.Terms, "KEV listed: "+f3(kevTerm))
	} else {
		sv.Terms = append(sv.Terms, "KEV not listed: 0")
	}
	args := []string{fe0(kev)}
	if t.EPSSKnown {
		sv.Terms = append(sv.Terms, "EPSS "+f3(t.EPSS))
		args = append(args, f3(t.EPSS))
	} else {
		sv.Terms = append(sv.Terms, "EPSS unknown (not used; unknown is not zero risk, the CVSS term stands in)")
	}
	cv := cvssWeight * t.Exploitability / exploitMax
	sv.Terms = append(sv.Terms, "CVSS v3 exploitability: 0.3 × "+f3(t.Exploitability)+" / 3.9 = "+f3(cv))
	args = append(args, f3(cv))
	base := math.Max(cv, kev)
	if t.EPSSKnown {
		base = math.Max(base, t.EPSS)
	}
	sv.Formula = "e = max(" + strings.Join(args, ", ") + ") = " + f3(base)
	want := base
	if t.Assumed {
		want = base * assumedFactor
		sv.Assumed = "× 0.5 for the assumed edge = " + f3(want)
	}
	sv.Mismatch = math.Abs(want-t.E) > recomputeSlack
	return sv
}

// fe0 formats a term that may be exactly zero.
func fe0(x float64) string {
	if x == 0 {
		return "0"
	}
	return f3(x)
}

func escapeText(r attackpath.EscapeReason) string {
	var out []string
	if r&attackpath.EscapePrivileged != 0 {
		out = append(out, "privileged container")
	}
	if r&attackpath.EscapeDockerSocket != 0 {
		out = append(out, "Docker socket mounted")
	}
	if r&attackpath.EscapeFindingNote != 0 {
		out = append(out, "finding with a container-escape note")
	}
	if len(out) == 0 {
		return "reason unknown"
	}
	return strings.Join(out, ", ")
}

// --- map and frame ---------------------------------------------------------------

type beam struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Rank     int    `json:"rank"`
	Assumed  bool   `json:"assumed"`
	Possible bool   `json:"possible"`
}

type mark struct {
	ID   string `json:"id"`
	Role string `json:"role"`
}

type overlayData struct {
	Version   int    `json:"version"`
	Beams     []beam `json:"beams"`
	Marks     []mark `json:"marks"`
	Truncated bool   `json:"truncated"`
}

// selection is the parsed query of the map page and frame.
type selection struct {
	path, target string
}

var errSelection = errors.New("invalid selection")

func parseSelection(raw string) (selection, error) {
	if len(raw) > maxRawQuery {
		return selection{}, errSelection
	}
	q, err := url.ParseQuery(raw)
	if err != nil {
		return selection{}, errSelection
	}
	var sel selection
	for k, vals := range q {
		if len(vals) != 1 {
			return selection{}, errSelection
		}
		switch k {
		case "path":
			if !validHash(vals[0]) {
				return selection{}, errSelection
			}
			sel.path = vals[0]
		case "target":
			if !validNodeID(vals[0]) {
				return selection{}, errSelection
			}
			sel.target = vals[0]
		default:
			return selection{}, errSelection
		}
	}
	if sel.path != "" && sel.target != "" {
		return selection{}, errSelection
	}
	return sel, nil
}

// selectedPaths returns the paths a selection shows, with their rank within
// their target. No selection: the top path of each target. ok is false if
// the selected path or target is not in the result.
type rankedPath struct {
	p    attackpath.Path
	rank int
}

func selectedPaths(res *attackpath.Result, sel selection) ([]rankedPath, bool) {
	var out []rankedPath
	if res == nil {
		return nil, sel == selection{}
	}
	switch {
	case sel.path != "":
		tp, i, ok := findPath(res, sel.path)
		if !ok {
			return nil, false
		}
		return []rankedPath{{tp.Paths[i], i + 1}}, true
	case sel.target != "":
		for _, tp := range res.Targets {
			if tp.Node == sel.target {
				for i, p := range tp.Paths {
					out = append(out, rankedPath{p, i + 1})
				}
				return out, true
			}
		}
		return nil, false
	}
	for _, tp := range res.Targets {
		if len(tp.Paths) > 0 {
			out = append(out, rankedPath{tp.Paths[0], 1})
		}
	}
	return out, true
}

// buildOverlay maps the selected paths onto traffic map IDs, within the
// beam, mark and byte limits (fitOverlay). Steps with an end that is not on
// the map are counted, not drawn.
func (h *Handler) buildOverlay(res *attackpath.Result, sel selection, ps []rankedPath) (overlayData, int, error) {
	o := overlayData{Version: overlayVersion, Beams: []beam{}, Marks: []mark{}}
	mapID := func(id string) (string, bool) {
		m, ok := h.o.MapNode(id)
		if !ok || !validMapID(m) {
			return "", false
		}
		return m, true
	}
	unmapped := 0
	beamAt := map[[2]string]int{}
	role := map[string]string{}
	var order []string
	setRole := func(id, r string) {
		old, seen := role[id]
		if !seen {
			order = append(order, id)
		}
		if old != "target" && (old != "entry" || r == "target") {
			role[id] = r
		}
	}
	for _, rp := range ps {
		for _, st := range rp.p.Steps {
			if st.From == st.To {
				continue
			}
			from, okF := mapID(st.From)
			to, okT := mapID(st.To)
			if okF {
				setRole(from, "step")
			}
			if okT {
				setRole(to, "step")
			}
			if !okF || !okT {
				unmapped++
				continue
			}
			k := [2]string{from, to}
			b := beam{From: from, To: to, Rank: rp.rank, Assumed: st.Edge.Assumed() || st.Terms.Assumed, Possible: st.Possible}
			if i, ok := beamAt[k]; ok {
				if b.Rank < o.Beams[i].Rank {
					o.Beams[i] = b
				}
				continue
			}
			if len(o.Beams) == MaxBeams {
				o.Truncated = true
				continue
			}
			beamAt[k] = len(o.Beams)
			o.Beams = append(o.Beams, b)
		}
	}
	if res != nil {
		for _, tp := range res.Targets {
			if sel.target != "" && tp.Node != sel.target {
				continue
			}
			if m, ok := mapID(tp.Node); ok {
				setRole(m, "target")
			}
		}
	}
	for _, id := range order {
		if len(o.Marks) == MaxMarks {
			o.Truncated = true
			break
		}
		o.Marks = append(o.Marks, mark{ID: id, Role: role[id]})
	}
	o, err := fitOverlay(o)
	if err != nil {
		return overlayData{}, 0, err
	}
	return o, unmapped, nil
}

type mapView struct {
	Window    string
	FrameSrc  string
	ListHref  string
	Selected  string
	Unmapped  string
	NoData    bool
	Truncated bool
	Paths     int
}

func (h *Handler) serveMap(w http.ResponseWriter, r *http.Request) {
	sel, err := parseSelection(r.URL.RawQuery)
	if err != nil {
		http.Error(w, "Invalid query.", http.StatusBadRequest)
		return
	}
	s, err := h.snapshot(r)
	if err != nil {
		h.fail(w, r, "snapshot", err)
		return
	}
	ps, ok := selectedPaths(s.Result, sel)
	if !ok {
		http.Error(w, "Path or target not found.", http.StatusNotFound)
		return
	}
	o, unmapped, err := h.buildOverlay(s.Result, sel, ps)
	if err != nil {
		h.fail(w, r, "overlay", err)
		return
	}
	lb := labeler{s.Labels}
	v := &mapView{Window: h.o.Window, ListHref: ListPath, NoData: s.Result == nil, Truncated: o.Truncated, Paths: len(ps)}
	v.FrameSrc = FramePath
	switch {
	case sel.path != "":
		v.FrameSrc += "?" + url.Values{"path": {sel.path}}.Encode()
		v.Selected = "Path " + sel.path[:12] + "… to " + lb.name(selTarget(s.Result, sel.path))
	case sel.target != "":
		v.FrameSrc += "?" + url.Values{"target": {sel.target}}.Encode()
		v.Selected = "All top paths to " + lb.name(sel.target)
	default:
		v.Selected = "The top path to each crown jewel"
	}
	switch unmapped {
	case 0:
	case 1:
		v.Unmapped = "1 step is not on the traffic map (an entry class, container or other node the map does not draw); see the list view."
	default:
		v.Unmapped = strconv.Itoa(unmapped) + " steps are not on the traffic map (entry classes, containers or other nodes the map does not draw); see the list view."
	}
	h.render(w, r, h.mapPage, "Attack paths on the traffic map", []string{bridgeScript}, v)
}

func selTarget(res *attackpath.Result, hash string) string {
	if tp, _, ok := findPath(res, hash); ok {
		return tp.Node
	}
	return ""
}

func (h *Handler) serveFrame(w http.ResponseWriter, r *http.Request) {
	sel, err := parseSelection(r.URL.RawQuery)
	if err != nil {
		http.Error(w, "Invalid query.", http.StatusBadRequest)
		return
	}
	s, err := h.snapshot(r)
	if err != nil {
		h.fail(w, r, "snapshot", err)
		return
	}
	ps, ok := selectedPaths(s.Result, sel)
	if !ok {
		http.Error(w, "Path or target not found.", http.StatusNotFound)
		return
	}
	o, _, err := h.buildOverlay(s.Result, sel, ps)
	if err != nil {
		h.fail(w, r, "overlay", err)
		return
	}
	data, err := overlayJSON(o)
	if err != nil {
		h.fail(w, r, "overlay", err)
		return
	}
	var b strings.Builder
	if err := h.frame.Execute(&b, data); err != nil {
		h.fail(w, r, "render frame", err)
		return
	}
	hd := w.Header()
	hd.Set("Content-Security-Policy", h.frameCSP)
	hd.Set("Content-Type", "text/html; charset=utf-8")
	hd.Set("Cache-Control", "no-store")
	hd.Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write([]byte(b.String()))
}
