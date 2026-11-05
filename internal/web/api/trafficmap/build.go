// SPDX-License-Identifier: AGPL-3.0-or-later

package trafficmap

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/flowagg"
)

// Flows is the read side of the traffic store (ADR 0009 D3);
// *trafficstore.Store implements it. Both methods return server-computed
// top sets; the model never asks for more.
type Flows interface {
	TopN(ctx context.Context, node netip.Addr, w flowagg.Window, n int) ([]flowagg.FlowTotal, error)
	OverviewUnion(ctx context.Context, nodes []netip.Addr, w flowagg.Window, n int) ([]flowagg.FlowTotal, error)
}

// Limits lower the output caps. Zero fields use the package caps; values
// above them are refused.
type Limits struct {
	Nodes         int
	Edges         int
	ResponseBytes int
	// Retention is the traffic store's retention (ADR 0009 D3: admins
	// may shorten it). Windows longer than it are not offered. Zero means
	// flowagg.Retention; it must lie in [1h, flowagg.Retention]. When
	// Flows reports its own retention (as *trafficstore.Store does), the
	// shorter of the two applies.
	Retention time.Duration
}

// retentionReporter is implemented by a Flows that knows its retention.
type retentionReporter interface {
	Retention() time.Duration
}

// Errors of Build. Callers branch on them for the HTTP status.
var (
	// ErrBadWindow: the window is not one of 1h, 24h, 7d, 21d, or it is
	// longer than the retention.
	ErrBadWindow = errors.New("trafficmap: unknown window")
	// ErrBadFocus: the focus is not a valid node ID.
	ErrBadFocus = errors.New("trafficmap: invalid focus")
	// ErrUnknownFocus: no node of the inventory has the focus ID.
	ErrUnknownFocus = errors.New("trafficmap: focus node not found")
	// ErrTooLarge: even a minimal model exceeds the response cap.
	ErrTooLarge = errors.New("trafficmap: model exceeds the response cap")
)

// Query selects the model.
type Query struct {
	// Window is a window name; empty means DefaultWindow.
	Window string
	// Focus is a node ID; empty means the overview.
	Focus string
}

// Builder builds bounded models.
type Builder struct {
	inventory func(ctx context.Context) (Inventory, error)
	flows     Flows
	now       func() time.Time
	limits    Limits
}

// NewBuilder returns a Builder. inventory and flows are required; now
// defaults to time.Now.
func NewBuilder(inventory func(ctx context.Context) (Inventory, error), flows Flows, now func() time.Time, l Limits) (*Builder, error) {
	if inventory == nil || flows == nil {
		return nil, errors.New("trafficmap: inventory and flows are required")
	}
	if now == nil {
		now = time.Now
	}
	var err error
	if l.Nodes, err = limit("nodes", l.Nodes, MaxNodes); err != nil {
		return nil, err
	}
	if l.Edges, err = limit("edges", l.Edges, MaxEdges); err != nil {
		return nil, err
	}
	if l.ResponseBytes, err = limit("response bytes", l.ResponseBytes, MaxResponseBytes); err != nil {
		return nil, err
	}
	if l.Retention == 0 {
		l.Retention = flowagg.Retention
	}
	if rr, ok := flows.(retentionReporter); ok {
		l.Retention = min(l.Retention, rr.Retention())
	}
	if l.Retention < time.Hour || l.Retention > flowagg.Retention {
		return nil, fmt.Errorf("trafficmap: retention %s outside %s..%s", l.Retention, time.Hour, flowagg.Retention)
	}
	return &Builder{inventory: inventory, flows: flows, now: now, limits: l}, nil
}

func limit(name string, v, max int) (int, error) {
	switch {
	case v == 0:
		return max, nil
	case v < 0 || v > max:
		return 0, fmt.Errorf("trafficmap: limit %s %d outside 1..%d", name, v, max)
	}
	return v, nil
}

// Windows returns the window names the builder accepts, shortest first:
// those no longer than the retention.
func (b *Builder) Windows() []string {
	out := make([]string, 0, len(windowOrder))
	for _, name := range windowOrder {
		if windowDuration[name] <= b.limits.Retention {
			out = append(out, name)
		}
	}
	return out
}

// defaultWindow is DefaultWindow, or the longest window the retention
// allows when it is shorter.
func (b *Builder) defaultWindow() string {
	if windowDuration[DefaultWindow] <= b.limits.Retention {
		return DefaultWindow
	}
	w := b.Windows()
	return w[len(w)-1]
}

// nodeRec is a cleaned node with the addresses it owns.
type nodeRec struct {
	node    Node
	addrs   []netip.Addr
	gateway bool
}

// priority orders nodes for the caps: routers and zone gateways first,
// then by kind, then by ID.
func priority(a, b *nodeRec) int {
	if a.gateway != b.gateway {
		if a.gateway {
			return -1
		}
		return 1
	}
	if c := cmp.Compare(kindRank[a.node.Kind], kindRank[b.node.Kind]); c != 0 {
		return c
	}
	return strings.Compare(a.node.ID, b.node.ID)
}

// Build returns the encoded JSON model for q, at most the response cap
// in size.
func (b *Builder) Build(ctx context.Context, q Query) ([]byte, error) {
	if q.Window == "" {
		q.Window = b.defaultWindow()
	}
	d, ok := windowDuration[q.Window]
	if !ok || d > b.limits.Retention {
		return nil, ErrBadWindow
	}
	if q.Focus != "" && !validID(q.Focus) {
		return nil, ErrBadFocus
	}
	now := b.now().UTC().Truncate(time.Second)
	w := flowagg.Window{From: now.Add(-d), To: now}
	inv, err := b.inventory(ctx)
	if err != nil {
		return nil, fmt.Errorf("trafficmap: read inventory: %w", err)
	}
	m := &Model{Window: q.Window, From: w.From.Format(time.RFC3339), To: w.To.Format(time.RFC3339), Focus: q.Focus}
	zones := cleanZones(inv.Zones, &m.Omitted)
	nodes := cleanNodes(inv.Nodes, zones, &m.Omitted)
	for _, z := range zones {
		if r, ok := nodes[z.Gateway]; ok {
			r.gateway = true
		} else {
			z.Gateway = ""
		}
	}
	owner := addrOwners(nodes, &m.Omitted)

	keep := make(map[string]bool)
	var flows []flowagg.FlowTotal
	if q.Focus == "" {
		for _, r := range capNodes(nodes, b.limits.Nodes, &m.Omitted) {
			keep[r.node.ID] = true
		}
		flows, err = b.overviewFlows(ctx, nodes, owner, keep, w, &m.Omitted)
	} else {
		f, ok := nodes[q.Focus]
		if !ok {
			return nil, ErrUnknownFocus
		}
		keep[q.Focus] = true
		flows, err = b.focusFlows(ctx, f, w)
	}
	if err != nil {
		return nil, err
	}
	accept := func(id string) bool { return keep[id] }
	if q.Focus != "" {
		accept = func(string) bool { return true }
	}
	edges, links, unmapped := aggregate(flows, owner, nodes, zones, accept, q.Focus, &m.Omitted)
	m.UnmappedFlows = unmapped
	if len(edges) > b.limits.Edges {
		m.Omitted.Edges += len(edges) - b.limits.Edges
		edges = edges[:b.limits.Edges]
	}
	if len(links) > MaxZoneLinks {
		m.Omitted.ZoneLinks += len(links) - MaxZoneLinks
		links = links[:MaxZoneLinks]
	}
	if q.Focus != "" {
		// The focus view shows the focus, its peers and the hops between.
		for _, e := range edges {
			keep[e.A], keep[e.B] = true, true
			for _, v := range e.Via {
				keep[v] = true
			}
		}
	}
	m.Edges, m.ZoneLinks = edges, links
	m.Nodes = make([]Node, 0, len(keep))
	for id := range keep {
		m.Nodes = append(m.Nodes, nodes[id].node)
	}
	m.Zones = make([]Zone, 0, len(zones))
	for _, z := range zones {
		m.Zones = append(m.Zones, *z)
	}
	slices.SortFunc(m.Zones, func(a, b Zone) int { return strings.Compare(a.ID, b.ID) })
	return b.encode(m, nodes)
}

// cleanZones validates the zones; invalid, duplicate and excess zones are
// counted as omitted.
func cleanZones(in []ZoneInput, om *Omitted) map[string]*Zone {
	if len(in) > maxInputZones {
		om.Zones += len(in) - maxInputZones
		in = in[:maxInputZones]
	}
	valid := make([]ZoneInput, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, z := range in {
		if !validID(z.ID) || seen[z.ID] {
			om.Zones++
			continue
		}
		seen[z.ID] = true
		valid = append(valid, z)
	}
	slices.SortFunc(valid, func(a, b ZoneInput) int { return strings.Compare(a.ID, b.ID) })
	if len(valid) > MaxZones {
		om.Zones += len(valid) - MaxZones
		valid = valid[:MaxZones]
	}
	out := make(map[string]*Zone, len(valid))
	for _, z := range valid {
		name, cut := cleanText(z.Name, MaxLabelBytes)
		if name == "" {
			name = z.ID
		}
		gw := ""
		if validID(z.Gateway) {
			gw = z.Gateway
		}
		out[z.ID] = &Zone{ID: z.ID, Name: name, NameCut: cut, VLAN: cleanVLAN(z.VLAN), Gateway: gw}
	}
	return out
}

// cleanNodes validates the nodes. Invalid and duplicate nodes are
// counted as omitted; a node in an unknown zone gets zone "".
func cleanNodes(in []NodeInput, zones map[string]*Zone, om *Omitted) map[string]*nodeRec {
	if len(in) > maxInputNodes {
		om.Nodes += len(in) - maxInputNodes
		in = in[:maxInputNodes]
	}
	out := make(map[string]*nodeRec, len(in))
	dup := make(map[string]bool)
	for i := range in {
		x := &in[i]
		if !validID(x.ID) {
			om.Nodes++
			continue
		}
		if _, ok := out[x.ID]; ok || dup[x.ID] {
			// Two nodes claim one ID: neither is trusted.
			if !dup[x.ID] {
				delete(out, x.ID)
				om.Nodes++
			}
			dup[x.ID] = true
			om.Nodes++
			continue
		}
		label, cut := cleanText(x.Label, MaxLabelBytes)
		if label == "" {
			label = x.ID
		}
		zone := ""
		if _, ok := zones[x.Zone]; ok {
			zone = x.Zone
		}
		n := Node{ID: x.ID, Label: label, LabelCut: cut, Kind: cleanKind(x.Kind), Zone: zone, VLAN: cleanVLAN(x.VLAN),
			Resources: cleanResources(x.Resources), Health: cleanHealth(x.Health)}
		n.Software, n.SoftwareCut = cleanSoftware(x.Software, om)
		r := &nodeRec{node: n}
		for _, a := range x.Addrs {
			c, ok := cleanAddr(a)
			if !ok || len(r.addrs) >= MaxAddrsPerNode {
				om.Addresses++
				continue
			}
			if !slices.Contains(r.addrs, c) {
				r.addrs = append(r.addrs, c)
			}
		}
		out[x.ID] = r
	}
	return out
}

// cleanSoftware validates symbols, merges duplicate keys and keeps the
// MaxSoftwarePerNode largest counts.
func cleanSoftware(in []Software, om *Omitted) ([]Software, bool) {
	byKey := make(map[string]int)
	out := make([]Software, 0, min(len(in), MaxSoftwarePerNode))
	for _, s := range in {
		if !validSoftwareKey(s.Key) || s.Count < 1 || s.Count > maxSoftwareCount {
			om.Software++
			continue
		}
		icon := ""
		if validIconHash(s.Icon) {
			icon = s.Icon
		}
		if i, ok := byKey[s.Key]; ok {
			out[i].Count = min(out[i].Count+s.Count, maxSoftwareCount)
			if out[i].Icon == "" {
				out[i].Icon = icon
			}
			continue
		}
		if len(byKey) >= 8*MaxSoftwarePerNode {
			// Bound the work per node on hostile input.
			om.Software++
			continue
		}
		byKey[s.Key] = len(out)
		out = append(out, Software{Key: s.Key, Count: s.Count, Icon: icon})
	}
	slices.SortFunc(out, func(a, b Software) int {
		if c := cmp.Compare(b.Count, a.Count); c != 0 {
			return c
		}
		return strings.Compare(a.Key, b.Key)
	})
	cut := false
	if len(out) > MaxSoftwarePerNode {
		om.Software += len(out) - MaxSoftwarePerNode
		out, cut = out[:MaxSoftwarePerNode], true
	}
	return out, cut
}

// addrOwners maps each address to its node. An address claimed by more
// than one node is ambiguous (a host may lie, ADR 0009) and maps to none.
func addrOwners(nodes map[string]*nodeRec, om *Omitted) map[netip.Addr]string {
	owner := make(map[netip.Addr]string)
	ambiguous := make(map[netip.Addr]bool)
	for id, r := range nodes {
		for _, a := range r.addrs {
			if prev, ok := owner[a]; ok && prev != id {
				ambiguous[a] = true
			}
			owner[a] = id
		}
	}
	for a := range ambiguous {
		delete(owner, a)
		om.Addresses++
	}
	for _, r := range nodes {
		r.addrs = slices.DeleteFunc(r.addrs, func(a netip.Addr) bool { return ambiguous[a] })
	}
	return owner
}

// capNodes returns the nodes the overview keeps, at most max, by priority.
func capNodes(nodes map[string]*nodeRec, max int, om *Omitted) []*nodeRec {
	all := make([]*nodeRec, 0, len(nodes))
	for _, r := range nodes {
		all = append(all, r)
	}
	slices.SortFunc(all, priority)
	if len(all) > max {
		om.Nodes += len(all) - max
		all = all[:max]
	}
	return all
}

// overviewFlows returns the union of every kept node's OverviewN largest
// flows, each node's set taken over all its addresses (ADR 0009 D3).
func (b *Builder) overviewFlows(ctx context.Context, nodes map[string]*nodeRec, owner map[netip.Addr]string, keep map[string]bool,
	w flowagg.Window, om *Omitted) ([]flowagg.FlowTotal, error) {
	kept := make([]*nodeRec, 0, len(keep))
	for id := range keep {
		kept = append(kept, nodes[id])
	}
	slices.SortFunc(kept, priority)
	var addrs []netip.Addr
	queried := make(map[netip.Addr]string)
	for _, r := range kept {
		for _, a := range r.addrs {
			if len(addrs) >= maxQueryAddrs {
				om.Addresses++
				continue
			}
			addrs = append(addrs, a)
			queried[a] = owner[a]
		}
	}
	if len(addrs) == 0 {
		return nil, nil
	}
	union, err := b.flows.OverviewUnion(ctx, addrs, w, OverviewN)
	if err != nil {
		return nil, fmt.Errorf("trafficmap: overview flows: %w", err)
	}
	return topPerNode(union, queried, OverviewN), nil
}

// topPerNode keeps, per node, the n largest flows over all the node's
// queried addresses and returns the union of these sets, largest first.
// The store's union holds the top n of every single address; a node's top
// n over all its addresses is a subset of it, so merging here gives the
// per-node set of ADR 0009 D3 instead of n per address.
func topPerNode(union []flowagg.FlowTotal, queried map[netip.Addr]string, n int) []flowagg.FlowTotal {
	union = slices.Clone(union)
	slices.SortFunc(union, compareTotal)
	taken := make(map[string]int)
	out := make([]flowagg.FlowTotal, 0, min(len(union), n*len(queried)))
	for _, f := range union {
		keepIt := false
		ia, okA := queried[f.Key.A]
		ib, okB := queried[f.Key.B]
		if okA && taken[ia] < n {
			taken[ia]++
			keepIt = true
		}
		if okB && (!okA || ib != ia) && taken[ib] < n {
			taken[ib]++
			keepIt = true
		}
		if keepIt {
			out = append(out, f)
		}
	}
	return out
}

// focusFlows returns exactly the FocusN largest flows of the focus node
// over all its addresses.
func (b *Builder) focusFlows(ctx context.Context, f *nodeRec, w flowagg.Window) ([]flowagg.FlowTotal, error) {
	byKey := make(map[flowagg.FlowKey]flowagg.FlowTotal)
	for _, a := range f.addrs {
		ts, err := b.flows.TopN(ctx, a, w, FocusN)
		if err != nil {
			return nil, fmt.Errorf("trafficmap: top flows of %s: %w", f.node.ID, err)
		}
		for _, t := range ts {
			byKey[t.Key] = t
		}
	}
	out := make([]flowagg.FlowTotal, 0, len(byKey))
	for _, t := range byKey {
		out = append(out, t)
	}
	slices.SortFunc(out, compareTotal)
	if len(out) > FocusN {
		out = out[:FocusN]
	}
	return out, nil
}

// compareTotal orders by total bytes descending, then by key.
func compareTotal(a, b flowagg.FlowTotal) int {
	if c := cmp.Compare(b.Total(), a.Total()); c != 0 {
		return c
	}
	x, y := a.Key, b.Key
	if c := x.A.Compare(y.A); c != 0 {
		return c
	}
	if c := x.B.Compare(y.B); c != 0 {
		return c
	}
	if c := cmp.Compare(x.Proto, y.Proto); c != 0 {
		return c
	}
	if c := cmp.Compare(x.ServerPort, y.ServerPort); c != 0 {
		return c
	}
	if c := cmp.Compare(x.Server, y.Server); c != 0 {
		return c
	}
	return strings.Compare(x.Tier, y.Tier)
}

type pair struct{ a, b string }

type edgeAcc struct {
	e   Edge
	svc map[Service]uint64
}

type linkAcc struct {
	l      ZoneLink
	ab, ba uint64
}

// via returns the router hops between zones za and zb, A's side first,
// without the ends themselves.
func via(zones map[string]*Zone, za, zb, a, b string) []string {
	out := []string{}
	if za == "" || zb == "" || za == zb {
		return out
	}
	for _, z := range []string{za, zb} {
		gw := zones[z].Gateway
		if gw != "" && gw != a && gw != b && !slices.Contains(out, gw) {
			out = append(out, gw)
		}
	}
	return out
}

// aggregate turns flows into node-pair edges and zone links. Flows with
// an end on a node left out by a cap are counted as omitted; flows that
// cannot form an edge at all (an end is no inventory node, such as an
// internet peer, or both ends are one node) are only counted in unmapped:
// they are not a cap and do not truncate the model. Edges and links come
// back largest first.
func aggregate(flows []flowagg.FlowTotal, owner map[netip.Addr]string, nodes map[string]*nodeRec, zones map[string]*Zone,
	accept func(string) bool, focus string, om *Omitted) ([]Edge, []ZoneLink, int) {
	edges := make(map[pair]*edgeAcc)
	links := make(map[pair]*linkAcc)
	unmapped := 0
	for _, f := range flows {
		ia, okA := owner[f.Key.A]
		ib, okB := owner[f.Key.B]
		if !okA || !okB || ia == ib || (focus != "" && ia != focus && ib != focus) {
			unmapped++
			continue
		}
		if !accept(ia) || !accept(ib) {
			om.Flows++
			continue
		}
		ab, ba := f.BytesAB, f.BytesBA
		if ia > ib {
			ia, ib, ab, ba = ib, ia, ba, ab
		}
		acc := edges[pair{ia, ib}]
		if acc == nil {
			acc = &edgeAcc{e: Edge{A: ia, B: ib, Confirmed: true}, svc: make(map[Service]uint64)}
			edges[pair{ia, ib}] = acc
		}
		acc.e.BytesAB = satAdd(acc.e.BytesAB, ab)
		acc.e.BytesBA = satAdd(acc.e.BytesBA, ba)
		acc.e.Connections = satAdd(acc.e.Connections, f.Connections)
		acc.e.LowerBound = acc.e.LowerBound || f.LowerBound
		acc.e.Confirmed = acc.e.Confirmed && f.Confirmed
		s := Service{Proto: f.Key.Proto.String(), Port: f.Key.ServerPort}
		acc.svc[s] = satAdd(acc.svc[s], f.Total())

		za, zb := nodes[ia].node.Zone, nodes[ib].node.Zone
		if za == "" || zb == "" || za == zb {
			continue
		}
		if za > zb {
			za, zb, ab, ba = zb, za, ba, ab
		}
		la := links[pair{za, zb}]
		if la == nil {
			la = &linkAcc{l: ZoneLink{A: za, B: zb, Via: via(zones, za, zb, "", "")}}
			links[pair{za, zb}] = la
		}
		la.ab, la.ba = satAdd(la.ab, ab), satAdd(la.ba, ba)
		la.l.Flows++
	}

	outE := make([]Edge, 0, len(edges))
	for _, acc := range edges {
		e := acc.e
		e.Via = via(zones, nodes[e.A].node.Zone, nodes[e.B].node.Zone, e.A, e.B)
		e.Services = make([]Service, 0, len(acc.svc))
		for s := range acc.svc {
			e.Services = append(e.Services, s)
		}
		slices.SortFunc(e.Services, func(x, y Service) int {
			if c := cmp.Compare(acc.svc[y], acc.svc[x]); c != 0 {
				return c
			}
			if c := strings.Compare(x.Proto, y.Proto); c != 0 {
				return c
			}
			return cmp.Compare(x.Port, y.Port)
		})
		if len(e.Services) > MaxServicesPerEdge {
			e.Services, e.ServicesCut = e.Services[:MaxServicesPerEdge], true
		}
		outE = append(outE, e)
	}
	slices.SortFunc(outE, func(x, y Edge) int {
		if c := cmp.Compare(satAdd(y.BytesAB, y.BytesBA), satAdd(x.BytesAB, x.BytesBA)); c != 0 {
			return c
		}
		if c := strings.Compare(x.A, y.A); c != 0 {
			return c
		}
		return strings.Compare(x.B, y.B)
	})

	outL := make([]ZoneLink, 0, len(links))
	for _, la := range links {
		l := la.l
		l.BytesAB, l.BytesBA = la.ab, la.ba
		outL = append(outL, l)
	}
	slices.SortFunc(outL, func(x, y ZoneLink) int {
		if c := cmp.Compare(satAdd(y.BytesAB, y.BytesBA), satAdd(x.BytesAB, x.BytesBA)); c != 0 {
			return c
		}
		if c := strings.Compare(x.A, y.A); c != 0 {
			return c
		}
		return strings.Compare(x.B, y.B)
	})
	return outE, outL, unmapped
}

// encode finishes the model and encodes it within the response cap.
// When the encoding is too large it drops the smallest edges, then zone
// links, then the lowest-priority nodes, halving each time, and says so.
func (b *Builder) encode(m *Model, nodes map[string]*nodeRec) ([]byte, error) {
	for {
		finish(m)
		data, err := json.Marshal(m)
		if err != nil {
			return nil, fmt.Errorf("trafficmap: encode model: %w", err)
		}
		if len(data) <= b.limits.ResponseBytes {
			return data, nil
		}
		switch {
		case len(m.Edges) > 0:
			n := len(m.Edges) / 2
			m.Omitted.Edges += len(m.Edges) - n
			m.Edges = m.Edges[:n]
		case len(m.ZoneLinks) > 0:
			n := len(m.ZoneLinks) / 2
			m.Omitted.ZoneLinks += len(m.ZoneLinks) - n
			m.ZoneLinks = m.ZoneLinks[:n]
		case len(m.Nodes) > 1:
			recs := make([]*nodeRec, 0, len(m.Nodes))
			for _, n := range m.Nodes {
				recs = append(recs, nodes[n.ID])
			}
			slices.SortFunc(recs, func(x, y *nodeRec) int {
				// The focus node is kept to the end.
				if (x.node.ID == m.Focus) != (y.node.ID == m.Focus) {
					if x.node.ID == m.Focus {
						return -1
					}
					return 1
				}
				return priority(x, y)
			})
			n := len(recs) / 2
			m.Omitted.Nodes += len(recs) - n
			m.Nodes = m.Nodes[:0]
			for _, r := range recs[:n] {
				m.Nodes = append(m.Nodes, r.node)
			}
		default:
			return nil, ErrTooLarge
		}
	}
}

// finish orders the nodes, removes references to nodes outside the
// model, counts zone members, clamps counters to exact JSON integers and
// sets the flags.
func finish(m *Model) {
	slices.SortFunc(m.Nodes, func(a, b Node) int { return strings.Compare(a.ID, b.ID) })
	in := make(map[string]bool, len(m.Nodes))
	count := make(map[string]int)
	for _, n := range m.Nodes {
		in[n.ID] = true
		count[n.Zone]++
	}
	absent := func(v string) bool { return !in[v] }
	for i := range m.Zones {
		z := &m.Zones[i]
		z.Nodes = count[z.ID]
		if !in[z.Gateway] {
			z.Gateway = ""
		}
	}
	m.LowerBound = false
	edges := m.Edges[:0]
	for _, e := range m.Edges {
		if !in[e.A] || !in[e.B] {
			m.Omitted.Edges++
			continue
		}
		e.Via = slices.DeleteFunc(e.Via, absent)
		e.BytesAB, e.BytesBA, e.Connections = jsonUint(e.BytesAB), jsonUint(e.BytesBA), jsonUint(e.Connections)
		m.LowerBound = m.LowerBound || e.LowerBound
		edges = append(edges, e)
	}
	m.Edges = edges
	for i := range m.ZoneLinks {
		l := &m.ZoneLinks[i]
		l.Via = slices.DeleteFunc(l.Via, absent)
		l.BytesAB, l.BytesBA = jsonUint(l.BytesAB), jsonUint(l.BytesBA)
	}
	m.Truncated = m.Omitted.any()
}
