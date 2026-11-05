// SPDX-License-Identifier: AGPL-3.0-or-later

// Package trafficmap builds the bounded, read-only traffic map model of
// ADR 0009 (D3, D4, D7) served as GET /api/v1/trafficmap.
//
// The model holds zones, nodes, edges between nodes and zone aggregates.
// Edges are node pairs summed over the server-computed top flows (the
// union of every node's top 5 in the overview, exactly the top 5 of one
// node in focus); the browser never receives raw flows, client ports or
// hourly buckets. Every count is capped, and a capped model says so in
// Truncated and Omitted instead of silently dropping data. Every text
// field is host data and is cleaned as spec 09 requires: valid UTF-8,
// printable only, bounded length.
package trafficmap

import (
	"math"
	"net/netip"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/flowagg"
)

// Windows a client may select (ADR 0009 D3).
const (
	Window1h  = "1h"
	Window24h = "24h"
	Window7d  = "7d"
	Window21d = "21d"
	// DefaultWindow applies when the request names none.
	DefaultWindow = Window24h
)

// windowDuration maps the window names to their length.
var windowDuration = map[string]time.Duration{
	Window1h:  time.Hour,
	Window24h: 24 * time.Hour,
	Window7d:  7 * 24 * time.Hour,
	Window21d: 21 * 24 * time.Hour,
}

// Top-set sizes (ADR 0009 D3).
const (
	// OverviewN is the per-node top set of the overview union.
	OverviewN = flowagg.DefaultOverviewN
	// FocusN is the number of flows a focused node shows.
	FocusN = 5
)

// Output caps (ADR 0009 D7). Limits may lower them, never raise them.
const (
	// MaxNodes bounds the nodes of one model; the stress target of
	// 1,000 hosts has about 1,625 nodes.
	MaxNodes = 2048
	// MaxZones bounds the zones of one model.
	MaxZones = 256
	// MaxEdges bounds the edges of one model; the top-5 union of
	// MaxNodes nodes has at most 5*MaxNodes/2 node pairs per address.
	MaxEdges = 8192
	// MaxZoneLinks bounds the zone aggregates of one model.
	MaxZoneLinks = 1024
	// MaxResponseBytes bounds the encoded JSON model.
	MaxResponseBytes = 4 << 20
)

// Per-item caps.
const (
	// MaxSoftwarePerNode bounds the software symbols of one node.
	MaxSoftwarePerNode = 16
	// MaxAddrsPerNode bounds the addresses of one node used to map flows.
	MaxAddrsPerNode = 16
	// MaxServicesPerEdge bounds the protocol/port pairs listed per edge.
	MaxServicesPerEdge = 4
	// MaxLabelBytes bounds node labels and zone names (spec 09 allows at
	// most 4 KiB per text field; a map label needs far less).
	MaxLabelBytes = 256
	// MaxIDBytes bounds node and zone identifiers.
	MaxIDBytes = 128
	// MaxSoftwareKeyBytes bounds software catalog keys (ADR 0009 D5).
	MaxSoftwareKeyBytes = 64
	// maxQueryAddrs bounds the addresses of one overview query; it equals
	// trafficstore.MaxOverviewNodes.
	maxQueryAddrs = 4096
	// maxInputZones and maxInputNodes bound the inventory read; anything
	// beyond is counted as omitted without being looked at.
	maxInputZones = 4 * MaxZones
	maxInputNodes = 64 * MaxNodes
	// maxSoftwareCount bounds a software symbol's count.
	maxSoftwareCount = 1 << 20
	// maxJSONInt is the largest integer a JavaScript number holds
	// exactly; byte counters are clamped to it.
	maxJSONInt = 1<<53 - 1
)

// Value ranges of node attributes; values outside are unknown (null).
const (
	maxVCPU        = 4096
	maxRAMMiB      = 1 << 30
	maxGPUs        = 64
	maxFailedUnits = 100000
	maxLoad        = 100000
	maxVLAN        = 4094
)

// Node kinds. Anything else from the inventory becomes KindUnknown.
const (
	KindHost      = "host"
	KindGuest     = "guest"
	KindContainer = "container"
	KindAsset     = "asset"
	KindEndpoint  = "endpoint"
	KindRouter    = "router"
	KindUnknown   = "unknown"
)

// kindRank orders kinds for the node cap: managed and routing nodes are
// kept before observed ones.
var kindRank = map[string]int{
	KindRouter: 0, KindHost: 1, KindGuest: 2, KindContainer: 3,
	KindAsset: 4, KindEndpoint: 5, KindUnknown: 6,
}

// Patch states of the health spike (ADR 0009 D4).
const (
	PatchesCurrent  = "current"
	PatchesPending  = "pending"
	PatchesCritical = "critical"
)

// Model is the JSON traffic map.
type Model struct {
	// Window is the selected window name; From and To are its bounds
	// (RFC 3339, UTC).
	Window string `json:"window"`
	From   string `json:"from"`
	To     string `json:"to"`
	// Focus is the focused node, empty in the overview.
	Focus     string     `json:"focus,omitempty"`
	Zones     []Zone     `json:"zones"`
	Nodes     []Node     `json:"nodes"`
	Edges     []Edge     `json:"edges"`
	ZoneLinks []ZoneLink `json:"zone_links"`
	// LowerBound is set when any edge may miss bytes (snapshot volumes
	// are a lower bound, ADR 0009 D3).
	LowerBound bool `json:"lower_bound"`
	// Truncated is set when anything was left out; Omitted says what.
	Truncated bool    `json:"truncated"`
	Omitted   Omitted `json:"omitted"`
}

// Omitted counts what a model left out.
type Omitted struct {
	// Zones and Nodes were invalid, duplicate or over a cap.
	Zones int `json:"zones"`
	Nodes int `json:"nodes"`
	// Edges and ZoneLinks were over a cap.
	Edges     int `json:"edges"`
	ZoneLinks int `json:"zone_links"`
	// Software symbols were invalid, duplicate or over the per-node cap.
	Software int `json:"software"`
	// Addresses were invalid, over the per-node cap, claimed by more
	// than one node or over the query cap.
	Addresses int `json:"addresses"`
	// Flows had an end that maps to no node of the model.
	Flows int `json:"flows"`
}

func (o Omitted) any() bool { return o != Omitted{} }

// Zone is a VLAN or subnet zone.
type Zone struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	NameCut bool   `json:"name_cut,omitempty"`
	// VLAN is the 802.1Q ID, null when unknown or untagged.
	VLAN *int `json:"vlan"`
	// Gateway is the node ID of the zone's router hop, empty if unknown.
	Gateway string `json:"gateway,omitempty"`
	// Nodes is the number of model nodes in the zone.
	Nodes int `json:"nodes"`
}

// Node is a star on the map.
type Node struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	LabelCut bool   `json:"label_cut,omitempty"`
	Kind     string `json:"kind"`
	// Zone is the zone ID, empty when the node is in no known zone.
	Zone      string    `json:"zone"`
	VLAN      *int      `json:"vlan"`
	Resources Resources `json:"resources"`
	Health    Health    `json:"health"`
	// Software lists symbols by count, largest first.
	Software    []Software `json:"software"`
	SoftwareCut bool       `json:"software_cut,omitempty"`
}

// Resources are a node's assigned resources; null means unknown.
type Resources struct {
	VCPU   *uint32 `json:"vcpu"`
	RAMMiB *uint64 `json:"ram_mib"`
	GPUs   *uint32 `json:"gpus"`
}

// Health holds the values behind the health spikes. Every field is null
// when not known: unknown is never rendered as healthy.
type Health struct {
	// Patches is PatchesCurrent, PatchesPending or PatchesCritical.
	Patches         *string  `json:"patches"`
	Reachable       *bool    `json:"reachable"`
	HostKeyMismatch *bool    `json:"host_key_mismatch"`
	BackupFresh     *bool    `json:"backup_fresh"`
	FailedUnits     *uint32  `json:"failed_units"`
	DiskUsedPct     *float64 `json:"disk_used_pct"`
	Load            *float64 `json:"load"`
}

// Software is one software symbol of a node.
type Software struct {
	// Key is the catalog key ([a-z0-9][a-z0-9._-]{0,63}).
	Key   string `json:"key"`
	Count int    `json:"count"`
	// Icon is the SHA-256 (lowercase hex) of the icon served under
	// /icons/, empty for the generic symbol.
	Icon string `json:"icon,omitempty"`
}

// Edge is the traffic between two nodes, A < B by ID, summed over the
// selected top flows.
type Edge struct {
	A string `json:"a"`
	B string `json:"b"`
	// BytesAB is A→B (out of A, into B), BytesBA the reverse.
	BytesAB     uint64 `json:"bytes_ab"`
	BytesBA     uint64 `json:"bytes_ba"`
	Connections uint64 `json:"connections"`
	// Via lists the router hops between different zones, A's side first.
	Via         []string  `json:"via"`
	Services    []Service `json:"services"`
	ServicesCut bool      `json:"services_cut,omitempty"`
	// LowerBound: bytes may be missing. Confirmed: both ends reported
	// every counted hour of every flow.
	LowerBound bool `json:"lower_bound"`
	Confirmed  bool `json:"confirmed"`
}

// Service is the server protocol and port of a flow.
type Service struct {
	Proto string `json:"proto"`
	Port  uint16 `json:"port"`
}

// ZoneLink is the traffic between two zones (A < B by ID) through the
// hop, summed over the flows the model selected (a lower bound of the
// zone traffic).
type ZoneLink struct {
	A       string   `json:"a"`
	B       string   `json:"b"`
	BytesAB uint64   `json:"bytes_ab"`
	BytesBA uint64   `json:"bytes_ba"`
	Via     []string `json:"via"`
	Flows   int      `json:"flows"`
}

// Inventory is the map's view of the inventory, supplied by the server.
// All of it may originate on managed hosts and is treated as untrusted.
type Inventory struct {
	Zones []ZoneInput
	Nodes []NodeInput
}

// ZoneInput is one zone of the inventory.
type ZoneInput struct {
	ID, Name string
	// VLAN is the 802.1Q ID, 0 when untagged or unknown.
	VLAN int
	// Gateway is the node ID of the zone's default gateway, if known.
	Gateway string
}

// NodeInput is one node of the inventory.
type NodeInput struct {
	ID, Label, Kind, Zone string
	// VLAN is the 802.1Q ID, 0 when untagged or unknown.
	VLAN int
	// Addrs map flow ends to the node.
	Addrs     []netip.Addr
	Resources Resources
	Health    Health
	Software  []Software
}

// validID reports whether s is a usable node or zone ID:
// [A-Za-z0-9][A-Za-z0-9._:-]{0,127}.
func validID(s string) bool {
	if s == "" || len(s) > MaxIDBytes {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case i > 0 && (c == '.' || c == '_' || c == ':' || c == '-'):
		default:
			return false
		}
	}
	return true
}

// validSoftwareKey reports whether s matches [a-z0-9][a-z0-9._-]{0,63}.
func validSoftwareKey(s string) bool {
	if s == "" || len(s) > MaxSoftwareKeyBytes {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case i > 0 && (c == '.' || c == '_' || c == '-'):
		default:
			return false
		}
	}
	return true
}

// validIconHash reports whether s is a lowercase hex SHA-256.
func validIconHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// cleanText returns s as printable, valid UTF-8 of at most max bytes
// (spec 09): invalid bytes become U+FFFD, whitespace becomes a space,
// control, format (bidi overrides, zero-width) and other non-printable
// runes are dropped. cut reports that s was shortened.
func cleanText(s string, max int) (out string, cut bool) {
	// Bound the work on hostile input before looking at runes.
	if len(s) > 4*max {
		s, cut = s[:4*max], true
	}
	s = strings.ToValidUTF8(s, string(utf8.RuneError))
	var b strings.Builder
	b.Grow(min(len(s), max))
	for _, r := range s {
		switch {
		case unicode.IsSpace(r):
			r = ' '
		case !unicode.IsPrint(r):
			continue
		}
		if b.Len()+utf8.RuneLen(r) > max {
			cut = true
			break
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String()), cut
}

// cleanVLAN returns a pointer to v when it is a valid tagged VLAN ID.
func cleanVLAN(v int) *int {
	if v < 1 || v > maxVLAN {
		return nil
	}
	return &v
}

// cleanResources keeps values in range and nulls the rest.
func cleanResources(r Resources) Resources {
	var out Resources
	if r.VCPU != nil && *r.VCPU <= maxVCPU {
		v := *r.VCPU
		out.VCPU = &v
	}
	if r.RAMMiB != nil && *r.RAMMiB <= maxRAMMiB {
		v := *r.RAMMiB
		out.RAMMiB = &v
	}
	if r.GPUs != nil && *r.GPUs <= maxGPUs {
		v := *r.GPUs
		out.GPUs = &v
	}
	return out
}

// cleanFloat returns a copy of p when it is finite and in [0, max].
func cleanFloat(p *float64, max float64) *float64 {
	if p == nil || math.IsNaN(*p) || *p < 0 || *p > max {
		return nil
	}
	v := *p
	return &v
}

func cloneBool(p *bool) *bool {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

// cleanHealth keeps known, in-range values and nulls the rest.
func cleanHealth(h Health) Health {
	var out Health
	if h.Patches != nil {
		switch *h.Patches {
		case PatchesCurrent, PatchesPending, PatchesCritical:
			v := *h.Patches
			out.Patches = &v
		}
	}
	out.Reachable = cloneBool(h.Reachable)
	out.HostKeyMismatch = cloneBool(h.HostKeyMismatch)
	out.BackupFresh = cloneBool(h.BackupFresh)
	if h.FailedUnits != nil && *h.FailedUnits <= maxFailedUnits {
		v := *h.FailedUnits
		out.FailedUnits = &v
	}
	out.DiskUsedPct = cleanFloat(h.DiskUsedPct, 100)
	out.Load = cleanFloat(h.Load, maxLoad)
	return out
}

// cleanKind maps unknown kinds to KindUnknown.
func cleanKind(k string) string {
	if _, ok := kindRank[k]; ok {
		return k
	}
	return KindUnknown
}

// cleanAddr returns the form flows are keyed by, or false for addresses
// that cannot be a flow end (invalid, unspecified, loopback, multicast,
// zoned non-link-local).
func cleanAddr(a netip.Addr) (netip.Addr, bool) {
	if !a.IsValid() {
		return netip.Addr{}, false
	}
	a = a.Unmap()
	if a.Zone() != "" {
		if !a.IsLinkLocalUnicast() {
			return netip.Addr{}, false
		}
		a = a.WithZone("")
	}
	if a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() {
		return netip.Addr{}, false
	}
	return a, true
}

// jsonUint clamps v to the integers a JavaScript number holds exactly.
func jsonUint(v uint64) uint64 { return min(v, maxJSONInt) }

// satAdd adds without overflow.
func satAdd(a, b uint64) uint64 {
	if s := a + b; s >= a {
		return s
	}
	return math.MaxUint64
}
