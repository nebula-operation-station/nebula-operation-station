// SPDX-License-Identifier: AGPL-3.0-or-later

// Package attackpath holds the attack-path graph of ADR 0011 D10: node and
// edge kinds, a builder that validates and bounds its input, and an
// immutable graph with a canonical snapshot and snapshot hash. The package
// is pure: no store, no I/O, no clock. Data adapters (flows, firewall rules,
// placements, Docker, executor credentials) live elsewhere (VU-22).
//
// Compute scores paths with formula ap-v1 (score.go), finds the top
// PathsPerTarget paths per crown-jewel target with Yen's algorithm at most
// MaxDepth steps deep (search.go) and ranks choke points (compute.go). The
// attacker's state on a node is "reached" (a network step) or "owned" (a
// local privilege escalation, or a control, credential or escape step);
// control, credential and escape steps start from an owned node. Every
// number comes from NOS data through a versioned formula, never from an
// LLM.
//
// Edges keep their basis. Policy edges (firewall allow and NAT), observed
// edges (traffic map flows) and assumed edges (L2 adjacency, all ports) are
// separate edges even between the same two nodes, so a later score can treat
// "assumed" differently and the UI can say which is which.
//
// Every node ID and label comes from data that may originate on a managed
// host and is treated as untrusted: IDs are short printable ASCII, labels are
// bounded UTF-8 text without control or bidi characters. Error messages name
// the field, never the rejected value.
package attackpath

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Limits enforced by this package (ADR 0011 D10).
const (
	// MaxNodes is the node cap of one graph. Nodes beyond it are dropped and
	// the graph is marked truncated.
	MaxNodes = 5000
	// MaxEdges is the edge cap of one graph. Edges beyond it are dropped and
	// the graph is marked truncated.
	MaxEdges = 50000
	// MaxInputNodes bounds the distinct nodes a Builder holds before Build
	// applies MaxNodes; it bounds memory on hostile or runaway input. At
	// the limit the node kept last is evicted (rank-aware, see Builder).
	MaxInputNodes = 4 * MaxNodes
	// MaxDroppedNodes bounds how many nodes dropped by the input limit a
	// Builder remembers (the best-ranked ones) to count each drop once.
	MaxDroppedNodes = MaxInputNodes
	// MaxInputEdgesPerKind bounds the distinct edges of one kind a Builder
	// holds before Build applies MaxEdges, with the same rank-aware
	// eviction. Edges held beyond what Build keeps are the remembered drops.
	MaxInputEdgesPerKind = 2 * MaxEdges
	// MaxIDBytes bounds a node ID.
	MaxIDBytes = 128
	// MaxLabelBytes bounds a node label.
	MaxLabelBytes = 256
)

// IDs of the synthetic entry nodes every graph contains.
const (
	InternetID = "internet"
	NetBirdID  = "netbird"
)

// Sentinel errors returned (wrapped) by the Builder.
var (
	// ErrInvalidNode reports a node with a bad ID, kind or label, or an ID
	// outside the namespace of its kind (see NodeKind.IDPrefix).
	ErrInvalidNode = errors.New("invalid node")
	// ErrReservedNode reports an attempt to add a synthetic entry node or
	// to reuse an entry ID.
	ErrReservedNode = errors.New("reserved node")
	// ErrConflict reports a node ID offered again with another label. The
	// builder keeps the label that sorts first, whichever came first.
	ErrConflict = errors.New("conflicting node")
	// ErrInvalidEdge reports an edge whose kind, endpoints, protocol, port
	// or escape reason break the rules of its kind.
	ErrInvalidEdge = errors.New("invalid edge")
	// ErrUnknownNode reports an edge endpoint that was not added first.
	ErrUnknownNode = errors.New("unknown node")
	// ErrInputLimit reports that the builder's input bound is reached and
	// the input ranks after everything held; the input is dropped and the
	// graph will be marked truncated.
	ErrInputLimit = errors.New("attack-path input limit reached")
)

// NodeKind classifies a node (ADR 0011 D10, node table).
type NodeKind uint8

// Node kinds. The numeric values are internal; snapshots use String.
const (
	// NodeInternet is the synthetic internet entry.
	NodeInternet NodeKind = iota + 1
	// NodeNetBird is the synthetic entry class for NetBird peers, separate
	// from the internet.
	NodeNetBird
	// NodeHost is a managed host from the inventory.
	NodeHost
	// NodePVENode is a Proxmox node (ADR 0006).
	NodePVENode
	// NodeGuest is a Proxmox guest (ADR 0006 placements).
	NodeGuest
	// NodeContainer is a Docker container from the Docker inventory.
	NodeContainer
	// NodeNetworkDevice is a network device (ADR 0010).
	NodeNetworkDevice
	// NodeUnmanaged is an endpoint observed in traffic (ADR 0009) without an
	// inventory entry.
	NodeUnmanaged
)

var nodeKindNames = [...]string{
	NodeInternet:      "internet",
	NodeNetBird:       "netbird",
	NodeHost:          "host",
	NodePVENode:       "pve_node",
	NodeGuest:         "guest",
	NodeContainer:     "container",
	NodeNetworkDevice: "network_device",
	NodeUnmanaged:     "unmanaged",
}

// String returns the stable snapshot name of k, or "invalid".
func (k NodeKind) String() string {
	if k.valid() {
		return nodeKindNames[k]
	}
	return "invalid"
}

func (k NodeKind) valid() bool { return k >= NodeInternet && k <= NodeUnmanaged }

// Entry reports whether k is a synthetic entry class.
func (k NodeKind) Entry() bool { return k == NodeInternet || k == NodeNetBird }

// Managed reports whether k is a host NOS manages over SSH, which the
// executor's credentials reach.
func (k NodeKind) Managed() bool { return k == NodeHost || k == NodePVENode || k == NodeGuest }

// keepRank orders node kinds for truncation: lower ranks are kept first.
// Entries always survive; unmanaged endpoints go first.
var keepRank = [...]uint8{
	NodeInternet:      0,
	NodeNetBird:       0,
	NodeNetworkDevice: 1,
	NodePVENode:       2,
	NodeHost:          3,
	NodeGuest:         4,
	NodeContainer:     5,
	NodeUnmanaged:     6,
}

// idPrefixes binds the node ID namespace to the kind: a node's ID must start
// with the prefix of its kind. An ID therefore names exactly one kind, and
// no input, hostile or not, can claim the ID of a node of another kind: an
// unmanaged endpoint can never take a managed host's ID.
var idPrefixes = [...]string{
	NodeHost:          "host:",
	NodePVENode:       "pve:",
	NodeGuest:         "guest:",
	NodeContainer:     "ctr:",
	NodeNetworkDevice: "dev:",
	NodeUnmanaged:     "unk:",
}

// IDPrefix returns the prefix every node ID of kind k must start with, or ""
// for the entry kinds and invalid kinds, which the Builder does not accept.
func (k NodeKind) IDPrefix() string {
	if k.valid() {
		return idPrefixes[k]
	}
	return ""
}

// Basis says what an edge rests on.
type Basis uint8

// Edge bases.
const (
	// BasisPolicy is a firewall allow rule or NAT (ADR 0010).
	BasisPolicy Basis = iota + 1
	// BasisObserved is a traffic map flow (ADR 0009).
	BasisObserved
	// BasisAssumed is an L2 adjacency: every port is assumed reachable.
	BasisAssumed
	// BasisInventory is a fact proven by NOS data: placement, Docker
	// inspect, executor credentials.
	BasisInventory
)

var basisNames = [...]string{
	BasisPolicy:    "policy",
	BasisObserved:  "observed",
	BasisAssumed:   "assumed",
	BasisInventory: "inventory",
}

// String returns the stable snapshot name of b, or "invalid".
func (b Basis) String() string {
	if b >= BasisPolicy && b <= BasisInventory {
		return basisNames[b]
	}
	return "invalid"
}

// EdgeKind classifies an edge (ADR 0011 D10, edge table).
type EdgeKind uint8

// Edge kinds. The numeric values are internal; snapshots use String.
const (
	// EdgeNetworkPolicy is a (proto, port) a firewall rule or NAT allows.
	EdgeNetworkPolicy EdgeKind = iota + 1
	// EdgeNetworkObserved is a (proto, port) seen in traffic flows.
	EdgeNetworkObserved
	// EdgeL2Adjacency is same-VLAN adjacency; all ports, flagged assumed.
	EdgeL2Adjacency
	// EdgeControl is PVE node → guest or Docker host → container: owning
	// the parent owns the child.
	EdgeControl
	// EdgeEscape is container → Docker host, only with an EscapeReason.
	EdgeEscape
	// EdgeCredential is executor host → managed host (SSH keys).
	EdgeCredential
)

var edgeKindNames = [...]string{
	EdgeNetworkPolicy:   "network_policy",
	EdgeNetworkObserved: "network_observed",
	EdgeL2Adjacency:     "l2_adjacency",
	EdgeControl:         "control",
	EdgeEscape:          "escape",
	EdgeCredential:      "credential",
}

// edgeKeepRank orders edge kinds for truncation: lower ranks are kept
// first. Proven edges before policy, policy before observed, assumed last.
var edgeKeepRank = [...]uint8{
	EdgeCredential:      0,
	EdgeControl:         1,
	EdgeEscape:          2,
	EdgeNetworkPolicy:   3,
	EdgeNetworkObserved: 4,
	EdgeL2Adjacency:     5,
}

// String returns the stable snapshot name of k, or "invalid".
func (k EdgeKind) String() string {
	if k.valid() {
		return edgeKindNames[k]
	}
	return "invalid"
}

func (k EdgeKind) valid() bool { return k >= EdgeNetworkPolicy && k <= EdgeCredential }

// Basis returns what edges of kind k rest on; 0 for an invalid kind.
func (k EdgeKind) Basis() Basis {
	switch k {
	case EdgeNetworkPolicy:
		return BasisPolicy
	case EdgeNetworkObserved:
		return BasisObserved
	case EdgeL2Adjacency:
		return BasisAssumed
	case EdgeControl, EdgeEscape, EdgeCredential:
		return BasisInventory
	}
	return 0
}

// Network reports whether k carries a (proto, port).
func (k EdgeKind) Network() bool { return k == EdgeNetworkPolicy || k == EdgeNetworkObserved }

// Proto is the transport protocol of a network edge.
type Proto uint8

// Protocols. The zero value means "no protocol" (non-network edges).
const (
	// ProtoTCP is TCP.
	ProtoTCP Proto = iota + 1
	// ProtoUDP is UDP.
	ProtoUDP
)

// String returns "tcp", "udp" or "" for the zero value and unknown values.
func (p Proto) String() string {
	switch p {
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	}
	return ""
}

// EscapeReason is a bit set of reasons a container can escape to its host.
type EscapeReason uint8

// Escape reasons (ADR 0011 D10, escape row).
const (
	// EscapePrivileged: the container runs privileged (docker.inspect).
	EscapePrivileged EscapeReason = 1 << iota
	// EscapeDockerSocket: the container mounts the Docker socket.
	EscapeDockerSocket
	// EscapeFindingNote: a finding on the container has a container-escape
	// note.
	EscapeFindingNote

	escapeAll = EscapePrivileged | EscapeDockerSocket | EscapeFindingNote
)

// names returns the reasons in bit order.
func (r EscapeReason) names() []string {
	var out []string
	if r&EscapePrivileged != 0 {
		out = append(out, "privileged")
	}
	if r&EscapeDockerSocket != 0 {
		out = append(out, "docker_socket")
	}
	if r&EscapeFindingNote != 0 {
		out = append(out, "finding_note")
	}
	return out
}

// Node is one vertex of the graph.
type Node struct {
	// ID is stable and unique within a graph, e.g. "host:<uuid>". Printable
	// ASCII without spaces, at most MaxIDBytes, starting with
	// Kind.IDPrefix() and longer than it.
	ID string
	// Kind classifies the node.
	Kind NodeKind
	// Label is display text, untrusted; at most MaxLabelBytes.
	Label string
}

// Edge is one directed step. Its identity is (From, To, Kind, Proto, Port);
// edges that differ in Kind are never merged, so an assumed L2 edge stays
// apart from observed or policy edges between the same nodes.
type Edge struct {
	// From and To are node IDs.
	From, To string
	// Kind classifies the edge and fixes its Basis.
	Kind EdgeKind
	// Proto and Port are set for network edges only. Port is 1–65535.
	Proto Proto
	// Port is the destination port of a network edge.
	Port uint16
	// Escape is set for escape edges only and must be non-zero there.
	Escape EscapeReason
}

// Assumed reports whether the edge is assumed rather than observed, allowed
// by policy or proven by inventory (ADR 0011 D10: L2 adjacency).
func (e Edge) Assumed() bool { return e.Kind.Basis() == BasisAssumed }

type edgeKey struct {
	from, to string
	kind     EdgeKind
	proto    Proto
	port     uint16
}

func (e Edge) key() edgeKey {
	return edgeKey{from: e.From, to: e.To, kind: e.Kind, proto: e.Proto, port: e.Port}
}

// validID reports whether id is 1..MaxIDBytes of [A-Za-z0-9._:/@-].
func validID(id string) bool {
	if id == "" || len(id) > MaxIDBytes {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == '_', c == ':', c == '/', c == '@', c == '-':
		default:
			return false
		}
	}
	return true
}

// validLabel reports whether s is bounded UTF-8 text; tab is the only
// control character allowed, bidi controls are rejected.
func validLabel(s string) bool {
	if len(s) > MaxLabelBytes || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r == '\t' {
			continue
		}
		if unicode.IsControl(r) || isBidiControl(r) {
			return false
		}
	}
	return true
}

func isBidiControl(r rune) bool {
	return r == 0x061c || r == 0x200e || r == 0x200f ||
		(r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069)
}

func validateNode(n Node) error {
	if n.Kind.Entry() || n.ID == InternetID || n.ID == NetBirdID {
		return fmt.Errorf("node kind or id: %w", ErrReservedNode)
	}
	if !validID(n.ID) {
		return fmt.Errorf("node id: %w", ErrInvalidNode)
	}
	if !n.Kind.valid() {
		return fmt.Errorf("node %s kind: %w", n.ID, ErrInvalidNode)
	}
	if p := n.Kind.IDPrefix(); !strings.HasPrefix(n.ID, p) || len(n.ID) == len(p) {
		return fmt.Errorf("node %s id namespace of kind %s: %w", n.ID, n.Kind, ErrInvalidNode)
	}
	if !validLabel(n.Label) {
		return fmt.Errorf("node %s label: %w", n.ID, ErrInvalidNode)
	}
	return nil
}

// validateEdge checks e against its kind's rules; from and to are the kinds
// of its (known) endpoints.
func validateEdge(e Edge, from, to NodeKind) error {
	bad := func(field string) error {
		return fmt.Errorf("edge %s -> %s %s: %s: %w", e.From, e.To, e.Kind, field, ErrInvalidEdge)
	}
	if !e.Kind.valid() {
		return bad("kind")
	}
	if e.From == e.To {
		return bad("self loop")
	}
	if to.Entry() {
		return bad("entry as target")
	}
	if e.Kind != EdgeEscape && e.Escape != 0 {
		return bad("escape reason")
	}
	if e.Kind.Network() {
		if e.Proto != ProtoTCP && e.Proto != ProtoUDP {
			return bad("proto")
		}
		if e.Port == 0 {
			return bad("port")
		}
		return nil
	}
	if e.Proto != 0 || e.Port != 0 {
		return bad("proto/port")
	}
	switch e.Kind {
	case EdgeL2Adjacency:
		if from.Entry() {
			return bad("entry in L2 adjacency")
		}
	case EdgeControl:
		ok := (from == NodePVENode && to == NodeGuest) ||
			(from.Managed() && to == NodeContainer)
		if !ok {
			return bad("endpoint kinds")
		}
	case EdgeEscape:
		if from != NodeContainer || !to.Managed() {
			return bad("endpoint kinds")
		}
		if e.Escape == 0 || e.Escape&^escapeAll != 0 {
			return bad("escape reason")
		}
	case EdgeCredential:
		if !from.Managed() || !to.Managed() {
			return bad("endpoint kinds")
		}
	}
	return nil
}
