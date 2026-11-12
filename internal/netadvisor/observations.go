// SPDX-License-Identifier: AGPL-3.0-or-later

package netadvisor

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netreach"
)

// Observations are the inputs of the checks that read more than the
// reachability snapshot: rule hit counts (zero-hits), observed flows
// (dns-bypass, model-contradiction), the firewall's own addresses (the
// designated DNS resolver, ADR 0012 Q9) and the management targets
// (mgmt-from-untrusted). Each part carries the freshness state the server
// store reports; the zero value of every part is missing, which no check
// reads as "nothing observed".
//
// Every value comes from a device, a host or a server store and is
// untrusted; SetObservations validates it.
type Observations struct {
	Hits          HitCounts
	Flows         Flows
	FirewallAddrs FirewallAddrs
	MgmtTargets   MgmtTargets
}

// HitCounts are the per-rule hit counters of one firewall read (ADR 0010
// ND-20) with the time they were observed. Rules are keyed by rule name,
// as PAN-OS reports them.
type HitCounts struct {
	State      netreach.InputState
	ObservedAt time.Time
	Rules      []RuleHits
}

// RuleHits is the hit counter of one security rule. FirstHit, LastHit and
// ResetAt are zero when the device did not report them. Created is the
// rule's creation time (from the device or from the first stored policy
// version that holds the rule UUID); the observed window starts at the
// later of Created and ResetAt (ADR 0012 D4 zero-hits).
type RuleHits struct {
	RuleName string
	Hits     uint64
	FirstHit time.Time
	LastHit  time.Time
	ResetAt  time.Time
	Created  netreach.Field[time.Time]
}

// Flows are observed flows from the traffic map (ADR 0009) and the
// firewall log aggregates (ADR 0012 D5) over one window. State is the
// freshness of the flow data as a whole; a cut at a key cap makes it
// incomplete.
type Flows struct {
	State netreach.InputState
	From  time.Time
	To    time.Time
	Flows []Flow
}

// FlowAction is what the observation says happened to a flow.
type FlowAction string

// Flow actions. A traffic-map flow was observed on a host and therefore
// passed (FlowAllow); log aggregates carry the firewall action.
const (
	FlowAllow FlowAction = "allow"
	FlowDeny  FlowAction = "deny"
)

// Flow is one observed flow aggregate. Origin names where it was seen
// ("traffic-map", "fw-log"); it is device or host text.
type Flow struct {
	Src      netip.Addr
	Dst      netip.Addr
	Protocol string
	Port     uint16
	Action   FlowAction
	Sessions uint64
	Origin   string
}

// FirewallAddrs are the firewall's own interface addresses (ADR 0010
// ND-16), the only designated DNS resolver (ADR 0012 Q9).
type FirewallAddrs struct {
	State netreach.InputState
	Addrs []netip.Addr
}

// MgmtTargets are the management targets of ADR 0012 D4 (operator data,
// defaults from ADR 0010 devices, PVE nodes, SSH of managed hosts, the NOS
// server and executor, BMCs).
type MgmtTargets struct {
	State   netreach.InputState
	Targets []MgmtTarget
}

// MgmtTarget is one management target with every address it has and its
// management ports. NetBird is what host data says about NetBird paths to
// it; uncollected facts give the verdict unknown for the netbird source.
type MgmtTarget struct {
	Name    string
	Addrs   []netip.Addr
	Ports   []MgmtPort
	NetBird netreach.NetBirdFacts
}

// MgmtPort is one management port.
type MgmtPort struct {
	Protocol string
	Port     uint16
}

// Limits of the observations.
const (
	// MaxHitEntries bounds the hit-count entries (one per rule).
	MaxHitEntries = netreach.MaxSecurityRules
	// MaxFlows bounds the observed flow aggregates of one run.
	MaxFlows = 100000
	// MaxFirewallAddrs bounds the firewall's own addresses.
	MaxFirewallAddrs = 4096
	// MaxMgmtTargets bounds the management targets.
	MaxMgmtTargets = 1024
	// MaxMgmtAddrsPerTarget bounds the addresses of one target.
	MaxMgmtAddrsPerTarget = 16
	// MaxMgmtPortsPerTarget bounds the management ports of one target.
	MaxMgmtPortsPerTarget = 16
	// MaxRoutingPeers bounds the NetBird routing peers of one target.
	MaxRoutingPeers = 64
)

// SetObservations validates o and makes it the observations of the run.
// It refuses, wrapping ErrInvalidInput, every part over its limit, every
// name or text that is not valid UTF-8 or longer than
// netreach.MaxNameBytes, every invalid address, a protocol other than tcp
// or udp on a management port, port 0 on a management port and an unknown
// input state. On error the previous observations stay.
func (in *Input) SetObservations(o Observations) error {
	if in == nil {
		return fmt.Errorf("set observations: %w: no input", ErrInvalidInput)
	}
	if err := checkObservations(&o); err != nil {
		return fmt.Errorf("set observations: %w: %w", ErrInvalidInput, err)
	}
	in.obs = o
	return nil
}

func validState(s netreach.InputState) bool {
	switch s {
	case netreach.InputMissing, netreach.InputFresh, netreach.InputStale, netreach.InputIncomplete:
		return true
	}
	return false
}

func checkObservations(o *Observations) error {
	for _, p := range []struct {
		what string
		st   netreach.InputState
	}{
		{"hit counts", o.Hits.State}, {"flows", o.Flows.State},
		{"firewall addresses", o.FirewallAddrs.State}, {"management targets", o.MgmtTargets.State},
	} {
		if !validState(p.st) {
			return fmt.Errorf("%s: unknown state %d", p.what, p.st)
		}
	}
	if len(o.Hits.Rules) > MaxHitEntries {
		return fmt.Errorf("%d hit-count entries, limit %d", len(o.Hits.Rules), MaxHitEntries)
	}
	for _, h := range o.Hits.Rules {
		if h.RuleName == "" || !validName(h.RuleName) {
			return fmt.Errorf("hit-count rule name empty, not valid UTF-8 or over %d bytes", netreach.MaxNameBytes)
		}
	}
	if len(o.Flows.Flows) > MaxFlows {
		return fmt.Errorf("%d flows, limit %d", len(o.Flows.Flows), MaxFlows)
	}
	for i, f := range o.Flows.Flows {
		if !f.Src.IsValid() || !f.Dst.IsValid() {
			return fmt.Errorf("flow %d: invalid address", i)
		}
		if f.Protocol == "" || !validName(f.Protocol) || !validName(f.Origin) || !validName(string(f.Action)) {
			return fmt.Errorf("flow %d: text empty, not valid UTF-8 or over %d bytes", i, netreach.MaxNameBytes)
		}
	}
	if len(o.FirewallAddrs.Addrs) > MaxFirewallAddrs {
		return fmt.Errorf("%d firewall addresses, limit %d", len(o.FirewallAddrs.Addrs), MaxFirewallAddrs)
	}
	for _, a := range o.FirewallAddrs.Addrs {
		if !a.IsValid() {
			return fmt.Errorf("invalid firewall address")
		}
	}
	if len(o.MgmtTargets.Targets) > MaxMgmtTargets {
		return fmt.Errorf("%d management targets, limit %d", len(o.MgmtTargets.Targets), MaxMgmtTargets)
	}
	for i, t := range o.MgmtTargets.Targets {
		if err := checkMgmtTarget(&t); err != nil {
			return fmt.Errorf("management target %d: %w", i, err)
		}
	}
	return nil
}

func checkMgmtTarget(t *MgmtTarget) error {
	switch {
	case t.Name == "" || !validName(t.Name):
		return fmt.Errorf("name empty, not valid UTF-8 or over %d bytes", netreach.MaxNameBytes)
	case len(t.Addrs) > MaxMgmtAddrsPerTarget:
		return fmt.Errorf("%d addresses, limit %d", len(t.Addrs), MaxMgmtAddrsPerTarget)
	case len(t.Ports) > MaxMgmtPortsPerTarget:
		return fmt.Errorf("%d ports, limit %d", len(t.Ports), MaxMgmtPortsPerTarget)
	case len(t.NetBird.RoutingPeers.Value) > MaxRoutingPeers:
		return fmt.Errorf("%d routing peers, limit %d", len(t.NetBird.RoutingPeers.Value), MaxRoutingPeers)
	}
	for _, a := range t.Addrs {
		if !a.IsValid() {
			return fmt.Errorf("invalid address")
		}
	}
	for _, p := range t.Ports {
		if (p.Protocol != "tcp" && p.Protocol != "udp") || p.Port == 0 {
			return fmt.Errorf("port must be tcp or udp 1-65535")
		}
	}
	for _, p := range t.NetBird.RoutingPeers.Value {
		if !validName(p.Name) || !p.Addr.IsValid() {
			return fmt.Errorf("routing peer name or address invalid")
		}
	}
	return nil
}

// observationState returns the state and reason of one observation part
// for a check that needs it fresh: missing gives StateDataNotCollected,
// stale or incomplete StateCannotDecide.
func observationState(what string, st netreach.InputState) (State, string) {
	switch st {
	case netreach.InputFresh:
		return StateOK, ""
	case netreach.InputMissing:
		return StateDataNotCollected, what + " not collected"
	}
	return StateCannotDecide, what + " " + st.String()
}
