// SPDX-License-Identifier: AGPL-3.0-or-later

package netreach

import (
	"errors"
	"fmt"
	"net/netip"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

// Hard limits of one snapshot and of the work per computation (ADR 0012
// D2 "Limits"). The input limits reuse the ADR 0010 D3 parse limits; the
// work limits are new. A computation that hits a limit returns an error
// wrapping ErrLimitReached, never a guessed result and never a panic; the
// caller turns it into the verdict unknown "limit reached".
const (
	// MaxSecurityRules bounds the security rules of a snapshot.
	MaxSecurityRules = netdevcontract.MaxSecurityRules
	// MaxNATRules bounds the NAT rules of a snapshot.
	MaxNATRules = netdevcontract.MaxNATRules
	// MaxAddressObjects bounds the address objects of a snapshot.
	MaxAddressObjects = netdevcontract.MaxAddressObjects
	// MaxServiceObjects bounds the service objects of a snapshot.
	MaxServiceObjects = netdevcontract.MaxServiceObjects
	// MaxAddressGroups bounds the address groups of a snapshot.
	MaxAddressGroups = netdevcontract.MaxAddressGroups
	// MaxServiceGroups bounds the service groups of a snapshot.
	MaxServiceGroups = netdevcontract.MaxServiceGroups
	// MaxGroupMembers bounds the static members of one group.
	MaxGroupMembers = netdevcontract.MaxGroupMembers
	// MaxRuleMembers bounds one member list of a rule.
	MaxRuleMembers = netdevcontract.MaxRuleMembers
	// MaxZones bounds the zones of a snapshot.
	MaxZones = netdevcontract.MaxZones
	// MaxInterfaces bounds the firewall interfaces of a snapshot.
	MaxInterfaces = netdevcontract.MaxFirewallInterfaces
	// MaxPrefixesPerInterface bounds the connected prefixes of one
	// interface.
	MaxPrefixesPerInterface = netdevcontract.MaxAddressesPerInterface
	// MaxSubnets bounds the IPAM subnets of a snapshot.
	MaxSubnets = 16384
	// MaxRoutes bounds the firewall routes of a snapshot.
	MaxRoutes = 10000
	// MaxMarkers bounds the <dropped:…> markers and outside-allowlist field
	// names of one rule, object or group.
	MaxMarkers = 64
	// MaxNameBytes bounds every name and short text of a snapshot (object,
	// rule, zone, interface, subnet ID, marker). It covers the PAN-OS name
	// limit and the interface name limit.
	MaxNameBytes = 255
	// MaxValueBytes bounds an address or port value text.
	MaxValueBytes = 1024

	// MaxGroupDepth bounds group nesting during expansion (the ND-09
	// limit): a group whose members are all objects or literals has
	// depth 1.
	MaxGroupDepth = netdevcontract.MaxGroupNestingDepth
	// MaxExpandedRangesPerField bounds the address ranges one rule field
	// expands to, after groups.
	MaxExpandedRangesPerField = 4096
	// MaxPortRangesPerField bounds the port ranges one service field
	// expands to, after groups.
	MaxPortRangesPerField = 4096
	// MaxExpansionSteps bounds the members visited while expanding one
	// rule field; it bounds the CPU time of shared nested groups.
	MaxExpansionSteps = 1 << 18
	// MaxInputs bounds the entries of Snapshot.Inputs. Only the
	// RequiredInputs are read; the bound keeps a hostile map small.
	MaxInputs = 64

	// MaxPathsPerQuery bounds the paths one query evaluates against the
	// security rules: the direct path, every NAT branch, every pre-NAT
	// destination of the reverse-NAT lookup and every NetBird routing
	// peer. A query needing more gives unknown "limit reached".
	MaxPathsPerQuery = 64
	// MaxChainSteps bounds the steps of one explanation chain. A query
	// whose chain would be longer gives unknown "limit reached".
	MaxChainSteps = 1 << 16
)

// ErrLimitReached is wrapped by every error caused by a limit. The caller
// maps it to the verdict unknown with the reason "limit reached".
var ErrLimitReached = errors.New("limit reached")

// ErrInvalidSnapshot is wrapped by errors for a snapshot that is
// malformed (invalid UTF-8, an empty or duplicate name, an invalid
// prefix). The caller maps it to the verdict unknown.
var ErrInvalidSnapshot = errors.New("invalid snapshot")

// CheckLimits checks the snapshot against the input limits and validates
// its texts and prefixes. It returns the first violation, wrapping
// ErrLimitReached or ErrInvalidSnapshot.
func CheckLimits(s *Snapshot) error {
	if s == nil {
		return fmt.Errorf("%w: no snapshot", ErrInvalidSnapshot)
	}
	counts := []struct {
		what string
		n    int
		max  int
	}{
		{"security rules", len(s.SecurityRules), MaxSecurityRules},
		{"NAT rules", len(s.NATRules), MaxNATRules},
		{"address objects", len(s.Addresses), MaxAddressObjects},
		{"service objects", len(s.Services), MaxServiceObjects},
		{"address groups", len(s.AddressGroups), MaxAddressGroups},
		{"service groups", len(s.ServiceGroups), MaxServiceGroups},
		{"zones", len(s.Zones), MaxZones},
		{"interfaces", len(s.Interfaces), MaxInterfaces},
		{"subnets", len(s.Subnets), MaxSubnets},
		{"routes", len(s.Routes), MaxRoutes},
		{"inputs", len(s.Inputs), MaxInputs},
	}
	for _, c := range counts {
		if c.n > c.max {
			return fmt.Errorf("%w: %d %s, limit %d", ErrLimitReached, c.n, c.what, c.max)
		}
	}
	if s.Vsys < 0 {
		return fmt.Errorf("%w: negative vsys count %d", ErrInvalidSnapshot, s.Vsys)
	}
	if err := checkInputs(s.Inputs); err != nil {
		return err
	}
	for _, z := range s.Zones {
		if err := checkText("zone name", z.Name, MaxNameBytes); err != nil {
			return err
		}
	}
	for _, in := range s.Interfaces {
		if err := checkInterface(in); err != nil {
			return err
		}
	}
	for _, sn := range s.Subnets {
		if err := checkText("subnet id", sn.ID, MaxNameBytes); err != nil {
			return err
		}
		if err := checkPrefix("subnet "+sn.ID, sn.Prefix); err != nil {
			return err
		}
	}
	for _, r := range s.Routes {
		if err := checkPrefix("route", r.Prefix); err != nil {
			return err
		}
		if err := checkOptionalText("route zone", r.Zone, MaxNameBytes); err != nil {
			return err
		}
		if err := checkOptionalText("route interface", r.Interface, MaxNameBytes); err != nil {
			return err
		}
	}
	for _, a := range s.Addresses {
		if err := checkText("address name", a.Name, MaxNameBytes); err != nil {
			return err
		}
		if err := checkOptionalText("address type", string(a.Type), MaxNameBytes); err != nil {
			return err
		}
		if err := checkOptionalText("address value", a.Value, MaxValueBytes); err != nil {
			return err
		}
		if err := checkMarkers(a.Name, a.Dropped); err != nil {
			return err
		}
	}
	for _, sv := range s.Services {
		if err := checkService(sv); err != nil {
			return err
		}
	}
	for _, groups := range [][]Group{s.AddressGroups, s.ServiceGroups} {
		for _, g := range groups {
			if err := checkGroup(g); err != nil {
				return err
			}
		}
	}
	for i := range s.SecurityRules {
		if err := checkSecurityRule(&s.SecurityRules[i]); err != nil {
			return err
		}
	}
	for i := range s.NATRules {
		if err := checkNATRule(&s.NATRules[i]); err != nil {
			return err
		}
	}
	if s.DefaultRules.Collected {
		if err := checkDefaultRules(&s.DefaultRules.Value); err != nil {
			return err
		}
	}
	return nil
}

// checkInputs bounds the input kinds, dataset IDs and redacted digests;
// they enter the snapshot hash and may be shown.
func checkInputs(inputs map[InputKind]Input) error {
	for k, in := range inputs {
		if err := checkText("input kind", string(k), MaxNameBytes); err != nil {
			return err
		}
		if err := checkOptionalText("input dataset id", in.DatasetID, MaxNameBytes); err != nil {
			return err
		}
		if err := checkOptionalText("input redacted digest", in.RedactedDigest, MaxNameBytes); err != nil {
			return err
		}
	}
	return nil
}

func checkDefaultRules(d *DefaultRules) error {
	if err := checkOptionalText("default intrazone action", string(d.Intrazone), MaxNameBytes); err != nil {
		return err
	}
	if err := checkOptionalText("default interzone action", string(d.Interzone), MaxNameBytes); err != nil {
		return err
	}
	if err := checkMarkers("default rules", d.Dropped); err != nil {
		return err
	}
	return checkMarkers("default rules", d.OutsideAllowlist)
}

func checkInterface(in Interface) error {
	if err := checkText("interface name", in.Name, MaxNameBytes); err != nil {
		return err
	}
	if err := checkOptionalText("interface zone", in.Zone, MaxNameBytes); err != nil {
		return err
	}
	if len(in.Prefixes) > MaxPrefixesPerInterface {
		return fmt.Errorf("%w: interface %q has %d prefixes, limit %d", ErrLimitReached, in.Name, len(in.Prefixes), MaxPrefixesPerInterface)
	}
	for _, p := range in.Prefixes {
		if err := checkPrefix("interface "+in.Name, p); err != nil {
			return err
		}
	}
	return nil
}

func checkService(sv ServiceObject) error {
	if err := checkText("service name", sv.Name, MaxNameBytes); err != nil {
		return err
	}
	if err := checkOptionalText("service protocol", sv.Protocol, MaxNameBytes); err != nil {
		return err
	}
	if err := checkOptionalText("service ports", sv.Ports, MaxValueBytes); err != nil {
		return err
	}
	if err := checkOptionalText("service source ports", sv.SourcePorts.Value, MaxValueBytes); err != nil {
		return err
	}
	return checkMarkers(sv.Name, sv.Dropped)
}

func checkGroup(g Group) error {
	if err := checkText("group name", g.Name, MaxNameBytes); err != nil {
		return err
	}
	if err := checkMembers("group "+g.Name, g.Static, MaxGroupMembers); err != nil {
		return err
	}
	return checkMarkers(g.Name, g.Dropped)
}

func checkSecurityRule(r *SecurityRule) error {
	if err := checkText("rule name", r.Name, MaxNameBytes); err != nil {
		return err
	}
	if err := checkOptionalText("rule uuid", r.UUID, MaxNameBytes); err != nil {
		return err
	}
	if err := checkOptionalText("rule schedule", r.Schedule.Value, MaxNameBytes); err != nil {
		return err
	}
	if err := checkOptionalText("rule type", string(r.Type.Value), MaxNameBytes); err != nil {
		return err
	}
	if err := checkOptionalText("rule action", string(r.Action), MaxNameBytes); err != nil {
		return err
	}
	lists := []Field[[]string]{r.From, r.To, r.Source, r.Destination, r.SourceHIP, r.DestinationHIP, r.SourceUser, r.Application, r.Service, r.Category}
	for _, l := range lists {
		if err := checkMembers("rule "+r.Name, l.Value, MaxRuleMembers); err != nil {
			return err
		}
	}
	if err := checkMarkers(r.Name, r.Dropped); err != nil {
		return err
	}
	return checkMarkers(r.Name, r.OutsideAllowlist)
}

func checkNATRule(r *NATRule) error {
	if err := checkText("NAT rule name", r.Name, MaxNameBytes); err != nil {
		return err
	}
	if err := checkOptionalText("NAT rule uuid", r.UUID, MaxNameBytes); err != nil {
		return err
	}
	for _, l := range []Field[[]string]{r.From, r.Source, r.Destination} {
		if err := checkMembers("NAT rule "+r.Name, l.Value, MaxRuleMembers); err != nil {
			return err
		}
	}
	if err := checkOptionalText("NAT rule to", r.To.Value, MaxNameBytes); err != nil {
		return err
	}
	if err := checkOptionalText("NAT rule service", r.Service.Value, MaxNameBytes); err != nil {
		return err
	}
	if dt := r.DestinationTranslation.Value; dt != nil {
		if err := checkOptionalText("NAT translated address", dt.Address, MaxValueBytes); err != nil {
			return err
		}
	}
	if err := checkMarkers(r.Name, r.Dropped); err != nil {
		return err
	}
	return checkMarkers(r.Name, r.OutsideAllowlist)
}

func checkMembers(owner string, members []string, max int) error {
	if len(members) > max {
		return fmt.Errorf("%w: %s has %d members, limit %d", ErrLimitReached, owner, len(members), max)
	}
	for _, m := range members {
		if err := checkText("member", m, MaxValueBytes); err != nil {
			return err
		}
	}
	return nil
}

func checkMarkers(owner string, markers []string) error {
	if len(markers) > MaxMarkers {
		return fmt.Errorf("%w: %d markers, limit %d", ErrLimitReached, len(markers), MaxMarkers)
	}
	for _, m := range markers {
		if err := checkText("marker", m, MaxNameBytes); err != nil {
			return fmt.Errorf("%s: %w", owner, err)
		}
	}
	return nil
}

// checkText requires a non-empty, valid UTF-8 text of at most max bytes
// without C0/C1 control or bidi formatting characters (isControl, the same
// set sanitizeText replaces).
func checkText(what, s string, max int) error {
	if s == "" {
		return fmt.Errorf("%w: empty %s", ErrInvalidSnapshot, what)
	}
	return checkOptionalText(what, s, max)
}

func checkOptionalText(what, s string, max int) error {
	if len(s) > max {
		return fmt.Errorf("%w: %s longer than %d bytes", ErrLimitReached, what, max)
	}
	if !utf8.ValidString(s) {
		return fmt.Errorf("%w: %s is not valid UTF-8", ErrInvalidSnapshot, what)
	}
	for _, r := range s {
		if isControl(r) {
			return fmt.Errorf("%w: %s contains a control or bidi formatting character", ErrInvalidSnapshot, what)
		}
	}
	return nil
}

// checkPrefix requires a valid, masked prefix without IPv6 zone and
// without an IPv4-mapped IPv6 form.
func checkPrefix(what string, p netip.Prefix) error {
	if !p.IsValid() {
		return fmt.Errorf("%w: %s has an invalid prefix", ErrInvalidSnapshot, what)
	}
	if p.Masked() != p {
		return fmt.Errorf("%w: %s prefix %s has host bits set", ErrInvalidSnapshot, what, p)
	}
	if p.Addr().Is4In6() {
		return fmt.Errorf("%w: %s prefix %s is IPv4-mapped", ErrInvalidSnapshot, what, p)
	}
	return nil
}
