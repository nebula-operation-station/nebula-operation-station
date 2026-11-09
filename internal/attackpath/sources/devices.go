// SPDX-License-Identifier: AGPL-3.0-or-later

package sources

// FirewallPolicy is the firewall allow-rule and NAT adapter (ADR 0011 D10,
// policy network edges). It needs ADR 0010 network-device data, which does
// not exist yet (follow-up after ND-16), so it is a stub: the source is
// unknown and no edge it would add may be read as "no edge".
func FirewallPolicy() Result {
	return missing(SourceFirewall)
}

// VLANAdjacency is the L2 adjacency adapter (same VLAN on ADR 0010 switches
// or ADR 0009 bridge VLANs). It waits for ADR 0010 device data (follow-up
// after ND-16) and is a stub: the source is unknown.
func VLANAdjacency() Result {
	return missing(SourceVLAN)
}

func missing(source string) Result {
	c := newCollector(source)
	c.r.Status = StatusUnknown
	c.uncertain(UncertainSourceMissing, "")
	return c.result()
}
