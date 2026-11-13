// SPDX-License-Identifier: AGPL-3.0-or-later

// Package exportconform holds the one table of device values that the server
// (internal/web/api) and the agent's client mirror (internal/vulnagent/nosclient)
// must classify the same way. Each side runs the table in its own tests, so a
// change to a pattern on one side that is not made on the other fails a test.
// The package has no code of its own beyond the table.
package exportconform

// Case is one device value and the verdict both sides must reach: OK is true
// when the value may be exported (or accepted by the client), and false when it
// must be refused. Value is the device field as the server reads it from the
// inventory.
type Case struct {
	Name  string
	Value string
	OK    bool
}

// Vendor cases (ADR 0011 D2). Only the covered vendors pass; a bare host label
// matches the slug pattern but is not a covered vendor.
var Vendor = []Case{
	{"cisco", "cisco", true},
	{"palo alto", "paloalto", true},
	{"host label as vendor", "core-sw", false},
	{"covered vendor with suffix", "cisco-1", false},
	{"upper case vendor", "Cisco", false},
	{"uncovered vendor", "juniper", false},
	{"empty vendor", "", false},
}

// Model cases (ADR 0011 D2). A model needs an upper-case letter and a digit;
// a lower-case host label, an address, an IPv6 literal and a hyphenated MAC are
// refused. The upper-case host label "SW01" is a documented D2 residual and is
// not in the table.
var Model = []Case{
	{"Cisco model", "CBS350", true},
	{"Palo Alto model", "PA-220", true},
	{"model with plus and underscore", "C9300_48U+", true},
	{"lower-case host label", "core-sw01", false},
	{"IPv4 literal", "10.0.0.7", false},
	{"IPv6 literal", "2001:DB8::1", false},
	{"hyphenated MAC", "AA-BB-CC-DD-EE-FF", false},
	{"empty model", "", false},
}

// Firmware cases (ADR 0011 D3). A version is a digit-first string of version
// characters. A private or otherwise non-public IPv4 address is never a version,
// whether it is written exactly, with a suffix, or with leading zeros. A MAC in
// any separator mix and a host label are refused.
var Firmware = []Case{
	{"three-part version", "17.3.4", true},
	{"three-part version with qualifier", "10.2.3-h1", true},
	{"plus and tilde", "17.3.4+build2", true},
	{"tilde release candidate", "17.3.4~rc1", true},
	{"public dotted quad", "3.1.1.7", true},
	{"public dotted quad as version", "8.8.8.8", true},

	{"private address", "10.0.0.7", false},
	{"private address with leading zeros", "192.168.001.010", false},
	{"private address with leading zero on every octet", "010.000.000.001", false},
	{"private address with extra leading zeros", "0010.0.0.1", false},
	{"private address with dash suffix", "192.168.10.5-1", false},
	{"private address with rc suffix", "10.0.0.7-rc1", false},
	{"private address with extra label", "10.0.0.7.0", false},
	{"private address 172.16/12", "172.16.5.4", false},
	{"private address 192.168/16", "192.168.1.1", false},
	{"shared address space with suffix", "100.110.12.7-1", false},
	{"loopback", "127.0.0.1", false},
	{"loopback with suffix", "127.0.0.1-2", false},
	{"zero network", "0.1.2.3", false},
	{"link-local", "169.254.1.1", false},
	{"multicast", "224.0.0.9", false},
	{"class E", "240.0.0.1", false},

	{"IPv6 literal", "2001:db8::1", false},
	{"hyphenated six-octet MAC", "00-11-22-33-44-55", false},
	{"dotted six-octet MAC", "00.11.22.33.44.55", false},
	{"mixed separator six-octet MAC", "00.11-22-33-44-55", false},
	{"mixed separator three-quad MAC", "0011.2233-4455", false},
	{"Cisco dotted MAC", "0011.2233.4455", false},
	{"bare MAC", "001122334455", false},
	{"host label", "sw01", false},
	{"host label after version", "3.1.1.7-core-sw01", false},
	{"empty firmware", "", false},
}
