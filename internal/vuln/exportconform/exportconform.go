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
// a lower-case host label, an address, an IPv6 literal and a MAC are refused.
// An address or a MAC embedded in the value, after a prefix or with a suffix,
// is refused too ("IP-10-0-0-7"). The upper-case host label "SW01" is a documented D2 residual and is
// not in the table.
var Model = []Case{
	{"Cisco model", "CBS350", true},
	{"Palo Alto model", "PA-220", true},
	{"model with plus and underscore", "C9300_48U+", true},
	{"lower-case host label", "core-sw01", false},
	{"IPv4 literal", "10.0.0.7", false},
	{"IPv6 literal", "2001:DB8::1", false},
	{"hyphenated MAC", "AA-BB-CC-DD-EE-FF", false},
	{"hyphenated MAC after a prefix", "PA-AA-BB-CC-DD-EE-FF", false},
	{"bare MAC", "AABBCCDDEEFF", false},
	{"host-name style address", "IP-10-0-0-7", false},
	{"host-name style private address with underscores", "SW_192_168_1_1", false},
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

	// A non-public address anywhere in the value, after a version prefix or
	// a separator, is an address and never a version (D3).
	{"private address after dash", "17.3.4-10.0.0.7", false},
	{"private address after underscore", "17.3.4_192.168.1.1", false},
	{"private address after plus", "17.3.4+172.16.5.4", false},
	{"private address after public leading quad", "1.10.0.0.7", false},
	{"private address after public leading quad with leading zeros", "1.010.000.000.007", false},
	{"private address after public quad with suffix", "3.1.1.7-10.0.0.7", false},
	{"shared address space after prefix", "17.3.4-100.110.12.7", false},
	{"loopback after dash", "17.3.4-127.0.0.1", false},
	{"public quad after prefix", "17.3.4-8.8.8.8", true},
	// An octet over 255 is not an address, so the quad alone is not
	// refused; a private quad elsewhere in the value still is.
	{"out-of-range quad is not an address", "300.0.0.1", true},
	{"out-of-range octet of four digits", "1000.10.0.0.1", false},
	{"out-of-range leading octet before private quad", "300.10.0.0.1", false},

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

	// Every allowed separator (. - _ + ~) is one separator for the MAC and
	// address checks, so each mix below is refused like its dotted form.
	{"six-octet MAC with underscores", "00_11_22_33_44_55", false},
	{"six-octet MAC with plus", "00+11+22+33+44+55", false},
	{"six-octet MAC with tilde", "00~11~22~33~44~55", false},
	{"six-octet MAC with dot and underscore", "00.11_22_33_44_55", false},
	{"six-octet MAC with dot and plus", "00.11+22+33+44+55", false},
	{"six-octet MAC with dot and tilde", "00.11~22~33~44~55", false},
	{"six-octet MAC with hyphen and underscore", "00-11_22-33_44-55", false},
	{"three-quad MAC with underscore", "0011_2233_4455", false},
	{"three-quad MAC with dot and underscore", "0011.2233_4455", false},
	{"three-quad MAC with plus", "0011+2233+4455", false},
	{"three-quad MAC with tilde", "0011~2233~4455", false},

	// A private or shared address written with each separator, after a
	// version prefix or a host-name prefix, is an address and is refused.
	{"private address with underscores after prefix", "1.10_0_0_7", false},
	{"private address with dashes after prefix", "17.3.4-10-0-0-7", false},
	{"private address with plus after prefix", "17.3.4+172+16+5+4", false},
	{"private address with tilde after prefix", "17.3.4~192~168~1~1", false},
	{"private address with underscores after public quad", "3.1.1.7_10_0_0_7", false},
	{"private address with underscore suffix", "192.168.10.5_1", false},
	{"private address with underscore leading zeros", "17.3.4_192_168_001_010", false},
	{"shared address space with dashes after prefix", "17.3.4-100-110-12-7", false},
	{"loopback with plus after prefix", "17.3.4+127+0+0+1", false},
	{"host-name style address", "ip-10-0-0-7", false},
	{"bare private address with underscores", "10_0_0_7", false},

	// A public quad written with underscores is a version, not an address.
	{"public quad after prefix with underscores", "17.3.4_8_8_8", true},

	// A MAC with a suffix or after a prefix is a MAC and is refused, like
	// the whole-value form (D3). The MAC is found at any position.
	{"six-octet MAC with dash suffix", "12.34.56.78.90.12-1", false},
	{"three-quad MAC with dash suffix", "1234.5678.9012-1", false},
	{"six-octet MAC after prefix with dashes", "17.3.4-12-34-56-78-90-12", false},
	{"six-octet MAC after prefix with dots", "17.3.4.12.34.56.78.90.12", false},
	{"six-octet MAC after single digit label", "1.12.34.56.78.90.12", false},
	{"three-quad MAC after prefix", "17.3.4-1234.5678.9012", false},
	{"three-quad MAC after prefix with underscore", "17.3.4_1234_5678_9012", false},
	{"bare MAC with dash suffix", "001122334455-1", false},
	{"bare MAC after prefix", "17.3.4-001122334455", false},
	{"longer digit run is not a bare MAC", "1.0011223344551", true},
	{"six pairs with a three-digit last label", "12.34.56.78.90.123", true},
	{"six octets with a one-digit last label are not a MAC", "12.34.56.78.90.1-2", true},
}
