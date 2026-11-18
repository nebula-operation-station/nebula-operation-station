// SPDX-License-Identifier: AGPL-3.0-or-later

package helpcmd

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// adrClassNames is the initial placeholder table of ADR 0014 D4, copied by
// hand from the ADR text so that a change to either side fails a test.
var adrClassNames = map[PlaceholderClass][]string{
	ClassHost:    {"host", "host-address", "ip", "rp-id", "firewall-mgmt-ip"},
	ClassDate:    {"date"},
	ClassVersion: {"version"},
	ClassID:      {"digest", "execution-id", "id"},
}

// TestPlaceholderNamesHaveTheirClass checks that every name of the ADR table
// maps to exactly its class.
func TestPlaceholderNamesHaveTheirClass(t *testing.T) {
	for class, names := range adrClassNames {
		for _, name := range names {
			got, ok := LookupPlaceholder(name)
			if !ok || got != class {
				t.Errorf("LookupPlaceholder(%q) = %v, %v; want %v, true", name, got, ok, class)
			}
		}
	}
}

// TestUnknownPlaceholderHasNoClass checks that there is no default class:
// a name outside the table, including near misses, has no class at all.
func TestUnknownPlaceholderHasNoClass(t *testing.T) {
	names := []string{
		"", "unknown", "hostname", "host ", " host", "Host", "HOST", "host_address",
		"host-addr", "ip4", "ips", "rp", "rp-id-x", "dates", "versions", "ids",
		"digests", "execution", "execution_id", "evil.example", "host.example",
	}
	for _, name := range names {
		if class, ok := LookupPlaceholder(name); ok || class != ClassNone {
			t.Errorf("LookupPlaceholder(%q) = %v, %v; want no class", name, class, ok)
		}
		err := CheckPlaceholderValue(ClassNone, "x", true)
		if !errors.Is(err, ErrNoPlaceholderClass) {
			t.Errorf("CheckPlaceholderValue(ClassNone) error = %v; want ErrNoPlaceholderClass", err)
		}
	}
}

// TestUnknownClassValueIsRejected checks that a class value outside the table
// is rejected rather than checked against some default rule.
func TestUnknownClassValueIsRejected(t *testing.T) {
	bogus := PlaceholderClass(99)
	if err := CheckPlaceholderValue(bogus, "10.0.0.1", true); !errors.Is(err, ErrNoPlaceholderClass) {
		t.Errorf("CheckPlaceholderValue(99) error = %v; want ErrNoPlaceholderClass", err)
	}
}

// TestVersionAcceptsADRExamples checks the version shape with and without a
// prerelease part.
func TestVersionAcceptsADRExamples(t *testing.T) {
	ok := []string{
		"1.4.0", "1.4.0-rc.1", "10.0.123", "1.4.0-beta2", "2026.11.17-rc.2",
		"0.0.1", "9999.9999.9999", "1.4.0-" + strings.Repeat("a", 16),
		"1.4.0-rc1.12",
	}
	for _, v := range ok {
		if err := CheckPlaceholderValue(ClassVersion, v, true); err != nil {
			t.Errorf("version %q: unexpected error %v", v, err)
		}
	}
}

// TestVersionRejectsBadShapes checks the counterexample of ADR 0014 D4
// (`1.4.0-evil.example`, a DNS suffix in the prerelease) and other shapes.
func TestVersionRejectsBadShapes(t *testing.T) {
	bad := []string{
		"1.4.0-evil.example", "1.4", "1.4.0.1", "12345.0.0", "1.4.0-",
		"1.4.0-rc.1.2", "1.4.0-" + strings.Repeat("a", 17), "v1.4.0", "1.4.x",
		"1.4.0-rc_1", "1.4.0 ", " 1.4.0", "1.4.0\n", "1.4.0-rc.12345",
		"evil.example", "", "1..0",
	}
	for _, v := range bad {
		if err := CheckPlaceholderValue(ClassVersion, v, true); !errors.Is(err, ErrPlaceholderValue) {
			t.Errorf("version %q: error = %v; want ErrPlaceholderValue", v, err)
		}
	}
}

// TestIDRejectsDNSNameAndIPv6 checks that an id value can never be a DNS name
// or an IP literal, whether it is the whole token or not.
func TestIDRejectsDNSNameAndIPv6(t *testing.T) {
	bad := []string{
		"evil.example", "a.b", "10.0.0.1", "fe80::1", "2001:db8::1", "::1",
		"a:b", "id:8006", "a/b", "a@b", "a b", "a?b", "a#b", "a%b", "",
	}
	for _, v := range bad {
		for _, whole := range []bool{true, false} {
			if err := CheckPlaceholderValue(ClassID, v, whole); !errors.Is(err, ErrPlaceholderValue) {
				t.Errorf("id %q (whole=%v): error = %v; want ErrPlaceholderValue", v, whole, err)
			}
		}
	}
}

// TestIDAcceptsShape checks the accepted id alphabet.
func TestIDAcceptsShape(t *testing.T) {
	ok := []string{"a", "digest-1_a", "ABC-xyz_09", "0", strings.Repeat("x", 128)}
	for _, v := range ok {
		if err := CheckPlaceholderValue(ClassID, v, true); err != nil {
			t.Errorf("id %q: unexpected error %v", v, err)
		}
	}
}

// TestIDLengthLimit checks the 128-byte limit at the limit and at limit+1.
func TestIDLengthLimit(t *testing.T) {
	if err := CheckPlaceholderValue(ClassID, strings.Repeat("a", 128), true); err != nil {
		t.Errorf("id of 128 bytes: unexpected error %v", err)
	}
	if err := CheckPlaceholderValue(ClassID, strings.Repeat("a", 129), true); !errors.Is(err, ErrPlaceholderValue) {
		t.Errorf("id of 129 bytes: error = %v; want ErrPlaceholderValue", err)
	}
}

// TestDateOnlyISOShape checks that a date is YYYY-MM-DD and nothing else.
func TestDateOnlyISOShape(t *testing.T) {
	ok := []string{"2026-11-17", "0001-01-01", "9999-12-31"}
	for _, v := range ok {
		if err := CheckPlaceholderValue(ClassDate, v, true); err != nil {
			t.Errorf("date %q: unexpected error %v", v, err)
		}
	}
	bad := []string{
		"2026-1-17", "2026/11/17", "20261117", "2026-11-17T00", " 2026-11-17",
		"2026-11-17\n", "2026-11-17 ", "26-11-17", "2026-11-1a", "", "2026.11.17",
		"2026-11-17-01", "evil.example",
	}
	for _, v := range bad {
		if err := CheckPlaceholderValue(ClassDate, v, true); !errors.Is(err, ErrPlaceholderValue) {
			t.Errorf("date %q: error = %v; want ErrPlaceholderValue", v, err)
		}
	}
}

// hostName builds a DNS name of n bytes out of 63-byte labels, with the rest
// in a last label.
func hostName(n int) string {
	label := strings.Repeat("a", 63)
	name := label + "." + label + "." + label + "."
	return name + strings.Repeat("b", n-len(name))
}

// TestHostLabelLengthLimit checks the 63-byte label limit at the limit and at
// limit+1.
func TestHostLabelLengthLimit(t *testing.T) {
	if err := CheckPlaceholderValue(ClassHost, strings.Repeat("a", 63)+".example", true); err != nil {
		t.Errorf("label of 63 bytes: unexpected error %v", err)
	}
	if err := CheckPlaceholderValue(ClassHost, strings.Repeat("a", 64)+".example", true); !errors.Is(err, ErrPlaceholderValue) {
		t.Errorf("label of 64 bytes: error = %v; want ErrPlaceholderValue", err)
	}
}

// TestHostNameLengthLimit checks the 253-byte limit of a DNS name at the limit
// and at limit+1.
func TestHostNameLengthLimit(t *testing.T) {
	if got := len(hostName(253)); got != 253 {
		t.Fatalf("test name has %d bytes, want 253", got)
	}
	if err := CheckPlaceholderValue(ClassHost, hostName(253), true); err != nil {
		t.Errorf("name of 253 bytes: unexpected error %v", err)
	}
	if err := CheckPlaceholderValue(ClassHost, hostName(254), true); !errors.Is(err, ErrPlaceholderValue) {
		t.Errorf("name of 254 bytes: error = %v; want ErrPlaceholderValue", err)
	}
}

// TestHostHyphenAtLabelEdge checks that a label may not start or end with `-`
// and that a hyphen inside a label is fine.
func TestHostHyphenAtLabelEdge(t *testing.T) {
	ok := []string{"a-b.example", "pve-01", "a--b", "x-y.z-w"}
	for _, v := range ok {
		if err := CheckPlaceholderValue(ClassHost, v, true); err != nil {
			t.Errorf("host %q: unexpected error %v", v, err)
		}
	}
	bad := []string{"-a.example", "a-.example", "a.-b", "a.b-", "-", "a.-", "-a"}
	for _, v := range bad {
		if err := CheckPlaceholderValue(ClassHost, v, true); !errors.Is(err, ErrPlaceholderValue) {
			t.Errorf("host %q: error = %v; want ErrPlaceholderValue", v, err)
		}
	}
}

// TestHostIPv6OnlyAsWholeToken checks that an IPv6 literal is a host value only
// when the placeholder is the whole token.
func TestHostIPv6OnlyAsWholeToken(t *testing.T) {
	ok := []string{"fe80::1", "2001:db8::1", "::1", "::ffff:192.0.2.1"}
	for _, v := range ok {
		if err := CheckPlaceholderValue(ClassHost, v, true); err != nil {
			t.Errorf("IPv6 %q as whole token: unexpected error %v", v, err)
		}
		if err := CheckPlaceholderValue(ClassHost, v, false); !errors.Is(err, ErrPlaceholderValue) {
			t.Errorf("IPv6 %q inside a token: error = %v; want ErrPlaceholderValue", v, err)
		}
	}
	bad := []string{
		"fe80::1%eth0", "[fe80::1]", "fe80::1/64", "fe80::g", "1:2:3", "fe80:::1",
		"10.0.0.1:8006", "::1:",
	}
	for _, v := range bad {
		if err := CheckPlaceholderValue(ClassHost, v, true); !errors.Is(err, ErrPlaceholderValue) {
			t.Errorf("host %q as whole token: error = %v; want ErrPlaceholderValue", v, err)
		}
	}
}

// TestHostIPv4AndDNSForms checks the accepted host forms and the out-of-range
// IPv4 values, which must not fall through to the DNS rule.
func TestHostIPv4AndDNSForms(t *testing.T) {
	ok := []string{"10.0.0.1", "255.255.255.255", "0.0.0.0", "nas", "pve-01.lan.example", "a1.b2.c3"}
	for _, v := range ok {
		if err := CheckPlaceholderValue(ClassHost, v, true); err != nil {
			t.Errorf("host %q: unexpected error %v", v, err)
		}
	}
	bad := []string{"10.0.0.256", "256.0.0.1", "01.2.3.4", "1.2.3.4.", "1.2.3.-4", ".1.2.3"}
	for _, v := range bad {
		if err := CheckPlaceholderValue(ClassHost, v, true); !errors.Is(err, ErrPlaceholderValue) {
			t.Errorf("host %q: error = %v; want ErrPlaceholderValue", v, err)
		}
	}
}

// TestHostRejectsEachForbiddenCharacter checks each character that ADR 0014
// forbids in a host value, alone, inside and as the whole token.
func TestHostRejectsEachForbiddenCharacter(t *testing.T) {
	for _, c := range "/:@?#%" {
		v := "host" + string(c) + "x.example"
		for _, whole := range []bool{true, false} {
			if err := CheckPlaceholderValue(ClassHost, v, whole); !errors.Is(err, ErrPlaceholderValue) {
				t.Errorf("host %q (whole=%v): error = %v; want ErrPlaceholderValue", v, whole, err)
			}
		}
	}
	// Other characters outside the label alphabet are rejected too.
	for _, c := range " _*\"'$`\\!~,=+<>()[]{}\t\x7f" {
		v := "host" + string(c) + "x"
		if err := CheckPlaceholderValue(ClassHost, v, true); !errors.Is(err, ErrPlaceholderValue) {
			t.Errorf("host %q: error = %v; want ErrPlaceholderValue", v, err)
		}
	}
	if err := CheckPlaceholderValue(ClassHost, "hö.example", true); !errors.Is(err, ErrPlaceholderValue) {
		t.Errorf("non-ASCII host: error = %v; want ErrPlaceholderValue", err)
	}
}

// TestHostEmptyAndTooLong checks the empty value and a value of 254 bytes made
// of labels that would each be valid.
func TestHostEmptyAndTooLong(t *testing.T) {
	if err := CheckPlaceholderValue(ClassHost, "", true); !errors.Is(err, ErrPlaceholderValue) {
		t.Errorf("empty host: error = %v; want ErrPlaceholderValue", err)
	}
	if err := CheckPlaceholderValue(ClassHost, strings.Repeat("a.", 127)+"a", true); !errors.Is(err, ErrPlaceholderValue) {
		t.Errorf("host of 255 bytes: error = %v; want ErrPlaceholderValue", err)
	}
}

// TestLookupIsExact checks that the lookup does not match suffixes, prefixes
// or case variants of a table name.
func TestLookupIsExact(t *testing.T) {
	for _, name := range []string{"xrp-id", "rp-idx", "firewall-mgmt-ip-2", "my-host", "host-address2", "ids-x"} {
		if class, ok := LookupPlaceholder(name); ok {
			t.Errorf("LookupPlaceholder(%q) = %v; want no class (exact names only)", name, class)
		}
	}
}

// FuzzPlaceholderHost checks that arbitrary host values never panic and that
// an accepted value contains no forbidden character, and a colon only in the
// whole-token IPv6 case.
func FuzzPlaceholderHost(f *testing.F) {
	for _, s := range []string{"10.0.0.1", "nas", "fe80::1", "a:b", "x/y", "a@b", "", "a.b-", "::1%eth0"} {
		f.Add(s, true)
		f.Add(s, false)
	}
	f.Fuzz(func(t *testing.T, value string, whole bool) {
		err := CheckPlaceholderValue(ClassHost, value, whole)
		if err != nil {
			return
		}
		if strings.ContainsAny(value, "/@?#%") {
			t.Fatalf("accepted host %q contains a forbidden character", value)
		}
		if strings.Contains(value, ":") {
			if !whole {
				t.Fatalf("accepted host %q with ':' outside a whole token", value)
			}
			addr, perr := netip.ParseAddr(value)
			if perr != nil || !addr.Is6() {
				t.Fatalf("accepted host %q with ':' is not an IPv6 literal", value)
			}
		}
		if len(value) > 253 {
			t.Fatalf("accepted host of %d bytes", len(value))
		}
	})
}

// FuzzPlaceholderID checks that arbitrary id values never panic and that an
// accepted value contains neither `.` nor `:`.
func FuzzPlaceholderID(f *testing.F) {
	for _, s := range []string{"digest-1", "evil.example", "fe80::1", "", "a_b-c"} {
		f.Add(s, true)
	}
	f.Fuzz(func(t *testing.T, value string, whole bool) {
		if err := CheckPlaceholderValue(ClassID, value, whole); err != nil {
			return
		}
		if strings.ContainsAny(value, ".:") {
			t.Fatalf("accepted id %q contains '.' or ':'", value)
		}
		if len(value) == 0 || len(value) > 128 {
			t.Fatalf("accepted id of %d bytes", len(value))
		}
	})
}

// FuzzPlaceholderDate checks that arbitrary date values never panic and that
// an accepted value has the YYYY-MM-DD shape.
func FuzzPlaceholderDate(f *testing.F) {
	for _, s := range []string{"2026-11-17", "2026-1-17", "", "2026-11-17\n"} {
		f.Add(s, true)
	}
	f.Fuzz(func(t *testing.T, value string, whole bool) {
		if err := CheckPlaceholderValue(ClassDate, value, whole); err != nil {
			return
		}
		if len(value) != 10 || value[4] != '-' || value[7] != '-' {
			t.Fatalf("accepted date %q does not have the YYYY-MM-DD shape", value)
		}
	})
}

// FuzzPlaceholderVersion checks that arbitrary version values never panic and
// that an accepted value has at most one `-` and no DNS-like label.
func FuzzPlaceholderVersion(f *testing.F) {
	for _, s := range []string{"1.4.0", "1.4.0-rc.1", "1.4.0-evil.example", "", "1.4"} {
		f.Add(s, true)
	}
	f.Fuzz(func(t *testing.T, value string, whole bool) {
		if err := CheckPlaceholderValue(ClassVersion, value, whole); err != nil {
			return
		}
		if strings.Count(value, "-") > 1 || strings.ContainsAny(value, "/:@?#%") {
			t.Fatalf("accepted version %q has a forbidden shape", value)
		}
		if i := strings.IndexByte(value, '-'); i >= 0 && strings.Count(value[i:], ".") > 1 {
			t.Fatalf("accepted version %q has more than one prerelease dot part", value)
		}
	})
}
