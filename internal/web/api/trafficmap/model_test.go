// SPDX-License-Identifier: AGPL-3.0-or-later

package trafficmap

import (
	"math"
	"net/netip"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func TestCleanTextMakesHostileNamesPrintable(t *testing.T) {
	tests := []struct {
		name, in, want string
		cut            bool
	}{
		{"plain", "web-01", "web-01", false},
		{"html stays text", "<script>alert(1)</script>", "<script>alert(1)</script>", false},
		{"invalid utf8", "a\xffb", "a\xef\xbf\xbdb", false},
		{"controls dropped", "a\x00b\x1b[31mc\x7f", "ab[31mc", false},
		{"newlines become spaces", "a\nb\tc", "a b c", false},
		{"bidi override dropped", "abc\xe2\x80\xaetxt.exe", "abctxt.exe", false},
		{"zero width dropped", "a\xe2\x80\x8bb\xef\xbb\xbf", "ab", false},
		{"trimmed", "  x  ", "x", false},
		{"only controls", "\x00\x01", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, cut := cleanText(tc.in, MaxLabelBytes)
			if got != tc.want || cut != tc.cut {
				t.Fatalf("cleanText(%q) = %q, %v; want %q, %v", tc.in, got, cut, tc.want, tc.cut)
			}
		})
	}
}

func TestCleanTextBoundsLength(t *testing.T) {
	for _, in := range []string{
		strings.Repeat("a", 10*MaxLabelBytes),
		strings.Repeat("ü", MaxLabelBytes),
		strings.Repeat("\U0001F600", MaxLabelBytes),
		strings.Repeat("\x00", 1<<20) + "x",
	} {
		got, cut := cleanText(in, MaxLabelBytes)
		if len(got) > MaxLabelBytes || !utf8.ValidString(got) || !cut {
			t.Fatalf("len %d valid %v cut %v", len(got), utf8.ValidString(got), cut)
		}
		for _, r := range got {
			if !unicode.IsPrint(r) {
				t.Fatalf("non-printable rune %U", r)
			}
		}
	}
}

func FuzzCleanText(f *testing.F) {
	f.Add("web\xe2\x80\xae-01\x00")
	f.Add(strings.Repeat("\xff", 600))
	f.Fuzz(func(t *testing.T, s string) {
		got, _ := cleanText(s, MaxLabelBytes)
		if len(got) > MaxLabelBytes || !utf8.ValidString(got) {
			t.Fatalf("bad output %q", got)
		}
		for _, r := range got {
			if !unicode.IsPrint(r) {
				t.Fatalf("non-printable rune %U", r)
			}
		}
	})
}

func TestValidIDRejectsHostileIDs(t *testing.T) {
	good := []string{"h1", "ep-0a1b", "pve:node1.vm.100", "Z_9"}
	bad := []string{"", "-x", ".x", "a b", "a/b", "a<b", "ä", "a\x00", strings.Repeat("a", MaxIDBytes+1)}
	for _, s := range good {
		if !validID(s) {
			t.Errorf("validID(%q) = false", s)
		}
	}
	for _, s := range bad {
		if validID(s) {
			t.Errorf("validID(%q) = true", s)
		}
	}
}

func TestSoftwareKeyAndIconValidation(t *testing.T) {
	if !validSoftwareKey("postgres") || !validSoftwareKey("nvidia-driver.550_x") {
		t.Fatal("good key rejected")
	}
	for _, k := range []string{"", "Postgres", "-x", "a/b", "a b", strings.Repeat("a", 65)} {
		if validSoftwareKey(k) {
			t.Errorf("key %q accepted", k)
		}
	}
	h := strings.Repeat("ab", 32)
	if !validIconHash(h) {
		t.Fatal("good hash rejected")
	}
	for _, s := range []string{"", strings.ToUpper(h), h[:63], h + "0", "https://example.com/x.png", "../" + h[3:]} {
		if validIconHash(s) {
			t.Errorf("hash %q accepted", s)
		}
	}
}

func TestUnknownHealthStaysNull(t *testing.T) {
	bad := "green"
	nan, neg, big := math.NaN(), -1.0, 101.0
	inf := math.Inf(1)
	units := uint32(maxFailedUnits + 1)
	h := cleanHealth(Health{Patches: &bad, DiskUsedPct: &big, Load: &nan, FailedUnits: &units})
	if h.Patches != nil || h.DiskUsedPct != nil || h.Load != nil || h.FailedUnits != nil ||
		h.Reachable != nil || h.BackupFresh != nil || h.HostKeyMismatch != nil {
		t.Fatalf("unknown or invalid values not null: %+v", h)
	}
	if cleanFloat(&neg, 1) != nil || cleanFloat(&inf, 100) != nil {
		t.Fatal("negative or infinite value kept")
	}
	ok, pct, f := PatchesCritical, 42.5, false
	h = cleanHealth(Health{Patches: &ok, DiskUsedPct: &pct, Reachable: &f})
	if *h.Patches != PatchesCritical || *h.DiskUsedPct != 42.5 || *h.Reachable {
		t.Fatalf("known values lost: %+v", h)
	}
}

func TestResourcesOutOfRangeAreUnknown(t *testing.T) {
	cpu, ram, gpu := uint32(maxVCPU+1), uint64(maxRAMMiB+1), uint32(maxGPUs+1)
	r := cleanResources(Resources{VCPU: &cpu, RAMMiB: &ram, GPUs: &gpu})
	if r.VCPU != nil || r.RAMMiB != nil || r.GPUs != nil {
		t.Fatalf("out of range kept: %+v", r)
	}
	if cleanVLAN(0) != nil || cleanVLAN(4095) != nil || cleanVLAN(-3) != nil || *cleanVLAN(20) != 20 {
		t.Fatal("vlan range")
	}
}

func TestCleanAddr(t *testing.T) {
	for _, s := range []string{"0.0.0.0", "::", "127.0.0.1", "::1", "224.0.0.1", "ff02::1", "fd00::1%eth0"} {
		if _, ok := cleanAddr(netip.MustParseAddr(s)); ok {
			t.Errorf("cleanAddr(%s) accepted", s)
		}
	}
	if _, ok := cleanAddr(netip.Addr{}); ok {
		t.Error("zero address accepted")
	}
	got, ok := cleanAddr(netip.MustParseAddr("::ffff:10.0.0.1"))
	if !ok || got != netip.MustParseAddr("10.0.0.1") {
		t.Errorf("mapped: %v %v", got, ok)
	}
	got, ok = cleanAddr(netip.MustParseAddr("fe80::1%eth0"))
	if !ok || got.Zone() != "" {
		t.Errorf("link-local: %v %v", got, ok)
	}
}

func TestJSONUintClampsToSafeInteger(t *testing.T) {
	if jsonUint(math.MaxUint64) != maxJSONInt || jsonUint(7) != 7 {
		t.Fatal("clamp")
	}
	if satAdd(math.MaxUint64, 1) != math.MaxUint64 {
		t.Fatal("satAdd overflow")
	}
}
