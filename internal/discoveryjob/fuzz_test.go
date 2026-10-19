// SPDX-License-Identifier: AGPL-3.0-or-later

package discoveryjob

import (
	"net/netip"
	"strings"
	"testing"
	"unicode"
)

// Nmap's XML is network data: parsing never panics, and every host it
// returns has a valid address and only clean text.
func FuzzParseNmapXML(f *testing.F) {
	f.Add(sampleXML)
	f.Add(`<nmaprun><host><status state="up"/><address addr="::1" addrtype="ipv6"/></host></nmaprun>`)
	f.Add(`<nmaprun><runstats><finished exit="error" errormsg="x"/></runstats></nmaprun>`)
	f.Fuzz(func(t *testing.T, s string) {
		hosts, err := ParseNmapXML(strings.NewReader(s))
		if err != nil {
			return
		}
		for _, h := range hosts {
			if _, err := netip.ParseAddr(h.Address); err != nil {
				t.Fatalf("address %q", h.Address)
			}
			for _, txt := range []string{h.Vendor, h.OS, h.Hostname} {
				checkText(t, txt)
			}
			if len(h.Ports) > MaxPortsPerHost {
				t.Fatal("too many ports")
			}
			for _, p := range h.Ports {
				checkText(t, p.Service+p.Product+p.Version)
			}
		}
	})
}

func checkText(t *testing.T, s string) {
	t.Helper()
	if len(s) > MaxText {
		t.Fatalf("text of %d bytes", len(s))
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			t.Fatalf("control character in %q", s)
		}
	}
}

// A job that validates produces arguments whose targets cannot be
// options, and only fixed options before them.
func FuzzJobArgs(f *testing.F) {
	f.Add("ping", "192.168.10.0/24", "", false, 0)
	f.Add("ports", "10.0.0.1", "22,80", false, 0)
	f.Add("custom", "fd00::/120", "53", true, 4)
	f.Fuzz(func(t *testing.T, mode, target, ports string, udp bool, timing int) {
		j := Job{Format: JobFormat, ID: "0b9c2f7e-4a51-4c8e-9a51-6f0d3c2b1a00", Mode: Mode(mode), Targets: []string{target}, CreatedAt: 1}
		if mode == string(ModePorts) {
			j.Ports = ports
		}
		if mode == string(ModeCustom) {
			j.Custom = &Custom{Ports: ports, UDP: udp, Timing: timing}
		}
		args, err := j.Args()
		if err != nil {
			return
		}
		last := args[len(args)-1]
		if strings.HasPrefix(last, "-") || strings.ContainsAny(last, " \t\n") {
			t.Fatalf("target %q", last)
		}
		for _, a := range args {
			if strings.Contains(a, "script") || strings.HasPrefix(a, "-i") || strings.HasPrefix(a, "-o") && a != "-oX" {
				t.Fatalf("argument %q", a)
			}
		}
	})
}
