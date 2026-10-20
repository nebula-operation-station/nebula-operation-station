// SPDX-License-Identifier: AGPL-3.0-or-later

package discoveryjob

import (
	"net/netip"
	"regexp"
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
				// The bound is per field (Text truncates each), not their sum.
				for _, txt := range []string{p.Service, p.Product, p.Version} {
					checkText(t, txt)
				}
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
		checkArgs(t, j, args)
	})
}

// checkArgs requires every option to come from the fixed set of spec 09:
// a pattern test would let a new option such as -sC or -A through.
func checkArgs(t *testing.T, j Job, args []string) {
	t.Helper()
	targets, err := Targets(j.Targets)
	if err != nil || len(args) < len(targets) {
		t.Fatalf("targets %v: %v", args, err)
	}
	opts, tgts := args[:len(args)-len(targets)], args[len(args)-len(targets):]
	for i, a := range tgts {
		want := targets[i].String()
		if targets[i].IsSingleIP() {
			want = targets[i].Addr().String()
		}
		if a != want || strings.HasPrefix(a, "-") {
			t.Fatalf("target %q, want %q", a, want)
		}
	}
	fixed := []string{"--privileged", "-oX", "-", "--no-stylesheet", "--max-retries", nmapMaxRetries, "--host-timeout", nmapHostTimeout}
	if len(opts) < len(fixed)+1 || strings.Join(opts[:len(fixed)], " ") != strings.Join(fixed, " ") {
		t.Fatalf("fixed options %q", opts)
	}
	rest := opts[len(fixed):]
	if last := rest[len(rest)-1]; last != "-T2" && last != "-T3" && last != "-T4" {
		t.Fatalf("timing %q", last)
	}
	rest = rest[:len(rest)-1]
	flags := map[string]bool{"-6": true, "-sn": true, "-sS": true, "-sU": true, "-sV": true, "-O": true, "-Pn": true, "--open": true, "-p-": true}
	for i := 0; i < len(rest); i++ {
		switch a := rest[i]; {
		case flags[a]:
		case a == "-p" && i+1 < len(rest) && argPortsRe.MatchString(rest[i+1]):
			i++
		case a == "--top-ports" && i+1 < len(rest) && argDigitsRe.MatchString(rest[i+1]):
			i++
		default:
			t.Fatalf("option %q not in the fixed set (%q)", a, args)
		}
	}
}

var (
	argPortsRe  = regexp.MustCompile(`^(T:)?[0-9][0-9,-]*(,U:[0-9][0-9,-]*)?$`)
	argDigitsRe = regexp.MustCompile(`^[0-9]{1,5}$`)
)
