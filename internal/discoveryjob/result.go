// SPDX-License-Identifier: AGPL-3.0-or-later

package discoveryjob

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Port is one port Nmap reported.
type Port struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"` // tcp, udp
	State    string `json:"state"`    // open, closed, filtered, …
	Service  string `json:"service,omitempty"`
	Product  string `json:"product,omitempty"`
	Version  string `json:"version,omitempty"`
}

// Host is one host Nmap found up.
type Host struct {
	Address  string `json:"address"`
	MAC      string `json:"mac,omitempty"` // only when the scanner shares the segment
	Vendor   string `json:"vendor,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	OS       string `json:"os,omitempty"`
	Ports    []Port `json:"ports,omitempty"`
}

// Result is what discovery writes back for a job.
type Result struct {
	Format     string `json:"format"`
	Job        string `json:"job"`
	StartedAt  int64  `json:"started_at"`
	FinishedAt int64  `json:"finished_at"`
	OK         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
	Hosts      []Host `json:"hosts"`
}

// Text makes untrusted text safe to store and show: valid UTF-8, control
// and invisible formatting characters replaced by spaces, trimmed, at most
// MaxText bytes.
func Text(s string) string {
	s = strings.ToValidUTF8(s, "?")
	var b strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' {
			r = ' '
		}
		if b.Len()+utf8.RuneLen(r) > MaxText {
			break
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

// hostname returns s if it is a plausible DNS name (lowercased), else "".
func hostname(s string) string {
	s = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	if s == "" || len(s) > 253 {
		return ""
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return ""
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return ""
			}
		}
	}
	return s
}

func mac(s string) string {
	hw, err := net.ParseMAC(strings.TrimSpace(s))
	if err != nil || len(hw) != 6 {
		return ""
	}
	return hw.String()
}

// Clean validates a host and normalizes its fields; ok is false for a
// host that must be dropped (no valid address).
func (h Host) Clean() (Host, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(h.Address))
	if err != nil || a.Zone() != "" {
		return Host{}, false
	}
	out := Host{Address: a.Unmap().String(), MAC: mac(h.MAC), Vendor: Text(h.Vendor), Hostname: hostname(h.Hostname), OS: Text(h.OS)}
	seen := map[string]bool{}
	for _, p := range h.Ports {
		if len(out.Ports) >= MaxPortsPerHost {
			break
		}
		if p.Port < 1 || p.Port > 65535 || p.Protocol != "tcp" && p.Protocol != "udp" {
			continue
		}
		key := p.Protocol + "/" + strconv.Itoa(p.Port)
		if seen[key] {
			continue
		}
		seen[key] = true
		out.Ports = append(out.Ports, Port{Port: p.Port, Protocol: p.Protocol, State: stateWord(p.State), Service: Text(p.Service),
			Product: Text(p.Product), Version: Text(p.Version)})
	}
	sort.Slice(out.Ports, func(i, j int) bool {
		if out.Ports[i].Protocol != out.Ports[j].Protocol {
			return out.Ports[i].Protocol < out.Ports[j].Protocol
		}
		return out.Ports[i].Port < out.Ports[j].Port
	})
	return out, true
}

func stateWord(s string) string {
	switch s {
	case "open", "closed", "filtered", "unfiltered", "open|filtered", "closed|filtered":
		return s
	}
	return "unknown"
}

// Clean validates a result read from the spool (by the server) or built
// from Nmap output (by discovery): hosts are cleaned, deduplicated by
// address, bounded and sorted; texts are made safe.
func (r *Result) Clean() error {
	if r.Format != ResultFormat || !ValidID(r.Job) {
		return errors.New("not a discovery result")
	}
	if len(r.Hosts) > MaxHosts {
		return errors.New("too many hosts in the result")
	}
	r.Error = Text(r.Error)
	seen := map[string]bool{}
	hosts := make([]Host, 0, len(r.Hosts))
	for _, h := range r.Hosts {
		c, ok := h.Clean()
		if !ok || seen[c.Address] {
			continue
		}
		seen[c.Address] = true
		hosts = append(hosts, c)
	}
	sort.Slice(hosts, func(i, j int) bool {
		a, _ := netip.ParseAddr(hosts[i].Address)
		b, _ := netip.ParseAddr(hosts[j].Address)
		return a.Less(b)
	})
	r.Hosts = hosts
	return nil
}

// --- Nmap XML ---

type xmlRun struct {
	XMLName  xml.Name  `xml:"nmaprun"`
	Hosts    []xmlHost `xml:"host"`
	RunStats struct {
		Finished struct {
			Exit   string `xml:"exit,attr"`
			Errmsg string `xml:"errormsg,attr"`
		} `xml:"finished"`
	} `xml:"runstats"`
}

type xmlHost struct {
	Status struct {
		State string `xml:"state,attr"`
	} `xml:"status"`
	Addresses []struct {
		Addr   string `xml:"addr,attr"`
		Type   string `xml:"addrtype,attr"`
		Vendor string `xml:"vendor,attr"`
	} `xml:"address"`
	Hostnames struct {
		Names []struct {
			Name string `xml:"name,attr"`
			Type string `xml:"type,attr"`
		} `xml:"hostname"`
	} `xml:"hostnames"`
	Ports struct {
		Ports []struct {
			Protocol string `xml:"protocol,attr"`
			PortID   string `xml:"portid,attr"`
			State    struct {
				State string `xml:"state,attr"`
			} `xml:"state"`
			Service struct {
				Name    string `xml:"name,attr"`
				Product string `xml:"product,attr"`
				Version string `xml:"version,attr"`
			} `xml:"service"`
		} `xml:"port"`
	} `xml:"ports"`
	OS struct {
		Matches []struct {
			Name string `xml:"name,attr"`
		} `xml:"osmatch"`
	} `xml:"os"`
}

// ParseNmapXML reads Nmap's XML output (at most MaxNmapXMLBytes) and
// returns the hosts that are up. The XML is untrusted: names, banners and
// versions come from the network.
func ParseNmapXML(r io.Reader) ([]Host, error) {
	lr := &io.LimitedReader{R: r, N: MaxNmapXMLBytes + 1}
	dec := xml.NewDecoder(lr)
	dec.Strict = true
	var run xmlRun
	if err := dec.Decode(&run); err != nil {
		if lr.N <= 0 {
			return nil, errors.New("nmap output is too large")
		}
		return nil, fmt.Errorf("nmap output is not valid XML: %w", err)
	}
	if lr.N <= 0 {
		return nil, errors.New("nmap output is too large")
	}
	if run.RunStats.Finished.Exit == "error" {
		return nil, fmt.Errorf("nmap failed: %s", Text(run.RunStats.Finished.Errmsg))
	}
	var out []Host
	for _, xh := range run.Hosts {
		if xh.Status.State != "up" {
			continue
		}
		var h Host
		for _, a := range xh.Addresses {
			switch a.Type {
			case "ipv4", "ipv6":
				if h.Address == "" {
					h.Address = a.Addr
				}
			case "mac":
				h.MAC, h.Vendor = a.Addr, a.Vendor
			}
		}
		for _, n := range xh.Hostnames.Names {
			if n.Type == "PTR" || n.Type == "user" || h.Hostname == "" {
				h.Hostname = n.Name
				if n.Type == "PTR" {
					break
				}
			}
		}
		for _, p := range xh.Ports.Ports {
			n, err := strconv.Atoi(p.PortID)
			if err != nil {
				continue
			}
			h.Ports = append(h.Ports, Port{Port: n, Protocol: p.Protocol, State: p.State.State, Service: p.Service.Name,
				Product: p.Service.Product, Version: p.Service.Version})
		}
		if len(xh.OS.Matches) > 0 {
			h.OS = xh.OS.Matches[0].Name
		}
		if c, ok := h.Clean(); ok {
			out = append(out, c)
		}
		if len(out) > MaxHosts {
			return nil, errors.New("too many hosts in the nmap output")
		}
	}
	return out, nil
}
