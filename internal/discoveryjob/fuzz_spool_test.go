// SPDX-License-Identifier: AGPL-3.0-or-later

package discoveryjob

import (
	"encoding/json"
	"net"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// Seeds use only documentation networks (RFC 5737, RFC 3849).
const (
	seedJobID    = "0b9c2f7e-4a51-4c8e-9a51-6f0d3c2b1a00"
	seedResultOK = `{"format":"nebula-discovery-result-v1","job":"` + seedJobID + `","started_at":1,"finished_at":2,"ok":true,` +
		`"hosts":[{"address":"192.0.2.10","hostname":"Host.example.","os":"Linux 5.x",` +
		`"ports":[{"port":22,"protocol":"tcp","state":"open","service":"ssh","product":"OpenSSH","version":"9.6"}]}]}`
)

// allowedStates is the state allowlist of spec 12 (stateWord). Any other
// state from the unprivileged process must come out as "unknown".
var allowedStates = map[string]bool{
	"open": true, "closed": true, "filtered": true, "unfiltered": true,
	"open|filtered": true, "closed|filtered": true, "unknown": true,
}

// FuzzDecodeResult: a result file is written by the unprivileged discovery
// process. After decodeStrict and Clean every bound holds, and Clean is
// idempotent and survives a round trip through JSON unchanged.
func FuzzDecodeResult(f *testing.F) {
	f.Add([]byte(seedResultOK))
	f.Add([]byte(seedResultOK + ` {}`))
	f.Add([]byte(`{"format":"nebula-discovery-result-v1","job":"` + seedJobID + `","ok":true,"unknown":1}`))
	f.Add([]byte(`{"format":"nebula-discovery-result-v1","job":"` + seedJobID + `","ok":true,` +
		`"hosts":[{"address":"192.0.2.10"},{"address":"192.0.2.10","vendor":"x"},{"address":"2001:db8::1%eth0"}]}`))
	// A control character (JSON escape) and a zero-width space (built in Go) in the error text.
	f.Add([]byte(`{"format":"nebula-discovery-result-v1","job":"` + seedJobID + `","ok":false,"error":"a\u0007b` +
		string(rune(0x200B)) + `c",` +
		`"hosts":[{"address":"::ffff:198.51.100.7","hostname":"Ünter.example"}]}`))
	f.Add([]byte(`{"format":"nebula-discovery-result-v1","job":"` + seedJobID + `","hosts":[{"address":"203.0.113.1",` +
		`"ports":[{"port":0,"protocol":"tcp"},{"port":80,"protocol":"sctp"},{"port":80,"protocol":"tcp"},{"port":80,"protocol":"tcp"}]}]}`))
	// Upper-case MAC with dashes must be normalised; an invalid one must be dropped.
	f.Add([]byte(`{"format":"nebula-discovery-result-v1","job":"` + seedJobID + `","hosts":[{"address":"192.0.2.11",` +
		`"mac":"00-1A-2B-3C-4D-5E"},{"address":"192.0.2.12","mac":"not a mac"}]}`))
	// Port states outside the allowlist must become "unknown"; ports arrive out of order.
	f.Add([]byte(`{"format":"nebula-discovery-result-v1","job":"` + seedJobID + `","hosts":[{"address":"192.0.2.13",` +
		`"ports":[{"port":443,"protocol":"tcp","state":"OPEN"},{"port":22,"protocol":"tcp","state":"open"},` +
		`{"port":53,"protocol":"udp","state":"open|filtered"},{"port":9,"protocol":"tcp","state":"<b>"}]}]}`))
	// U+2028 and U+2029 in vendor and product text (built in Go) must be replaced.
	f.Add([]byte(`{"format":"nebula-discovery-result-v1","job":"` + seedJobID + `","hosts":[{"address":"192.0.2.14",` +
		`"vendor":"a` + string(rune(0x2028)) + `b","ports":[{"port":22,"protocol":"tcp","state":"open",` +
		`"product":"c` + string(rune(0x2029)) + `d"}]}]}`))
	// A hostname that is not a DNS name must be dropped.
	f.Add([]byte(`{"format":"nebula-discovery-result-v1","job":"` + seedJobID + `","hosts":[{"address":"192.0.2.15",` +
		`"hostname":"bad_label.example"}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var r Result
		if err := decodeStrict(data, &r); err != nil {
			return
		}
		if err := r.Clean(); err != nil {
			return
		}
		checkResult(t, r)

		// A second Clean on a deep copy changes nothing. A shallow copy would
		// share Hosts and Ports arrays with r, so an in-place rewrite by Clean
		// would change both values the same way and go unnoticed.
		again := cloneResult(r)
		if err := again.Clean(); err != nil {
			t.Fatalf("second Clean: %v", err)
		}
		if !reflect.DeepEqual(r, again) {
			t.Fatalf("second Clean changed the result:\n%+v\n%+v", r, again)
		}

		// Encoding, decoding and cleaning again gives the same value.
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var rt Result
		if err := decodeStrict(b, &rt); err != nil {
			t.Fatalf("decode of own encoding: %v", err)
		}
		if err := rt.Clean(); err != nil {
			t.Fatalf("clean of own encoding: %v", err)
		}
		if !reflect.DeepEqual(r, rt) {
			t.Fatalf("round trip changed the result:\n%+v\n%+v", r, rt)
		}
	})
}

// cloneResult copies r including the Hosts slice and each Ports slice, so
// that the copy shares no backing array with r. Nil and empty slices stay
// as they are, so reflect.DeepEqual compares like with like.
func cloneResult(r Result) Result {
	c := r
	if r.Hosts != nil {
		c.Hosts = make([]Host, len(r.Hosts))
		for i, h := range r.Hosts {
			if h.Ports != nil {
				h.Ports = append(make([]Port, 0, len(h.Ports)), h.Ports...)
			}
			c.Hosts[i] = h
		}
	}
	return c
}

// checkResultText requires untrusted text to be valid UTF-8, within MaxText,
// free of control and invisible formatting characters, and free of the
// Unicode line and paragraph separators that Text replaces.
func checkResultText(t *testing.T, s string) {
	t.Helper()
	checkText(t, s)
	if !utf8.ValidString(s) {
		t.Fatalf("invalid UTF-8 in %q", s)
	}
	if strings.ContainsRune(s, ' ') || strings.ContainsRune(s, ' ') {
		t.Fatalf("line or paragraph separator in %q", s)
	}
}

// checkMAC requires an empty MAC or the normalised form that mac() produces:
// six octets, lower-case, colon-separated.
func checkMAC(t *testing.T, s string) {
	t.Helper()
	if s == "" {
		return
	}
	hw, err := net.ParseMAC(s)
	if err != nil || len(hw) != 6 {
		t.Fatalf("MAC %q is not six octets", s)
	}
	if hw.String() != s {
		t.Fatalf("MAC %q is not in normalised form %q", s, hw.String())
	}
}

// checkHostname requires an empty hostname or a lower-case DNS name without
// a trailing dot, at most 253 bytes, with labels of 1 to 63 bytes made of
// [a-z0-9-] that neither start nor end with a hyphen (the hostname rule).
func checkHostname(t *testing.T, s string) {
	t.Helper()
	if s == "" {
		return
	}
	if len(s) > 253 || strings.HasSuffix(s, ".") {
		t.Fatalf("hostname %q has bad length or trailing dot", s)
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			t.Fatalf("hostname %q has a bad label %q", s, label)
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				t.Fatalf("hostname %q has character %q", s, c)
			}
		}
	}
}

// checkResult requires every bound of a cleaned result (spec 12, see
// Result.Clean and the limits in job.go).
func checkResult(t *testing.T, r Result) {
	t.Helper()
	if r.Format != ResultFormat {
		t.Fatalf("format %q", r.Format)
	}
	if !ValidID(r.Job) {
		t.Fatalf("job ID %q", r.Job)
	}
	checkResultText(t, r.Error)
	if len(r.Hosts) > MaxHosts {
		t.Fatalf("%d hosts", len(r.Hosts))
	}
	seen := map[string]bool{}
	for i, h := range r.Hosts {
		a, err := netip.ParseAddr(h.Address)
		if err != nil {
			t.Fatalf("address %q: %v", h.Address, err)
		}
		if a.Zone() != "" || a.Unmap().String() != h.Address {
			t.Fatalf("address %q is not a plain canonical address", h.Address)
		}
		if seen[h.Address] {
			t.Fatalf("duplicate address %q", h.Address)
		}
		seen[h.Address] = true
		if i > 0 {
			prev, _ := netip.ParseAddr(r.Hosts[i-1].Address)
			if !prev.Less(a) {
				t.Fatalf("hosts not sorted: %q before %q", prev, a)
			}
		}
		checkMAC(t, h.MAC)
		checkResultText(t, h.Vendor)
		checkResultText(t, h.OS)
		checkHostname(t, h.Hostname)
		if len(h.Ports) > MaxPortsPerHost {
			t.Fatalf("%d ports on %s", len(h.Ports), h.Address)
		}
		ports := map[string]bool{}
		for pi, p := range h.Ports {
			if p.Port < 1 || p.Port > 65535 {
				t.Fatalf("port %d", p.Port)
			}
			if p.Protocol != "tcp" && p.Protocol != "udp" {
				t.Fatalf("protocol %q", p.Protocol)
			}
			if !allowedStates[p.State] {
				t.Fatalf("state %q is not on the allowlist", p.State)
			}
			key := p.Protocol + "/" + strconv.Itoa(p.Port)
			if ports[key] {
				t.Fatalf("duplicate port %d/%s on %s", p.Port, p.Protocol, h.Address)
			}
			ports[key] = true
			if pi > 0 {
				prev := h.Ports[pi-1]
				if prev.Protocol > p.Protocol || prev.Protocol == p.Protocol && prev.Port >= p.Port {
					t.Fatalf("ports not sorted on %s: %s/%d before %s/%d", h.Address, prev.Protocol, prev.Port, p.Protocol, p.Port)
				}
			}
			checkResultText(t, p.Service)
			checkResultText(t, p.Product)
			checkResultText(t, p.Version)
		}
	}
}

// FuzzDecodeJob: a job file is written by the server and read by discovery.
// A job that decodes and validates must yield arguments that pass checkArgs.
func FuzzDecodeJob(f *testing.F) {
	f.Add([]byte(`{"format":"nebula-discovery-job-v1","id":"` + seedJobID + `","mode":"ports",` +
		`"targets":["192.0.2.0/24"],"ports":"22,80","created_at":1}`))
	f.Add([]byte(`{"format":"nebula-discovery-job-v1","id":"` + seedJobID + `","mode":"ping",` +
		`"targets":["198.51.100.7"],"created_at":1} {}`))
	f.Add([]byte(`{"format":"nebula-discovery-job-v1","id":"` + seedJobID + `","mode":"custom",` +
		`"targets":["2001:db8::/120"],"created_at":1,"custom":{"udp":true,"ports":"53","timing":4}}`))
	f.Add([]byte(`{"format":"nebula-discovery-job-v1","id":"` + seedJobID + `","mode":"ping",` +
		`"targets":["203.0.113.0/24","203.0.113.0/24"],"created_at":1,"unknown":true}`))
	f.Add([]byte(`{"format":"nebula-discovery-job-v1","id":"` + seedJobID + `","mode":"ping",` +
		`"targets":["2001:db8::1%eth0"],"created_at":1}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var j Job
		if err := decodeStrict(data, &j); err != nil {
			return
		}
		if err := j.Validate(); err != nil {
			return
		}
		args, err := j.Args()
		if err != nil {
			t.Fatalf("valid job has no arguments: %v", err)
		}
		checkArgs(t, j, args)
	})
}
