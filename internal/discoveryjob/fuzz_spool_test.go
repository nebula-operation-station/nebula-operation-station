// SPDX-License-Identifier: AGPL-3.0-or-later

package discoveryjob

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"strconv"
	"testing"
)

// Seeds use only documentation networks (RFC 5737, RFC 3849).
const (
	seedJobID    = "0b9c2f7e-4a51-4c8e-9a51-6f0d3c2b1a00"
	seedResultOK = `{"format":"nebula-discovery-result-v1","job":"` + seedJobID + `","started_at":1,"finished_at":2,"ok":true,` +
		`"hosts":[{"address":"192.0.2.10","hostname":"Host.example.","os":"Linux 5.x",` +
		`"ports":[{"port":22,"protocol":"tcp","state":"open","service":"ssh","product":"OpenSSH","version":"9.6"}]}]}`
)

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
	f.Fuzz(func(t *testing.T, data []byte) {
		var r Result
		if err := decodeStrict(data, &r); err != nil {
			return
		}
		if err := r.Clean(); err != nil {
			return
		}
		checkResult(t, r)

		// A second Clean changes nothing.
		again := r
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
	checkText(t, r.Error)
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
		checkText(t, h.Vendor)
		checkText(t, h.OS)
		checkText(t, h.Hostname)
		if len(h.Ports) > MaxPortsPerHost {
			t.Fatalf("%d ports on %s", len(h.Ports), h.Address)
		}
		ports := map[string]bool{}
		for _, p := range h.Ports {
			if p.Port < 1 || p.Port > 65535 {
				t.Fatalf("port %d", p.Port)
			}
			if p.Protocol != "tcp" && p.Protocol != "udp" {
				t.Fatalf("protocol %q", p.Protocol)
			}
			key := p.Protocol + "/" + strconv.Itoa(p.Port)
			if ports[key] {
				t.Fatalf("duplicate port %d/%s on %s", p.Port, p.Protocol, h.Address)
			}
			ports[key] = true
			checkText(t, p.Service)
			checkText(t, p.Product)
			checkText(t, p.Version)
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
