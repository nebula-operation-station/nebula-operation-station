// SPDX-License-Identifier: AGPL-3.0-or-later

package servicecheck

import (
	"strings"
	"testing"
	"time"
)

func TestValidateCheck(t *testing.T) {
	for name, tc := range map[string]struct {
		check  Check
		ok     bool
		reason string
	}{
		"hostname http":       {check: Check{Protocol: "http", Destination: "web1", Port: 80}, ok: true},
		"hostname https":      {check: Check{Protocol: "https", Destination: "web1.lab.example", Port: 443}, ok: true},
		"public ip tcp":       {check: Check{Protocol: "tcp", Destination: "192.0.2.10", Port: 5432}, ok: true},
		"public ip boundary":  {check: Check{Protocol: "tcp", Destination: "172.32.0.1", Port: 80}, ok: true},
		"cgNat boundary":      {check: Check{Protocol: "tcp", Destination: "100.128.0.1", Port: 80}, ok: true},
		"longest hostname":    {check: Check{Protocol: "tcp", Destination: strings.Repeat("a", 63) + "." + strings.Repeat("a", 63) + "." + strings.Repeat("a", 63) + "." + strings.Repeat("a", 61), Port: 80}, ok: true},
		"longest label":       {check: Check{Protocol: "tcp", Destination: strings.Repeat("a", 63), Port: 80}, ok: true},
		"port boundary high":  {check: Check{Protocol: "http", Destination: "web1", Port: 65535}, ok: true},
		"private approved":    {check: Check{Protocol: "tcp", Destination: "192.168.1.10", Port: 9000, InternalApproved: true}, ok: true},
		"ipv6 literal approved": {check: Check{Protocol: "tcp", Destination: "2001:db8::10", Port: 8080, InternalApproved: true}, ok: true},
		"loopback approved":   {check: Check{Protocol: "tcp", Destination: "127.0.0.1", Port: 22, InternalApproved: true}, ok: true},
		"metadata approved":   {check: Check{Protocol: "http", Destination: "169.254.169.254", Port: 80, InternalApproved: true}, ok: true},
		"private":             {check: Check{Protocol: "tcp", Destination: "192.168.1.10", Port: 9000}, ok: false, reason: "internal"},
		"private 10":          {check: Check{Protocol: "tcp", Destination: "10.0.0.5", Port: 445}, ok: false, reason: "internal"},
		"private 172.16":      {check: Check{Protocol: "tcp", Destination: "172.16.0.1", Port: 80}, ok: false, reason: "internal"},
		"link-local metadata": {check: Check{Protocol: "http", Destination: "169.254.169.254", Port: 80}, ok: false, reason: "internal"},
		"loopback":            {check: Check{Protocol: "tcp", Destination: "127.0.0.1", Port: 22}, ok: false, reason: "internal"},
		"this network":        {check: Check{Protocol: "tcp", Destination: "0.0.0.0", Port: 80}, ok: false, reason: "internal"},
		"cgNat":               {check: Check{Protocol: "tcp", Destination: "100.64.0.1", Port: 80}, ok: false, reason: "internal"},
		"cgNat high":          {check: Check{Protocol: "tcp", Destination: "100.127.255.255", Port: 80}, ok: false, reason: "internal"},
		"multicast":           {check: Check{Protocol: "tcp", Destination: "224.0.0.1", Port: 80}, ok: false, reason: "internal"},
		"broadcast":           {check: Check{Protocol: "tcp", Destination: "255.255.255.255", Port: 80}, ok: false, reason: "internal"},
		"ipv6 loopback":       {check: Check{Protocol: "tcp", Destination: "::1", Port: 80}, ok: false, reason: "internal"},
		"ipv6 link-local":     {check: Check{Protocol: "tcp", Destination: "fe80::1", Port: 80}, ok: false, reason: "internal"},
		"ipv6 unique local":   {check: Check{Protocol: "tcp", Destination: "fc00::1", Port: 80}, ok: false, reason: "internal"},
		"ipv6 multicast":      {check: Check{Protocol: "tcp", Destination: "ff02::1", Port: 80}, ok: false, reason: "internal"},
		"scheme":              {check: Check{Protocol: "tcp", Destination: "http://web1", Port: 80}, ok: false, reason: "destination"},
		"embedded port":       {check: Check{Protocol: "tcp", Destination: "web1:80", Port: 80}, ok: false, reason: "destination"},
		"path":                {check: Check{Protocol: "tcp", Destination: "web1.evil/x", Port: 80}, ok: false, reason: "destination"},
		"userinfo":            {check: Check{Protocol: "tcp", Destination: "web1@evil", Port: 80}, ok: false, reason: "destination"},
		"space":               {check: Check{Protocol: "tcp", Destination: " web1", Port: 80}, ok: false, reason: "destination"},
		"leading hyphen":      {check: Check{Protocol: "tcp", Destination: "-web1", Port: 80}, ok: false, reason: "destination"},
		"trailing dot":        {check: Check{Protocol: "tcp", Destination: "web1.", Port: 80}, ok: false, reason: "destination"},
		"underscore":          {check: Check{Protocol: "tcp", Destination: "web_1", Port: 80}, ok: false, reason: "destination"},
		"empty label":         {check: Check{Protocol: "tcp", Destination: "a..b", Port: 80}, ok: false, reason: "destination"},
		"empty":               {check: Check{Protocol: "tcp", Destination: "", Port: 80}, ok: false, reason: "destination"},
		"too long":            {check: Check{Protocol: "tcp", Destination: strings.Repeat("a", 254), Port: 80}, ok: false, reason: "destination"},
		"long label":          {check: Check{Protocol: "tcp", Destination: strings.Repeat("a", 64), Port: 80}, ok: false, reason: "destination"},
		"bad protocol":        {check: Check{Protocol: "udp", Destination: "web1", Port: 80}, ok: false, reason: "protocol"},
		"port zero":           {check: Check{Protocol: "http", Destination: "web1", Port: 0}, ok: false, reason: "port"},
		"port high":           {check: Check{Protocol: "http", Destination: "web1", Port: 65536}, ok: false, reason: "port"},
	} {
		t.Run(name, func(t *testing.T) {
			err := ValidateCheck(tc.check)
			if tc.ok {
				if err != nil {
					t.Fatalf("rejected: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("accepted %v", tc.check)
			}
			if !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("error %q does not name %q", err, tc.reason)
			}
		})
	}
}

func TestParseResult(t *testing.T) {
	for name, tc := range map[string]struct {
		doc  string
		want Result
	}{
		"ok http": {
			doc:  `{"format":"service-check-v1","phase":"done","status":"ok","latency_ms":12,"http_status":200}`,
			want: Result{Status: StatusOK, Latency: 12 * time.Millisecond, HTTPStatus: 200},
		},
		"ok tcp": {
			doc:  `{"format":"service-check-v1","phase":"done","status":"ok","latency_ms":0,"http_status":0}`,
			want: Result{Status: StatusOK, Latency: 0, HTTPStatus: 0},
		},
		"redirect": {
			doc:  `{"format":"service-check-v1","phase":"done","status":"redirect","latency_ms":8,"http_status":301}`,
			want: Result{Status: StatusRedirect, Latency: 8 * time.Millisecond, HTTPStatus: 301},
		},
		"http error": {
			doc:  `{"format":"service-check-v1","phase":"done","status":"http-error","latency_ms":23,"http_status":503}`,
			want: Result{Status: StatusHTTPError, Latency: 23 * time.Millisecond, HTTPStatus: 503},
		},
		"refused": {
			doc:  `{"format":"service-check-v1","phase":"done","status":"refused","latency_ms":3,"http_status":0}`,
			want: Result{Status: StatusRefused, Latency: 3 * time.Millisecond, HTTPStatus: 0},
		},
		"timeout": {
			doc:  `{"format":"service-check-v1","phase":"done","status":"timeout","latency_ms":5000,"http_status":0}`,
			want: Result{Status: StatusTimeout, Latency: 5 * time.Second, HTTPStatus: 0},
		},
		"unresolved": {
			doc:  `{"format":"service-check-v1","phase":"done","status":"unresolved","latency_ms":0,"http_status":0}`,
			want: Result{Status: StatusUnresolved, Latency: 0, HTTPStatus: 0},
		},
		"tls error": {
			doc:  `{"format":"service-check-v1","phase":"done","status":"tls-error","latency_ms":40,"http_status":0}`,
			want: Result{Status: StatusTLS, Latency: 40 * time.Millisecond, HTTPStatus: 0},
		},
		"error": {
			doc:  `{"format":"service-check-v1","phase":"done","status":"error","latency_ms":7,"http_status":0}`,
			want: Result{Status: StatusError, Latency: 7 * time.Millisecond, HTTPStatus: 0},
		},
		"wrong format": {
			doc: `{"format":"other-v1","phase":"done","status":"ok","latency_ms":1,"http_status":200}`,
		},
		"precheck phase": {
			doc: `{"format":"service-check-v1","phase":"precheck","reason":"x"}`,
		},
		"negative latency": {
			doc: `{"format":"service-check-v1","phase":"done","status":"ok","latency_ms":-1,"http_status":200}`,
		},
		"latency above bound": {
			doc: `{"format":"service-check-v1","phase":"done","status":"ok","latency_ms":60001,"http_status":200}`,
		},
		"ok with redirect code": {
			doc: `{"format":"service-check-v1","phase":"done","status":"ok","latency_ms":1,"http_status":301}`,
		},
		"redirect with ok code": {
			doc: `{"format":"service-check-v1","phase":"done","status":"redirect","latency_ms":1,"http_status":200}`,
		},
		"http error with ok code": {
			doc: `{"format":"service-check-v1","phase":"done","status":"http-error","latency_ms":1,"http_status":200}`,
		},
		"refused with code": {
			doc: `{"format":"service-check-v1","phase":"done","status":"refused","latency_ms":1,"http_status":200}`,
		},
		"unknown status": {
			doc: `{"format":"service-check-v1","phase":"done","status":"weird","latency_ms":1,"http_status":0}`,
		},
		"status code out of range": {
			doc: `{"format":"service-check-v1","phase":"done","status":"ok","latency_ms":1,"http_status":600}`,
		},
		"body field": {
			doc: `{"format":"service-check-v1","phase":"done","status":"ok","latency_ms":1,"http_status":200,"body":"<html>secret</html>"}`,
		},
		"url field": {
			doc: `{"format":"service-check-v1","phase":"done","status":"ok","latency_ms":1,"http_status":200,"url":"http://169.254.169.254/latest/meta-data/"}`,
		},
		"oversized": {
			doc: `{"format":"service-check-v1","phase":"done","status":"ok","latency_ms":1,"http_status":200,"pad":"` + strings.Repeat("x", MaxDocSize) + `"}`,
		},
		"not json": {
			doc: `this is not json`,
		},
		"trailing data": {
			doc: `{"format":"service-check-v1","phase":"done","status":"ok","latency_ms":1,"http_status":200} trailing`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := ParseResult([]byte(tc.doc))
			if tc.want.Status == "" {
				if err == nil {
					t.Fatalf("accepted: %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("rejected: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}
