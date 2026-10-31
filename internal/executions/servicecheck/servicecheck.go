// SPDX-License-Identifier: AGPL-3.0-or-later

// Package servicecheck is the service.check contract (ADR 0006 P1-27):
// one bounded HTTP(S) or TCP probe to an operator-approved destination and
// port. Only the status and the latency cross the wire; no redirects are
// followed, no response body is ever stored. Reserved (internal) IP
// literals — loopback, link-local (including 169.254.169.254), private,
// CGNAT, multicast/reserved, and every IPv6 literal — additionally need
// the explicit internal=yes approval.
package servicecheck

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// Format is the result document format this action emits.
const Format = "service-check-v1"

// Limits.
const (
	// MaxDestinationLen is the RFC 1123 maximum for a hostname.
	MaxDestinationLen = 253
	// MaxLatencyMS bounds the reported latency: the probe's fixed
	// total timeout is 5 s, so anything larger is not a probe result.
	MaxLatencyMS = 5000
	// MaxDocSize bounds the result document (the probe emits a few dozen
	// bytes; a larger one is not a probe result).
	MaxDocSize = 1 << 10
)

// Status is one fixed outcome of a probe.
type Status string

// The probe can only report these.
const (
	StatusOK         Status = "ok"
	StatusRedirect   Status = "redirect"
	StatusHTTPError  Status = "http-error"
	StatusRefused    Status = "refused"
	StatusUnresolved Status = "unresolved"
	StatusTimeout    Status = "timeout"
	StatusTLS        Status = "tls-error"
	StatusError      Status = "error"
)

// Result is the only data a probe may report: a fixed status, the latency
// and (for HTTP) the status code. No body, no URL, no host text.
type Result struct {
	Status     Status
	Latency    time.Duration
	HTTPStatus int
}

// Check is one operator-approved probe destination.
type Check struct {
	Protocol string // "http", "https" or "tcp"
	// Destination is a hostname or an IP literal, nothing else.
	Destination      string
	Port             int
	InternalApproved bool
}

// numericHostRe rejects legacy inet_aton forms before a resolver can reinterpret them.
var numericHostRe = regexp.MustCompile(`(?i)^(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+))*$`)

// hostnameRe is a strict RFC 1123 hostname: labels of 1-63 characters of
// [a-z0-9-], starting and ending with [a-z0-9], no trailing dot. It is
// deliberately narrower than what a resolver would accept: the destination
// is embedded in a URL, so it must stay a bare name.
var hostnameRe = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)

// ValidateCheck checks one probe destination. Hostnames are accepted as
// written; the host probe also validates and pins every DNS answer before
// connecting. IP literals are checked against reserved ranges unless approved.
func ValidateCheck(c Check) error {
	switch c.Protocol {
	case "http", "https", "tcp":
	default:
		return fmt.Errorf("protocol must be http, https or tcp")
	}
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("port must be 1-65535")
	}
	d := c.Destination
	if d == "" || len(d) > MaxDestinationLen || strings.Contains(d, "%") {
		return fmt.Errorf("destination must be a hostname or IP literal of at most %d characters", MaxDestinationLen)
	}
	if addr, err := netip.ParseAddr(d); err == nil {
		if !c.InternalApproved {
			if reason, reserved := reserved(addr); reserved {
				return fmt.Errorf("destination %s is an internal address (%s) and is not explicitly approved", d, reason)
			}
		}
		return nil
	}
	// Hostnames are case-insensitive; the destination is embedded in a
	// URL, so it must stay a bare name.
	if !hostnameRe.MatchString(d) || numericHostRe.MatchString(d) {
		return fmt.Errorf("destination must be a hostname or IP literal")
	}
	return nil
}

// reserved reports whether addr is in a range a probe must not touch
// without explicit approval, with the fixed reason.
func reserved(addr netip.Addr) (string, bool) {
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	if !addr.Is4() {
		// Every IPv6 literal (loopback, link-local, unique local,
		// multicast, …) needs the explicit approval.
		return "IPv6 literal", true
	}
	o := addr.As4()
	switch {
	case o[0] == 0:
		return "0.0.0.0/8 (this network)", true
	case o[0] == 10:
		return "10.0.0.0/8 (private)", true
	case o[0] == 127:
		return "127.0.0.0/8 (loopback)", true
	case o[0] == 169 && o[1] == 254:
		return "169.254.0.0/16 (link-local, incl. 169.254.169.254 metadata)", true
	case o[0] == 100 && o[1] >= 64 && o[1] <= 127:
		return "100.64.0.0/10 (CGNAT)", true
	case o[0] == 172 && o[1] >= 16 && o[1] <= 31:
		return "172.16.0.0/12 (private)", true
	case o[0] == 192 && o[1] == 168:
		return "192.168.0.0/16 (private)", true
	case o[0] >= 224:
		return "224.0.0.0/4 (multicast/reserved)", true
	}
	return "", false
}

// doc is the exact shape of a probe result; any other key (a body, a URL,
// host text) is refused.
type doc struct {
	Format     string `json:"format"`
	Phase      string `json:"phase"`
	Status     string `json:"status"`
	LatencyMS  int64  `json:"latency_ms"`
	HTTPStatus int    `json:"http_status"`
}

// ParseResult parses and validates one probe result document. It returns
// an error for any document that is not exactly the fixed contract, so a
// hostile host cannot smuggle a body or host text into the result.
func ParseResult(b []byte) (Result, error) {
	if len(b) == 0 || len(b) > MaxDocSize {
		return Result{}, fmt.Errorf("result must be 1-%d bytes", MaxDocSize)
	}
	if !utf8.Valid(b) {
		return Result{}, fmt.Errorf("result is not UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return Result{}, fmt.Errorf("result must be an object")
	}
	raw := make(map[string]json.RawMessage)
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return Result{}, fmt.Errorf("result is not a JSON document")
		}
		key, ok := tok.(string)
		if !ok {
			return Result{}, fmt.Errorf("result has an invalid key")
		}
		if _, exists := raw[key]; exists {
			return Result{}, fmt.Errorf("result has a duplicate field")
		}
		switch key {
		case "format", "phase", "status", "latency_ms", "http_status":
		default:
			return Result{}, fmt.Errorf("result carries an unexpected field")
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil || bytes.Equal(value, []byte("null")) {
			return Result{}, fmt.Errorf("result field is invalid")
		}
		raw[key] = value
	}
	if _, err := dec.Token(); err != nil {
		return Result{}, fmt.Errorf("result is not a JSON document")
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return Result{}, fmt.Errorf("result must be exactly one JSON document")
	}
	if len(raw) != 5 {
		return Result{}, fmt.Errorf("result requires exactly five fields")
	}
	d := &doc{}
	if err := json.Unmarshal(b, d); err != nil {
		return Result{}, fmt.Errorf("result is not a JSON document")
	}
	if d.Format != Format || d.Phase != "done" {
		return Result{}, fmt.Errorf("result is not a %s done document", Format)
	}
	if d.LatencyMS < 0 || d.LatencyMS > MaxLatencyMS {
		return Result{}, fmt.Errorf("latency is outside 0-%d ms", MaxLatencyMS)
	}
	r := Result{Status: Status(d.Status), Latency: time.Duration(d.LatencyMS) * time.Millisecond, HTTPStatus: d.HTTPStatus}
	if err := ValidateResult(r); err != nil {
		return Result{}, err
	}
	return r, nil
}

// ValidateResult rejects inconsistent statuses and values outside the probe bounds.
func ValidateResult(r Result) error {
	if r.Latency < 0 || r.Latency > MaxLatencyMS*time.Millisecond {
		return fmt.Errorf("latency is outside probe bounds")
	}
	if r.HTTPStatus < 0 || r.HTTPStatus > 599 {
		return fmt.Errorf("http status is outside 0-599")
	}
	switch r.Status {
	case StatusOK:
		if r.HTTPStatus != 0 && (r.HTTPStatus < 200 || r.HTTPStatus > 299) {
			return fmt.Errorf("status ok requires a 2xx or no status code")
		}
	case StatusRedirect:
		if r.HTTPStatus < 300 || r.HTTPStatus > 399 {
			return fmt.Errorf("status redirect requires a 3xx status code")
		}
	case StatusHTTPError:
		if r.HTTPStatus < 400 || r.HTTPStatus > 599 {
			return fmt.Errorf("status http-error requires a 4xx or 5xx status code")
		}
	case StatusRefused, StatusUnresolved, StatusTimeout, StatusTLS, StatusError:
		if r.HTTPStatus != 0 {
			return fmt.Errorf("failed probe must not carry a status code")
		}
	default:
		return fmt.Errorf("unknown probe status")
	}
	return nil
}
