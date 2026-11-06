// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestRebootNodeSendsExactRequest pins the exact request for a node reboot:
// POST /nodes/{node}/status with only command=reboot (ADR 0006 P2-01: "Node
// reboot: HIGH standalone; CRITICAL cluster; exact node"). PVE answers a node
// reboot without a UPID, so the documented empty/null data response is the
// success case.
func TestRebootNodeSendsExactRequest(t *testing.T) {
	f := &fakeWriteServer{body: `{"data":null}`}
	w := newTestWriter(t, f)
	if err := w.RebootNode(context.Background(), "pve1"); err != nil {
		t.Fatalf("RebootNode: %v", err)
	}
	r := f.only(t)
	if r.method != http.MethodPost || r.path != "/api2/json/nodes/pve1/status" {
		t.Errorf("request = %s %s", r.method, r.path)
	}
	if r.auth != testToken || r.ctype != "application/x-www-form-urlencoded" {
		t.Errorf("headers auth=%q ctype=%q", r.auth, r.ctype)
	}
	want := url.Values{"command": {"reboot"}}
	if len(r.form) != 1 || r.form.Encode() != want.Encode() {
		t.Errorf("form = %v, want %v", r.form, want)
	}
}

// TestRebootNodeAcceptsOnlyNullData pins that only the documented
// {"data":null} answer is success: PVE answers a node reboot with no UPID.
// A missing data member, a bare null, an empty data value or an error-shaped
// body is a schema error with an unknown outcome, never a dispatched reboot.
func TestRebootNodeAcceptsOnlyNullData(t *testing.T) {
	f := &fakeWriteServer{body: `{"data":null}`}
	w := newTestWriter(t, f)
	if err := w.RebootNode(context.Background(), "pve1"); err != nil {
		t.Fatalf("RebootNode: %v", err)
	}
	for name, body := range map[string]string{
		"missing data":   `{}`,
		"bare null":      `null`,
		"errors":         `{"errors":{"node":"bad"}}`,
		"message":        `{"message":"permission denied"}`,
		"data and error": `{"data":null,"errors":{"x":"y"}}`,
		"empty string":   `{"data":""}`,
		"object data":    `{"data":{}}`,
		"upid data":      `{"data":"UPID:pve1:00000001:00000001:00000001:srvreboot::root@pam:"}`,
	} {
		t.Run(name, func(t *testing.T) {
			f := &fakeWriteServer{body: body}
			w := newTestWriter(t, f)
			err := w.RebootNode(context.Background(), "pve1")
			var we *WriteError
			if !errors.As(err, &we) || we.Reason != ReasonSchema || !we.OutcomeUnknown() {
				t.Fatalf("err = %v, want schema WriteError with unknown outcome", err)
			}
		})
	}
}

// TestRebootNodeRejectsDuplicateEnvelopeKeys pins that a repeated top-level
// key in the response envelope is a schema error with an unknown outcome:
// the envelope decodes into a map that keeps only the last value, so
// {"data":"UPID:…","data":null} must not read as the documented null answer
// nor as a dispatched task.
func TestRebootNodeRejectsDuplicateEnvelopeKeys(t *testing.T) {
	for name, body := range map[string]string{
		"upid then null": `{"data":"UPID:pve1:00000001:00000001:00000001:srvreboot::root@pam:","data":null}`,
		"null then upid": `{"data":null,"data":"UPID:pve1:00000001:00000001:00000001:srvreboot::root@pam:"}`,
		"null then null": `{"data":null,"data":null}`,
		"null then text": `{"data":null,"data":"rebooted"}`,
		"dup other key":  `{"data":null,"x":1,"x":2}`,
	} {
		t.Run(name, func(t *testing.T) {
			f := &fakeWriteServer{body: body}
			w := newTestWriter(t, f)
			err := w.RebootNode(context.Background(), "pve1")
			var we *WriteError
			if !errors.As(err, &we) || we.Reason != ReasonSchema || !we.OutcomeUnknown() {
				t.Fatalf("err = %v, want schema WriteError with unknown outcome", err)
			}
		})
	}
}

// TestDuplicateTopLevelKeys pins the token walk: only a repeated top-level
// key of a JSON object reports true; nested duplicates, other value types
// and malformed input report false (the caller's unmarshal fails on the
// latter with its own reason).
func TestDuplicateTopLevelKeys(t *testing.T) {
	for name, tc := range map[string]struct {
		raw  string
		want bool
	}{
		"single key":     {`{"data":null}`, false},
		"empty object":   {`{}`, false},
		"distinct keys":  {`{"data":null,"errors":{}}`, false},
		"dup data":       {`{"data":"UPID:x","data":null}`, true},
		"dup data null":  {`{"data":null,"data":null}`, true},
		"dup other key":  {`{"data":null,"x":1,"x":2}`, true},
		"nested dup":     {`{"data":{"a":1,"a":2}}`, false},
		"dup in array":   {`{"data":[1,{"a":1,"a":2}]}`, false},
		"not object":     {`null`, false},
		"array":          {`[1,2]`, false},
		"scalar":         {`"x"`, false},
		"malformed":      {`{"data":`, false},
		"trailing data":  {`{"data":null}x`, false},
		"whitespace dup": {` { "data" : null , "data" : 1 } `, true},
	} {
		t.Run(name, func(t *testing.T) {
			if got := duplicateTopLevelKeys([]byte(tc.raw)); got != tc.want {
				t.Fatalf("duplicateTopLevelKeys(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

// TestRebootNodeRejectsInvalidNode checks that an invalid node name is
// refused before anything is sent (no request reaches the server).
func TestRebootNodeRejectsInvalidNode(t *testing.T) {
	for name, node := range map[string]string{
		"empty":    "",
		"path":     "../pve1",
		"slash":    "pve1/x",
		"upper":    "PVE/1",
		"space":    "pve 1",
		"too long": strings.Repeat("a", MaxNodeNameBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			f := &fakeWriteServer{body: `{"data":null}`}
			w := newTestWriter(t, f)
			if err := w.RebootNode(context.Background(), node); !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("err = %v, want ErrInvalidArgument", err)
			}
			if f.count() != 0 {
				t.Error("invalid request reached the server")
			}
		})
	}
}

// TestRebootNodeRejectsUnexpectedBody checks that any data member other than
// the documented empty/null response (a UPID string, an object, a plain
// string) is a schema error with an unknown outcome: a node reboot that
// reports a task cannot be reconciled through the task list, so it must be
// treated as unknown rather than success.
func TestRebootNodeRejectsUnexpectedBody(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"upid data", upidBody(upidStart)},
		{"object data", `{"data":{"upid":"UPID:pve1:00001234:00ABCDEF:6900A000:noreboot:120:nos@pve!action:"}}`},
		{"string data", `{"data":"OK"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeWriteServer{body: tc.body}
			w := newTestWriter(t, f)
			err := w.RebootNode(context.Background(), "pve1")
			var we *WriteError
			if !errors.As(err, &we) || !errors.Is(err, ErrWriteFailed) {
				t.Fatalf("err = %v, want *WriteError", err)
			}
			if we.Reason != ReasonSchema || !we.OutcomeUnknown() {
				t.Errorf("reason=%q unknown=%v, want schema + unknown", we.Reason, we.OutcomeUnknown())
			}
		})
	}
}

// TestRebootNodeTimeoutIsOutcomeUnknown pins that a request that never
// completes is a timeout with an unknown outcome (ADR 0006 P2-01: "timeouts
// are unknown, not failures"), like the other writes.
func TestRebootNodeTimeoutIsOutcomeUnknown(t *testing.T) {
	release := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(ts.Close)
	t.Cleanup(func() { close(release) })
	w, err := NewWriter(ts.URL, ts.Client(), func(context.Context) (string, error) { return testToken, nil }, 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	err = w.RebootNode(context.Background(), "pve1")
	var we *WriteError
	if !errors.As(err, &we) || we.Reason != ReasonTimeout || !we.OutcomeUnknown() {
		t.Fatalf("err = %v, want timeout with unknown outcome", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want DeadlineExceeded in chain", err)
	}
}

// TestRebootNodeRejectsHostileResponses checks that hostile PVE responses are
// mapped to fixed-reason errors with the correct outcome classification and
// leak nothing, exactly like the other writes (ADR 0006 P2-01).
func TestRebootNodeRejectsHostileResponses(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		reason  string
		unknown bool
	}{
		{"oversize", 200, `{"data":"` + strings.Repeat("A", MaxWriteResponseBytes) + `"}`, ReasonOversize, true},
		{"invalid utf8", 200, "{\"data\":\"\xff\"}", ReasonInvalidUTF8, true},
		{"not json", 200, `<html>`, ReasonInvalidJSON, true},
		{"forbidden", 403, `{"message":"secret-echo"}`, ReasonHTTPError, false},
		{"bad request", 400, `{"errors":{"command":"x"}}`, ReasonHTTPError, false},
		{"not found", 404, ``, ReasonHTTPError, false},
		{"redirect", 302, ``, ReasonHTTPError, true},
		{"server error", 500, `{"data":null}`, ReasonHTTPError, true},
		{"bad gateway", 502, ``, ReasonHTTPError, true},
		{"gateway timeout", 504, ``, ReasonHTTPError, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeWriteServer{status: tc.status, body: tc.body}
			w := newTestWriter(t, f)
			err := w.RebootNode(context.Background(), "pve1")
			var we *WriteError
			if !errors.As(err, &we) || !errors.Is(err, ErrWriteFailed) {
				t.Fatalf("err = %v, want *WriteError", err)
			}
			if we.Reason != tc.reason || we.OutcomeUnknown() != tc.unknown {
				t.Errorf("reason=%q unknown=%v, want %q %v", we.Reason, we.OutcomeUnknown(), tc.reason, tc.unknown)
			}
			if strings.Contains(err.Error(), "secret-echo") || strings.Contains(err.Error(), testToken) {
				t.Errorf("error leaks response or token: %v", err)
			}
		})
	}
}
