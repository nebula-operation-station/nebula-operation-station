// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/notifylog"
)

// TestInboxCheckFailureLogsOncePerMinute: a failing admin check writes one
// log line per inboxCheckLogEvery, not one per page view.
func TestInboxCheckFailureLogsOncePerMinute(t *testing.T) {
	var buf bytes.Buffer
	now := time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)
	h := &Handler{
		log: slog.New(slog.NewTextHandler(&buf, nil)),
		now: func() time.Time { return now },
	}
	errBoom := errors.New("executor down")
	for range 5 {
		h.logInboxCheckFailure(errBoom)
	}
	if n := strings.Count(buf.String(), "notifications: admin check"); n != 1 {
		t.Fatalf("log lines in the first minute = %d, want 1", n)
	}
	now = now.Add(inboxCheckLogEvery)
	h.logInboxCheckFailure(errBoom)
	if n := strings.Count(buf.String(), "notifications: admin check"); n != 2 {
		t.Errorf("log lines after a minute = %d, want 2", n)
	}
}

// TestRenderLinkRuleIsTheStoreRule fixes the render-time link rule: a link is
// shown only when notifylog.IsNOSLink, the same rule the store applies on
// write, accepts it.
func TestRenderLinkRuleIsTheStoreRule(t *testing.T) {
	ok := []string{"/operations/ex-1", "/deployments/run-7", "/"}
	bad := []string{
		"",
		"operations/ex-1",
		"//evil.example/x",
		"/\\evil.example",
		"/x//y",
		"https://evil.example",
		"javascript:alert(1)",
		"/a?b=c",
		"/a#frag",
		"/a b",
		"/a\tb",
		"/a\nb",
		"/café",
		strings.Repeat("/a", notifylog.MaxLink),
	}
	for _, s := range ok {
		if !notifylog.IsNOSLink(s) {
			t.Errorf("IsNOSLink(%q) = false, want true", s)
		}
	}
	for _, s := range bad {
		if notifylog.IsNOSLink(s) {
			t.Errorf("IsNOSLink(%q) = true, want false", s)
		}
	}
}
