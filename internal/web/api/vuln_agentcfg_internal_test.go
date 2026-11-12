// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"testing"
	"time"
)

// Two tokens have separate agent-config windows: one token at its limit
// leaves the other's budget untouched.
func TestAgentConfigWindowsAreSeparatePerToken(t *testing.T) {
	a := &agentConfigHandler{limits: map[string]*rateWindow{}}
	now := time.Unix(1_000_000, 0)
	for i := range MaxAgentConfigRequests {
		if ok, _ := a.allow("token-a", now); !ok {
			t.Fatalf("token-a request %d refused", i)
		}
	}
	if ok, wait := a.allow("token-a", now); ok || wait <= 0 {
		t.Fatalf("token-a over its limit: ok=%v wait=%v", ok, wait)
	}
	for i := range MaxAgentConfigRequests {
		if ok, _ := a.allow("token-b", now); !ok {
			t.Fatalf("token-b request %d refused after token-a used its budget", i)
		}
	}
	if ok, _ := a.allow("token-a", now.Add(AgentConfigWindow+time.Second)); !ok {
		t.Fatal("token-a still refused after its window passed")
	}
}
