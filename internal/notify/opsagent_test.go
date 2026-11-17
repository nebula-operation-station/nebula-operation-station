// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/opsconfig"
)

// recordSender captures the events it is asked to send.
type recordSender struct {
	mu     sync.Mutex
	events []Event
}

func (r *recordSender) Name() string { return "record" }

func (r *recordSender) Send(_ context.Context, e Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
	return nil
}

func opsChange() OpsAgentSettingsChange {
	old := opsconfig.Settings{Enabled: true, BaseURL: "http://10.0.0.20:11434/v1", Model: "qwen3.5-9b",
		DataClass: opsconfig.DataClassLab, Language: opsconfig.LanguageDE, Instructions: "secret-free but private text"}
	next := old
	next.DataClass = opsconfig.DataClassExternal
	return OpsAgentSettingsChange{Old: old, New: next, OldVersion: 4, NewVersion: 5}
}

func TestOpsAgentEventCarriesDataClassChangeAndVersions(t *testing.T) {
	at := time.Unix(1791960000, 0)
	e := OpsAgentSettingsEvent(opsChange(), at)
	if KindOpsAgentSettingsChanged != "opsagent.settings_changed" {
		t.Fatalf("kind constant = %q", KindOpsAgentSettingsChanged)
	}
	if e.Kind != KindOpsAgentSettingsChanged {
		t.Fatalf("kind = %q", e.Kind)
	}
	for _, want := range []string{
		"The ops agent settings were changed.",
		"Version 4 -> 5.",
		"data_class: lab -> external",
	} {
		if !strings.Contains(e.Reason, want) {
			t.Errorf("reason %q lacks %q", e.Reason, want)
		}
	}
	if strings.Contains(e.Reason, "enabled:") || strings.Contains(e.Reason, "model:") {
		t.Errorf("reason lists unchanged fields: %q", e.Reason)
	}
	if !e.Time.Equal(at) {
		t.Errorf("time = %v, want %v", e.Time, at)
	}
}

func TestOpsAgentEventShowsFullURLAndModelOnChange(t *testing.T) {
	c := opsChange()
	c.New.BaseURL = "http://10.0.0.21:11434/v1"
	c.New.Model = "llama3.1-8b"
	e := OpsAgentSettingsEvent(c, time.Unix(1, 0))
	for _, want := range []string{"base_url: http://10.0.0.20:11434/v1 -> http://10.0.0.21:11434/v1", "model: qwen3.5-9b -> llama3.1-8b"} {
		if !strings.Contains(e.Reason, want) {
			t.Errorf("reason %q lacks %q", e.Reason, want)
		}
	}
}

func TestOpsAgentEventNeverCarriesInstructionText(t *testing.T) {
	c := opsChange()
	c.New.Instructions = "Prefer Debian trackers; token=abc123"
	e := OpsAgentSettingsEvent(c, time.Unix(1, 0))
	if strings.Contains(e.Reason, "token=abc123") || strings.Contains(e.Text(), "Prefer Debian") {
		t.Fatalf("operator instruction text leaked into the event: %q", e.Reason)
	}
	if !strings.Contains(e.Reason, "operator_instructions: changed (") {
		t.Errorf("reason %q does not report the instruction change by size", e.Reason)
	}
}

func TestNotifyOpsAgentSettingsChangedSendsOnce(t *testing.T) {
	var rec recordSender
	n := NewWithSenders(quiet(), nil, &rec)
	if got := n.NotifyOpsAgentSettingsChanged(context.Background(), opsChange(), time.Unix(1, 0)); got != 1 {
		t.Fatalf("delivered to %d providers, want 1", got)
	}
	if len(rec.events) != 1 || rec.events[0].Kind != KindOpsAgentSettingsChanged {
		t.Fatalf("events = %+v", rec.events)
	}
}
