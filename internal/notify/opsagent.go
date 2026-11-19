// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/opsconfig"
)

// KindOpsAgentSettingsChanged is the event of a saved change of the ops
// agent settings (ADR 0016 D12). It is sent after the commit, never before.
const KindOpsAgentSettingsChanged = "opsagent.settings_changed"

// opsAgentFixedText is the fixed sentence that starts every settings event.
const opsAgentFixedText = "The ops agent settings were changed."

// opsAgentFields are the settings fields the event may list, in a fixed
// order. Each has a <name>_changed flag in opsconfig.Diff.
var opsAgentFields = []string{"enabled", "base_url", "model", "allow_plain_http", "data_class", "language", "operator_instructions"}

// OpsAgentSettingsChange is a committed change of the ops agent settings.
type OpsAgentSettingsChange struct {
	// Old and New are the settings before and after the change.
	Old, New opsconfig.Settings
	// OldVersion and NewVersion are the stored versions before and after.
	OldVersion, NewVersion int64
}

// OpsAgentSettingsEvent builds the settings_changed event. Its reason
// starts with the fixed sentence and the versions, then lists each changed
// field with its old and new value from opsconfig.Diff. The operator
// instructions are reported by their size only, never by their text.
// Event text passes through the notifier's cleaning, which limits the
// reason length.
func OpsAgentSettingsEvent(c OpsAgentSettingsChange, at time.Time) Event {
	d := opsconfig.Diff(c.Old, c.New)
	parts := make([]string, 0, len(opsAgentFields))
	for _, f := range opsAgentFields {
		if d[f+"_changed"] != "true" {
			continue
		}
		if f == "operator_instructions" {
			parts = append(parts, fmt.Sprintf("operator_instructions: changed (%s -> %s bytes)",
				d["old_operator_instructions_bytes"], d["new_operator_instructions_bytes"]))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s: %s -> %s", f, d["old_"+f], d["new_"+f]))
	}
	reason := fmt.Sprintf("%s Version %d -> %d.", opsAgentFixedText, c.OldVersion, c.NewVersion)
	if len(parts) > 0 {
		reason += " " + strings.Join(parts, "; ") + "."
	}
	return Event{Kind: KindOpsAgentSettingsChanged, State: "saved", Reason: reason, Time: at}
}

// NotifyOpsAgentSettingsChanged sends the settings_changed event to every
// provider and returns how many accepted it. Call it after the change is
// committed; a failed delivery does not undo the change.
func (n *Notifier) NotifyOpsAgentSettingsChanged(ctx context.Context, c OpsAgentSettingsChange, at time.Time) int {
	return n.Notify(ctx, OpsAgentSettingsEvent(c, at))
}
