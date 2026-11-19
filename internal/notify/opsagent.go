// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/opsconfig"
)

// KindOpsAgentSettingsChanged is the event of a saved change of the ops
// agent settings (ADR 0016 D12). It is sent after the commit, never before.
const KindOpsAgentSettingsChanged = "opsagent.settings_changed"

// opsAgentFixedText is the fixed sentence that starts every settings event.
const opsAgentFixedText = "The ops agent settings were changed."

// opsAgentFields are the settings fields the event may list, in a fixed
// order: the security-relevant ones first (data class, model, base URL),
// so that they survive the notifier's cap on the reason length. Each has a
// <name>_changed flag in opsconfig.Diff.
var opsAgentFields = []string{"data_class", "model", "base_url", "enabled", "allow_plain_http", "language", "operator_instructions"}

// opsAgentShortLimit bounds the part of a long value (base URL, model) that
// the event shows; a longer value is cut and followed by a digest of the
// whole value. It keeps two 512-byte URLs within the reason cap.
const opsAgentShortLimit = 32

// opsAgentDigestLen is the number of hex digits of the digest that follows a
// cut value (32 bits: enough to tell two values apart in an event).
const opsAgentDigestLen = 8

// opsAgentShortValue returns s whole when it is short, and otherwise its
// first opsAgentShortLimit bytes, cut at a rune boundary, followed by "…#"
// and a digest of the whole value.
func opsAgentShortValue(s string) string {
	if len(s) <= opsAgentShortLimit {
		return s
	}
	cut := opsAgentShortLimit
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	sum := sha256.Sum256([]byte(s))
	return s[:cut] + "…#" + hex.EncodeToString(sum[:])[:opsAgentDigestLen]
}

// OpsAgentSettingsChange is a committed change of the ops agent settings.
type OpsAgentSettingsChange struct {
	// Old and New are the settings before and after the change.
	Old, New opsconfig.Settings
	// OldVersion and NewVersion are the stored versions before and after.
	OldVersion, NewVersion int64
}

// OpsAgentSettingsEvent builds the settings_changed event. Its reason
// starts with the fixed sentence and the versions, then the names of the
// changed fields, then each changed field with its old and new value from
// opsconfig.Diff; the security-relevant fields come first. A long base URL
// or model is shown cut with a digest (opsAgentShortValue). The operator
// instructions are reported by their size only, never by their text.
// Event text passes through the notifier's cleaning, which limits the
// reason length to maxField runes.
func OpsAgentSettingsEvent(c OpsAgentSettingsChange, at time.Time) Event {
	d := opsconfig.Diff(c.Old, c.New)
	var names, parts []string
	for _, f := range opsAgentFields {
		if d[f+"_changed"] != "true" {
			continue
		}
		names = append(names, f)
		switch f {
		case "operator_instructions":
			parts = append(parts, fmt.Sprintf("operator_instructions: changed (%s -> %s bytes)",
				d["old_operator_instructions_bytes"], d["new_operator_instructions_bytes"]))
		case "model":
			parts = append(parts, fmt.Sprintf("model: %s -> %s",
				opsAgentShortValue(c.Old.Model), opsAgentShortValue(c.New.Model)))
		case "base_url":
			parts = append(parts, fmt.Sprintf("base_url: %s -> %s",
				opsAgentShortValue(c.Old.BaseURL), opsAgentShortValue(c.New.BaseURL)))
		default:
			parts = append(parts, fmt.Sprintf("%s: %s -> %s", f, d["old_"+f], d["new_"+f]))
		}
	}
	reason := fmt.Sprintf("%s Version %d -> %d.", opsAgentFixedText, c.OldVersion, c.NewVersion)
	if len(names) > 0 {
		reason += " Changed: " + strings.Join(names, ", ") + "."
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
