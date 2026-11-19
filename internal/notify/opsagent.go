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

// The reason budget. The notifier cuts a reason at maxField (300) runes, so
// the security fields must fit in it even in the worst case of the allowed
// inputs: a 128-byte model and two 512-byte base URLs, all changed, with
// int64 versions. The fixed text, the versions, the "Changed:" list and the
// data_class line take 184 runes in that case (the value lines are not
// counted). The 116 runes left are split as follows:
//   - each model value (old and new): at most opsAgentModelLimit runes, 32 in total;
//   - each base URL value (old and new): at most opsAgentURLLimit runes, 84 in total.
//
// 184 + 32 + 84 = 300 = maxField. A value that is longer than its limit is
// shown as a prefix plus a digest, so the event shows that it changed and
// the digest tells the old and new values apart.
const (
	// opsAgentModelLimit is the rune budget of one model value.
	opsAgentModelLimit = 16
	// opsAgentURLLimit is the rune budget of one base URL value. It keeps the
	// scheme and the host of a typical destination whole.
	opsAgentURLLimit = 42
	// opsAgentDigestLen is the number of hex digits of the digest that follows a
	// cut value (32 bits: enough to tell two values apart in an event).
	opsAgentDigestLen = 8
	// opsAgentCutMark separates a cut value from its digest; it is one rune.
	opsAgentCutMark = "…#"
)

// opsAgentShortValue returns s whole when it has at most limit runes.
// Otherwise it returns the first runes of s, cut so that the result, with
// opsAgentCutMark and the digest of the whole s, has exactly limit runes.
func opsAgentShortValue(s string, limit int) string {
	if utf8.RuneCountInString(s) <= limit {
		return s
	}
	sum := sha256.Sum256([]byte(s))
	suffix := opsAgentCutMark + hex.EncodeToString(sum[:])[:opsAgentDigestLen]
	keep := limit - utf8.RuneCountInString(suffix)
	var b strings.Builder
	for _, r := range s {
		if keep == 0 {
			break
		}
		b.WriteRune(r)
		keep--
	}
	return b.String() + suffix
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
				opsAgentShortValue(c.Old.Model, opsAgentModelLimit), opsAgentShortValue(c.New.Model, opsAgentModelLimit)))
		case "base_url":
			parts = append(parts, fmt.Sprintf("base_url: %s -> %s",
				opsAgentShortValue(c.Old.BaseURL, opsAgentURLLimit), opsAgentShortValue(c.New.BaseURL, opsAgentURLLimit)))
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
