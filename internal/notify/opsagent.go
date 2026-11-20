// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
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
// so that their values come before the notifier's cap on the reason
// length cuts anything. Each has a <name>_changed flag in opsconfig.Diff.
var opsAgentFields = []string{"data_class", "model", "base_url", "enabled", "allow_plain_http", "language", "operator_instructions"}

// The reason budget. The notifier cuts a reason at maxField (300) runes.
// The reason is built as:
//
//	<fixed text> Version <old> -> <new>. <value lines>. Changed: <names>.
//
// The value lines come before the Changed list, and the security lines
// (data_class, model, base_url) come first among the value lines, so the
// security values are never behind a cut. Their budget is:
//
//	fixed text and versions  88 runes (int64 versions, 19 digits each)
//	data_class (old, new)    opsAgentDataClassLimit runes each
//	model (old, new)         opsAgentModelLimit runes each
//	base_url (old, new)      opsAgentURLLimit runes each
//	labels, separators       the rest
//
// In the worst case (data_class, model and base_url changed, a 128-byte
// model, two 512-byte base URLs) the security part measures 286 runes, see
// TestOpsAgentBudgetsFitTheCap. The Changed list and the non-security lines
// come after these values and may be cut by the cap.
const (
	// opsAgentDataClassLimit is the rune budget of one data class value: the
	// longest allowed class (opsconfig validates the value).
	opsAgentDataClassLimit = len(opsconfig.DataClassExternal)
	// opsAgentModelLimit is the rune budget of one model value. A cut model
	// keeps 8 runes and the cut mark with its digest.
	opsAgentModelLimit = 26
	// opsAgentURLLimit is the rune budget of one base URL value. It keeps the
	// scheme and the host (or the end of the host) whole, see opsAgentURLShort.
	opsAgentURLLimit = 48
	// opsAgentDigestLen is the number of hex digits of the digest that
	// follows a cut value: 64 bits of SHA-256.
	opsAgentDigestLen = 16
	// opsAgentCutMark separates a cut value from its digest. It is two runes.
	opsAgentCutMark = "…#"
	// opsAgentEllipsis marks a host whose start was cut.
	opsAgentEllipsis = "…"
)

// opsAgentDigest returns the first opsAgentDigestLen hex digits of the
// SHA-256 of s. It covers the whole value, so two values that share a
// visible prefix or host still get different short forms.
func opsAgentDigest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:opsAgentDigestLen]
}

// firstRunes returns the first n runes of s.
func firstRunes(s string, n int) string {
	if n <= 0 {
		return ""
	}
	var b strings.Builder
	for _, r := range s {
		if n == 0 {
			break
		}
		b.WriteRune(r)
		n--
	}
	return b.String()
}

// lastRunes returns the last n runes of s.
func lastRunes(s string, n int) string {
	rs := []rune(s)
	if n >= len(rs) {
		return s
	}
	if n <= 0 {
		return ""
	}
	return string(rs[len(rs)-n:])
}

// opsAgentShortValue returns s whole when it has at most limit runes.
// Otherwise it returns the first runes of s, followed by opsAgentCutMark and
// the digest of the whole s, with exactly limit runes in total. It is used
// for the model and the data class, whose ends are not security-relevant.
// If limit is too small for the mark and a digest, the result is the start
// of that suffix, still with at most limit runes.
func opsAgentShortValue(s string, limit int) string {
	if utf8.RuneCountInString(s) <= limit {
		return s
	}
	suffix := opsAgentCutMark + opsAgentDigest(s)
	keep := limit - utf8.RuneCountInString(suffix)
	if keep <= 0 {
		return firstRunes(suffix, limit)
	}
	return firstRunes(s, keep) + suffix
}

// opsAgentURLShort returns the short form of a base URL with at most limit
// runes. A URL that fits is returned whole. Otherwise the form is the scheme,
// the host and opsAgentCutMark with the digest of the whole URL, so that the
// destination's host is shown: "https://llm.internal.example.org…#<digest>"
// for a host that fits the budget. If the host does not fit, its end is shown
// after an ellipsis, because the registrable domain is at the end of a host
// ("https://…attacker.net…#<digest>"); a lookalike prefix is never shown.
// A value that does not parse as a URL with a host falls back to its first
// runes and the digest.
func opsAgentURLShort(raw string, limit int) string {
	if utf8.RuneCountInString(raw) <= limit {
		return raw
	}
	suffix := opsAgentCutMark + opsAgentDigest(raw)
	room := limit - utf8.RuneCountInString(suffix)
	if room <= 0 {
		return firstRunes(suffix, limit)
	}
	scheme, host, ok := splitURLSchemeHost(raw)
	if !ok {
		return firstRunes(raw, room) + suffix
	}
	head := scheme + "://"
	if n := utf8.RuneCountInString(head + host); n <= room {
		return head + host + suffix
	}
	tail := room - utf8.RuneCountInString(head+opsAgentEllipsis)
	if tail <= 0 {
		return firstRunes(raw, room) + suffix
	}
	return head + opsAgentEllipsis + lastRunes(host, tail) + suffix
}

// splitURLSchemeHost returns the scheme as written in raw and the host of
// raw. ok is false when raw has no scheme or no host. Userinfo is not part
// of the host; it is covered by the digest of the whole URL.
func splitURLSchemeHost(raw string) (scheme, host string, ok bool) {
	i := strings.Index(raw, "://")
	if i <= 0 {
		return "", "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", "", false
	}
	return raw[:i], u.Host, true
}

// OpsAgentSettingsChange is a committed change of the ops agent settings.
type OpsAgentSettingsChange struct {
	// Old and New are the settings before and after the change.
	Old, New opsconfig.Settings
	// OldVersion and NewVersion are the stored versions before and after.
	OldVersion, NewVersion int64
}

// OpsAgentSettingsEvent builds the settings_changed event. Its reason
// starts with the fixed sentence and the versions, then each changed field
// with its old and new value from opsconfig.Diff, the security fields
// (data class, model, base URL) first; the names of the changed fields come
// last, so the cap cuts that list first. Long values are shown in short
// forms (opsAgentShortValue, opsAgentURLShort). The operator instructions
// are reported by their size only, never by their text. Event text passes
// through the notifier's cleaning, which limits the reason length to maxField
// runes.
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
		case "data_class":
			parts = append(parts, fmt.Sprintf("data_class: %s -> %s",
				opsAgentShortValue(c.Old.DataClass, opsAgentDataClassLimit), opsAgentShortValue(c.New.DataClass, opsAgentDataClassLimit)))
		case "model":
			parts = append(parts, fmt.Sprintf("model: %s -> %s",
				opsAgentShortValue(c.Old.Model, opsAgentModelLimit), opsAgentShortValue(c.New.Model, opsAgentModelLimit)))
		case "base_url":
			parts = append(parts, fmt.Sprintf("base_url: %s -> %s",
				opsAgentURLShort(c.Old.BaseURL, opsAgentURLLimit), opsAgentURLShort(c.New.BaseURL, opsAgentURLLimit)))
		default:
			parts = append(parts, fmt.Sprintf("%s: %s -> %s", f, d["old_"+f], d["new_"+f]))
		}
	}
	reason := fmt.Sprintf("%s Version %d -> %d.", opsAgentFixedText, c.OldVersion, c.NewVersion)
	if len(parts) > 0 {
		reason += " " + strings.Join(parts, "; ") + "."
	}
	if len(names) > 0 {
		reason += " Changed: " + strings.Join(names, ", ") + "."
	}
	return Event{Kind: KindOpsAgentSettingsChanged, State: "saved", Reason: reason, Time: at}
}

// NotifyOpsAgentSettingsChanged sends the settings_changed event to every
// provider and returns how many accepted it. Call it after the change is
// committed; a failed delivery does not undo the change.
func (n *Notifier) NotifyOpsAgentSettingsChanged(ctx context.Context, c OpsAgentSettingsChange, at time.Time) int {
	return n.Notify(ctx, OpsAgentSettingsEvent(c, at))
}
