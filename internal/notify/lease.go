// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"time"
	"unicode"
	"unicode/utf8"
)

// Event kinds of the deterministic server events (ADR 0016 D10, spec 13).
// The decision of when they are due is in internal/leasewatch and
// internal/opsdigest; this file only turns a decision into a fixed template.
const (
	// KindLeaseExpiring is a read lease or schedule grant that expires within
	// 7 days, and again within 1 day.
	KindLeaseExpiring = "lease.expiring"
	// KindLeaseRunFailed is a leased run that failed.
	KindLeaseRunFailed = "lease.run_failed"
	// KindDailyDigest is the optional daily digest. Its text is built by
	// internal/opsdigest from counts only.
	KindDailyDigest = "daily_digest"
)

// MaxDailyDigestBytes bounds the digest text. It matches opsdigest.MaxDigestBytes.
const MaxDailyDigestBytes = 1024

// maxLeaseField bounds grant names, action names and host labels in lease
// messages.
const maxLeaseField = 128

// ErrInvalidLeaseEvent reports a lease event or digest text that cannot be
// turned into a message: a malformed ID, an invalid NOS base URL, a missing
// time or text outside the limits.
var ErrInvalidLeaseEvent = errors.New("invalid lease event")

// leaseIDRe matches a grant ID as the executor issues it. A slash, a dot-only
// name or whitespace can never form a different NOS path.
var leaseIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// LeaseExpiry is one lease.expiring decision as the caller passes it in.
type LeaseExpiry struct {
	// GrantID is the grant's ID; it forms the NOS link /leases/<id>.
	GrantID string
	// GrantName is the display name. It is shown as plain text.
	GrantName string
	// Threshold is the threshold that was crossed. It is not shown; the
	// remaining time is computed from ExpiresAt and At.
	Threshold time.Duration
	// ExpiresAt is the grant's end of validity.
	ExpiresAt time.Time
	// At is the decision time.
	At time.Time
}

// LeaseRunFailure is one lease.run_failed decision as the caller passes it in.
type LeaseRunFailure struct {
	// GrantID is the grant the run used; it forms the NOS link /leases/<id>.
	GrantID string
	// GrantName is the grant's display name.
	GrantName string
	// Action is the failed action's name.
	Action string
	// HostLabel is the host of the failed run, as the admin sees it.
	HostLabel string
	// At is when the run failed.
	At time.Time
}

// NewLeaseExpiring returns the lease.expiring event. base is the NOS origin
// (for example "https://nebula.example.org"); it is validated, and any path,
// query, fragment or userinfo is refused.
func NewLeaseExpiring(base string, x LeaseExpiry) (Event, error) {
	link, err := leaseLink(base, x.GrantID)
	if err != nil {
		return Event{}, err
	}
	if x.ExpiresAt.IsZero() || x.At.IsZero() {
		return Event{}, fmt.Errorf("%w: expiry without time", ErrInvalidLeaseEvent)
	}
	remaining := leftText(x.ExpiresAt.Sub(x.At))
	return Event{
		Kind:   KindLeaseExpiring,
		State:  "expiring",
		Reason: "Grant " + clean(x.GrantName, maxLeaseField) + ": " + remaining,
		link:   link,
		Time:   x.At,
	}, nil
}

// NewLeaseRunFailed returns the lease.run_failed event. The host label is the
// Host of the event, so the notification log records it as a host.
func NewLeaseRunFailed(base string, x LeaseRunFailure) (Event, error) {
	link, err := leaseLink(base, x.GrantID)
	if err != nil {
		return Event{}, err
	}
	if x.Action == "" || len(x.Action) > maxLeaseField || !utf8.ValidString(x.Action) {
		return Event{}, fmt.Errorf("%w: action name", ErrInvalidLeaseEvent)
	}
	if x.At.IsZero() {
		return Event{}, fmt.Errorf("%w: failure without time", ErrInvalidLeaseEvent)
	}
	return Event{
		Kind:  KindLeaseRunFailed,
		Host:  clean(x.HostLabel, maxLeaseField),
		State: "failed",
		Reason: "Grant " + clean(x.GrantName, maxLeaseField) + ", action " + clean(x.Action, maxLeaseField) +
			" on " + clean(x.HostLabel, maxLeaseField),
		link: link,
		Time: x.At,
	}, nil
}

// NewDailyDigest returns the digest event whose text is body (see
// opsdigest.Build). body is sent unchanged apart from the check: non-empty,
// valid UTF-8, at most MaxDailyDigestBytes, and only printable characters
// and newlines.
func NewDailyDigest(body string, at time.Time) (Event, error) {
	if body == "" || len(body) > MaxDailyDigestBytes || !utf8.ValidString(body) {
		return Event{}, fmt.Errorf("%w: digest text", ErrInvalidLeaseEvent)
	}
	for _, r := range body {
		if r != '\n' && (!isPrintRune(r)) {
			return Event{}, fmt.Errorf("%w: digest text has a control character", ErrInvalidLeaseEvent)
		}
	}
	if at.IsZero() {
		return Event{}, fmt.Errorf("%w: digest without time", ErrInvalidLeaseEvent)
	}
	return Event{Kind: KindDailyDigest, body: body, Time: at}, nil
}

// leaseLink returns base + "/leases/" + id after checking both parts.
func leaseLink(base, id string) (string, error) {
	if !leaseIDRe.MatchString(id) {
		return "", fmt.Errorf("%w: grant id", ErrInvalidLeaseEvent)
	}
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" ||
		u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", fmt.Errorf("%w: NOS base URL", ErrInvalidLeaseEvent)
	}
	return u.Scheme + "://" + u.Host + "/leases/" + id, nil
}

// leftText renders the remaining time in whole hours or days.
func leftText(d time.Duration) string {
	hours := int(d / time.Hour)
	switch {
	case hours < 1:
		return "under 1 hour left"
	case hours < 48:
		return strconv.Itoa(hours) + " hours left"
	default:
		return strconv.Itoa(hours/24) + " days left"
	}
}

// isPrintRune reports whether r is a printable character that may appear in
// a digest line.
func isPrintRune(r rune) bool {
	return unicode.IsPrint(r) && !unicode.Is(unicode.Bidi_Control, r)
}
