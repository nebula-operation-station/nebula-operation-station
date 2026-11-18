// SPDX-License-Identifier: AGPL-3.0-or-later

// The notifications inbox (ADR 0016 D10, AG-06): GET /notifications lists
// the notification log, newest first, one page at a time.
//
// The page only reads the log. It has no form and no POST, calls no
// provider and no agent, and needs no LLM, so it works without them. The
// log holds structured fields only; every value is rendered as escaped
// text. A link is shown only when it is a plain NOS path, checked again
// here before rendering (the store checks it on write too).
//
// Visibility: the page is for admins only. Rows show what NOS sent or held
// back, so a non-admin gets 403, the same answer as the network device
// pages, and an admin check that fails denies access.
package ui

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/notifylog"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
)

const (
	// notificationsPageSize is the number of rows per page. It is at most
	// notifylog.MaxPage.
	notificationsPageSize = 50
	// notificationsCallTimeout bounds the log read and the admin check.
	notificationsCallTimeout = 5 * time.Second
	// notificationsCursorMaxDigits is the longest accepted cursor: the digits
	// of the largest int64.
	notificationsCursorMaxDigits = 19
)

// NotificationLog reads the notification log. *notifylog.Store satisfies it.
type NotificationLog interface {
	// List returns up to limit entries, newest first, with Seq below
	// afterSeq (0 means the newest page).
	List(ctx context.Context, afterSeq int64, limit int) ([]notifylog.Entry, error)
}

// NotificationAdminFunc reports whether the logged-in web user has the
// admin role. An error denies access.
type NotificationAdminFunc func(ctx context.Context, user string) (bool, error)

// notificationsData is the data of the notifications page.
type notificationsData struct {
	// Unavailable is true when the log could not be read; the page then
	// shows a fixed text and no detail.
	Unavailable bool
	// Items are the rows of this page, newest first.
	Items []notificationRow
	// HasNext is true when an older page may exist; NextAfter is its cursor.
	HasNext   bool
	NextAfter int64
}

// notificationRow is one row, already reduced to display text.
type notificationRow struct {
	At           time.Time
	Kind         string
	Host         string
	State        string
	Reason       string
	OutcomeText  string
	OutcomeBadge string
	ExecutionID  string
	// Href is the NOS link, empty when the entry has none or it is not a
	// plain NOS path.
	Href string
}

// notificationOutcome maps an outcome code to its label and badge class.
// Unknown codes are shown as such.
func notificationOutcome(o notifylog.Outcome) (text, badge string) {
	switch o {
	case notifylog.OutcomeSent:
		return "Sent", "badge--ok"
	case notifylog.OutcomeHeldRateLimit:
		return "Throttled", "badge--amber"
	case notifylog.OutcomeHeldMuted:
		return "Muted", "badge--grey"
	case notifylog.OutcomeFailed:
		return "Failed", "badge--critical"
	}
	return "Unknown", "badge--unknown"
}

// safeNOSLink reports whether s is a plain NOS path: it starts with "/",
// has no "//", backslash, "?" or "#", holds only printable ASCII without
// spaces, and is at most notifylog.MaxLink bytes. It is the same rule the
// notification log applies on write, checked again before a link is shown.
func safeNOSLink(s string) bool {
	if s == "" || len(s) > notifylog.MaxLink || s[0] != '/' {
		return false
	}
	if strings.Contains(s, "//") || strings.ContainsAny(s, `\?#`) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}

// parseNotificationCursor reads the after parameter strictly. Empty means
// the newest page (0). Anything else must be a decimal integer of at most
// notificationsCursorMaxDigits digits, at least 1, with no sign, space or
// other character.
func parseNotificationCursor(raw string) (int64, error) {
	if raw == "" {
		return 0, nil
	}
	if len(raw) > notificationsCursorMaxDigits {
		return 0, errors.New("cursor too long")
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < '0' || raw[i] > '9' {
			return 0, errors.New("cursor is not a decimal number")
		}
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 1 {
		return 0, errors.New("cursor out of range")
	}
	return n, nil
}

// handleNotifications serves GET /notifications.
func (h *Handler) handleNotifications(w http.ResponseWriter, r *http.Request) {
	if h.inbox == nil {
		http.NotFound(w, r)
		return
	}
	s, ok := auth.SessionFrom(r.Context())
	if !ok || s.UserName == "" {
		http.Error(w, "forbidden: notifications need the admin role", http.StatusForbidden)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), notificationsCallTimeout)
	defer cancel()
	admin := false
	if h.inboxAdmin != nil {
		var err error
		admin, err = h.inboxAdmin(ctx, s.UserName)
		if err != nil {
			h.log.Error("notifications: admin check", "error", err)
			admin = false
		}
	}
	if !admin {
		http.Error(w, "forbidden: notifications need the admin role", http.StatusForbidden)
		return
	}

	vals := r.URL.Query()["after"]
	if len(vals) > 1 {
		http.Error(w, "invalid cursor", http.StatusBadRequest)
		return
	}
	after := ""
	if len(vals) == 1 {
		after = vals[0]
	}
	cursor, err := parseNotificationCursor(after)
	if err != nil {
		http.Error(w, "invalid cursor", http.StatusBadRequest)
		return
	}

	data := pageData{Title: "Notifications", Active: "notifications", Content: "notifications"}
	page := &notificationsData{}
	entries, err := h.inbox.List(ctx, cursor, notificationsPageSize)
	if err != nil {
		h.log.Error("notifications: list", "error", err)
		page.Unavailable = true
	} else {
		for _, e := range entries {
			text, badge := notificationOutcome(e.Outcome)
			row := notificationRow{
				At:           e.At,
				Kind:         string(e.Kind),
				Host:         e.Host,
				State:        string(e.State),
				Reason:       string(e.Reason),
				OutcomeText:  text,
				OutcomeBadge: badge,
				ExecutionID:  e.ExecutionID,
			}
			if safeNOSLink(e.Link) {
				row.Href = e.Link
			}
			page.Items = append(page.Items, row)
		}
		if len(entries) == notificationsPageSize {
			page.HasNext = true
			page.NextAfter = entries[len(entries)-1].Seq
		}
	}
	data.Notifications = page
	h.render(w, r, data)
}
