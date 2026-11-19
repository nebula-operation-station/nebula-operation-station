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
	"sync"
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

// inboxCheckLogEvery is the least time between two log lines for a failing
// admin check, so a broken check does not write a line on every page view.
const inboxCheckLogEvery = time.Minute

// inboxVisible reports whether the request's user may see the inbox: the
// log is wired, there is a session, and the admin check passes. An admin
// check error denies (it is logged, at most once a minute; its detail is not
// shown). Pages reach this rule through navVisible, which runs it once per
// request.
func (h *Handler) inboxVisible(r *http.Request) bool {
	if h.inbox == nil || h.inboxAdmin == nil {
		return false
	}
	s, ok := auth.SessionFrom(r.Context())
	if !ok || s.UserName == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(r.Context(), notificationsCallTimeout)
	defer cancel()
	admin, err := h.inboxAdmin(ctx, s.UserName)
	if err != nil {
		h.logInboxCheckFailure(err)
		return false
	}
	return admin
}

// logInboxCheckFailure logs a failed admin check, at most once per
// inboxCheckLogEvery.
func (h *Handler) logInboxCheckFailure(err error) {
	h.inboxLogMu.Lock()
	defer h.inboxLogMu.Unlock()
	now := time.Now()
	if h.now != nil {
		now = h.now()
	}
	if !h.inboxLogAt.IsZero() && now.Sub(h.inboxLogAt) < inboxCheckLogEvery {
		return
	}
	h.inboxLogAt = now
	h.log.Error("notifications: admin check", "error", err)
}

// inboxNavKey is the request-context key of the per-request inbox cache.
type inboxNavKey struct{}

// inboxNav caches the result of inboxVisible for one request. The page, the
// page's navigation data and the navigation of the subpackage pages ask it,
// so the admin check runs at most once per request.
type inboxNav struct {
	h       *Handler
	once    sync.Once
	visible bool
}

// withInboxNav returns r carrying a fresh inbox cache for h, unless r already
// carries one for h.
func (h *Handler) withInboxNav(r *http.Request) *http.Request {
	if n, ok := r.Context().Value(inboxNavKey{}).(*inboxNav); ok && n.h == h {
		return r
	}
	return r.WithContext(context.WithValue(r.Context(), inboxNavKey{}, &inboxNav{h: h}))
}

// navVisible is inboxVisible, computed at most once for the request when r
// carries a cache (see withInboxNav).
func (h *Handler) navVisible(r *http.Request) bool {
	n, ok := r.Context().Value(inboxNavKey{}).(*inboxNav)
	if !ok || n.h != h {
		return h.inboxVisible(r)
	}
	n.once.Do(func() { n.visible = h.inboxVisible(r) })
	return n.visible
}

// WithNotificationsNav wraps next so that the requests it serves share one
// inbox visibility check. The server wraps the mux that holds the subpackage
// pages with it; NotificationsNavVisible then reads the same answer.
func (h *Handler) WithNotificationsNav(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, h.withInboxNav(r))
	})
}

// NotificationsNavVisible reports whether the Notifications navigation entry
// is shown for r. It is for the Chrome adapters of the subpackage pages. It
// reports false when the request does not come through WithNotificationsNav,
// so an unwired server never shows the entry.
func NotificationsNavVisible(r *http.Request) bool {
	n, ok := r.Context().Value(inboxNavKey{}).(*inboxNav)
	if !ok {
		return false
	}
	return n.h.navVisible(r)
}

// handleNotifications serves GET /notifications.
func (h *Handler) handleNotifications(w http.ResponseWriter, r *http.Request) {
	if h.inbox == nil {
		http.NotFound(w, r)
		return
	}
	r = h.withInboxNav(r)
	if !h.navVisible(r) {
		http.Error(w, "forbidden: notifications need the admin role", http.StatusForbidden)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), notificationsCallTimeout)
	defer cancel()

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
			if notifylog.IsNOSLink(e.Link) {
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
