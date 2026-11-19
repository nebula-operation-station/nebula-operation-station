// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/notifylog"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// inboxWiring is the notifications inbox of the server (ADR 0016 D10): the
// notification log over the server database and the admin rule of the page.
type inboxWiring struct {
	Log   ui.NotificationLog
	Admin ui.NotificationAdminFunc
}

// newInboxWiring builds the inbox over db. The admin rule is the one of the
// other admin pages (isAdmin, the privileged session of the request, see
// vulnAdmin), so the inbox needs no separate role. Without this wiring the
// /notifications page answers 404 and the navigation entry stays hidden.
func newInboxWiring(db *sql.DB, isAdmin func(ctx context.Context) bool) (inboxWiring, error) {
	if isAdmin == nil {
		return inboxWiring{}, errors.New("notification inbox: nil admin rule")
	}
	store, err := notifylog.New(db, time.Now)
	if err != nil {
		return inboxWiring{}, fmt.Errorf("notification inbox: %w", err)
	}
	return inboxWiring{
		Log: store,
		Admin: func(ctx context.Context, _ string) (bool, error) {
			return isAdmin(ctx), nil
		},
	}, nil
}
