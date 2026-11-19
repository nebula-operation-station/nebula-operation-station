// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/notifylog"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
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
// cachedVulnAdmin), so the inbox needs no separate role. An error from
// isAdmin (the executor status could not be read) reaches the inbox, which
// denies and logs it; it is not turned into "not an admin". Without this
// wiring the /notifications page answers 404 and the navigation entry stays
// hidden.
func newInboxWiring(db *sql.DB, isAdmin func(ctx context.Context) (bool, error)) (inboxWiring, error) {
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
			return isAdmin(ctx)
		},
	}, nil
}

// inboxStatusTTL is how long the inbox reuses the executor's privileged-session
// status. The inbox check runs on every page render (navigation entry), and
// vulnAdmin asks the executor each time, with a timeout of vulnStatusTimeout;
// without the cache every page view costs an RPC and waits on a hung executor.
// Whether the request itself holds the privileged session is still checked on
// every call, so only the server-wide "a session is active" bit can be up to
// this old.
const inboxStatusTTL = 3 * time.Second

// cachedVulnAdmin is vulnAdmin with the executor status cached for ttl. A
// failed status read is cached as well, with its error, so a hung executor
// delays at most one request per ttl and every request in that ttl is logged
// as a failed check with the same error; concurrent callers wait for the one
// read in flight instead of each starting their own. A read that failed
// because the caller's own context ended is not cached: it says nothing about
// the executor, and the next request reads again. A status error is returned
// with false, never as "no session" silently.
func cachedVulnAdmin(status ui.StatusProvider, ttl time.Duration, now func() time.Time) func(ctx context.Context) (bool, error) {
	var (
		mu      sync.Mutex
		at      time.Time
		fetched bool
		active  bool
		expiry  int64
		readErr error
	)
	return func(ctx context.Context) (bool, error) {
		if status == nil {
			return false, nil
		}
		mu.Lock()
		if !fetched || now().Sub(at) >= ttl {
			sctx, cancel := context.WithTimeout(ctx, vulnStatusTimeout)
			st, err := status.GetStatus(sctx, &pb.GetStatusRequest{})
			cancel()
			if err != nil && ctx.Err() != nil {
				mu.Unlock()
				return false, err
			}
			active, expiry, readErr = false, 0, err
			if err == nil {
				active, expiry = st.GetPrivilegedSessionActive(), st.GetPrivilegedSessionExpiryUnix()
			}
			at, fetched = now(), true
		}
		a, e, rerr := active, expiry, readErr
		mu.Unlock()
		if rerr != nil {
			return false, rerr
		}
		return a && auth.HoldsPrivilegedSession(ctx, e), nil
	}
}
