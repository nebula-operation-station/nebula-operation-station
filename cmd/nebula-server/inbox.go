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

// cachedVulnAdmin is vulnAdmin with the executor status cached for ttl; see
// cachedVulnAdminWithTimeout.
func cachedVulnAdmin(status ui.StatusProvider, ttl time.Duration, now func() time.Time) func(ctx context.Context) (bool, error) {
	return cachedVulnAdminWithTimeout(status, ttl, now, vulnStatusTimeout)
}

// cachedVulnAdminWithTimeout is vulnAdmin with the executor status cached for
// ttl. The status is read by the cache, not by the caller: the read runs on a
// context that the caller's cancellation does not reach, bounded by
// statusTimeout, and its result, a failed read included, is cached for ttl
// from the moment it completes. So a hung executor costs one read per ttl,
// and a caller whose own deadline is shorter only stops waiting for that read
// (it gets its context error and the read still completes and is cached).
// Concurrent callers share the read in flight; no lock is held while waiting.
// The one exception is a caller whose context has already ended before any
// read starts: it starts no read and caches nothing. A status error is
// returned with false, never as "no session" silently.
func cachedVulnAdminWithTimeout(status ui.StatusProvider, ttl time.Duration, now func() time.Time, statusTimeout time.Duration) func(ctx context.Context) (bool, error) {
	type read struct {
		done   chan struct{}
		active bool
		expiry int64
		err    error
	}
	var (
		mu       sync.Mutex
		at       time.Time
		fetched  bool
		cached   *read // the last completed read, valid while fetched
		inflight *read // the read in progress, if any
	)
	return func(ctx context.Context) (bool, error) {
		if status == nil {
			return false, nil
		}
		mu.Lock()
		r := cached
		switch {
		case fetched && now().Sub(at) < ttl:
		case inflight != nil:
			r = inflight
		default:
			if err := ctx.Err(); err != nil {
				mu.Unlock()
				return false, err
			}
			nr := &read{done: make(chan struct{})}
			inflight = nr
			go func() {
				sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), statusTimeout)
				st, err := status.GetStatus(sctx, &pb.GetStatusRequest{})
				cancel()
				if err == nil {
					nr.active, nr.expiry = st.GetPrivilegedSessionActive(), st.GetPrivilegedSessionExpiryUnix()
				}
				nr.err = err
				mu.Lock()
				cached, inflight, at, fetched = nr, nil, now(), true
				mu.Unlock()
				close(nr.done)
			}()
			r = nr
		}
		mu.Unlock()
		select {
		case <-r.done:
		default:
			// Only a read still in flight makes the caller wait, and only
			// until its own context ends.
			select {
			case <-r.done:
			case <-ctx.Done():
				return false, ctx.Err()
			}
		}
		if r.err != nil {
			return false, r.err
		}
		return r.active && auth.HoldsPrivilegedSession(ctx, r.expiry), nil
	}
}
