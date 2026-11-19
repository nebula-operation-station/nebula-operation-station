// SPDX-License-Identifier: AGPL-3.0-or-later

// Ops agent settings (ADR 0016 D12): the server's backend of the settings
// section "Ops-Agent" over opsconfig.Store and the audit log, and the
// opsagent.settings_changed notification after a commit.
//
// The rules are those of the vulnerability agent settings
// (vuln_agentcfg.go). A change needs the maintainer, checked at begin and
// again at commit, and a fresh user-verified assertion from the executor's
// login (BeginLogin/FinishLogin). The server binds the single-use
// challenge to the user who began the change and to its change digest
// (opsconfig.ChangeDigest): a commit is refused unless the user, the digest
// and the asserting user all match. The store writes the change and its
// audit entry in one transaction. The notification follows the commit; a
// failed delivery does not undo the change.
//
// The LLM credential is never part of this backend: the settings carry no
// credential field.

package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/notify"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsconfig"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Limits of the ops agent settings challenges.
const (
	// opsAgentChallengeTTL bounds a begun change; the executor's login
	// challenge expires after two minutes as well.
	opsAgentChallengeTTL = 2 * time.Minute
	// maxOpsAgentChallenges bounds the begun, not yet committed changes.
	maxOpsAgentChallenges = 32
	// opsAgentNotifyTimeout bounds the settings_changed delivery after a
	// commit. It runs on a context detached from the request: the request's
	// own bound (vulnCallTimeout) is already partly used by the executor
	// calls, and a client disconnect must not cancel the event.
	opsAgentNotifyTimeout = 60 * time.Second
)

// errOpsAgentChallengeFull: too many begun changes.
var errOpsAgentChallengeFull = errors.New("too many ops agent setting changes in progress")

// opsAgentNotifier sends the settings_changed event after a commit;
// *notify.Notifier implements it.
type opsAgentNotifier interface {
	NotifyOpsAgentSettingsChanged(ctx context.Context, c notify.OpsAgentSettingsChange, at time.Time) int
}

// opsAgentChallenge is a begun change: the challenge belongs to user and to
// the change with digest.
type opsAgentChallenge struct {
	user    string
	digest  [sha256.Size]byte
	expires time.Time
}

// opsAgentSettings implements ui.OpsAgentSettings.
type opsAgentSettings struct {
	store    *opsconfig.Store
	audit    opsconfig.Auditor
	admin    func(ctx context.Context) bool
	login    vulnAgentLogin
	notifier opsAgentNotifier
	now      func() time.Time
	log      *slog.Logger

	mu      sync.Mutex
	pending map[string]opsAgentChallenge
	// reserved counts the begins that hold a slot while they ask the
	// executor for a challenge; pending+reserved never exceeds the limit.
	reserved int
}

var _ ui.OpsAgentSettings = (*opsAgentSettings)(nil)

// newOpsAgentSettings returns the backend; every dependency is required
// except now (time.Now).
func newOpsAgentSettings(store *opsconfig.Store, audit opsconfig.Auditor, admin func(context.Context) bool,
	login vulnAgentLogin, notifier opsAgentNotifier, now func() time.Time, log *slog.Logger) (*opsAgentSettings, error) {
	if store == nil || audit == nil || admin == nil || login == nil || notifier == nil || log == nil {
		return nil, errors.New("ops agent settings: store, audit log, admin check, executor, notifier and log are required")
	}
	if now == nil {
		now = time.Now
	}
	return &opsAgentSettings{store: store, audit: audit, admin: admin, login: login, notifier: notifier, now: now,
		log: log, pending: map[string]opsAgentChallenge{}}, nil
}

// newOpsAgentWiring builds the settings store on db and the backend over it.
func newOpsAgentWiring(db *sql.DB, audit opsconfig.Auditor, admin func(context.Context) bool,
	login vulnAgentLogin, notifier opsAgentNotifier, log *slog.Logger) (*opsAgentSettings, error) {
	store, err := opsconfig.NewStore(db, nil)
	if err != nil {
		return nil, fmt.Errorf("ops agent settings: %w", err)
	}
	return newOpsAgentSettings(store, audit, admin, login, notifier, nil, log)
}

// OpsAgentConfig reads the stored settings row.
func (s *opsAgentSettings) OpsAgentConfig(ctx context.Context) (opsconfig.Row, error) {
	return s.store.Get(ctx)
}

// OpsAgentCorePrompt returns the fixed core prompt.
func (s *opsAgentSettings) OpsAgentCorePrompt() string { return opsAgentCorePrompt }

// OpsAgentMaintainer reports whether the request's session holds the
// privileged session; the session comes from ctx, user is its name.
func (s *opsAgentSettings) OpsAgentMaintainer(ctx context.Context, _ string) (bool, error) {
	return s.admin(ctx), nil
}

// BeginOpsAgentChange re-checks the maintainer and the settings, starts an
// executor login challenge and binds it to user and the change digest.
func (s *opsAgentSettings) BeginOpsAgentChange(ctx context.Context, user string, c ui.OpsAgentChange) (ui.VulnChallenge, error) {
	if !s.admin(ctx) {
		return ui.VulnChallenge{}, ui.ErrOpsAgentNotMaintainer
	}
	if err := c.Settings.Validate(); err != nil {
		return ui.VulnChallenge{}, fmt.Errorf("begin ops agent settings change: %w", err)
	}
	digest, err := c.Digest()
	if err != nil {
		return ui.VulnChallenge{}, fmt.Errorf("begin ops agent settings change: digest: %w", err)
	}
	// The slot is checked and held before the executor is asked, so a begin
	// refused as full leaves no challenge behind at the executor.
	if err := s.reserve(); err != nil {
		return ui.VulnChallenge{}, err
	}
	held := true
	defer func() {
		if held {
			s.unreserve()
		}
	}()
	b, err := s.login.BeginLogin(ctx, &pb.BeginLoginRequest{})
	if err != nil {
		return ui.VulnChallenge{}, fmt.Errorf("begin ops agent settings change: executor login challenge: %w", err)
	}
	now := s.now()
	exp := now.Add(opsAgentChallengeTTL)
	if e := b.GetExpiryUnix(); e > 0 && time.Unix(e, 0).Before(exp) {
		exp = time.Unix(e, 0)
	}
	id := b.GetLoginId()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reserved--
	held = false
	s.pruneLocked(now)
	if _, dup := s.pending[id]; dup || id == "" {
		return ui.VulnChallenge{}, errors.New("begin ops agent settings change: executor returned a reused challenge")
	}
	s.pending[id] = opsAgentChallenge{user: user, digest: digest, expires: exp}
	return ui.VulnChallenge{ID: id, Options: b.GetRequestOptionsJson()}, nil
}

// reserve holds one slot for a begin that asks the executor. It fails when
// the pending challenges and the held slots fill the limit.
func (s *opsAgentSettings) reserve() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(s.now())
	if len(s.pending)+s.reserved >= maxOpsAgentChallenges {
		return errOpsAgentChallengeFull
	}
	s.reserved++
	return nil
}

// unreserve releases a slot that was not turned into a pending challenge.
func (s *opsAgentSettings) unreserve() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reserved--
}

// pruneLocked drops the expired challenges; s.mu must be held.
func (s *opsAgentSettings) pruneLocked(now time.Time) {
	for k, p := range s.pending {
		if !now.Before(p.expires) {
			delete(s.pending, k)
		}
	}
}

// take removes the challenge id and reports whether it was begun by user
// for the change with digest and is still live. A challenge is single use:
// it is removed whatever the outcome.
func (s *opsAgentSettings) take(id, user string, digest [sha256.Size]byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[id]
	if !ok {
		return false
	}
	delete(s.pending, id)
	return p.user == user && p.digest == digest && s.now().Before(p.expires)
}

// CommitOpsAgentChange re-checks the maintainer, consumes the challenge (it
// must have been begun by user for exactly this change), has the executor
// verify the assertion (which must come from user's credential), and stores
// the change with its audit entry in one transaction. After the commit it
// sends the settings_changed event.
func (s *opsAgentSettings) CommitOpsAgentChange(ctx context.Context, user, challengeID string, c ui.OpsAgentChange, assertion []byte) error {
	if !s.admin(ctx) {
		return ui.ErrOpsAgentNotMaintainer
	}
	digest, err := c.Digest()
	if err != nil {
		return fmt.Errorf("commit ops agent settings change: digest: %w", err)
	}
	if !s.take(challengeID, user, digest) {
		s.log.Warn("audit", "kind", "opsagent.settings_refused", "user", user, "reason", "challenge")
		return fmt.Errorf("commit ops agent settings change: challenge not begun by this user for this change: %w", ui.ErrOpsAgentAssertionRefused)
	}
	res, err := s.login.FinishLogin(ctx, &pb.FinishLoginRequest{LoginId: challengeID, AssertionJson: assertion})
	if err != nil {
		switch status.Code(err) {
		case codes.Unauthenticated, codes.InvalidArgument, codes.NotFound, codes.PermissionDenied:
			s.log.Warn("audit", "kind", "opsagent.settings_refused", "user", user, "reason", "assertion")
			return fmt.Errorf("commit ops agent settings change: %w", ui.ErrOpsAgentAssertionRefused)
		}
		return fmt.Errorf("commit ops agent settings change: executor assertion check: %w", err)
	}
	if res.GetUserName() != user {
		s.log.Warn("audit", "kind", "opsagent.settings_refused", "user", user, "reason", "other_user")
		return fmt.Errorf("commit ops agent settings change: assertion of another user: %w", ui.ErrOpsAgentAssertionRefused)
	}
	old, err := s.store.Get(ctx)
	if err != nil {
		return fmt.Errorf("commit ops agent settings change: read stored settings: %w", err)
	}
	if old.Version != c.BaseVersion {
		return fmt.Errorf("commit ops agent settings change: base version %d, stored %d: %w",
			c.BaseVersion, old.Version, opsconfig.ErrStale)
	}
	cur, err := s.store.Save(ctx, user, c.Settings, c.BaseVersion, s.audit)
	if err != nil {
		return fmt.Errorf("commit ops agent settings change: %w", err)
	}
	change := notify.OpsAgentSettingsChange{Old: old.Settings, New: c.Settings, OldVersion: old.Version, NewVersion: cur.Version}
	// The change is committed: the event must not depend on the request.
	nctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), opsAgentNotifyTimeout)
	defer cancel()
	if s.notifier.NotifyOpsAgentSettingsChanged(nctx, change, s.now()) == 0 {
		s.log.Warn("ops agent settings saved; no notification provider accepted the settings_changed event")
	}
	return nil
}
