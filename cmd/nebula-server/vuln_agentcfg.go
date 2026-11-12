// SPDX-License-Identifier: AGPL-3.0-or-later

// Vulnerability agent LLM settings (ADR 0011 A1.8; autopilot va09): the
// server's backend of the settings section "Vulnerability agent – LLM"
// over vulnstore.AgentConfigStore and the audit log, and the agent's read
// GET /api/v1/vuln/agent-config.
//
// A change needs the maintainer (the holder of the executor's privileged
// session, the admin rule of every admin-only page) and a fresh
// user-verified WebAuthn assertion. The executor offers no RPC that binds
// an assertion to an arbitrary digest, so the assertion is a login
// assertion (BeginLogin/FinishLogin: the executor makes the single-use
// challenge, verifies the assertion against the registered credentials
// and names the credential's user), and the server binds the challenge to
// the change: the challenge ID is kept with the user and the change
// digest, single use, and a commit is refused unless the user, the digest
// and the asserting user all match. The store writes the change and its
// audit entry in one transaction.

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Limits of the agent settings challenges.
const (
	// vulnAgentChallengeTTL bounds a begun change; the executor's login
	// challenge expires after two minutes as well.
	vulnAgentChallengeTTL = 2 * time.Minute
	// maxVulnAgentChallenges bounds the begun, not yet committed changes.
	maxVulnAgentChallenges = 32
)

// vulnAgentCorePrompt is the agent's fixed core prompt shown on the
// settings page and covered by prompt_version. This build carries none
// (the agent ships its own); the page then shows no prompt.
const vulnAgentCorePrompt = ""

// errVulnAgentChallengeFull: too many begun changes.
var errVulnAgentChallengeFull = errors.New("too many vulnerability agent setting changes in progress")

// vulnAgentLogin is the executor's login relay (lazyExecutor).
type vulnAgentLogin interface {
	BeginLogin(ctx context.Context, in *pb.BeginLoginRequest, opts ...grpc.CallOption) (*pb.BeginLoginResponse, error)
	FinishLogin(ctx context.Context, in *pb.FinishLoginRequest, opts ...grpc.CallOption) (*pb.FinishLoginResponse, error)
}

// vulnAgentChallenge is a begun change: the challenge belongs to user and
// to the change with digest.
type vulnAgentChallenge struct {
	user    string
	digest  string
	expires time.Time
}

// vulnAgentSettings implements ui.VulnAgentSettings.
type vulnAgentSettings struct {
	store *vulnstore.AgentConfigStore
	audit vulnstore.AgentAuditor
	admin func(ctx context.Context) bool
	login vulnAgentLogin
	now   func() time.Time
	log   *slog.Logger

	mu      sync.Mutex
	pending map[string]vulnAgentChallenge
}

var _ ui.VulnAgentSettings = (*vulnAgentSettings)(nil)

// newVulnAgentSettings returns the backend; every dependency is required
// except now (time.Now).
func newVulnAgentSettings(store *vulnstore.AgentConfigStore, audit vulnstore.AgentAuditor, admin func(context.Context) bool,
	login vulnAgentLogin, now func() time.Time, log *slog.Logger) (*vulnAgentSettings, error) {
	if store == nil || audit == nil || admin == nil || login == nil || log == nil {
		return nil, errors.New("vulnerability agent settings: store, audit log, admin check, executor and log are required")
	}
	if now == nil {
		now = time.Now
	}
	return &vulnAgentSettings{store: store, audit: audit, admin: admin, login: login, now: now, log: log,
		pending: map[string]vulnAgentChallenge{}}, nil
}

// newVulnAgentWiring builds the settings store on db and the settings
// backend over it, the audit log, the admin check and the executor.
func newVulnAgentWiring(db *sql.DB, audit vulnstore.AgentAuditor, admin func(context.Context) bool,
	login vulnAgentLogin, log *slog.Logger) (*vulnstore.AgentConfigStore, *vulnAgentSettings, error) {
	store, err := vulnstore.NewAgentConfigStore(db, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("vulnerability agent settings: %w", err)
	}
	s, err := newVulnAgentSettings(store, audit, admin, login, nil, log)
	if err != nil {
		return nil, nil, err
	}
	return store, s, nil
}

// VulnAgentConfig reads the stored settings.
func (s *vulnAgentSettings) VulnAgentConfig(ctx context.Context) (vulnstore.AgentConfig, error) {
	return s.store.Get(ctx)
}

// VulnAgentCorePrompt returns the fixed core prompt.
func (s *vulnAgentSettings) VulnAgentCorePrompt() string { return vulnAgentCorePrompt }

// VulnMaintainer reports whether the request's session holds the
// privileged session; the session comes from ctx, user is its name.
func (s *vulnAgentSettings) VulnMaintainer(ctx context.Context, _ string) (bool, error) {
	return s.admin(ctx), nil
}

// BeginVulnAgentChange re-checks the maintainer and the settings, starts
// an executor login challenge and binds it to user and the change digest.
func (s *vulnAgentSettings) BeginVulnAgentChange(ctx context.Context, user string, c ui.VulnAgentChange) (ui.VulnChallenge, error) {
	if !s.admin(ctx) {
		return ui.VulnChallenge{}, ui.ErrVulnAgentNotMaintainer
	}
	if err := c.Settings.Validate(); err != nil {
		return ui.VulnChallenge{}, fmt.Errorf("begin agent settings change: %w", err)
	}
	b, err := s.login.BeginLogin(ctx, &pb.BeginLoginRequest{})
	if err != nil {
		return ui.VulnChallenge{}, fmt.Errorf("begin agent settings change: executor login challenge: %w", err)
	}
	now := s.now()
	exp := now.Add(vulnAgentChallengeTTL)
	if e := b.GetExpiryUnix(); e > 0 && time.Unix(e, 0).Before(exp) {
		exp = time.Unix(e, 0)
	}
	id := b.GetLoginId()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, p := range s.pending {
		if !now.Before(p.expires) {
			delete(s.pending, k)
		}
	}
	if _, dup := s.pending[id]; dup || id == "" {
		return ui.VulnChallenge{}, errors.New("begin agent settings change: executor returned a reused challenge")
	}
	if len(s.pending) >= maxVulnAgentChallenges {
		return ui.VulnChallenge{}, errVulnAgentChallengeFull
	}
	s.pending[id] = vulnAgentChallenge{user: user, digest: c.Digest(), expires: exp}
	return ui.VulnChallenge{ID: id, Options: b.GetRequestOptionsJson()}, nil
}

// take removes the challenge id and reports whether it was begun by user
// for the change with digest and is still live.
func (s *vulnAgentSettings) take(id, user, digest string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[id]
	if !ok {
		return false
	}
	delete(s.pending, id)
	return p.user == user && p.digest == digest && s.now().Before(p.expires)
}

// CommitVulnAgentChange re-checks the maintainer, consumes the challenge
// (it must have been begun by user for exactly this change), has the
// executor verify the assertion (which must come from user's credential),
// and stores the change with its audit entry in one transaction.
func (s *vulnAgentSettings) CommitVulnAgentChange(ctx context.Context, user, challengeID string, c ui.VulnAgentChange, assertion []byte) error {
	if !s.admin(ctx) {
		return ui.ErrVulnAgentNotMaintainer
	}
	if !s.take(challengeID, user, c.Digest()) {
		s.log.Warn("audit", "kind", "vuln.agent_llm_refused", "user", user, "reason", "challenge")
		return fmt.Errorf("commit agent settings change: challenge not begun by this user for this change: %w", ui.ErrVulnAssertionRefused)
	}
	res, err := s.login.FinishLogin(ctx, &pb.FinishLoginRequest{LoginId: challengeID, AssertionJson: assertion})
	if err != nil {
		switch status.Code(err) {
		case codes.Unauthenticated, codes.InvalidArgument, codes.NotFound, codes.PermissionDenied:
			s.log.Warn("audit", "kind", "vuln.agent_llm_refused", "user", user, "reason", "assertion")
			return fmt.Errorf("commit agent settings change: %w", ui.ErrVulnAssertionRefused)
		}
		return fmt.Errorf("commit agent settings change: executor assertion check: %w", err)
	}
	if res.GetUserName() != user {
		s.log.Warn("audit", "kind", "vuln.agent_llm_refused", "user", user, "reason", "other_user")
		return fmt.Errorf("commit agent settings change: assertion of another user: %w", ui.ErrVulnAssertionRefused)
	}
	if _, _, err := s.store.Change(ctx, vulnstore.AgentChange{Settings: c.Settings, BaseVersion: c.BaseVersion, Actor: user}, s.audit); err != nil {
		return fmt.Errorf("commit agent settings change: %w", err)
	}
	return nil
}
