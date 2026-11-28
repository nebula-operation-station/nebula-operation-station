// SPDX-License-Identifier: AGPL-3.0-or-later

// Maintainer decisions on findings, backend (ADR 0011 D5, D6, Q4; decision
// of 2026-11-21 "variant A", docs/implementation/vuln-decisions-assertion.md):
// the server side of the decision endpoints of internal/web/ui/vuln_decide.go.
//
// A decision of any of the five kinds needs a fresh WebAuthn assertion, and
// the assertion is a login assertion (BeginLogin/FinishLogin: the executor
// makes the single-use challenge, verifies the assertion against the
// registered credentials and names the credential's user). The server binds
// the challenge to the decision: BeginVulnDecision keeps the challenge ID
// with the user, the decision digest and the expiry; CommitVulnDecision
// takes the challenge out (single use) and applies the decision only when
// the user, the digest and the expiry match, the asserting user is the
// requesting user and the requester is still the maintainer. The decision
// and its audit line are written in one transaction by the vulnstore
// methods (DecisionAuditor).
//
// The version basis of accept_risk and false_positive and the reset value
// of mark_reset come from the server's own state, never from the browser.

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Limits of the decision challenges. The TTL is the bound of the agent
// settings challenges (vuln_agentcfg.go): the executor's login challenge
// expires after two minutes as well. The pool of begun decisions is as large
// as the UI's pending table (ui.maxVulnPending), so a full server pool cannot
// be reached before the UI's own bound answers 429.
const (
	vulnDecisionChallengeTTL  = vulnAgentChallengeTTL
	maxVulnDecisionChallenges = 64
)

// vulnDecisionChallenge is a begun decision: its challenge belongs to user
// and to the decision with digest, until expires.
type vulnDecisionChallenge struct {
	user    string
	digest  string
	expires time.Time
}

// vulnDecider implements the decision backend of ui.VulnPages.
type vulnDecider struct {
	v     *vulnService
	audit vulnstore.DecisionAuditor
	admin func(ctx context.Context) bool
	login vulnAgentLogin
	now   func() time.Time
	log   *slog.Logger

	mu      sync.Mutex
	pending map[string]vulnDecisionChallenge
}

// newVulnDecider returns the decision backend over the findings service v;
// every dependency is required except now (time.Now).
func newVulnDecider(v *vulnService, audit vulnstore.DecisionAuditor, admin func(context.Context) bool,
	login vulnAgentLogin, now func() time.Time, log *slog.Logger) (*vulnDecider, error) {
	if v == nil || v.store == nil || audit == nil || admin == nil || login == nil || log == nil {
		return nil, errors.New("vulnerability decisions: findings store, audit log, admin check, executor and log are required")
	}
	if now == nil {
		now = time.Now
	}
	return &vulnDecider{v: v, audit: audit, admin: admin, login: login, now: now, log: log,
		pending: map[string]vulnDecisionChallenge{}}, nil
}

// BeginVulnDecision re-checks the maintainer, starts an executor login
// challenge and binds it to user and the decision's digest. The pool bound is
// checked before the executor is asked, so a refused begin uses no challenge.
func (d *vulnDecider) BeginVulnDecision(ctx context.Context, user string, dec ui.VulnDecision) (ui.VulnChallenge, error) {
	if !d.admin(ctx) {
		return ui.VulnChallenge{}, ui.ErrVulnAssertionRefused
	}
	if err := d.reserve(); err != nil {
		return ui.VulnChallenge{}, err
	}
	b, err := d.login.BeginLogin(ctx, &pb.BeginLoginRequest{})
	if err != nil {
		return ui.VulnChallenge{}, fmt.Errorf("begin decision: executor login challenge: %w", err)
	}
	now := d.now()
	exp := now.Add(vulnDecisionChallengeTTL)
	if e := b.GetExpiryUnix(); e > 0 && time.Unix(e, 0).Before(exp) {
		exp = time.Unix(e, 0)
	}
	id := b.GetLoginId()
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pruneLocked(now)
	if _, dup := d.pending[id]; dup || id == "" {
		return ui.VulnChallenge{}, errors.New("begin decision: executor returned a reused challenge")
	}
	// Another begin may have filled the pool while the executor was asked;
	// the challenge of this begin is then dropped (the executor expires it).
	if len(d.pending) >= maxVulnDecisionChallenges {
		return ui.VulnChallenge{}, errVulnDecisionChallengeFull
	}
	d.pending[id] = vulnDecisionChallenge{user: user, digest: dec.Digest(), expires: exp}
	return ui.VulnChallenge{ID: id, Options: b.GetRequestOptionsJson()}, nil
}

// errVulnDecisionChallengeFull: too many begun decisions.
var errVulnDecisionChallengeFull = errors.New("too many vulnerability decisions in progress")

// reserve reports errVulnDecisionChallengeFull when the pool of begun
// decisions has no room, after the expired ones are dropped.
func (d *vulnDecider) reserve() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pruneLocked(d.now())
	if len(d.pending) >= maxVulnDecisionChallenges {
		return errVulnDecisionChallengeFull
	}
	return nil
}

// pruneLocked drops the begun decisions that have expired at now. d.mu must
// be held.
func (d *vulnDecider) pruneLocked(now time.Time) {
	for k, p := range d.pending {
		if !now.Before(p.expires) {
			delete(d.pending, k)
		}
	}
}

// take removes challenge id and reports whether it was begun by user for
// the decision with digest and has not expired. It is removed in every case.
func (d *vulnDecider) take(id, user, digest string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	p, ok := d.pending[id]
	if !ok {
		return false
	}
	delete(d.pending, id)
	return p.user == user && p.digest == digest && d.now().Before(p.expires)
}

// CommitVulnDecision re-checks the maintainer, consumes the challenge (it
// must have been begun by user for exactly this decision), has the executor
// verify the assertion (which must come from user's credential) and applies
// the decision. The applied decision and its audit line are one transaction
// in the vulnstore.
func (d *vulnDecider) CommitVulnDecision(ctx context.Context, user, challengeID string, dec ui.VulnDecision, assertion []byte) error {
	if !d.admin(ctx) {
		d.refused(user, "not_maintainer")
		return fmt.Errorf("commit decision: not the maintainer: %w", ui.ErrVulnAssertionRefused)
	}
	if !d.take(challengeID, user, dec.Digest()) {
		d.refused(user, "challenge")
		return fmt.Errorf("commit decision: challenge not begun by this user for this decision: %w", ui.ErrVulnAssertionRefused)
	}
	res, err := d.login.FinishLogin(ctx, &pb.FinishLoginRequest{LoginId: challengeID, AssertionJson: assertion})
	if err != nil {
		switch status.Code(err) {
		case codes.Unauthenticated, codes.InvalidArgument, codes.NotFound, codes.PermissionDenied:
			d.refused(user, "assertion")
			return fmt.Errorf("commit decision: %w", ui.ErrVulnAssertionRefused)
		}
		return fmt.Errorf("commit decision: executor assertion check: %w", err)
	}
	if res.GetUserName() != user {
		d.refused(user, "other_user")
		return fmt.Errorf("commit decision: assertion of another user: %w", ui.ErrVulnAssertionRefused)
	}
	if err := d.apply(ctx, user, dec); err != nil {
		return fmt.Errorf("commit decision: %w", err)
	}
	return nil
}

// refused logs a refused decision (the audit line of a refusal; no secret
// is logged).
func (d *vulnDecider) refused(user, reason string) {
	d.log.Warn("audit", "kind", "vuln.decision_refused", "user", user, "reason", reason)
}

// apply writes the decision of the kind it names through the vulnstore
// method of that kind, with the maintainer user as the actor. The approver
// of accept_risk is that maintainer too: the name the browser sent is part
// of the digest the maintainer asserted, but it is not trusted as the actor.
func (d *vulnDecider) apply(ctx context.Context, user string, dec ui.VulnDecision) error {
	switch dec.Kind {
	case ui.VulnAcceptRisk:
		basis, err := d.basis(ctx, dec.Key)
		if err != nil {
			return err
		}
		return d.v.store.SetAcceptedRisk(ctx, dec.Key, vulnstore.AcceptRisk{Approver: user, Reason: dec.Reason,
			Expires: dec.Expires, BasisVersion: basis}, d.audit)
	case ui.VulnFalsePositive:
		basis, err := d.basis(ctx, dec.Key)
		if err != nil {
			return err
		}
		return d.v.store.SetFalsePositive(ctx, dec.Key, vulnstore.MarkFalsePositive{By: user, Category: dec.Category,
			Reason: dec.Reason, BasisVersion: basis}, d.audit)
	case ui.VulnConfirmHold:
		_, err := d.v.store.ConfirmHeld(ctx, dec.RunID, dec.Key, user, dec.Reason, d.audit)
		return err
	case ui.VulnDiscardHold:
		return d.v.store.DiscardHeld(ctx, dec.RunID, dec.Key, user, d.audit)
	case ui.VulnMarkReset:
		// The reset value is the one the latest regressed run reported, as
		// the server reads it; the browser names only the run.
		view, err := d.v.store.MarkResetCandidate(ctx, dec.SourceID)
		if err != nil {
			return err
		}
		if view.RunID == "" || view.RunID != dec.RunID {
			return fmt.Errorf("mark reset %s: the latest regressed run changed: %w", dec.SourceID, vulnstore.ErrResetRefused)
		}
		m, err := d.v.store.ResetMark(ctx, vulnstore.MarkResetRequest{SourceID: dec.SourceID, RunID: dec.RunID,
			ContentDate: view.ReportedDate, Sequence: view.ReportedSeq, Admin: user, Reason: dec.Reason}, d.audit)
		if err != nil {
			return err
		}
		// Once per applied reset, and only after it committed (ADR 0011 D5).
		d.v.enqueue("mark_reset", func(ctx context.Context) { d.v.notifier.MarkReset(ctx, m) })
		return nil
	default:
		return fmt.Errorf("decision kind %q: %w", dec.Kind, vulnstore.ErrInvalidInput)
	}
}

// basis returns NOS's current version basis of the finding's component
// (ADR 0011 D4), from NOS's own inventory. A finding NOS cannot judge has
// no basis and no human decision can be bound to it.
func (d *vulnDecider) basis(ctx context.Context, key vulnfinding.Key) (string, error) {
	f, err := d.v.store.Get(ctx, key)
	if err != nil {
		return "", err
	}
	a := d.v.assessFinding(ctx, f)
	if a.nosVersion == "" {
		return "", fmt.Errorf("NOS does not know the component's version: %w", vulnstore.ErrInvalidInput)
	}
	return a.nosVersion, nil
}
