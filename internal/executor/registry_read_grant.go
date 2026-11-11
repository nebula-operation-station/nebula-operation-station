// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
)

// Production read-grant profile for private registry reads (ADR 0006,
// cu06 part 1, G13; Q6 answered 2026-11-11, recommended profile).
//
// Every ReadPrivateRegistry call needs an approved, unexpired, unrevoked
// read grant of rate profile schedgrant.RegistryReadProfile whose frozen
// target for the registry names exactly the executor's current record
// (digest and vault version) and credential (random identity and vault
// version), and which lists the method and the exact repository. Nothing
// re-binds: a rotation, a removal and re-add or any record change leaves
// every older lease stale until a new one is approved.
//
// Reads obey the permit authority's read pause (lock, recovery login,
// restart until local credential unlock, pending recovery) exactly like
// SSH, provider and device reads. The spend is reserved durably in the
// shared read-grant counters before any registry I/O: one unit of the
// per-registry rolling-hour budget and the per-repository, per-method
// interval (at least schedgrant.RegistryMinInterval). A refusal of the
// re-check right after the reservation releases it again.
//
// The lease never names or carries a credential value: the credential
// stays in the executor vault, and ReadPrivateRegistry returns sanitized
// values only.

// Sentinel errors of the registry read lease check. Callers branch with
// errors.Is; registryLeaseStatus maps them to gRPC codes.
var (
	// ErrRegistryNoLease: no approved, unrevoked lease names the registry.
	ErrRegistryNoLease = errors.New("executor: no approved registry read lease covers the private registry")
	// ErrRegistryLeaseExpired: the only leases naming the registry expired.
	ErrRegistryLeaseExpired = errors.New("executor: the registry read lease has expired")
	// ErrRegistryLeaseStale: a lease names the registry, but its record or
	// credential identity is no longer the executor's.
	ErrRegistryLeaseStale = errors.New("executor: the private registry record or credential changed; the registry read lease needs replacement")
	// ErrRegistryReadNotLeased: a current lease names the registry but not
	// this method on this repository.
	ErrRegistryReadNotLeased = errors.New("executor: the registry read lease does not cover this repository or method")
	// ErrRegistryBudget: the per-registry rolling-hour budget is exhausted.
	ErrRegistryBudget = errors.New("executor: the private registry's rolling-hour read budget is exhausted")
	// ErrRegistryTooSoon: the same read ran within its interval.
	ErrRegistryTooSoon = errors.New("executor: the same private registry read ran less than its minimum interval ago")
	// ErrRegistryReadPaused: the permit authority's read pause holds.
	ErrRegistryReadPaused = errors.New("executor: private registry reads are paused until local credential unlock")
	// errRegistryLeaseNoStore: the executor has no read-grant store.
	errRegistryLeaseNoStore = errors.New("executor: no read-grant store")
)

// registryGrantKeyPrefix keeps registry counters disjoint from host,
// provider ("pve:") and device ("netdev:") keys in the shared counters.
const registryGrantKeyPrefix = "registry:"

// registryBudgetKey is the rolling-hour budget key of a registry.
func registryBudgetKey(registryID string) string { return registryGrantKeyPrefix + registryID }

// registryActionKey is the interval key of one method on one repository;
// combined with the budget key it is per registry, repository and method.
func registryActionKey(method, repository string) string {
	return registryGrantKeyPrefix + method + ":" + repository
}

// RegistryReadGrants returns the production RegistryReadAuthorizer: the
// registry read leases in the executor's read-grant store.
// cmd/nebula-executor wires it with SetRegistryReadAuthorizer.
func (s *Service) RegistryReadGrants() RegistryReadAuthorizer { return registryReadGrants{s: s} }

type registryReadGrants struct{ s *Service }

// AuthorizeRegistryRead implements RegistryReadAuthorizer.
func (g registryReadGrants) AuthorizeRegistryRead(r RegistryRead) (RegistryReadClaim, error) {
	c, err := g.s.checkRegistryLease(context.Background(), r, g.s.clock())
	if err != nil {
		if g.s.log != nil && !isRegistryLeaseRefusal(err) {
			g.s.log.Error("registry read lease check failed", "registry", r.RegistryID, "error", err.Error())
		}
		return nil, registryLeaseStatus(err)
	}
	return c, nil
}

// registryLeaseClaim is one reserved registry read.
type registryLeaseClaim struct {
	s       *Service
	grantID string
	epoch   uint64
}

// ID names the lease whose budget paid for the read.
func (c *registryLeaseClaim) ID() string { return c.grantID }

// Check re-verifies the claim without spending: the read pause still
// allows reads in the same lock generation and the lease is still stored,
// unrevoked and unexpired.
func (c *registryLeaseClaim) Check() error {
	if err := c.s.registryLeaseRecheck(c.epoch, c.grantID); err != nil {
		return registryLeaseStatus(err)
	}
	return nil
}

func (s *Service) registryReadEpoch() (uint64, error) {
	if s.auth == nil {
		return 0, ErrRegistryReadPaused
	}
	epoch, err := s.auth.ReadDispatchEpoch()
	if err == nil {
		return epoch, nil
	}
	switch permit.CodeOf(err) {
	case permit.CodeLeaseInactive, permit.CodeLeaseUnavailable:
		return 0, ErrRegistryReadPaused
	}
	return 0, fmt.Errorf("read pause: %w", err)
}

func (s *Service) registryLeaseRecheck(epoch uint64, grantID string) error {
	cur, err := s.registryReadEpoch()
	if err != nil {
		return err
	}
	if cur != epoch {
		return ErrRegistryReadPaused
	}
	g, ok, err := s.db.ReadGrant(grantID)
	if err != nil {
		return fmt.Errorf("load read grant %s: %w", grantID, err)
	}
	if !ok || !g.RevokedAt.IsZero() {
		return ErrRegistryNoLease
	}
	effective, err := s.db.ReadGrantClock(s.clock())
	if err != nil {
		return fmt.Errorf("read grant clock: %w", err)
	}
	if !effective.Before(g.ExpiresAt) {
		return ErrRegistryLeaseExpired
	}
	return nil
}

// registryLeaseDoc parses a stored grant if it is a registry read lease.
// It returns false for every other grant; a registry read lease that does
// not verify against its stored digest, id and expiry is an error.
func registryLeaseDoc(g permit.StoredReadGrant) (permit.ReadGrantDoc, bool, error) {
	var header struct {
		Grant       string `json:"grant"`
		RateProfile string `json:"rate_profile"`
	}
	if err := json.Unmarshal(g.Doc, &header); err != nil {
		return permit.ReadGrantDoc{}, false, fmt.Errorf("read grant %s: stored document is not JSON", g.ID)
	}
	if header.Grant != permit.ReadGrantFormat || header.RateProfile != schedgrant.RegistryReadProfile {
		return permit.ReadGrantDoc{}, false, nil
	}
	doc, _, digest, err := permit.ParseReadGrant(g.Doc, g.CreatedAt)
	if err != nil || digest != g.Digest || doc.ID != g.ID || doc.ExpiryUnix != g.ExpiresAt.Unix() ||
		doc.RateProfile != schedgrant.RegistryReadProfile {
		return permit.ReadGrantDoc{}, false, fmt.Errorf("read grant %s: stored registry read lease does not verify", g.ID)
	}
	return doc, true, nil
}

// registryTargetMatches reports whether a frozen target names exactly the
// record and credential the read is about to use.
func registryTargetMatches(t permit.RegistryTarget, r RegistryRead) bool {
	return t.RegistryID == r.RegistryID && t.ConfigDigest == r.ConfigDigest && t.ConfigVersion == r.ConfigVersion &&
		t.CredentialID == r.CredentialID && t.CredentialVersion == r.CredentialVersion
}

// checkRegistryLease authorizes one registry read at now and durably
// spends it. It refuses, in this order: paused reads; then, over the
// registry read leases naming the registry, a stale binding, an uncovered
// repository or method, an expired lease or no lease; and when the shared
// counters refuse, ErrRegistryTooSoon or ErrRegistryBudget.
func (s *Service) checkRegistryLease(ctx context.Context, r RegistryRead, now time.Time) (*registryLeaseClaim, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !schedgrant.IsRegistryReadMethod(r.Method) || !schedgrant.ValidRegistryID(r.RegistryID) ||
		!schedgrant.ValidRegistryRepository(r.Repository) {
		return nil, ErrRegistryReadNotLeased
	}
	if s.db == nil {
		return nil, errRegistryLeaseNoStore
	}
	epoch, err := s.registryReadEpoch()
	if err != nil {
		return nil, err
	}
	effective, err := s.db.ReadGrantClock(now)
	if err != nil {
		return nil, fmt.Errorf("read grant clock: %w", err)
	}
	grants, err := s.db.ReadGrants()
	if err != nil {
		return nil, fmt.Errorf("load read grants: %w", err)
	}
	slices.SortFunc(grants, func(x, y permit.StoredReadGrant) int { return strings.Compare(x.ID, y.ID) })

	type candidate struct {
		id  string
		doc permit.ReadGrantDoc
	}
	var candidates []candidate
	var sawStale, sawNotLeased, sawExpired bool
	for _, g := range grants {
		if !g.RevokedAt.IsZero() {
			continue
		}
		doc, isLease, err := registryLeaseDoc(g)
		if err != nil {
			return nil, err
		}
		if !isLease {
			continue
		}
		t, ok := doc.RegistryTarget(r.RegistryID)
		switch {
		case !ok:
			continue
		case !effective.Before(g.ExpiresAt):
			sawExpired = true
		case !registryTargetMatches(t, r):
			sawStale = true
		case !t.AllowsRead(r.Method, r.Repository):
			sawNotLeased = true
		default:
			candidates = append(candidates, candidate{id: g.ID, doc: doc})
		}
	}
	if len(candidates) == 0 {
		switch {
		case sawStale:
			return nil, ErrRegistryLeaseStale
		case sawNotLeased:
			return nil, ErrRegistryReadNotLeased
		case sawExpired:
			return nil, ErrRegistryLeaseExpired
		}
		return nil, ErrRegistryNoLease
	}

	actionKey, budgetKey := registryActionKey(r.Method, r.Repository), registryBudgetKey(r.RegistryID)
	denied := false
	var deniedInterval time.Duration
	for _, c := range candidates {
		interval := max(time.Duration(c.doc.MinIntervalS)*time.Second, schedgrant.RegistryMinInterval)
		budget := min(int(c.doc.RunBudget), schedgrant.RegistryMaxRunBudget)
		prev, hadPrev, err := s.db.ReadActionLastRun(actionKey, budgetKey)
		if err != nil {
			return nil, fmt.Errorf("registry read interval: %w", err)
		}
		reserved, err := s.db.ReserveReadRun(c.id, actionKey, budgetKey, now, budget, interval)
		if errors.Is(err, permit.ErrReadGrantInactive) {
			sawExpired = true
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("reserve registry read on lease %s: %w", c.id, err)
		}
		if !reserved {
			denied, deniedInterval = true, max(deniedInterval, interval)
			continue
		}
		claim := &registryLeaseClaim{s: s, grantID: c.id, epoch: epoch}
		if err := s.registryLeaseRecheck(epoch, c.id); err != nil {
			// No registry I/O happened: give the spend back.
			if _, rerr := s.db.ReleaseReadRun(c.id, actionKey, budgetKey, prev, hadPrev); rerr != nil && s.log != nil {
				s.log.Error("release registry read reservation", "registry", r.RegistryID, "grant", c.id, "error", rerr.Error())
			}
			return nil, err
		}
		if s.log != nil {
			s.log.Info("audit", "kind", "registry_read_authorized", "registry", r.RegistryID, "repository", r.Repository,
				"method", r.Method, "grant", c.id)
		}
		return claim, nil
	}
	switch {
	case denied:
		last, ok, err := s.db.ReadActionLastRun(actionKey, budgetKey)
		if err != nil {
			return nil, fmt.Errorf("registry read interval: %w", err)
		}
		if ok && last.Unix() > effective.Unix()-int64(deniedInterval/time.Second) {
			return nil, ErrRegistryTooSoon
		}
		return nil, ErrRegistryBudget
	case sawExpired:
		return nil, ErrRegistryLeaseExpired
	}
	return nil, ErrRegistryNoLease
}

// isRegistryLeaseRefusal reports whether err is an expected refusal (not
// an internal failure worth an error log line).
func isRegistryLeaseRefusal(err error) bool {
	for _, e := range []error{ErrRegistryNoLease, ErrRegistryLeaseExpired, ErrRegistryLeaseStale, ErrRegistryReadNotLeased,
		ErrRegistryBudget, ErrRegistryTooSoon, ErrRegistryReadPaused, context.Canceled, context.DeadlineExceeded} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// registryLeaseStatus maps a lease check error to a gRPC status with a
// fixed message: missing or unusable authority is PermissionDenied,
// exhausted limits ResourceExhausted, the read pause FailedPrecondition,
// anything else Internal.
func registryLeaseStatus(err error) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return status.FromContextError(err).Err()
	case errors.Is(err, ErrRegistryNoLease):
		return status.Error(codes.PermissionDenied, "read private registry: no approved registry read lease covers the registry")
	case errors.Is(err, ErrRegistryLeaseExpired):
		return status.Error(codes.PermissionDenied, "read private registry: the registry read lease has expired")
	case errors.Is(err, ErrRegistryLeaseStale):
		return status.Error(codes.PermissionDenied, "read private registry: the registry record or credential changed; the registry read lease needs replacement")
	case errors.Is(err, ErrRegistryReadNotLeased):
		return status.Error(codes.PermissionDenied, "read private registry: the registry read lease does not cover this repository or method")
	case errors.Is(err, ErrRegistryTooSoon):
		return status.Error(codes.ResourceExhausted, "read private registry: the same read ran less than its minimum interval ago")
	case errors.Is(err, ErrRegistryBudget):
		return status.Error(codes.ResourceExhausted, "read private registry: the registry's rolling-hour read budget is exhausted")
	case errors.Is(err, ErrRegistryReadPaused):
		return status.Error(codes.FailedPrecondition, "read private registry: reads are paused until local credential unlock")
	}
	return status.Error(codes.Internal, "read private registry: read lease check failed")
}
