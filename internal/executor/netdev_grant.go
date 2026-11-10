// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vault"
)

// Device read lease enforcement (ADR 0010 D4; ND-13 part 2).
//
// Every ReadNetDevice call needs an approved, unexpired, unrevoked read
// grant of rate profile schedgrant.NetDeviceReadProfile whose frozen
// target for the device names exactly the current registry row: trust
// pin, trust generation and read credential version, and the typed read.
// Nothing re-binds: a re-pin, a credential rotation or a removal leaves
// every older lease stale (ErrGrantStale) until a new one is approved.
//
// Reads are paused while the executor is locked: after Lock or restart no
// read is authorized until local credential unlock (keyring and vault),
// mirroring the permit authority's read pause, and never during recovery.
//
// The spend is reserved durably in the executor's shared read-grant
// counters (executordb ReserveReadRun) before any device I/O: one unit of
// the per-device rolling-hour budget and the per-read interval, at least
// schedgrant.NetDeviceMinInterval (15 minutes). The counters are shared by
// every grant, so overlapping leases cannot multiply either limit, and
// they are atomic, so concurrent calls cannot overspend.

// Sentinel errors of checkNetDeviceGrant. Callers branch with errors.Is;
// netDeviceGrantStatus maps them to gRPC codes.
var (
	// ErrNoGrant: no approved, unrevoked device read lease names the device.
	ErrNoGrant = errors.New("executor: no approved device read lease covers the network device")
	// ErrGrantExpired: the only leases naming the device have expired.
	ErrGrantExpired = errors.New("executor: the device read lease has expired")
	// ErrGrantStale: a lease names the device, but its trust pin, trust
	// generation or read credential version is no longer the registry's.
	ErrGrantStale = errors.New("executor: the network device's trust or read credential changed; the device read lease needs replacement")
	// ErrReadNotGranted: a current lease names the device but not the read.
	ErrReadNotGranted = errors.New("executor: the device read lease does not grant this read")
	// ErrBudget: the per-device rolling-hour read budget is exhausted.
	ErrBudget = errors.New("executor: the network device's rolling-hour read budget is exhausted")
	// ErrTooSoon: the same read of the device ran within its interval.
	ErrTooSoon = errors.New("executor: the same read of the network device ran less than its minimum interval ago")
	// ErrNetDevReadPaused: the executor is locked, restarted without local
	// credential unlock, or in recovery.
	ErrNetDevReadPaused = errors.New("executor: network device reads are paused until local credential unlock")
	// ErrNetDevReadBlocked: the device is blocked.
	ErrNetDevReadBlocked = errors.New("executor: the network device is blocked")
	// ErrNetDevReadGone: the device is unknown or removed.
	ErrNetDevReadGone = errors.New("executor: the network device is not registered")
	// ErrNetDevReadNoCredential: the device has no read credential.
	ErrNetDevReadNoCredential = errors.New("executor: the network device has no read credential")
)

// netDeviceReadEnumPrefix is the enum name prefix stripped to get the
// schedgrant read name.
const netDeviceReadEnumPrefix = "NET_DEVICE_READ_"

// netDevGrantKeyPrefix keeps the device counters disjoint from host,
// provider ("pve:") and action keys in the shared read counters.
const netDevGrantKeyPrefix = "netdev:"

// netDeviceGrant is one authorized and spent device read.
type netDeviceGrant struct {
	// GrantID names the lease whose budget paid for the read.
	GrantID string
	// Read is the schedgrant read name.
	Read string
	// Target is the frozen device target of the paying lease; it equals
	// the registry row at reservation time.
	Target permit.NetDeviceTarget
}

// netDeviceGrantRead returns the schedgrant name of a typed read: the
// lowercase enum suffix, one to one (schedgrant.NetDeviceReads).
func netDeviceGrantRead(r pb.NetDeviceRead) (string, bool) {
	if _, ok := netDeviceReadFamily(r); !ok {
		return "", false
	}
	name := strings.ToLower(strings.TrimPrefix(r.String(), netDeviceReadEnumPrefix))
	return name, schedgrant.IsNetDeviceRead(name)
}

// netDevBudgetKey is the rolling-hour budget key of a device.
func netDevBudgetKey(deviceID string) string { return netDevGrantKeyPrefix + deviceID }

// netDevActionKey is the interval key of one read; combined with the
// budget key it is per device and read.
func netDevActionKey(read string) string { return netDevGrantKeyPrefix + read }

// netDevTooSoonHints remembers the last successful reservation per store,
// device and read in this process. It only chooses between ErrTooSoon and
// ErrBudget after the durable counters refused; it never authorizes.
var netDevTooSoonHints struct {
	mu   sync.Mutex
	last map[netDevHintKey]time.Time
}

type netDevHintKey struct {
	db           *executordb.DB
	device, read string
}

func netDevHintRecord(k netDevHintKey, at time.Time) {
	netDevTooSoonHints.mu.Lock()
	defer netDevTooSoonHints.mu.Unlock()
	if netDevTooSoonHints.last == nil {
		netDevTooSoonHints.last = map[netDevHintKey]time.Time{}
	}
	netDevTooSoonHints.last[k] = at
}

func netDevHintTooSoon(k netDevHintKey, now time.Time, interval time.Duration) bool {
	netDevTooSoonHints.mu.Lock()
	defer netDevTooSoonHints.mu.Unlock()
	last, ok := netDevTooSoonHints.last[k]
	return ok && now.Sub(last) < interval
}

// netDevReadsPaused reports whether device reads are paused: no unlocked
// keyring (lock, restart until local credential unlock), no unlocked vault,
// no permit authority, or pending recovery.
func (s *Service) netDevReadsPaused() (bool, error) {
	if s.auth == nil || s.keys == nil || !s.keys.Unlocked() || s.vault == nil {
		return true, nil
	}
	st, err := s.vault.State()
	if err != nil {
		return true, fmt.Errorf("vault state: %w", err)
	}
	if st != vault.StateUnlocked {
		return true, nil
	}
	_, pending, err := s.db.RecoveryPending()
	if err != nil {
		return true, fmt.Errorf("recovery state: %w", err)
	}
	return pending, nil
}

// netDevCurrentCredentialVersion returns the vault version of the
// device's read credential, 0 if none is stored. It reads metadata only.
func (s *Service) netDevCurrentCredentialVersion(d executordb.NetDevice) (int64, error) {
	rows, err := s.db.ListSecrets()
	if err != nil {
		return 0, fmt.Errorf("list vault secrets: %w", err)
	}
	ref := netDevReadCredRef(d)
	for _, r := range rows {
		if r.ID == ref {
			return r.Version, nil
		}
	}
	return 0, nil
}

// netDevLiveIdentity loads the device and returns its current frozen
// identity, refusing an unknown, removed or blocked device and one
// without read credential.
func (s *Service) netDevLiveIdentity(deviceID string) (executordb.NetDevice, int64, error) {
	dev, ok, err := s.db.GetNetDevice(deviceID)
	if err != nil {
		return executordb.NetDevice{}, 0, fmt.Errorf("load network device %s: %w", deviceID, err)
	}
	switch {
	case !ok || dev.TombstonedAt != nil:
		return executordb.NetDevice{}, 0, ErrNetDevReadGone
	case dev.Blocked:
		return executordb.NetDevice{}, 0, ErrNetDevReadBlocked
	}
	version, err := s.netDevCurrentCredentialVersion(dev)
	if err != nil {
		return executordb.NetDevice{}, 0, fmt.Errorf("network device %s: %w", deviceID, err)
	}
	if version < 1 {
		return executordb.NetDevice{}, 0, ErrNetDevReadNoCredential
	}
	return dev, version, nil
}

// netDevTargetMatches reports whether a frozen target names exactly the
// device's current trust and credential.
func netDevTargetMatches(t permit.NetDeviceTarget, dev executordb.NetDevice, credVersion int64) bool {
	return t.DeviceID == dev.ID && t.TrustPin == dev.PinValue && t.TrustGeneration == dev.TrustGeneration &&
		t.CredentialVersion == credVersion
}

// netDevGrantCandidate is one active lease covering the read.
type netDevGrantCandidate struct {
	id     string
	doc    permit.ReadGrantDoc
	target permit.NetDeviceTarget
}

// netDevLeaseDoc parses a stored grant if it is a device read lease. It
// returns false for every other grant; a device read lease that does not
// verify against its stored digest, id and expiry is an error.
func netDevLeaseDoc(g permit.StoredReadGrant) (permit.ReadGrantDoc, bool, error) {
	var header struct {
		Grant       string `json:"grant"`
		RateProfile string `json:"rate_profile"`
	}
	if err := json.Unmarshal(g.Doc, &header); err != nil {
		return permit.ReadGrantDoc{}, false, fmt.Errorf("read grant %s: stored document is not JSON", g.ID)
	}
	if header.Grant != permit.ReadGrantFormat || header.RateProfile != schedgrant.NetDeviceReadProfile {
		return permit.ReadGrantDoc{}, false, nil
	}
	doc, _, digest, err := permit.ParseReadGrant(g.Doc, g.CreatedAt)
	if err != nil || digest != g.Digest || doc.ID != g.ID || doc.ExpiryUnix != g.ExpiresAt.Unix() ||
		doc.RateProfile != schedgrant.NetDeviceReadProfile {
		return permit.ReadGrantDoc{}, false, fmt.Errorf("read grant %s: stored device read lease does not verify", g.ID)
	}
	return doc, true, nil
}

// checkNetDeviceGrant authorizes one typed read of deviceID at now and
// durably spends it. It refuses, in this order: paused reads
// (ErrNetDevReadPaused); an unknown, removed or blocked device or one
// without read credential, before any lease lookup; then, over the
// device read leases naming the device, ErrGrantStale, ErrReadNotGranted,
// ErrGrantExpired or ErrNoGrant; and when the shared counters refuse,
// ErrTooSoon or ErrBudget. Other errors are internal and carry no secret.
func (s *Service) checkNetDeviceGrant(ctx context.Context, deviceID string, r pb.NetDeviceRead, now time.Time) (netDeviceGrant, error) {
	if err := ctx.Err(); err != nil {
		return netDeviceGrant{}, err
	}
	read, ok := netDeviceGrantRead(r)
	if !ok {
		return netDeviceGrant{}, fmt.Errorf("%w: unknown read", ErrReadNotGranted)
	}
	if s.db == nil {
		return netDeviceGrant{}, ErrNetDevNoStore
	}
	paused, err := s.netDevReadsPaused()
	if err != nil {
		return netDeviceGrant{}, err
	}
	if paused {
		return netDeviceGrant{}, ErrNetDevReadPaused
	}
	vaultGen := s.vault.LockGeneration()
	dev, credVersion, err := s.netDevLiveIdentity(deviceID)
	if err != nil {
		return netDeviceGrant{}, err
	}
	if string(dev.Family) != schedgrant.NetDeviceReadFamily(read) {
		return netDeviceGrant{}, fmt.Errorf("%w: read of another device family", ErrReadNotGranted)
	}
	effective, err := s.db.ReadGrantClock(now)
	if err != nil {
		return netDeviceGrant{}, fmt.Errorf("read grant clock: %w", err)
	}
	grants, err := s.db.ReadGrants()
	if err != nil {
		return netDeviceGrant{}, fmt.Errorf("load read grants: %w", err)
	}
	slices.SortFunc(grants, func(x, y permit.StoredReadGrant) int { return strings.Compare(x.ID, y.ID) })

	var candidates []netDevGrantCandidate
	var sawStale, sawNotGranted, sawExpired bool
	for _, g := range grants {
		if !g.RevokedAt.IsZero() {
			continue
		}
		doc, isLease, err := netDevLeaseDoc(g)
		if err != nil {
			return netDeviceGrant{}, err
		}
		if !isLease {
			continue
		}
		t, ok := doc.NetDeviceTarget(deviceID)
		switch {
		case !ok:
			continue
		case !effective.Before(g.ExpiresAt):
			sawExpired = true
		case !netDevTargetMatches(t, dev, credVersion):
			sawStale = true
		case !t.AllowsRead(read):
			sawNotGranted = true
		default:
			candidates = append(candidates, netDevGrantCandidate{id: g.ID, doc: doc, target: t})
		}
	}
	if len(candidates) == 0 {
		switch {
		case sawStale:
			return netDeviceGrant{}, ErrGrantStale
		case sawNotGranted:
			return netDeviceGrant{}, ErrReadNotGranted
		case sawExpired:
			return netDeviceGrant{}, ErrGrantExpired
		}
		return netDeviceGrant{}, ErrNoGrant
	}

	hint := netDevHintKey{db: s.db, device: deviceID, read: read}
	denied := false
	var deniedInterval time.Duration
	for _, c := range candidates {
		interval := max(time.Duration(c.doc.MinIntervalS)*time.Second, schedgrant.NetDeviceMinInterval)
		budget := min(int(c.doc.RunBudget), schedgrant.NetDeviceMaxRunBudget)
		reserved, err := s.db.ReserveReadRun(c.id, netDevActionKey(read), netDevBudgetKey(deviceID), now, budget, interval)
		if errors.Is(err, permit.ErrReadGrantInactive) {
			// Revoked, expired or recovery started since the lookup.
			sawExpired = true
			continue
		}
		if err != nil {
			return netDeviceGrant{}, fmt.Errorf("reserve device read on lease %s: %w", c.id, err)
		}
		if !reserved {
			denied, deniedInterval = true, max(deniedInterval, interval)
			continue
		}
		netDevHintRecord(hint, now)
		// The spend stands; the read is discarded if the device or the
		// lock state changed while it was reserved.
		if paused, err := s.netDevReadsPaused(); err != nil || paused || s.vault.LockGeneration() != vaultGen {
			return netDeviceGrant{}, ErrNetDevReadPaused
		}
		cur, curVersion, err := s.netDevLiveIdentity(deviceID)
		if err != nil {
			return netDeviceGrant{}, err
		}
		if !netDevTargetMatches(c.target, cur, curVersion) {
			return netDeviceGrant{}, ErrGrantStale
		}
		if s.log != nil {
			s.log.Info("audit", "kind", "netdev_read_authorized", "device", deviceID, "read", read, "grant", c.id)
		}
		return netDeviceGrant{GrantID: c.id, Read: read, Target: c.target}, nil
	}
	switch {
	case denied && netDevHintTooSoon(hint, now, deniedInterval):
		return netDeviceGrant{}, ErrTooSoon
	case denied:
		return netDeviceGrant{}, ErrBudget
	case sawExpired:
		return netDeviceGrant{}, ErrGrantExpired
	}
	return netDeviceGrant{}, ErrNoGrant
}

// netDeviceGrantStatus maps a checkNetDeviceGrant error to its gRPC status
// with a fixed message, consistent with ReadPVE: missing or unusable
// authority is PermissionDenied, exhausted limits ResourceExhausted, a
// device or executor state FailedPrecondition. Anything else is Internal
// (the caller logs it).
func netDeviceGrantStatus(err error) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return status.FromContextError(err).Err()
	case errors.Is(err, ErrNoGrant):
		return status.Error(codes.PermissionDenied, "read network device: no approved device read lease covers the device")
	case errors.Is(err, ErrGrantExpired):
		return status.Error(codes.PermissionDenied, "read network device: the device read lease has expired")
	case errors.Is(err, ErrGrantStale):
		return status.Error(codes.PermissionDenied, "read network device: the device's trust or read credential changed; the device read lease needs replacement")
	case errors.Is(err, ErrReadNotGranted):
		return status.Error(codes.PermissionDenied, "read network device: the device read lease does not grant this read")
	case errors.Is(err, ErrTooSoon):
		return status.Error(codes.ResourceExhausted, "read network device: the same read ran less than its minimum interval ago")
	case errors.Is(err, ErrBudget):
		return status.Error(codes.ResourceExhausted, "read network device: the device's rolling-hour read budget is exhausted")
	case errors.Is(err, ErrNetDevReadPaused):
		return status.Error(codes.FailedPrecondition, "read network device: reads are paused until local credential unlock")
	case errors.Is(err, ErrNetDevReadBlocked):
		return status.Error(codes.FailedPrecondition, "read network device: device is blocked")
	case errors.Is(err, ErrNetDevReadNoCredential):
		return status.Error(codes.FailedPrecondition, "read network device: device has no read credential")
	case errors.Is(err, ErrNetDevReadGone):
		return status.Error(codes.NotFound, "read network device: device not found")
	}
	return status.Error(codes.Internal, netDevRPCFailed)
}
