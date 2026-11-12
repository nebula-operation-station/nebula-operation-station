// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vault"
)

// Approved config baseline of a network device (ADR 0010 D4 "Approved
// baseline"; ND-17 part 2).
//
// The executor alone holds, per device, the approved baseline: the
// server's config version id and the raw_digest of that version. It is
// stored in the executor vault under the device-scoped id
// netDevBaselineRef (envelope-encrypted, bound to its id, durable in
// executor.db, so it survives a restart) and is deleted with the device.
//
// Setting it is the only write and goes through the approval path of ADR
// 0007: ProposeNetDeviceBaseline returns a MEDIUM permit (raised to the
// risk floor if one applies) that binds the device, its trust generation
// and pin, the version id, the raw_digest and the baseline it replaces;
// CommitNetDeviceBaseline stores the baseline only under the approved,
// unexpired, single-use permit of exactly that binding. There is no other
// setter: the server can read the baseline (GetNetDeviceBaseline) but not
// set, change or clear it. Every approval is an audit event.
//
// Drift is "the current raw_digest differs from the approved one"
// (NetDevBaselineDrift); a compromised server cannot make drift disappear
// in the executor's view.
//
// The raw_digest must not be chosen by the server alone (ADR 0010 D4):
// propose and commit require NetDevAdmin.VerifyBaselineDigest to confirm
// that the executor itself computed rawDigest for that device and version.
// The executor does not read device configs yet, so production leaves the
// verifier nil and every baseline proposal and commit is refused with
// ErrNetDevBaselineUnverified: the handlers below are deliberately
// unwirable (no proto method, no MethodRoles entry, guarded by
// TestNetDevBaselineRPCNotWired) until ND-14 lands.
//
// TODO(ND-14): set VerifyBaselineDigest from the executor's own config
// reads, then add the proto messages and admin-only MethodRoles entries.

const (
	// netDevBaselineAction is the reserved action id of a baseline
	// approval; ProposeExecution refuses the nebula. namespace.
	netDevBaselineAction = "nebula.netdev.baseline"
	// netDevBaselineVersion is the operation version the permit binds.
	netDevBaselineVersion = "1.0.0"
	// netDevBaselineLifetime bounds approval and commit.
	netDevBaselineLifetime = 15 * time.Minute
	// netDevBaselineMagic prefixes a stored baseline record.
	netDevBaselineMagic = "NOSNDBL1"
	// maxNetDevBaselineRecord bounds a stored baseline record.
	maxNetDevBaselineRecord = 1 << 10
	// maxNetDevBaselineTarget bounds the permit host id of a baseline
	// approval (canonical hostIDRe: at most 63 characters).
	maxNetDevBaselineTarget = 63
)

// netDevBaselineArtifact is the fixed "script" of a baseline approval:
// nothing runs on the device; the bytes name the operation for the permit
// hash.
var netDevBaselineArtifact = []byte("nebula.netdev.baseline 1.0.0\nMark the bound config version (version id and raw_digest) as the approved baseline of the network device.\n")

// stagePlanNetDevBaseline is the stage plan hash of a baseline approval
// (one step, no stages).
var stagePlanNetDevBaseline = func() string {
	s, _ := canonical.HashParameters([]byte(`{"plan":"netdev-baseline-v1"}`))
	return s
}()

// netDevRawDigestRe matches a raw_digest: lowercase hex HMAC-SHA-256.
var netDevRawDigestRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

var (
	// ErrNetDevBaselineRequest marks a malformed baseline request.
	ErrNetDevBaselineRequest = errors.New("executor: invalid network device baseline request")
	// ErrNetDevBaselineApproval is returned when no approved permit
	// covers exactly this baseline.
	ErrNetDevBaselineApproval = errors.New("executor: network device baseline requires an approved permit")
	// ErrNetDevBaselineConcurrent is returned when the device or its
	// baseline changed between the approved binding and the commit.
	ErrNetDevBaselineConcurrent = errors.New("executor: network device baseline changed concurrently")
	// ErrNetDevBaselineFormat is returned for a stored baseline record
	// that does not decode or belongs to another device.
	ErrNetDevBaselineFormat = errors.New("executor: stored network device baseline is malformed")
	// ErrNetDevNoBaseline is returned when a device has no approved
	// baseline.
	ErrNetDevNoBaseline = errors.New("executor: network device has no approved baseline")
	// ErrNetDevBaselineUnverified is returned when the executor cannot
	// confirm that it computed the raw_digest itself (ADR 0010 D4); until
	// ND-14 this refuses every baseline.
	ErrNetDevBaselineUnverified = errors.New("executor: network device baseline digest is not executor-verified")
	// ErrNetDevBaselineBlocked is returned for a baseline on a blocked
	// device: its trust is in question.
	ErrNetDevBaselineBlocked = errors.New("executor: network device is blocked")
)

// NetDevBaseline is the approved baseline of one device as the executor
// holds it. It carries no secret.
type NetDevBaseline struct {
	DeviceID string `json:"device_id"`
	// VersionID is the server's config version id at approval time.
	VersionID int64 `json:"version_id"`
	// RawDigest is the keyed digest of the approved raw config.
	RawDigest string `json:"raw_digest"`
	// TrustGeneration is the device trust generation at approval.
	TrustGeneration uint64 `json:"trust_generation"`
	// ExecutionDigest is the digest of the permit that approved it.
	ExecutionDigest string `json:"execution_digest"`
	// CommittedBy is the admin caller that committed the approval.
	CommittedBy string `json:"committed_by"`
	// ApprovedAtUnix is the commit time.
	ApprovedAtUnix int64 `json:"approved_at"`
	// Revision is the vault version of the record (1 for the first
	// baseline); not stored in the record itself.
	Revision int64 `json:"-"`
}

// validate checks a decoded record against the device it was read for.
func (b NetDevBaseline) validate(deviceID string) error {
	if b.DeviceID != deviceID || b.VersionID < 1 || !netDevRawDigestRe.MatchString(b.RawDigest) ||
		!netDevRawDigestRe.MatchString(b.ExecutionDigest) || b.ApprovedAtUnix <= 0 ||
		!validNetDevText(b.CommittedBy, maxNetDevActorBytes) {
		return ErrNetDevBaselineFormat
	}
	return nil
}

// NetDevBaselineDrift reports whether currentRawDigest differs from the
// approved baseline. A malformed current digest is a request error; a
// zero baseline is ErrNetDevNoBaseline (no verdict without a baseline).
func NetDevBaselineDrift(b NetDevBaseline, currentRawDigest string) (bool, error) {
	if !netDevRawDigestRe.MatchString(currentRawDigest) {
		return false, fmt.Errorf("%w: current raw_digest must be 64 lowercase hex characters", ErrNetDevBaselineRequest)
	}
	if b.RawDigest == "" {
		return false, ErrNetDevNoBaseline
	}
	return currentRawDigest != b.RawDigest, nil
}

// netDevBaselineRef returns the device-scoped vault id of the baseline,
// with the same scoping as netDevKeyRefs and its own suffix.
func netDevBaselineRef(id string) string {
	dk, _ := netDevKeyRefs(id)
	return strings.TrimSuffix(dk, "-dk") + "-bl"
}

// netDevBaselineTarget is the permit host id of a baseline approval:
// "netdev-<id>-baseline" while that fits canonical's host id limit, else
// "netdev--<first 16 bytes of sha256(id), hex>-baseline". Device ids never
// start with a hyphen, so the two forms cannot collide.
func netDevBaselineTarget(id string) string {
	const prefix, suffix = "netdev-", "-baseline"
	scope := id
	if len(prefix)+len(id)+len(suffix) > maxNetDevBaselineTarget {
		sum := sha256.Sum256([]byte(id))
		scope = "-" + hex.EncodeToString(sum[:16])
	}
	return prefix + scope + suffix
}

func encodeNetDevBaseline(b NetDevBaseline) ([]byte, error) {
	j, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	return append([]byte(netDevBaselineMagic), j...), nil
}

func decodeNetDevBaseline(deviceID string, v []byte) (NetDevBaseline, error) {
	if len(v) > maxNetDevBaselineRecord || !bytes.HasPrefix(v, []byte(netDevBaselineMagic)) {
		return NetDevBaseline{}, ErrNetDevBaselineFormat
	}
	dec := json.NewDecoder(bytes.NewReader(v[len(netDevBaselineMagic):]))
	dec.DisallowUnknownFields()
	var b NetDevBaseline
	if err := dec.Decode(&b); err != nil || dec.More() {
		return NetDevBaseline{}, ErrNetDevBaselineFormat
	}
	if err := b.validate(deviceID); err != nil {
		return NetDevBaseline{}, err
	}
	return b, nil
}

// NetDevBaselineBinding is everything a baseline permit binds: the
// device's trust state, the approved version and the baseline it
// replaces (empty digest and revision 0 for the first one).
type NetDevBaselineBinding struct {
	DeviceID          string                 `json:"device_id"`
	Family            netdevcontract.Family  `json:"family"`
	PinKind           netdevcontract.PinKind `json:"pin_kind"`
	Pin               string                 `json:"pin"`
	TrustGeneration   uint64                 `json:"trust_generation"`
	VersionID         int64                  `json:"version_id"`
	RawDigest         string                 `json:"raw_digest"`
	PreviousVersionID int64                  `json:"previous_version_id"`
	PreviousRawDigest string                 `json:"previous_raw_digest"`
	PreviousRevision  int64                  `json:"previous_revision"`
}

// params returns the canonical permit parameters and target.
func (b NetDevBaselineBinding) params() ([]byte, canonical.Target, error) {
	params, err := json.Marshal(b)
	if err != nil {
		return nil, canonical.Target{}, err
	}
	fp, err := hex.DecodeString(b.Pin)
	if err != nil || len(fp) != 32 {
		return nil, canonical.Target{}, ErrNetDevBaselineApproval
	}
	return params, canonical.Target{HostID: netDevBaselineTarget(b.DeviceID), HostKeyFingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(fp)}, nil
}

// checkBaselineRequest validates the caller-supplied version and digest.
func checkBaselineRequest(versionID int64, rawDigest string) error {
	if versionID < 1 {
		return fmt.Errorf("%w: version id must be positive", ErrNetDevBaselineRequest)
	}
	if !netDevRawDigestRe.MatchString(rawDigest) {
		return fmt.Errorf("%w: raw_digest must be 64 lowercase hex characters", ErrNetDevBaselineRequest)
	}
	return nil
}

// Baseline returns the approved baseline of a live device; false if the
// device has none. It needs an unlocked vault.
func (a *NetDevAdmin) Baseline(_ context.Context, id string) (NetDevBaseline, bool, error) {
	if err := a.checkVault(); err != nil {
		return NetDevBaseline{}, false, err
	}
	dev, err := a.liveDevice(id)
	if err != nil {
		return NetDevBaseline{}, false, err
	}
	return a.storedBaseline(dev.ID)
}

func (a *NetDevAdmin) storedBaseline(id string) (NetDevBaseline, bool, error) {
	v, rev, err := a.Vault.OpenVersion(netDevBaselineRef(id))
	if errors.Is(err, vault.ErrNotFound) {
		return NetDevBaseline{}, false, nil
	}
	if err != nil {
		return NetDevBaseline{}, false, fmt.Errorf("load baseline of network device %s: %w", id, err)
	}
	defer clear(v)
	b, err := decodeNetDevBaseline(id, v)
	if err != nil {
		return NetDevBaseline{}, false, fmt.Errorf("load baseline of network device %s: %w", id, err)
	}
	b.Revision = rev
	return b, true, nil
}

// BaselineBinding returns the binding of approving version versionID with
// rawDigest as the baseline of a live, unblocked device.
func (a *NetDevAdmin) BaselineBinding(ctx context.Context, id string, versionID int64, rawDigest string) (NetDevBaselineBinding, error) {
	if err := checkBaselineRequest(versionID, rawDigest); err != nil {
		return NetDevBaselineBinding{}, err
	}
	if err := a.checkVault(); err != nil {
		return NetDevBaselineBinding{}, err
	}
	dev, err := a.liveDevice(id)
	if err != nil {
		return NetDevBaselineBinding{}, err
	}
	if dev.Blocked {
		return NetDevBaselineBinding{}, fmt.Errorf("baseline of network device %s: %w", id, ErrNetDevBaselineBlocked)
	}
	if a.VerifyBaselineDigest == nil {
		return NetDevBaselineBinding{}, fmt.Errorf("baseline of network device %s: %w", id, ErrNetDevBaselineUnverified)
	}
	if err := a.VerifyBaselineDigest(ctx, dev.ID, versionID, rawDigest); err != nil {
		return NetDevBaselineBinding{}, fmt.Errorf("baseline of network device %s: %w: %w", id, ErrNetDevBaselineUnverified, err)
	}
	cur, _, err := a.storedBaseline(dev.ID)
	if err != nil {
		return NetDevBaselineBinding{}, err
	}
	return NetDevBaselineBinding{
		DeviceID: dev.ID, Family: dev.Family, PinKind: dev.PinKind, Pin: dev.PinValue, TrustGeneration: dev.TrustGeneration,
		VersionID: versionID, RawDigest: rawDigest,
		PreviousVersionID: cur.VersionID, PreviousRawDigest: cur.RawDigest, PreviousRevision: cur.Revision,
	}, nil
}

// ApproveBaseline stores the approved baseline under the permit digest:
// the binding is rebuilt from the current record and the current
// baseline, the permit is consumed, and the record is written only if the
// vault entry is still at the bound revision.
func (a *NetDevAdmin) ApproveBaseline(ctx context.Context, id string, versionID int64, rawDigest, digest, by string) (NetDevBaseline, error) {
	if a.AuthorizeBaseline == nil {
		return NetDevBaseline{}, ErrNetDevBaselineApproval
	}
	if !validNetDevText(by, maxNetDevActorBytes) {
		return NetDevBaseline{}, fmt.Errorf("%w: actor is missing or malformed", ErrNetDevBaselineRequest)
	}
	b, err := a.BaselineBinding(ctx, id, versionID, rawDigest)
	if err != nil {
		return NetDevBaseline{}, err
	}
	if err := a.AuthorizeBaseline(ctx, b, digest); err != nil {
		a.event("baseline_refused", id)
		return NetDevBaseline{}, fmt.Errorf("baseline of network device %s: %w", id, ErrNetDevBaselineApproval)
	}
	rec := NetDevBaseline{DeviceID: b.DeviceID, VersionID: versionID, RawDigest: rawDigest, TrustGeneration: b.TrustGeneration,
		ExecutionDigest: digest, CommittedBy: by, ApprovedAtUnix: a.now().Unix()}
	value, err := encodeNetDevBaseline(rec)
	if err != nil {
		a.commitRefused(b.DeviceID, digest, "encode")
		return NetDevBaseline{}, fmt.Errorf("baseline of network device %s: %w", id, err)
	}
	want := b.PreviousRevision + 1
	rev, err := a.Vault.PutWithCommit(netDevBaselineRef(b.DeviceID), value, by, func(s executordb.VaultSecret) error {
		if s.Version != want {
			return ErrNetDevBaselineConcurrent
		}
		// The device must still be in the bound trust state.
		cur, err := a.liveDevice(b.DeviceID)
		if err != nil {
			return err
		}
		if cur.Blocked || cur.TrustGeneration != b.TrustGeneration || cur.PinValue != b.Pin || cur.PinKind != b.PinKind {
			return ErrNetDevBaselineConcurrent
		}
		return a.Store.PutSecret(s)
	})
	if err != nil {
		reason := "store"
		if errors.Is(err, ErrNetDevBaselineConcurrent) {
			reason = "concurrent_change"
		}
		a.commitRefused(b.DeviceID, digest, reason)
		return NetDevBaseline{}, fmt.Errorf("store baseline of network device %s: %w", id, err)
	}
	rec.Revision = rev
	a.log().Info("audit", "kind", "netdev_admin", "action", "baseline_approved", "device", b.DeviceID,
		"version_id", versionID, "raw_digest", rawDigest, "previous_version_id", b.PreviousVersionID,
		"previous_raw_digest", b.PreviousRawDigest, "revision", rev, "execution_digest", digest, "by", by)
	return rec, nil
}

// commitRefused audits a commit refused after its single-use permit was
// consumed: the approval is burnt and nothing was stored. reason is a
// fixed word, never error text.
func (a *NetDevAdmin) commitRefused(deviceID, digest, reason string) {
	a.log().Info("audit", "kind", "netdev_admin", "action", "baseline_commit_refused", "device", deviceID,
		"execution_digest", digest, "reason", reason)
}

func (a *NetDevAdmin) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// --- RPC surface ---
//
// These handlers are the executor side of the baseline RPCs. They take
// plain values until the proto messages exist (proto/ is outside this
// change); the wiring must keep them admin-only in MethodRoles like every
// other network device admin method.

// ProposeNetDeviceBaseline proposes approving version versionID with
// rawDigest as the device's baseline and returns a permit of at least
// MEDIUM risk bound to the device, its trust state, the version and the
// baseline it replaces. It changes nothing.
func (s *Service) ProposeNetDeviceBaseline(ctx context.Context, deviceID string, versionID int64, rawDigest string) (*pb.ProposeExecutionResponse, error) {
	netDevAdminMu.Lock()
	defer netDevAdminMu.Unlock()
	if s.auth == nil {
		return nil, s.netDevRPCError("propose baseline", ErrNetDevBaselineApproval)
	}
	b, err := s.netDevAdmin().BaselineBinding(ctx, deviceID, versionID, rawDigest)
	if err != nil {
		return nil, s.netDevRPCError("propose baseline", err)
	}
	params, target, err := b.params()
	if err != nil {
		return nil, s.netDevRPCError("propose baseline", err)
	}
	ph, err := canonical.HashParameters(params)
	if err != nil {
		return nil, s.netDevRPCError("propose baseline", err)
	}
	id, err := newExecutionID()
	if err != nil {
		return nil, s.netDevRPCError("propose baseline", err)
	}
	rq := canonical.Request{ExecutionID: id, ActionID: netDevBaselineAction, ModuleVersion: netDevBaselineVersion,
		ArtifactSHA256: sha256Hex(netDevBaselineArtifact), ParametersHash: ph, CredentialRefs: []string{netDevBaselineRef(b.DeviceID)},
		RiskClass: canonical.RiskMedium, StagePlanHash: stagePlanNetDevBaseline,
		ExpiryUnix: s.clock().Add(netDevBaselineLifetime).Unix(), ResolvedTargets: []canonical.Target{target}}
	res, err := s.auth.ProposeAtLeastMinimum(rq, params)
	if err != nil {
		return nil, toStatus(err)
	}
	return s.permitResponse(res.Permit)
}

// CommitNetDeviceBaseline stores the baseline only under the approved,
// unexpired permit of a matching proposal. Without one nothing changes.
func (s *Service) CommitNetDeviceBaseline(ctx context.Context, deviceID string, versionID int64, rawDigest, executionDigest string) (NetDevBaseline, error) {
	netDevAdminMu.Lock()
	defer netDevAdminMu.Unlock()
	b, err := s.netDevAdmin().ApproveBaseline(ctx, deviceID, versionID, rawDigest, executionDigest, callerName(ctx))
	if err != nil {
		return NetDevBaseline{}, s.netDevRPCError("commit baseline", err)
	}
	return b, nil
}

// GetNetDeviceBaseline returns the approved baseline of a device (ids and
// digests only); false if it has none. It never writes.
func (s *Service) GetNetDeviceBaseline(ctx context.Context, deviceID string) (NetDevBaseline, bool, error) {
	if !netdevcontract.ValidDeviceID(deviceID) {
		return NetDevBaseline{}, false, s.netDevRPCError("get baseline", ErrNetDevBaselineRequest)
	}
	b, ok, err := s.netDevAdmin().Baseline(ctx, deviceID)
	if err != nil {
		return NetDevBaseline{}, false, s.netDevRPCError("get baseline", err)
	}
	return b, ok, nil
}

func (s *Service) authorizeNetDevBaseline(_ context.Context, b NetDevBaselineBinding, digest string) error {
	d, err := canonical.ParseDigest(digest)
	if err != nil {
		return ErrNetDevBaselineApproval
	}
	params, target, err := b.params()
	if err != nil {
		return ErrNetDevBaselineApproval
	}
	if _, err := s.auth.AuthorizeGrant(d, permit.Run{HostID: target.HostID, HostKeyFingerprint: target.HostKeyFingerprint,
		ActionID: netDevBaselineAction, ModuleVersion: netDevBaselineVersion, Artifact: netDevBaselineArtifact, ParametersJSON: params,
		CredentialRef: netDevBaselineRef(b.DeviceID)}); err != nil {
		return ErrNetDevBaselineApproval
	}
	return nil
}
