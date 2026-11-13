// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/integrity"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// This file is the I1 reaction (ADR 0015 D4 "What happens on a mismatch",
// Q4; spec 06 "I1 unlock refusal and nebula integrity ack"): while a
// locking finding is open the executor refuses `nebula unlock` and every
// mutation and read-grant dispatch with ErrIntegrityLocked. The refusal
// only withholds authority: it deletes, restores, rolls back, wipes and
// cancels nothing; a run that already started keeps running and can be
// observed. Only the local admin clears a finding, one at a time, with
// `nebula integrity ack <finding>` (audited); a later run that finds the
// same deviation opens it again.

// Limits of the open findings.
const (
	// maxIntegrityLockFindings bounds the stored open findings; further
	// locking deviations are folded into one IntegrityLockOmitted finding,
	// for which the last slot is reserved.
	maxIntegrityLockFindings = 2 * maxIntegrityRunDeviations
	// integrityFindingIDPrefix starts every finding ID.
	integrityFindingIDPrefix = "i1-"
	// integrityFindingIDHex is the number of hex digits after the prefix.
	integrityFindingIDHex = 16
)

// Sentinel errors.
var (
	// ErrIntegrityLocked is the fixed refusal while a locking I1 finding
	// is open.
	ErrIntegrityLocked = errors.New("integrity_locked: an open I1 integrity finding withholds unlock and all mutation and read-grant dispatch; " +
		"see `nebula integrity status` on the executor host (ADR 0015 D4)")
	// ErrIntegrityFindingInvalid is a malformed finding ID.
	ErrIntegrityFindingInvalid = errors.New("executor: malformed integrity finding id")
	// ErrIntegrityFindingNotFound: no open finding has this ID.
	ErrIntegrityFindingNotFound = errors.New("executor: no open integrity finding with this id")
)

// IntegrityFinding is one open locking finding. It never holds file
// content.
type IntegrityFinding struct {
	// ID is stable for the same cause, path, class and status, so a later
	// run that finds the same deviation updates it (or, after an ack,
	// opens it again under the same ID).
	ID string `json:"id"`
	// Cause is deviation, deviations-omitted or state-unreadable.
	Cause IntegrityLockCause `json:"cause"`
	// Path, Class, Status and Reason describe a deviation; empty for the
	// other causes.
	Path string `json:"path,omitempty"`
	// Class is the ADR 0015 D4 class.
	Class integrity.Class `json:"class,omitempty"`
	// Status is different, missing or extra.
	Status integrity.Status `json:"status,omitempty"`
	// Reason details a different file.
	Reason integrity.Reason `json:"reason,omitempty"`
	// FirstSeen is the start of the run that opened the finding.
	FirstSeen time.Time `json:"first_seen"`
	// LastSeen is the start of the latest run that found it.
	LastSeen time.Time `json:"last_seen"`
	// Count is the number of locking deviations an IntegrityLockOmitted
	// finding stands for in the latest run that had any.
	Count int `json:"count,omitempty"`
}

// integrityFindingID derives the stable finding ID.
func integrityFindingID(cause IntegrityLockCause, d IntegrityDeviation) string {
	h := sha256.New()
	for _, part := range []string{string(cause), d.Path, string(d.Class), string(d.Status)} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return integrityFindingIDPrefix + hex.EncodeToString(h.Sum(nil))[:integrityFindingIDHex]
}

func newIntegrityFinding(cause IntegrityLockCause, d IntegrityDeviation, seen time.Time) IntegrityFinding {
	f := IntegrityFinding{ID: integrityFindingID(cause, d), Cause: cause, FirstSeen: seen, LastSeen: seen}
	if cause == IntegrityLockDeviation {
		f.Path, f.Class, f.Status, f.Reason = d.Path, d.Class, d.Status, d.Reason
	}
	return f
}

// validIntegrityFindingID checks the ID format only.
func validIntegrityFindingID(id string) bool {
	rest, ok := strings.CutPrefix(id, integrityFindingIDPrefix)
	if !ok || len(rest) != integrityFindingIDHex {
		return false
	}
	for i := 0; i < len(rest); i++ {
		if !('0' <= rest[i] && rest[i] <= '9' || 'a' <= rest[i] && rest[i] <= 'f') {
			return false
		}
	}
	return true
}

// mergeIntegrityFindings adds the locking deviations of run to lock and
// returns the findings it newly opened. Open findings are never removed
// here: a clean run does not close the lock.
func mergeIntegrityFindings(lock *IntegrityLock, run IntegrityRun) []IntegrityFinding {
	if run.Locking == 0 {
		return nil
	}
	var added []IntegrityFinding
	index := make(map[string]int, len(lock.Findings))
	for i, f := range lock.Findings {
		index[f.ID] = i
	}
	omitted := run.Locking
	for _, d := range run.Deviations {
		if !d.Locks {
			continue
		}
		id := integrityFindingID(IntegrityLockDeviation, d)
		if i, ok := index[id]; ok {
			lock.Findings[i].LastSeen, lock.Findings[i].Reason = run.Started, d.Reason
			omitted--
			continue
		}
		// The last slot is kept for the omitted finding.
		if len(lock.Findings) >= maxIntegrityLockFindings-1 {
			continue
		}
		f := newIntegrityFinding(IntegrityLockDeviation, d, run.Started)
		index[id] = len(lock.Findings)
		lock.Findings = append(lock.Findings, f)
		added = append(added, f)
		omitted--
	}
	if omitted > 0 {
		id := integrityFindingID(IntegrityLockOmitted, IntegrityDeviation{})
		if i, ok := index[id]; ok {
			lock.Findings[i].LastSeen, lock.Findings[i].Count = run.Started, omitted
		} else {
			f := newIntegrityFinding(IntegrityLockOmitted, IntegrityDeviation{}, run.Started)
			f.Count = omitted
			lock.Findings = append(lock.Findings, f)
			added = append(added, f)
		}
	}
	if !lock.Open && len(lock.Findings) > 0 {
		lock.Open, lock.Cause, lock.Since, lock.Deviations = true, IntegrityLockDeviation, run.Started, run.Locking
	}
	return added
}

// migrateIntegrityLock gives an open lock stored without findings (state
// written before findings existed) one finding with its cause, so the
// admin can ack it; it stays open until then.
func migrateIntegrityLock(lock *IntegrityLock) {
	if !lock.Open || len(lock.Findings) > 0 {
		return
	}
	switch lock.Cause {
	case IntegrityLockDeviation, IntegrityLockStateUnreadable:
	default:
		return // validateIntegrityState rejects it
	}
	cause := lock.Cause
	if cause == IntegrityLockDeviation {
		// The deviations of the opening run were not kept with the lock.
		cause = IntegrityLockOmitted
	}
	f := newIntegrityFinding(cause, IntegrityDeviation{}, lock.Since)
	if cause == IntegrityLockOmitted {
		f.Count = lock.Deviations
	}
	lock.Findings = []IntegrityFinding{f}
}

func validateIntegrityFindings(lock IntegrityLock) error {
	if lock.Open != (len(lock.Findings) > 0) {
		return errors.New("lock and findings disagree")
	}
	if len(lock.Findings) > maxIntegrityLockFindings {
		return errors.New("too many findings")
	}
	seen := make(map[string]bool, len(lock.Findings))
	for _, f := range lock.Findings {
		switch f.Cause {
		case IntegrityLockDeviation:
			if f.Path == "" || len(f.Path) > maxIntegrityPath || !printableASCII(f.Path) || f.Class == "" || f.Status == "" {
				return errors.New("invalid deviation finding")
			}
		case IntegrityLockOmitted, IntegrityLockStateUnreadable:
			if f.Path != "" || f.Class != "" || f.Status != "" || f.Reason != "" {
				return errors.New("invalid finding")
			}
		default:
			return errors.New("unknown finding cause")
		}
		if f.Count < 0 || !printableASCII(string(f.Reason)) || len(f.Reason) > maxIntegrityPath {
			return errors.New("invalid finding")
		}
		if f.ID != integrityFindingID(f.Cause, IntegrityDeviation{Path: f.Path, Class: f.Class, Status: f.Status}) || seen[f.ID] {
			return errors.New("invalid finding id")
		}
		seen[f.ID] = true
	}
	return nil
}

// integrityFindingAttrs are the audit attributes of a finding: ID, cause,
// class and status; never the path (like the run record) or content.
func integrityFindingAttrs(f IntegrityFinding) []slog.Attr {
	return []slog.Attr{
		slog.String("finding", f.ID), slog.String("cause", string(f.Cause)),
		slog.String("class", string(f.Class)), slog.String("status", string(f.Status)),
		slog.Int("count", f.Count),
	}
}

// AckIntegrityFindingLocal clears exactly the open finding id on behalf of
// by (the caller from peer credentials) and returns it with the remaining
// lock. The new state is stored before it takes effect: if it cannot be
// stored, nothing is cleared. It fails with ErrIntegrityCheckRunning while
// a check runs. Deleting, restoring or rolling back files is never part of
// an ack.
func (s *Service) AckIntegrityFindingLocal(id, by string) (IntegrityFinding, IntegrityLock, error) {
	if !validIntegrityFindingID(id) {
		return IntegrityFinding{}, IntegrityLock{}, ErrIntegrityFindingInvalid
	}
	s.integrityCheck.mu.Lock()
	cfg := s.integrityCheck.cfg
	s.integrityCheck.mu.Unlock()
	if cfg == nil {
		return IntegrityFinding{}, IntegrityLock{}, ErrIntegrityCheckNotConfigured
	}
	// running serializes every state change and write with the runs.
	if !s.integrityCheck.running.CompareAndSwap(false, true) {
		return IntegrityFinding{}, IntegrityLock{}, ErrIntegrityCheckRunning
	}
	defer s.integrityCheck.running.Store(false)

	s.integrityCheck.mu.Lock()
	next := copyIntegrityState(s.integrityCheck.state)
	s.integrityCheck.mu.Unlock()

	var acked IntegrityFinding
	found := false
	kept := next.Lock.Findings[:0]
	for _, f := range next.Lock.Findings {
		if f.ID == id && !found {
			acked, found = f, true
			continue
		}
		kept = append(kept, f)
	}
	if !found {
		s.auditLog(slog.LevelWarn, "integrity_ack_refused", slog.String("by", by), slog.String("finding", id),
			slog.String("detail", "not open"))
		return IntegrityFinding{}, IntegrityLock{}, ErrIntegrityFindingNotFound
	}
	next.Lock.Findings = kept
	if len(kept) == 0 {
		next.Lock = IntegrityLock{}
	}
	if err := storeIntegrityCheckState(cfg.StatePath, next); err != nil {
		s.auditLog(slog.LevelError, "integrity_check_state_failed", slog.String("detail", err.Error()))
		return IntegrityFinding{}, IntegrityLock{}, fmt.Errorf("ack integrity finding %s: %w", id, err)
	}
	s.integrityCheck.mu.Lock()
	s.integrityCheck.state = next
	s.integrityCheck.mu.Unlock()

	attrs := append([]slog.Attr{slog.String("by", by)}, integrityFindingAttrs(acked)...)
	attrs = append(attrs, slog.Int("remaining", len(kept)), slog.Bool("lock_open", next.Lock.Open),
		slog.String("note", integrity.RootCompromiseNote))
	s.auditLog(slog.LevelWarn, "integrity_finding_acked", attrs...)
	if !next.Lock.Open {
		s.auditLog(slog.LevelWarn, "integrity_lock_closed", slog.String("by", by))
	}
	return acked, next.Lock, nil
}

// integrityLockedMethods classifies every executor RPC for the I1 lock:
// true means it is refused while a locking finding is open (unlock and
// every RPC that dispatches a mutation or a read with NOS credentials),
// false means it stays available (status, proposals, approvals that do not
// dispatch, observing running jobs, Lock, trust and admin bookkeeping,
// and the integrity RPCs themselves). A method missing here is refused
// while locked; TestIntegrityLockClassifiesEveryMethod keeps the table
// complete.
var integrityLockedMethods = map[string]bool{
	// Unlock.
	pb.ExecutorService_Unlock_FullMethodName: true,
	// Mutation dispatch: runs, enrollments, re-pins, guest actions and
	// SSH logins with the managed-host key.
	pb.ExecutorService_AuthorizeRun_FullMethodName:            true,
	pb.ExecutorService_RunAttached_FullMethodName:             true,
	pb.ExecutorService_StartDurable_FullMethodName:            true,
	pb.ExecutorService_RunScheduled_FullMethodName:            true,
	pb.ExecutorService_RunBatchMember_FullMethodName:          true,
	pb.ExecutorService_CommitRepin_FullMethodName:             true,
	pb.ExecutorService_CommitEnroll_FullMethodName:            true,
	pb.ExecutorService_CommitPairedEnroll_FullMethodName:      true,
	pb.ExecutorService_CommitGuestJoin_FullMethodName:         true,
	pb.ExecutorService_TestConnection_FullMethodName:          true,
	pb.ExecutorService_CommitPVEGuestPower_FullMethodName:     true,
	pb.ExecutorService_CommitPVEGuestSnapshot_FullMethodName:  true,
	pb.ExecutorService_CommitPVEGuestProvision_FullMethodName: true,
	// Read-grant dispatch and credentialed typed reads.
	pb.ExecutorService_RunReadGrant_FullMethodName:        true,
	pb.ExecutorService_ReadPVE_FullMethodName:             true,
	pb.ExecutorService_ReadNetDevice_FullMethodName:       true,
	pb.ExecutorService_ReadPrivateRegistry_FullMethodName: true,

	// Not locked.
	pb.ExecutorService_GetStatus_FullMethodName:                       false,
	pb.ExecutorService_ProposeExecution_FullMethodName:                false,
	pb.ExecutorService_SubmitAssertion_FullMethodName:                 false,
	pb.ExecutorService_BeginPrivilegedSession_FullMethodName:          false,
	pb.ExecutorService_CompletePrivilegedSession_FullMethodName:       false,
	pb.ExecutorService_GetSessionState_FullMethodName:                 false,
	pb.ExecutorService_GetRun_FullMethodName:                          false,
	pb.ExecutorService_Lock_FullMethodName:                            false,
	pb.ExecutorService_ListPending_FullMethodName:                     false,
	pb.ExecutorService_ApproveCLI_FullMethodName:                      false,
	pb.ExecutorService_GetPermitState_FullMethodName:                  false,
	pb.ExecutorService_TrustArtifact_FullMethodName:                   false,
	pb.ExecutorService_UntrustArtifact_FullMethodName:                 false,
	pb.ExecutorService_ListTrustedArtifacts_FullMethodName:            false,
	pb.ExecutorService_SetHostCriticality_FullMethodName:              false,
	pb.ExecutorService_ListHostCriticality_FullMethodName:             false,
	pb.ExecutorService_CreateRegistrationCode_FullMethodName:          false,
	pb.ExecutorService_BeginRegistration_FullMethodName:               false,
	pb.ExecutorService_FinishRegistration_FullMethodName:              false,
	pb.ExecutorService_ListWebAuthnCredentials_FullMethodName:         false,
	pb.ExecutorService_RemoveWebAuthnCredential_FullMethodName:        false,
	pb.ExecutorService_BeginLogin_FullMethodName:                      false,
	pb.ExecutorService_FinishLogin_FullMethodName:                     false,
	pb.ExecutorService_CheckCredential_FullMethodName:                 false,
	pb.ExecutorService_BeginTOTPSetup_FullMethodName:                  false,
	pb.ExecutorService_ConfirmTOTPSetup_FullMethodName:                false,
	pb.ExecutorService_RemoveTOTP_FullMethodName:                      false,
	pb.ExecutorService_GetTOTPStatus_FullMethodName:                   false,
	pb.ExecutorService_RecoveryLogin_FullMethodName:                   false,
	pb.ExecutorService_FinishRecovery_FullMethodName:                  false,
	pb.ExecutorService_ProbeHostKey_FullMethodName:                    false,
	pb.ExecutorService_PinHostKey_FullMethodName:                      false,
	pb.ExecutorService_UnpinHostKey_FullMethodName:                    false,
	pb.ExecutorService_ListHostKeys_FullMethodName:                    false,
	pb.ExecutorService_ProposeRepin_FullMethodName:                    false,
	pb.ExecutorService_ProposeEnroll_FullMethodName:                   false,
	pb.ExecutorService_CreateEnrollOffer_FullMethodName:               false,
	pb.ExecutorService_FetchEnrollScript_FullMethodName:               false,
	pb.ExecutorService_ShowEnrollScript_FullMethodName:                false,
	pb.ExecutorService_DownloadEnrollScript_FullMethodName:            false,
	pb.ExecutorService_RevokeEnrollOffer_FullMethodName:               false,
	pb.ExecutorService_ListEnrollOffers_FullMethodName:                false,
	pb.ExecutorService_SubmitPairingCode_FullMethodName:               false,
	pb.ExecutorService_ProposeGuestJoin_FullMethodName:                false,
	pb.ExecutorService_GetSSHPublicKey_FullMethodName:                 false,
	pb.ExecutorService_InitVault_FullMethodName:                       false,
	pb.ExecutorService_SetSecret_FullMethodName:                       false,
	pb.ExecutorService_ListSecrets_FullMethodName:                     false,
	pb.ExecutorService_DeleteSecret_FullMethodName:                    false,
	pb.ExecutorService_BeginGate_FullMethodName:                       false,
	pb.ExecutorService_CommitGate_FullMethodName:                      false,
	pb.ExecutorService_AbortRollout_FullMethodName:                    false,
	pb.ExecutorService_GetRollout_FullMethodName:                      false,
	pb.ExecutorService_ApproveGateCLI_FullMethodName:                  false,
	pb.ExecutorService_BeginTrustArtifact_FullMethodName:              false,
	pb.ExecutorService_CommitTrustArtifact_FullMethodName:             false,
	pb.ExecutorService_GetArtifactTrust_FullMethodName:                false,
	pb.ExecutorService_RegisterModule_FullMethodName:                  false,
	pb.ExecutorService_AddSigner_FullMethodName:                       false,
	pb.ExecutorService_RemoveSigner_FullMethodName:                    false,
	pb.ExecutorService_ConfirmModuleSigner_FullMethodName:             false,
	pb.ExecutorService_ListSigners_FullMethodName:                     false,
	pb.ExecutorService_ProposeScheduleGrant_FullMethodName:            false,
	pb.ExecutorService_CommitScheduleGrant_FullMethodName:             false,
	pb.ExecutorService_ListPendingScheduleGrants_FullMethodName:       false,
	pb.ExecutorService_ApproveScheduleGrantCLI_FullMethodName:         false,
	pb.ExecutorService_ListScheduleGrants_FullMethodName:              false,
	pb.ExecutorService_RevokeScheduleGrant_FullMethodName:             false,
	pb.ExecutorService_ProposeReadGrant_FullMethodName:                false,
	pb.ExecutorService_CommitReadGrant_FullMethodName:                 false,
	pb.ExecutorService_ListPendingReadGrants_FullMethodName:           false,
	pb.ExecutorService_ApproveReadGrantCLI_FullMethodName:             false,
	pb.ExecutorService_ListReadGrants_FullMethodName:                  false,
	pb.ExecutorService_RevokeReadGrant_FullMethodName:                 false,
	pb.ExecutorService_ProposeBatch_FullMethodName:                    false,
	pb.ExecutorService_CommitBatch_FullMethodName:                     false,
	pb.ExecutorService_ReviewBatch_FullMethodName:                     false,
	pb.ExecutorService_ApproveBatchCLI_FullMethodName:                 false,
	pb.ExecutorService_GetBatchStatus_FullMethodName:                  false,
	pb.ExecutorService_GetBatchCredentialVersions_FullMethodName:      false,
	pb.ExecutorService_ReviewBuiltinTrust_FullMethodName:              false,
	pb.ExecutorService_CommitBuiltinTrust_FullMethodName:              false,
	pb.ExecutorService_UnpinBuiltinVersion_FullMethodName:             false,
	pb.ExecutorService_GetBuiltinTrustStatus_FullMethodName:           false,
	pb.ExecutorService_ReviewRootRotation_FullMethodName:              false,
	pb.ExecutorService_CommitRootRotation_FullMethodName:              false,
	pb.ExecutorService_ListEvents_FullMethodName:                      false,
	pb.ExecutorService_BackupExecutor_FullMethodName:                  false,
	pb.ExecutorService_ProbePVERemote_FullMethodName:                  false,
	pb.ExecutorService_AddPVERemote_FullMethodName:                    false,
	pb.ExecutorService_RotatePVEToken_FullMethodName:                  false,
	pb.ExecutorService_RemovePVERemote_FullMethodName:                 false,
	pb.ExecutorService_ListPVEAdminRemotes_FullMethodName:             false,
	pb.ExecutorService_SetPVERemoteSite_FullMethodName:                false,
	pb.ExecutorService_ProposePVERepin_FullMethodName:                 false,
	pb.ExecutorService_CommitPVERepin_FullMethodName:                  false,
	pb.ExecutorService_ProposePVEGuestPower_FullMethodName:            false,
	pb.ExecutorService_ProposePVEGuestSnapshot_FullMethodName:         false,
	pb.ExecutorService_ProposePVEGuestProvision_FullMethodName:        false,
	pb.ExecutorService_ListPVERemotes_FullMethodName:                  false,
	pb.ExecutorService_AddPrivateRegistry_FullMethodName:              false,
	pb.ExecutorService_RotatePrivateRegistryCredential_FullMethodName: false,
	pb.ExecutorService_RemovePrivateRegistry_FullMethodName:           false,
	pb.ExecutorService_ListPrivateRegistries_FullMethodName:           false,
	pb.ExecutorService_PutContainerDefinition_FullMethodName:          false,
	pb.ExecutorService_RemoveContainerDefinition_FullMethodName:       false,
	pb.ExecutorService_ListContainerDefinitions_FullMethodName:        false,
	pb.ExecutorService_ListContainerRecreations_FullMethodName:        false,
	pb.ExecutorService_SetContainerRecoveryPlan_FullMethodName:        false,
	pb.ExecutorService_ClearContainerRecoveryPlan_FullMethodName:      false,
	pb.ExecutorService_ResolveContainerRecreation_FullMethodName:      false,
	pb.ExecutorService_ProbeNetDevice_FullMethodName:                  false,
	pb.ExecutorService_RegisterNetDevice_FullMethodName:               false,
	pb.ExecutorService_SetNetDeviceCredential_FullMethodName:          false,
	pb.ExecutorService_RotateNetDeviceCredential_FullMethodName:       false,
	pb.ExecutorService_ProposeNetDeviceRepin_FullMethodName:           false,
	pb.ExecutorService_CommitNetDeviceRepin_FullMethodName:            false,
	pb.ExecutorService_BlockNetDevice_FullMethodName:                  false,
	pb.ExecutorService_UnblockNetDevice_FullMethodName:                false,
	pb.ExecutorService_RemoveNetDevice_FullMethodName:                 false,
	pb.ExecutorService_ListNetDevices_FullMethodName:                  false,
	pb.ExecutorService_GetIntegrityStatus_FullMethodName:              false,
	pb.ExecutorService_AckIntegrityFinding_FullMethodName:             false,
}

// IntegrityLockRefuses reports whether method is refused right now
// because a locking finding is open. Unclassified methods count as
// locked.
func (s *Service) IntegrityLockRefuses(method string) bool {
	locked, known := integrityLockedMethods[method]
	if known && !locked {
		return false
	}
	return s.IntegrityLockOpen()
}

// integrityGate refuses method with ErrIntegrityLocked while the lock is
// open. It is checked when a call starts; a call that already started is
// never interrupted.
func (s *Service) integrityGate(ctx context.Context, method string) error {
	if !s.IntegrityLockRefuses(method) {
		return nil
	}
	s.auditLog(slog.LevelWarn, "integrity_lock_refused", slog.String("by", callerName(ctx)), slog.String("method", method))
	return status.Error(codes.FailedPrecondition, ErrIntegrityLocked.Error())
}

// integrityUnaryInterceptor runs after the peer-credential policy.
func (s *Service) integrityUnaryInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if err := s.integrityGate(ctx, info.FullMethod); err != nil {
		return nil, err
	}
	return handler(ctx, req)
}

// integrityStreamInterceptor runs after the peer-credential policy.
func (s *Service) integrityStreamInterceptor(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if err := s.integrityGate(ss.Context(), info.FullMethod); err != nil {
		return err
	}
	return handler(srv, ss)
}

// GetIntegrityStatus is `nebula integrity status`: read-only.
func (s *Service) GetIntegrityStatus(_ context.Context, _ *pb.GetIntegrityStatusRequest) (*pb.GetIntegrityStatusResponse, error) {
	st := s.IntegrityCheckStatus()
	out := &pb.GetIntegrityStatusResponse{
		Configured: st.Configured, Running: st.Running, TotalRuns: st.Total,
		Locked: st.Lock.Open, Note: integrity.RootCompromiseNote,
	}
	if st.Lock.Open {
		out.LockedSinceUnix = st.Lock.Since.Unix()
	}
	if n := len(st.Runs); n > 0 {
		out.LastRun = integrityRunToProto(st.Runs[n-1])
	}
	for _, f := range st.Lock.Findings {
		out.Findings = append(out.Findings, integrityFindingToProto(f))
	}
	return out, nil
}

// AckIntegrityFinding is `nebula integrity ack <finding>`; the method
// table allows only the admin role.
func (s *Service) AckIntegrityFinding(ctx context.Context, req *pb.AckIntegrityFindingRequest) (*pb.AckIntegrityFindingResponse, error) {
	f, lock, err := s.AckIntegrityFindingLocal(req.GetFindingId(), callerName(ctx))
	switch {
	case errors.Is(err, ErrIntegrityFindingInvalid):
		return nil, status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, ErrIntegrityFindingNotFound):
		return nil, status.Error(codes.NotFound, err.Error())
	case errors.Is(err, ErrIntegrityCheckRunning):
		return nil, status.Error(codes.Unavailable, err.Error())
	case errors.Is(err, ErrIntegrityCheckNotConfigured):
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	case err != nil:
		return nil, status.Error(codes.Internal, "ack integrity finding: the state could not be stored; nothing was cleared")
	}
	return &pb.AckIntegrityFindingResponse{Finding: integrityFindingToProto(f), Remaining: int32(len(lock.Findings)), Locked: lock.Open}, nil
}

func integrityFindingToProto(f IntegrityFinding) *pb.IntegrityFinding {
	return &pb.IntegrityFinding{
		Id: f.ID, Cause: string(f.Cause), Path: f.Path, Class: string(f.Class), Status: string(f.Status),
		Reason: string(f.Reason), FirstSeenUnix: f.FirstSeen.Unix(), LastSeenUnix: f.LastSeen.Unix(), Count: int32(f.Count),
	}
}

func integrityRunToProto(r IntegrityRun) *pb.IntegrityRun {
	out := &pb.IntegrityRun{
		StartedUnix: r.Started.Unix(), FinishedUnix: r.Finished.Unix(), State: string(r.State), Complete: r.Complete,
		Incomplete: r.Incomplete, ReleaseVersion: r.ReleaseVersion, ManifestSha256: r.ManifestSHA256,
		Files: int32(r.Files), Different: int32(r.Different), Missing: int32(r.Missing), Extra: int32(r.Extra),
		Unreadable: int32(r.Unreadable), Locking: int32(r.Locking), DeviationsOmitted: int32(r.DeviationsOmitted),
	}
	for _, d := range r.Deviations {
		out.Deviations = append(out.Deviations, &pb.IntegrityDeviation{
			Path: d.Path, Class: string(d.Class), Status: string(d.Status), Reason: string(d.Reason), Locks: d.Locks,
		})
	}
	return out
}
