// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"errors"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/totp"
)

// TOTP recovery (M2, spec 05). The admin sets up the secret on the executor
// host. A recovery login (server role) only lets the web server open a
// reading session: the executor ends the privileged session, revokes every
// permit and refuses privileged sessions and browser approvals until a new
// WebAuthn credential is registered.

// RecoveryCredentialID is the credential ID a web session opened by a
// recovery login carries; CheckCredential reports it registered while TOTP
// recovery is set up and active.
const RecoveryCredentialID = "totp-recovery"

// Recovery login rate limit: after maxRecoveryFailures wrong codes within
// recoveryWindow, every attempt is refused until the window has passed.
const (
	maxRecoveryFailures = 5
	recoveryWindow      = 15 * time.Minute
	totpIssuer          = "Nebula Operation Station"
)

var errRecoveryPending = status.Error(codes.FailedPrecondition,
	"recovery_pending: a recovery login happened; register a new security key before any privileged action")

type recoveryLimiter struct {
	mu       sync.Mutex
	failures []time.Time
}

// allow reports whether another attempt may be made now.
func (l *recoveryLimiter) allow(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	kept := l.failures[:0]
	for _, f := range l.failures {
		if now.Sub(f) < recoveryWindow {
			kept = append(kept, f)
		}
	}
	l.failures = kept
	return len(l.failures) < maxRecoveryFailures
}

func (l *recoveryLimiter) fail(now time.Time) {
	l.mu.Lock()
	l.failures = append(l.failures, now)
	l.mu.Unlock()
}

// checkNotRecovering refuses privileged work while a recovery is pending.
// A store error refuses too (fail closed).
func (s *Service) checkNotRecovering() error {
	_, pending, err := s.db.RecoveryPending()
	if err != nil {
		s.log.Error("audit", "kind", "store_error", "op", "recovery_state", "detail", err.Error())
		return status.Error(codes.Unavailable, "storage_error: recovery state unavailable")
	}
	if pending {
		return errRecoveryPending
	}
	return nil
}

func (s *Service) BeginTOTPSetup(ctx context.Context, req *pb.BeginTOTPSetupRequest) (*pb.BeginTOTPSetupResponse, error) {
	account := req.GetAccount()
	if account == "" {
		account = "admin"
	}
	if len(account) > 100 {
		return nil, status.Error(codes.InvalidArgument, "account label longer than 100 bytes")
	}
	secret, err := totp.NewSecret()
	if err != nil {
		return nil, status.Error(codes.Internal, "cannot create secret")
	}
	who := callerName(ctx)
	if err := s.db.SetTOTP(secret, who); err != nil {
		return nil, s.adminStoreError("set_totp", err)
	}
	s.log.Warn("audit", "kind", "totp_setup_started", "by", who)
	return &pb.BeginTOTPSetupResponse{SecretBase32: totp.EncodeSecret(secret), Uri: totp.URI(secret, totpIssuer, account)}, nil
}

func (s *Service) ConfirmTOTPSetup(ctx context.Context, req *pb.ConfirmTOTPSetupRequest) (*pb.ConfirmTOTPSetupResponse, error) {
	t, err := s.db.GetTOTP()
	if errors.Is(err, executordb.ErrNoTOTP) {
		return nil, status.Error(codes.FailedPrecondition, "run `nebula totp setup` first")
	}
	if err != nil {
		return nil, s.adminStoreError("get_totp", err)
	}
	step, err := totp.Verify(t.Secret, req.GetCode(), time.Now(), t.LastStep)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "code not accepted: check the phone's clock and enter the current code")
	}
	if err := s.db.UseTOTPStep(step); err != nil {
		return nil, s.adminStoreError("use_totp_step", err)
	}
	s.log.Warn("audit", "kind", "totp_activated", "by", callerName(ctx))
	return &pb.ConfirmTOTPSetupResponse{}, nil
}

func (s *Service) RemoveTOTP(ctx context.Context, _ *pb.RemoveTOTPRequest) (*pb.RemoveTOTPResponse, error) {
	removed, err := s.db.RemoveTOTP()
	if err != nil {
		return nil, s.adminStoreError("remove_totp", err)
	}
	if removed {
		s.log.Warn("audit", "kind", "totp_removed", "by", callerName(ctx))
	}
	return &pb.RemoveTOTPResponse{Removed: removed}, nil
}

func (s *Service) GetTOTPStatus(_ context.Context, _ *pb.GetTOTPStatusRequest) (*pb.GetTOTPStatusResponse, error) {
	out := &pb.GetTOTPStatusResponse{}
	t, err := s.db.GetTOTP()
	switch {
	case err == nil:
		out.Configured, out.Activated = true, t.Activated
	case !errors.Is(err, executordb.ErrNoTOTP):
		return nil, s.adminStoreError("get_totp", err)
	}
	since, pending, err := s.db.RecoveryPending()
	if err != nil {
		return nil, s.adminStoreError("recovery_state", err)
	}
	if pending {
		out.RecoveryPending, out.RecoveryPendingSinceUnix = true, since.Unix()
	}
	return out, nil
}

func (s *Service) RecoveryLogin(ctx context.Context, req *pb.RecoveryLoginRequest) (*pb.RecoveryLoginResponse, error) {
	now := time.Now()
	who := callerName(ctx)
	if !s.recovery.allow(now) {
		s.log.Warn("audit", "kind", "recovery_login_limited", "by", who)
		return nil, status.Error(codes.ResourceExhausted, "too many wrong recovery codes; wait 15 minutes")
	}
	t, err := s.db.GetTOTP()
	if errors.Is(err, executordb.ErrNoTOTP) || (err == nil && !t.Activated) {
		return nil, status.Error(codes.FailedPrecondition, "recovery_not_set_up")
	}
	if err != nil {
		s.log.Error("audit", "kind", "store_error", "op", "get_totp", "detail", err.Error())
		return nil, status.Error(codes.Unavailable, "storage_error")
	}
	step, err := totp.Verify(t.Secret, req.GetCode(), now, t.LastStep)
	if err == nil {
		err = s.db.UseTOTPStep(step)
	}
	if err != nil {
		s.recovery.fail(now)
		s.log.Warn("audit", "kind", "recovery_login_failed", "by", who)
		return nil, status.Error(codes.Unauthenticated, "recovery code not accepted")
	}
	if err := s.db.SetRecoveryPending(); err != nil {
		s.log.Error("audit", "kind", "store_error", "op", "set_recovery_pending", "detail", err.Error())
		return nil, status.Error(codes.Unavailable, "storage_error")
	}
	// A recovery login means a key may be lost: whatever was approved or
	// opened before goes, as on credential removal.
	s.auth.Lock(who + ":recovery")
	s.log.Warn("audit", "kind", "recovery_login", "by", who)
	return &pb.RecoveryLoginResponse{}, nil
}
