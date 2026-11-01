// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"time"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// GetSessionState reports the executor's authoritative privileged session
// state (spec 05, ADR 0007 E19d): whether the session is active, its
// expiry, the executor-configured duration and the remaining time. The
// server displays these values; the request carries no fields, so the
// server cannot choose or extend the duration.
func (s *Service) GetSessionState(_ context.Context, _ *pb.GetSessionStateRequest) (*pb.GetSessionStateResponse, error) {
	if err := s.checkNotRecovering(); err != nil {
		return nil, err
	}
	active, till := s.auth.Session()
	var expiry, remaining int64
	if active {
		expiry = till.Unix()
		remaining = int64(till.Sub(s.clock()) / time.Second)
		if remaining < 0 {
			remaining = 0
		}
	}
	return &pb.GetSessionStateResponse{
		Active:           active,
		ExpiryUnix:       expiry,
		DurationSeconds:  int64(s.auth.SessionLength() / time.Second),
		RemainingSeconds: remaining,
	}, nil
}
