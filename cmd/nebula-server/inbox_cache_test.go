// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"google.golang.org/grpc"
)

type countingStatus struct {
	calls atomic.Int32
	err   error
}

func (c *countingStatus) GetStatus(ctx context.Context, _ *pb.GetStatusRequest, _ ...grpc.CallOption) (*pb.GetStatusResponse, error) {
	c.calls.Add(1)
	if c.err != nil {
		return nil, c.err
	}
	return &pb.GetStatusResponse{}, nil
}

// The inbox admin check runs on every page render, so it must not ask the
// executor more than once per inboxStatusTTL, also when the executor fails.
func TestCachedVulnAdminAsksTheExecutorOncePerTTL(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{{"status ok", nil}, {"executor fails", errors.New("executor unavailable")}} {
		t.Run(tc.name, func(t *testing.T) {
			st := &countingStatus{err: tc.err}
			clock := time.Unix(1_800_000_000, 0)
			admin := cachedVulnAdmin(st, inboxStatusTTL, func() time.Time { return clock })
			for range 20 {
				if admin(context.Background()) {
					t.Fatal("admin without a privileged session in the request")
				}
			}
			if got := st.calls.Load(); got != 1 {
				t.Fatalf("%d status reads within the TTL, want 1", got)
			}
			clock = clock.Add(inboxStatusTTL)
			admin(context.Background())
			if got := st.calls.Load(); got != 2 {
				t.Fatalf("%d status reads after the TTL, want 2", got)
			}
		})
	}
}

func TestCachedVulnAdminWithoutStatusDenies(t *testing.T) {
	if cachedVulnAdmin(nil, inboxStatusTTL, time.Now)(context.Background()) {
		t.Fatal("admin without a status provider")
	}
}
