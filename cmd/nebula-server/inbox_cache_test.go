// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"google.golang.org/grpc"
)

// testSpawn starts the status reads in a WaitGroup that the test waits for at
// its end, as run joins bg.Go in the server.
func testSpawn(t *testing.T) func(func()) {
	var wg sync.WaitGroup
	t.Cleanup(wg.Wait)
	return wg.Go
}

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
			admin := cachedVulnAdmin(st, inboxStatusTTL, func() time.Time { return clock }, testSpawn(t))
			for range 20 {
				if ok, _ := admin(context.Background()); ok {
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

// An executor status error must reach the caller, so the inbox can log it
// (logInboxCheckFailure) instead of hiding the inbox silently. It is returned
// on every call within the TTL, from the cache, and the check still denies.
func TestCachedVulnAdminReturnsTheExecutorStatusError(t *testing.T) {
	boom := errors.New("executor unavailable")
	st := &countingStatus{err: boom}
	clock := time.Unix(1_800_000_000, 0)
	admin := cachedVulnAdmin(st, inboxStatusTTL, func() time.Time { return clock }, testSpawn(t))
	for i := range 3 {
		ok, err := admin(context.Background())
		if ok {
			t.Fatalf("call %d: admin granted on a failed status read", i)
		}
		if !errors.Is(err, boom) {
			t.Fatalf("call %d: error = %v, want the executor status error", i, err)
		}
	}
	if got := st.calls.Load(); got != 1 {
		t.Fatalf("%d status reads within the TTL, want 1", got)
	}
}

func TestCachedVulnAdminNoErrorWhenStatusIsRead(t *testing.T) {
	st := &countingStatus{}
	admin := cachedVulnAdmin(st, inboxStatusTTL, time.Now, testSpawn(t))
	if ok, err := admin(context.Background()); ok || err != nil {
		t.Fatalf("admin = %v, err = %v; want false and no error", ok, err)
	}
}

// ctxStatus fails with the caller's context error when that context ended,
// as a real gRPC call does.
type ctxStatus struct{ calls atomic.Int32 }

func (c *ctxStatus) GetStatus(ctx context.Context, _ *pb.GetStatusRequest, _ ...grpc.CallOption) (*pb.GetStatusResponse, error) {
	c.calls.Add(1)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &pb.GetStatusResponse{}, nil
}

// A read that failed because the caller went away must not be cached: the
// next request, with a live context, reads the executor again instead of
// being denied for the whole TTL.
func TestCachedVulnAdminDoesNotCacheCallerCancellation(t *testing.T) {
	st := &ctxStatus{}
	clock := time.Unix(1_800_000_000, 0)
	admin := cachedVulnAdmin(st, inboxStatusTTL, func() time.Time { return clock }, testSpawn(t))

	gone, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := admin(gone); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled request: error = %v, want context.Canceled", err)
	}
	// The caller was gone before any read started, so no read happens for it
	// and nothing is cached; the next request reads once.
	if got := st.calls.Load(); got != 0 {
		t.Fatalf("%d status reads for an already cancelled request, want 0", got)
	}
	if _, err := admin(context.Background()); err != nil {
		t.Fatalf("next request: error = %v, want none", err)
	}
	if got := st.calls.Load(); got != 1 {
		t.Fatalf("%d status reads after the cancelled request, want 1", got)
	}
}

// hangStatus never answers until the read's own context ends, as a hung
// executor behind a gRPC call does, and then fails with that context error.
type hangStatus struct{ calls atomic.Int32 }

func (h *hangStatus) GetStatus(ctx context.Context, _ *pb.GetStatusRequest, _ ...grpc.CallOption) (*pb.GetStatusResponse, error) {
	h.calls.Add(1)
	<-ctx.Done()
	return nil, ctx.Err()
}

// A hung executor with a caller deadline shorter than the status timeout: every
// render gives up at its own deadline, but the executor is read once per TTL,
// and the failure of that read is cached for the TTL. Before the fix the
// caller's deadline always fired first, the failure was never cached, and every
// render asked the executor again.
func TestCachedVulnAdminHungExecutorReadOncePerTTL(t *testing.T) {
	const (
		statusTimeout = 200 * time.Millisecond
		callerWait    = 10 * time.Millisecond
		renders       = 30
	)
	st := &hangStatus{}
	clock := time.Unix(1_800_000_000, 0)
	var (
		spawned atomic.Int32
		wg      sync.WaitGroup
	)
	t.Cleanup(wg.Wait)
	spawn := func(f func()) {
		spawned.Add(1)
		wg.Go(f)
	}
	admin := cachedVulnAdminWithTimeout(st, inboxStatusTTL, func() time.Time { return clock }, statusTimeout, spawn)

	for i := range renders {
		ctx, cancel := context.WithTimeout(context.Background(), callerWait)
		ok, err := admin(ctx)
		cancel()
		if ok {
			t.Fatalf("render %d: admin granted on a hung executor", i)
		}
		if err == nil {
			t.Fatalf("render %d: no error on a hung executor", i)
		}
	}
	if got := st.calls.Load(); got != 1 {
		t.Fatalf("%d status reads within the TTL, want 1", got)
	}
	if got := spawned.Load(); got != 1 {
		t.Fatalf("%d read goroutines started within the TTL, want 1 (joined through spawn)", got)
	}

	// Past the TTL, the next request starts one new read. A request without
	// a deadline waits for it and gets its failure.
	clock = clock.Add(inboxStatusTTL)
	if _, err := admin(context.Background()); err == nil {
		t.Fatal("request after the TTL: no error on a hung executor")
	}
	if got := st.calls.Load(); got != 2 {
		t.Fatalf("%d status reads after the TTL, want 2", got)
	}
}

func TestCachedVulnAdminWithoutStatusDenies(t *testing.T) {
	ok, err := cachedVulnAdmin(nil, inboxStatusTTL, time.Now, testSpawn(t))(context.Background())
	if ok {
		t.Fatal("admin without a status provider")
	}
	if err != nil {
		t.Fatalf("error = %v, want none without a status provider", err)
	}
}
