// SPDX-License-Identifier: AGPL-3.0-or-later

package registrymeta

import (
	"context"
	"fmt"
	"testing"
	"time"

	"google.golang.org/grpc"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
)

// slowReadExecutor moves the reader's clock forward by step on every
// executor read, like reads that take their time. The reader calls it from
// its own goroutine only, so the clock is not shared while it runs.
type slowReadExecutor struct {
	*fakeExecutor
	clock *time.Time
	step  time.Duration
}

func (s *slowReadExecutor) ReadPrivateRegistry(ctx context.Context, in *pb.ReadPrivateRegistryRequest, o ...grpc.CallOption) (*pb.ReadPrivateRegistryResponse, error) {
	*s.clock = s.clock.Add(s.step)
	return s.fakeExecutor.ReadPrivateRegistry(ctx, in, o...)
}

// TestDigestReaderStampsEachBackgroundRead: in one background batch every
// host charge and cache entry is stamped when its read starts and every
// held failure when its read failed, not once at the start of the batch.
func TestDigestReaderStampsEachBackgroundRead(t *testing.T) {
	const step = 30 * time.Second
	images := []string{"registry.corp.example/team/app:a", "registry.corp.example/team/app:b", "registry.corp.example/team/app:c"}
	ctx := WithReadHost(WithCacheOnly(context.Background()), "web-1")

	t.Run("charges and cache", func(t *testing.T) {
		f, _, clock := leasedReader(t)
		start := *clock
		r := NewDigestReader(&slowReadExecutor{fakeExecutor: f, clock: clock, step: step}, func() time.Time { return *clock })
		r.PrivateDigests(ctx, images)
		drain(t, r)
		r.mu.Lock()
		defer r.mu.Unlock()
		spent := r.spent[hostRegistry{host: "web-1", registry: "corp"}]
		if len(spent) != len(images) {
			t.Fatalf("charges = %+v", spent)
		}
		for i, x := range spent {
			want := start.Add(time.Duration(i) * step)
			if x.tag != fmt.Sprintf("%c", 'a'+i) || !x.at.Equal(want) {
				t.Errorf("charge %d = %s at %s, want %c at %s", i, x.tag, x.at, 'a'+i, want)
			}
		}
		if len(r.cache) != len(images) {
			t.Fatalf("cache holds %d", len(r.cache))
		}
		for k, c := range r.cache {
			i := int(k.tag[0] - 'a')
			if want := start.Add(time.Duration(i)*step + schedgrant.RegistryMinInterval); !c.expires.Equal(want) {
				t.Errorf("cache %s expires %s, want %s", k.tag, c.expires, want)
			}
		}
	})

	t.Run("held failures", func(t *testing.T) {
		now := time.Unix(1_800_000_000, 0)
		clock := now
		f := newFakeExecutor(now) // no lease: every read is refused
		r := NewDigestReader(&slowReadExecutor{fakeExecutor: f, clock: &clock, step: step}, func() time.Time { return clock })
		r.PrivateDigests(ctx, images)
		drain(t, r)
		r.mu.Lock()
		defer r.mu.Unlock()
		if len(r.failed) != len(images) {
			t.Fatalf("held failures = %d", len(r.failed))
		}
		for k, h := range r.failed {
			i := int(k.k.tag[0] - 'a')
			if want := now.Add(time.Duration(i+1)*step + failureHold); !h.until.Equal(want) {
				t.Errorf("failure %s held until %s, want %s", k.k.tag, h.until, want)
			}
		}
	})
}

// TestDigestReaderSynchronousReadsStampedPerRead: a call without
// WithCacheOnly stamps each read at its own time too.
func TestDigestReaderSynchronousReadsStampedPerRead(t *testing.T) {
	const step = 30 * time.Second
	f, _, clock := leasedReader(t)
	start := *clock
	r := NewDigestReader(&slowReadExecutor{fakeExecutor: f, clock: clock, step: step}, func() time.Time { return *clock })
	images := []string{"registry.corp.example/team/app:a", "registry.corp.example/team/app:b"}
	if got, _, err := r.PrivateDigests(WithReadHost(context.Background(), "web-1"), images); err != nil || len(got) != 2 {
		t.Fatalf("got=%v err=%v", got, err)
	}
	spent := r.spent[hostRegistry{host: "web-1", registry: "corp"}]
	if len(spent) != 2 || !spent[0].at.Equal(start) || !spent[1].at.Equal(start.Add(step)) {
		t.Fatalf("charges = %+v", spent)
	}
}

// ctxBlockingExecutor blocks every executor call until its context ends,
// like an executor that hangs.
type ctxBlockingExecutor struct {
	*fakeExecutor
	entered chan struct{}
}

func (c *ctxBlockingExecutor) ListPrivateRegistries(ctx context.Context, _ *pb.ListPrivateRegistriesRequest, _ ...grpc.CallOption) (*pb.ListPrivateRegistriesResponse, error) {
	select {
	case c.entered <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

// TestDigestReaderCloseStopsBackgroundWorker: Close cancels the batch in
// flight (it does not run out backgroundBatchTimeout), waits for the
// worker, and afterwards a cache-only render queues nothing.
func TestDigestReaderCloseStopsBackgroundWorker(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	f := newFakeExecutor(now)
	exec := &ctxBlockingExecutor{fakeExecutor: f, entered: make(chan struct{}, 1)}
	r := NewDigestReader(exec, func() time.Time { return now })
	ctx := WithCacheOnly(context.Background())
	r.PrivateDigests(ctx, []string{privateImage})
	select {
	case <-exec.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("background worker never called the executor")
	}
	closeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	if err := r.Close(closeCtx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if d := time.Since(start); d >= backgroundBatchTimeout {
		t.Fatalf("Close took %s", d)
	}
	r.PrivateDigests(ctx, []string{privateImage, "registry.corp.example/team/app:2"})
	r.mu.Lock()
	queued, running := len(r.queue), r.running
	r.mu.Unlock()
	if queued != 0 || running {
		t.Fatalf("after Close: %d queued, worker running %v", queued, running)
	}
	if n := f.readCount(); n != 0 {
		t.Fatalf("executor reads = %d", n)
	}
	// Close is idempotent.
	if err := r.Close(closeCtx); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}
