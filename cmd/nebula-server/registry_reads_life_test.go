// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/dockerhost"
	"github.com/nebula-operation-station/nebula-operation-station/internal/registrymeta"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// hangingRegistryExec is an executor whose registry list hangs until the
// caller's context ends; it counts the lists that started.
type hangingRegistryExec struct {
	*registryExecFake
	lists   atomic.Int32
	entered chan struct{}
}

func (h *hangingRegistryExec) ListPrivateRegistries(ctx context.Context, _ *pb.ListPrivateRegistriesRequest, _ ...grpc.CallOption) (*pb.ListPrivateRegistriesResponse, error) {
	h.lists.Add(1)
	select {
	case h.entered <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

// TestServerRegistryReadsStopWithServerLifetime: the background reads a
// page render queued stop when the server's lifetime context ends
// (closeRegistryReads, as runServer wires it): the batch in flight is
// cancelled long before its own timeout, closeRegistryReads returns, and a
// later cache-only render starts no executor call.
func TestServerRegistryReadsStopWithServerLifetime(t *testing.T) {
	exec := &hangingRegistryExec{registryExecFake: newRegistryExecFake(time.Unix(1_800_000_000, 0)), entered: make(chan struct{}, 1)}
	s := newServerRegistryReads(exec, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	life, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		closeRegistryReads(life, s, 10*time.Second, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}()

	u := dockerhost.ImageUpdates{Phase: "done", Images: []dockerhost.ImageUpdate{{Image: "registry.corp.example/team/app:1.0", Status: "unknown"}}}
	render := registrymeta.WithReadHost(registrymeta.WithCacheOnly(context.Background()), "web-1")
	s.ResolveImageUpdates(render, u)
	select {
	case <-exec.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("no background read started")
	}
	select {
	case <-done:
		t.Fatal("closed before the server's lifetime ended")
	default:
	}
	stop()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("background read kept running after the server's lifetime ended")
	}
	before := exec.lists.Load()
	s.ResolveImageUpdates(render, u)
	time.Sleep(50 * time.Millisecond) // a started worker would list at once
	if n := exec.lists.Load(); n != before {
		t.Fatalf("a render after shutdown started %d executor calls", n-before)
	}
}
