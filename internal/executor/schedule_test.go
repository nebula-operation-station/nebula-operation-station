// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type blockingReadCloser struct {
	calls   atomic.Int32
	entered chan struct{}
	release chan struct{}
}

func (c *blockingReadCloser) Close() error {
	if c.calls.Add(1) == 1 {
		close(c.entered)
	}
	<-c.release
	return nil
}

func TestReadCancellationRacingCompletionClosesConnectionOnce(t *testing.T) {
	for _, cancelFirst := range []bool{false, true} {
		name := "completion-first"
		if cancelFirst {
			name = "cancellation-first"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			c := &blockingReadCloser{entered: make(chan struct{}), release: make(chan struct{})}
			release := sync.OnceFunc(func() { close(c.release) })
			defer release()
			cleanup := closeReadConnectionOnCancel(ctx, c)
			finished := make(chan struct{})
			if cancelFirst {
				cancel()
			} else {
				go func() { cleanup(); close(finished) }()
			}
			select {
			case <-c.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("connection close did not start")
			}
			if cancelFirst {
				go func() { cleanup(); close(finished) }()
			} else {
				cancel()
			}
			select {
			case <-finished:
				t.Fatal("cleanup returned before connection close finished")
			case <-time.After(50 * time.Millisecond):
			}
			release()
			select {
			case <-finished:
			case <-time.After(5 * time.Second):
				t.Fatal("cleanup did not finish")
			}
			if got := c.calls.Load(); got != 1 {
				t.Fatalf("connection closed %d times, want 1", got)
			}
		})
	}
}
