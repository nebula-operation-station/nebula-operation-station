// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executorclient"
	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcollect"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

const payloadMarker = "PAYLOAD-MARKER-91c2"

// fakeClient answers with one CBS device whose reads block until release
// is closed.
type fakeClient struct {
	release chan struct{}
	started chan struct{}
	once    sync.Once
	closed  atomic.Bool
	reads   atomic.Int32
}

func newFakeClient() *fakeClient {
	return &fakeClient{release: make(chan struct{}), started: make(chan struct{})}
}

func (f *fakeClient) ListNetDeviceInfos(context.Context) ([]*pb.NetDeviceInfo, error) {
	return []*pb.NetDeviceInfo{{DeviceId: "core-sw-01", Family: "cbs", TrustGeneration: 2, CredentialVersion: 1}}, nil
}

func (f *fakeClient) ReadNetDeviceByID(ctx context.Context, id string, read pb.NetDeviceRead) (*pb.ReadNetDeviceResponse, error) {
	f.reads.Add(1)
	f.once.Do(func() { close(f.started) })
	select {
	case <-f.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return &pb.ReadNetDeviceResponse{DeviceId: id, TrustGeneration: 2,
		Payload: &pb.ReadNetDeviceResponse_CbsVersion{CbsVersion: &pb.NetDevCBSVersion{Model: payloadMarker}}}, nil
}

func (f *fakeClient) Close() error {
	f.closed.Store(true)
	return nil
}

// memSpool records payloads in memory.
type memSpool struct {
	mu       sync.Mutex
	payloads []string
}

func (s *memSpool) Write(_ context.Context, _, _ string, _ uint64, _ bool, payload []byte) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.payloads = append(s.payloads, string(payload))
	return "x", nil
}

func (s *memSpool) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.payloads)
}

func testDeps(c *fakeClient, s *memSpool, euid int) deps {
	return deps{
		geteuid: func() int { return euid },
		newClient: func(context.Context, executorclient.Options) (collectorClient, error) {
			return c, nil
		},
		newSpool: func(string) netdevcollect.SpoolWriter { return s },
		now:      time.Now,
		rand:     func() float64 { return 0.5 },
	}
}

func validOptions() options {
	return options{socket: defaultSocket, executorUser: defaultExecutorUser, spoolDir: defaultSpool, interval: defaultInterval}
}

func TestParseFlagsDefaults(t *testing.T) {
	o, err := parseFlags(nil)
	if err != nil {
		t.Fatal(err)
	}
	if o != validOptions() {
		t.Fatalf("defaults = %+v", o)
	}
}

func TestParseFlagsValidation(t *testing.T) {
	tests := []struct {
		name string
		args []string
		ok   bool
	}{
		{"all flags", []string{"-socket", "/run/x.sock", "-executor-user", "ex", "-spool", "/var/lib/x", "-interval", "30s"}, true},
		{"relative socket", []string{"-socket", "x.sock"}, false},
		{"relative spool", []string{"-spool", "spool"}, false},
		{"empty executor user", []string{"-executor-user", ""}, false},
		{"interval too short", []string{"-interval", "100ms"}, false},
		{"interval above the floor", []string{"-interval", "16m"}, false},
		{"interval at the floor", []string{"-interval", "15m"}, true},
		{"positional argument", []string{"extra"}, false},
		{"unknown flag", []string{"-once"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseFlags(tt.args)
			if (err == nil) != tt.ok {
				t.Fatalf("parseFlags(%v) = %v, want ok=%v", tt.args, err, tt.ok)
			}
		})
	}
}

func TestRunRefusesRoot(t *testing.T) {
	c := newFakeClient()
	built := false
	d := testDeps(c, &memSpool{}, 0)
	d.newClient = func(context.Context, executorclient.Options) (collectorClient, error) {
		built = true
		return c, nil
	}
	err := run(context.Background(), validOptions(), slog.New(slog.DiscardHandler), d)
	if !errors.Is(err, errRunAsRoot) {
		t.Fatalf("run as root = %v, want errRunAsRoot", err)
	}
	if built {
		t.Fatal("run as root connected to the executor")
	}
}

func TestRunReportsClientError(t *testing.T) {
	boom := errors.New("dial failed")
	d := testDeps(newFakeClient(), &memSpool{}, 1000)
	d.newClient = func(context.Context, executorclient.Options) (collectorClient, error) { return nil, boom }
	if err := run(context.Background(), validOptions(), slog.New(slog.DiscardHandler), d); !errors.Is(err, boom) {
		t.Fatalf("run = %v, want %v", err, boom)
	}
}

func TestRunShutdownDrainsAndClosesClient(t *testing.T) {
	c := newFakeClient()
	s := &memSpool{}
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, validOptions(), log, testDeps(c, s, 1000)) }()
	<-c.started
	cancel() // what SIGTERM does via signal.NotifyContext
	select {
	case err := <-done:
		t.Fatalf("run returned %v before the in-flight read drained", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(c.release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not stop")
	}
	if s.count() != 1 || c.reads.Load() != 1 {
		t.Fatalf("spooled %d, reads %d; want the one drained read", s.count(), c.reads.Load())
	}
	if !c.closed.Load() {
		t.Fatal("executor client not closed")
	}
	out := buf.String()
	if !strings.Contains(out, "stopped") {
		t.Fatalf("no stop line in log:\n%s", out)
	}
	if strings.Contains(out, payloadMarker) {
		t.Fatalf("log contains a payload:\n%s", out)
	}
}
