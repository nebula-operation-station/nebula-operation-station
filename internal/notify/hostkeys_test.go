// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
)

type recorder struct {
	events []Event
	fail   bool
}

func (r *recorder) Name() string { return "rec" }
func (r *recorder) Send(_ context.Context, e Event) error {
	if r.fail {
		return context.DeadlineExceeded
	}
	r.events = append(r.events, e)
	return nil
}

func TestHostKeyWatcherNotifiesOncePerBlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.db")
	db, err := serverdb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	pins := []*pb.HostKeyPin{
		{HostId: "ok", Fingerprint: "SHA256:a"},
		{HostId: "strompi", Fingerprint: "SHA256:old", Blocked: true, BlockedAtUnix: 100, BlockedEndpoint: "10.8.0.5:22", BlockedFingerprint: "SHA256:new"},
	}
	rec := &recorder{}
	w := &HostKeyWatcher{Notifier: NewWithSenders(quiet(), nil, rec), DB: db, Log: quiet(), Interval: time.Hour,
		List: func(context.Context) ([]*pb.HostKeyPin, error) { return pins, nil }}
	ctx := context.Background()

	rec.fail = true
	if err := w.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	rec.fail = false
	for i := 0; i < 3; i++ {
		if err := w.Poll(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if len(rec.events) != 1 || rec.events[0].Host != "strompi" || rec.events[0].Kind != KindHostKeyMismatch {
		t.Fatalf("events %+v (a failed send must be retried, a sent one never repeated)", rec.events)
	}

	// A restart keeps what was sent.
	w2 := *w
	if err := w2.Poll(ctx); err != nil || len(rec.events) != 1 {
		t.Fatalf("repeated after restart: %v %d", err, len(rec.events))
	}

	// Re-pinned, later blocked again: notifies again.
	pins[1] = &pb.HostKeyPin{HostId: "strompi", Fingerprint: "SHA256:new"}
	if err := w.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	pins[1] = &pb.HostKeyPin{HostId: "strompi", Fingerprint: "SHA256:new", Blocked: true, BlockedAtUnix: 200, BlockedEndpoint: "192.168.0.5:22"}
	if err := w.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if len(rec.events) != 2 {
		t.Fatalf("second block: %d events", len(rec.events))
	}
}

func TestHostKeyWatcherIdleWithoutProviders(t *testing.T) {
	called := false
	w := &HostKeyWatcher{Notifier: NewWithSenders(quiet(), nil), Interval: time.Millisecond, Log: quiet(),
		List: func(context.Context) ([]*pb.HostKeyPin, error) { called = true; return nil, nil }}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	w.Run(ctx)
	if called {
		t.Fatal("polled without providers")
	}
}
