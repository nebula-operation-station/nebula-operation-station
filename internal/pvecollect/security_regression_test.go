// SPDX-License-Identifier: AGPL-3.0-or-later
package pvecollect

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"golang.org/x/sys/unix"
)

func TestSpoolReaderPinsDirectoryAndNeverChangesPermissions(t *testing.T) {
	s := newTestSpool(t)
	ctx := context.Background()
	path, err := s.WriteFile(ctx, mkObs("remote-a", 1, testNow))
	if err != nil {
		t.Fatal(err)
	}
	reader, err := OpenSpool(s.root)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	before, err := os.Stat(s.ResultsDir())
	if err != nil {
		t.Fatal(err)
	}
	if before.Mode().Perm()&0o070 != 0o070 {
		t.Fatalf("server group cannot list, read and consume: %o", before.Mode())
	}
	rootInfo, err := os.Stat(s.root)
	if err != nil {
		t.Fatal(err)
	}
	if rootInfo.Mode().Perm()&0o050 != 0o050 || rootInfo.Mode().Perm()&0o022 != 0 {
		t.Fatalf("unsafe spool root mode: %o", rootInfo.Mode())
	}
	if before.Mode()&os.ModeSetgid == 0 {
		t.Fatal("results must preserve the shared group on collector writes")
	}
	if err := os.Chmod(s.ResultsDir(), 0o750|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenSpool(s.root)
	if err != nil {
		t.Fatal(err)
	}
	reopened.Close()
	after, err := os.Stat(s.ResultsDir())
	if err != nil {
		t.Fatal(err)
	}
	if after.Mode().Perm() != 0o750 {
		t.Fatalf("read opener changed permissions: %o", after.Mode())
	}
	if err := os.Chmod(s.ResultsDir(), before.Mode()); err != nil {
		t.Fatal(err)
	}
	pinned := s.ResultsDir() + "-pinned"
	if err := os.Rename(s.ResultsDir(), pinned); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	name := filepath.Base(path)
	raw, err := pvecontract.MarshalObservation(mkObs("remote-a", 1, testNow.Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(outside, name)
	if err := os.WriteFile(victim, raw, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, s.ResultsDir()); err != nil {
		t.Fatal(err)
	}
	got, err := reader.ReadFile(ctx, name)
	if err != nil || !got.ObservedAt.Equal(testNow) {
		t.Fatalf("read escaped pinned directory: %+v, %v", got, err)
	}
	names, err := reader.List(ctx)
	if err != nil || len(names) != 1 {
		t.Fatalf("List: %v, %v", names, err)
	}
	if err := reader.Remove(ctx, name); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("consumption touched outside file: %v", err)
	}
	if _, err := reader.WriteFile(ctx, mkObs("remote-a", 2, testNow)); err == nil {
		t.Fatal("read-side spool accepted a write")
	}
}

func TestSpoolRejectsUnsafeExistingFilesWithoutBlocking(t *testing.T) {
	for _, kind := range []string{"fifo", "directory", "oversize", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			s := newTestSpool(t)
			obs := mkObs("remote-a", 1, testNow)
			name, err := spoolFileName(obs.RemoteID, obs.CollectionGeneration)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(s.ResultsDir(), name)
			switch kind {
			case "fifo":
				err = unix.Mkfifo(path, 0o640)
			case "directory":
				err = os.Mkdir(path, 0o750)
			case "oversize":
				var f *os.File
				f, err = os.Create(path)
				if err == nil {
					err = f.Truncate(maxSpoolFileBytes + 1)
					f.Close()
				}
			case "symlink":
				err = os.Symlink("/dev/zero", path)
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, write := range []bool{false, true} {
				done := make(chan error, 1)
				go func() {
					if write {
						_, err := s.WriteFile(context.Background(), obs)
						done <- err
					} else {
						_, err := s.ReadFile(context.Background(), name)
						done <- err
					}
				}()
				select {
				case err := <-done:
					if err == nil {
						t.Fatal("unsafe file accepted")
					}
					if kind == "oversize" && !errors.Is(err, ErrOversize) {
						t.Fatalf("want size rejection, got %v", err)
					}
					if kind == "symlink" && !errors.Is(err, ErrSymlink) {
						t.Fatalf("want symlink rejection, got %v", err)
					}
				case <-time.After(time.Second):
					// Unblock a broken FIFO implementation before failing the test.
					if kind == "fifo" {
						fd, e := unix.Open(path, unix.O_RDWR|unix.O_NONBLOCK, 0)
						if e == nil {
							unix.Close(fd)
						}
					}
					t.Fatal("unsafe file read blocked")
				}
			}
		})
	}
}

func TestCollectorRestartAdvancesPendingAndDurableGenerations(t *testing.T) {
	im, spool, store := newTestImporter(t)
	ctx := context.Background()
	fr := &fakeReader{remotes: []*pb.PVERemoteInfo{activeRemote("remote-a")}, readFn: defaultReadFn}
	collectInto(t, spool, fr)
	// Reopening both spool and collector must preserve a pending generation.
	fresh, err := NewSpool(spool.root)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	collectInto(t, fresh, fr)
	names, err := fresh.List(ctx)
	if err != nil || len(names) != 2 {
		t.Fatalf("restart lost pending generation: %v, %v", names, err)
	}
	first, err := fresh.ReadFile(ctx, names[0])
	if err != nil {
		t.Fatal(err)
	}
	second, err := fresh.ReadFile(ctx, names[1])
	if err != nil {
		t.Fatal(err)
	}
	if second.CollectionGeneration <= first.CollectionGeneration {
		t.Fatal("generation did not advance")
	}
	if rep, err := im.ImportOnce(ctx); err != nil || rep.Imported != 2 {
		t.Fatalf("import pending: %+v, %v", rep, err)
	}
	// No files remain to infer the next generation from; the durable inventory
	// watermark still requires an advance, even with a clock moving backwards.
	c, err := New(fr, fresh, Config{Now: func() time.Time { return testNow.Add(-time.Minute) }, Jitter: func() float64 { return 0 }})
	if err != nil {
		t.Fatal(err)
	}
	if rep, err := c.PollOnce(ctx); err != nil || rep.Polled != 1 {
		t.Fatalf("restart poll: %+v, %v", rep, err)
	}
	names, err = fresh.List(ctx)
	if err != nil || len(names) != 1 {
		t.Fatalf("list: %v %v", names, err)
	}
	third, err := fresh.ReadFile(ctx, names[0])
	if err != nil {
		t.Fatal(err)
	}
	if third.CollectionGeneration <= second.CollectionGeneration {
		t.Fatal("consumed generation reused")
	}
	if _, err := store.IngestObservation(ctx, third); err != nil {
		t.Fatalf("durable watermark rejected restarted collector: %v", err)
	}
}

func TestCollectionFailuresGrowCapAndResetBackoff(t *testing.T) {
	for _, method := range []pb.PVEReadMethod{pb.PVEReadMethod_PVE_READ_METHOD_NODES, pb.PVEReadMethod_PVE_READ_METHOD_GUEST_CONFIG} {
		for _, unavailable := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/unavailable=%v", method, unavailable), func(t *testing.T) {
				fail := true
				fr := &fakeReader{remotes: []*pb.PVERemoteInfo{activeRemote("remote-a")}, readFn: func(req *pb.ReadPVERequest) (*pb.ReadPVEResponse, error) {
					if fail && req.Method == method {
						if !unavailable {
							return nil, errors.New("read failed")
						}
						if method == pb.PVEReadMethod_PVE_READ_METHOD_NODES {
							return &pb.ReadPVEResponse{Payload: &pb.ReadPVEResponse_Nodes{Nodes: &pb.PVENodes{State: pb.PVEDatasetState_PVE_DATASET_STATE_UNAVAILABLE}}}, nil
						}
						return &pb.ReadPVEResponse{Payload: &pb.ReadPVEResponse_GuestConfig{GuestConfig: &pb.PVEGuestConfig{State: pb.PVEDatasetState_PVE_DATASET_STATE_UNAVAILABLE}}}, nil
					}
					return defaultReadFn(req)
				}}
				c, spool, now := newTestCollector(t, fr)
				c.cfg.Interval = time.Second
				c.cfg.InitialBackoff = 3 * time.Second
				c.cfg.MaxBackoff = 10 * time.Second
				ctx := context.Background()
				for _, delay := range []time.Duration{3 * time.Second, 6 * time.Second, 10 * time.Second, 10 * time.Second} {
					rep, err := c.PollOnce(ctx)
					if err != nil || rep.Failed != 1 || rep.Polled != 0 {
						t.Fatalf("failed read reported success: %+v %v", rep, err)
					}
					if got := c.nextPoll["remote-a"].Sub(*now); got != delay {
						t.Fatalf("delay %v, want %v", got, delay)
					}
					names, err := spool.List(ctx)
					if err != nil || len(names) == 0 {
						t.Fatalf("partial observation missing: %v %v", names, err)
					}
					*now = now.Add(delay - time.Nanosecond)
					rep, err = c.PollOnce(ctx)
					if err != nil || rep.Skipped != 1 {
						t.Fatalf("backoff not enforced: %+v %v", rep, err)
					}
					*now = now.Add(time.Nanosecond)
				}
				fail = false
				rep, err := c.PollOnce(ctx)
				if err != nil || rep.Polled != 1 || c.failures["remote-a"] != 0 {
					t.Fatalf("recovery failed: %+v %v", rep, err)
				}
				*now = now.Add(c.cfg.Interval)
				fail = true
				if rep, err := c.PollOnce(ctx); err != nil || rep.Failed != 1 {
					t.Fatalf("failure after recovery: %+v %v", rep, err)
				}
				if got := c.nextPoll["remote-a"].Sub(*now); got != c.cfg.InitialBackoff {
					t.Fatalf("backoff not reset: %v", got)
				}
			})
		}
	}
}

func TestGuestListRejectedBeforeDetailScheduling(t *testing.T) {
	for _, kind := range []string{"page-limit", "remote-limit", "invalid-id", "duplicate", "nil"} {
		t.Run(kind, func(t *testing.T) {
			fr := &fakeReader{remotes: []*pb.PVERemoteInfo{activeRemote("remote-a")}, readFn: func(req *pb.ReadPVERequest) (*pb.ReadPVEResponse, error) {
				resp, err := defaultReadFn(req)
				if req.Method == pb.PVEReadMethod_PVE_READ_METHOD_GUESTS {
					guests := resp.GetGuests()
					switch kind {
					case "page-limit", "remote-limit":
						n := pvecontract.MaxObjectsPerPage + 1
						if kind == "remote-limit" {
							n = pvecontract.MaxGuestsPerRemote + 1
						}
						guests.Guests = make([]*pb.PVEGuest, n)
						for i := range guests.Guests {
							guests.Guests[i] = &pb.PVEGuest{Vmid: uint64(100 + i), Kind: "qemu", Node: "p1", Name: "vm", Status: "running", Generation: 1}
						}
					case "invalid-id":
						guests.Guests[0].Vmid = pvecontract.MaxVMID + 1
					case "duplicate":
						guests.Guests = append(guests.Guests, guests.Guests[0])
					case "nil":
						guests.Guests[0] = nil
					}
				}
				return resp, err
			}}
			c, _, _ := newTestCollector(t, fr)
			rep, err := c.PollOnce(context.Background())
			if err != nil || rep.Failed != 1 {
				t.Fatalf("invalid guest list accepted: %+v %v", rep, err)
			}
			if fr.readCalls != 5 {
				t.Fatalf("invalid list scheduled detail work: %d calls", fr.readCalls)
			}
		})
	}
}

func TestReadWorkersBoundQueuedResponsesAndGoroutines(t *testing.T) {
	fr := &fakeReader{readFn: defaultReadFn}
	c, _, _ := newTestCollector(t, fr)
	reqs := make([]readReq, 4000)
	for i := range reqs {
		reqs[i].method = pb.PVEReadMethod_PVE_READ_METHOD_NODES
	}
	baseline := runtime.NumGoroutine()
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	done := make(chan error, 1)
	go func() {
		done <- c.runReads(context.Background(), "remote-a", reqs, func(readResult) error {
			select {
			case <-entered:
			default:
				close(entered)
			}
			<-release
			return nil
		})
	}()
	<-entered
	// Let workers fill their result buffer while consumption is held.
	time.Sleep(30 * time.Millisecond)
	fr.mu.Lock()
	calls := fr.readCalls
	fr.mu.Unlock()
	if calls > 2*c.cfg.MaxConcurrentReads+1 {
		t.Errorf("unbounded response retention: %d reads while consumer blocked", calls)
	}
	if delta := runtime.NumGoroutine() - baseline; delta > c.cfg.MaxConcurrentReads+4 {
		t.Errorf("unbounded queued goroutines: %d", delta)
	}
	once.Do(func() { close(release) })
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if fr.readCalls != len(reqs) {
		t.Fatalf("lost reads: %d", fr.readCalls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := fr.readCalls
	if err := c.runReads(ctx, "remote-a", reqs, func(readResult) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
	if fr.readCalls != before {
		t.Fatal("cancelled work still scheduled RPCs")
	}
}

func TestImporterRejectionNeverLogsUntrustedValidationText(t *testing.T) {
	for _, kind := range []string{"decoder", "validation", "identity"} {
		t.Run(kind, func(t *testing.T) {
			im, spool, _ := newTestImporter(t)
			var logs bytes.Buffer
			im.log = slog.New(slog.NewJSONHandler(&logs, nil))
			marker := "untrusted-field-marker"
			obs := mkObs("remote-a", 1, testNow)
			raw, err := pvecontract.MarshalObservation(obs)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "decoder":
				raw = append([]byte(`{"`+marker+`":true,`), raw[1:]...)
			case "validation":
				raw = bytes.Replace(raw, []byte(`"pve-collector"`), []byte(`"`+marker+`!"`), 1)
			case "identity":
				raw = bytes.Replace(raw, []byte(`"remote-a"`), []byte(`"`+marker+`"`), 1)
			}
			name, _ := spoolFileName("remote-a", 1)
			if err := os.WriteFile(filepath.Join(spool.ResultsDir(), name), raw, 0o640); err != nil {
				t.Fatal(err)
			}
			rep, err := im.ImportOnce(context.Background())
			if err != nil || rep.Rejected != 1 {
				t.Fatalf("report: %+v %v", rep, err)
			}
			if strings.Contains(logs.String(), marker) || strings.Contains(fmt.Sprint(rep.Errors), marker) {
				t.Fatalf("untrusted validation text persisted: %s %+v", logs.String(), rep.Errors)
			}
			if !strings.Contains(logs.String(), `"reason":"invalid_observation"`) {
				t.Fatalf("missing bounded rejection code: %s", logs.String())
			}
		})
	}
}

func TestGenerationAllocationRecoversReservationsAndRejectsUnsafeState(t *testing.T) {
	ctx := context.Background()
	t.Run("pending migration and reservation recovery", func(t *testing.T) {
		spool := newTestSpool(t)
		if _, err := spool.WriteFile(ctx, mkObs("remote-a", 41, testNow)); err != nil {
			t.Fatal(err)
		}
		reserved, err := spool.allocateGeneration(ctx, "remote-a")
		if err != nil || reserved != 42 {
			t.Fatalf("migrate pending generation: %d %v", reserved, err)
		}
		// Simulate a crash after the durable reservation, before publication.
		fresh, err := NewSpool(spool.root)
		if err != nil {
			t.Fatal(err)
		}
		defer fresh.Close()
		recovered, err := fresh.allocateGeneration(ctx, "remote-a")
		if err != nil || recovered != 43 {
			t.Fatalf("reused unpublished reservation: %d %v", recovered, err)
		}
	})
	for _, kind := range []string{"malformed", "exhausted", "oversize", "symlink", "fifo", "directory"} {
		t.Run(kind, func(t *testing.T) {
			spool := newTestSpool(t)
			path := filepath.Join(spool.root, ".generation-remote-a")
			var err error
			switch kind {
			case "malformed":
				err = os.WriteFile(path, []byte("invalid\n"), 0o600)
			case "exhausted":
				err = os.WriteFile(path, []byte(fmt.Sprint(pvecontract.MaxCollectionGeneration)+"\n"), 0o600)
			case "oversize":
				err = os.WriteFile(path, bytes.Repeat([]byte("9"), maxGenerationBytes+1), 0o600)
			case "symlink":
				err = os.Symlink("/dev/zero", path)
			case "fifo":
				err = unix.Mkfifo(path, 0o600)
			case "directory":
				err = os.Mkdir(path, 0o700)
			}
			if err != nil {
				t.Fatal(err)
			}
			if gen, err := spool.allocateGeneration(ctx, "remote-a"); err == nil {
				t.Fatalf("unsafe state allocated %d", gen)
			}
		})
	}
}

func TestGenerationAllocationSerializesSpoolInstances(t *testing.T) {
	spool := newTestSpool(t)
	other, err := NewSpool(spool.root)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	ctx := context.Background()
	var wg sync.WaitGroup
	generations := make(chan uint64, 12)
	for i := range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := spool
			if i%2 == 0 {
				s = other
			}
			gen, err := s.allocateGeneration(ctx, "remote-a")
			if err != nil {
				t.Error(err)
				return
			}
			generations <- gen
		}()
	}
	wg.Wait()
	close(generations)
	seen := map[uint64]bool{}
	for gen := range generations {
		if gen < 1 || gen > 12 || seen[gen] {
			t.Fatalf("invalid or repeated generation: %d", gen)
		}
		seen[gen] = true
	}
	if len(seen) != 12 {
		t.Fatalf("missing reservations: %v", seen)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := spool.allocateGeneration(cancelled, "remote-a"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled allocator: %v", err)
	}
}

func TestReadWorkersStopOnConsumerRejection(t *testing.T) {
	fr := &fakeReader{readFn: defaultReadFn}
	c, _, _ := newTestCollector(t, fr)
	reqs := make([]readReq, 1000)
	for i := range reqs {
		reqs[i].method = pb.PVEReadMethod_PVE_READ_METHOD_NODES
	}
	rejected := errors.New("consumer rejected response")
	if err := c.runReads(context.Background(), "remote-a", reqs, func(readResult) error { return rejected }); !errors.Is(err, rejected) {
		t.Fatalf("lost rejection: %v", err)
	}
	if fr.readCalls > 2*c.cfg.MaxConcurrentReads+1 {
		t.Fatalf("queued work continued after rejection: %d", fr.readCalls)
	}
}

func TestCollectorBoundsAccumulatedDetailResponses(t *testing.T) {
	fr := &fakeReader{remotes: []*pb.PVERemoteInfo{activeRemote("remote-a")}, readFn: func(req *pb.ReadPVERequest) (*pb.ReadPVEResponse, error) {
		resp, err := defaultReadFn(req)
		switch req.Method {
		case pb.PVEReadMethod_PVE_READ_METHOD_GUEST_CONFIG:
			resp.GetGuestConfig().Tags = []string{strings.Repeat("x", maxSpoolFileBytes/2+1)}
		case pb.PVEReadMethod_PVE_READ_METHOD_GUEST_AGENT:
			resp.GetGuestAgent().Os = strings.Repeat("x", maxSpoolFileBytes/2+1)
		}
		return resp, err
	}}
	c, _, _ := newTestCollector(t, fr)
	rep, err := c.PollOnce(context.Background())
	if err != nil || rep.Failed != 1 || len(rep.Errors) != 1 || !strings.Contains(rep.Errors[0], ErrOversize.Error()) {
		t.Fatalf("aggregate response budget not enforced: %+v %v", rep, err)
	}
}
