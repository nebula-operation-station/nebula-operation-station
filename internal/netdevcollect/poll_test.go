// SPDX-License-Identifier: AGPL-3.0-or-later

package netdevcollect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"math/rand/v2"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executorclient"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// payloadMarker is planted in device output and executor error details;
// it must never reach a log line.
const payloadMarker = "PAYLOAD-MARKER-7f3a"

var pollStart = time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC)

// fakeClock is a manually advanced clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock { return &fakeClock{t: pollStart} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// call is one ReadNetDeviceByID call seen by the fake client.
type call struct {
	device string
	read   pb.NetDeviceRead
	at     time.Time
}

// fakeClient is an in-memory executor: it lists fixed devices and answers
// reads with a typed payload carrying payloadMarker.
type fakeClient struct {
	clock *fakeClock

	mu          sync.Mutex
	devices     []*pb.NetDeviceInfo
	listErr     error
	readErr     map[pb.NetDeviceRead]error
	respond     func(device string, read pb.NetDeviceRead) *pb.ReadNetDeviceResponse
	calls       []call
	inflight    map[string]int
	maxInflight map[string]int
	totalNow    int
	totalMax    int

	// block, when set, holds every read until it is closed; started gets
	// one value per read that began.
	block   chan struct{}
	started chan string
}

func newFakeClient(clock *fakeClock, devices ...*pb.NetDeviceInfo) *fakeClient {
	return &fakeClient{
		clock:       clock,
		devices:     devices,
		readErr:     map[pb.NetDeviceRead]error{},
		inflight:    map[string]int{},
		maxInflight: map[string]int{},
	}
}

func (f *fakeClient) ListNetDeviceInfos(ctx context.Context) ([]*pb.NetDeviceInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	return append([]*pb.NetDeviceInfo(nil), f.devices...), nil
}

func (f *fakeClient) ReadNetDeviceByID(ctx context.Context, deviceID string, read pb.NetDeviceRead) (*pb.ReadNetDeviceResponse, error) {
	f.mu.Lock()
	f.calls = append(f.calls, call{device: deviceID, read: read, at: f.clock.Now()})
	f.inflight[deviceID]++
	f.maxInflight[deviceID] = max(f.maxInflight[deviceID], f.inflight[deviceID])
	f.totalNow++
	f.totalMax = max(f.totalMax, f.totalNow)
	block, started := f.block, f.started
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.inflight[deviceID]--
		f.totalNow--
		f.mu.Unlock()
	}()
	if started != nil {
		started <- deviceID
	}
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	f.mu.Lock()
	err, respond := f.readErr[read], f.respond
	var gen uint64
	for _, d := range f.devices {
		if d.GetDeviceId() == deviceID {
			gen = d.GetTrustGeneration()
		}
	}
	f.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if respond != nil {
		return respond(deviceID, read), nil
	}
	return okResponse(deviceID, gen, read), nil
}

func (f *fakeClient) setReadErr(read pb.NetDeviceRead, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err == nil {
		delete(f.readErr, read)
		return
	}
	f.readErr[read] = err
}

func (f *fakeClient) callsFor(device string, read pb.NetDeviceRead) []time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []time.Time
	for _, c := range f.calls {
		if c.device == device && c.read == read {
			out = append(out, c.at)
		}
	}
	return out
}

func (f *fakeClient) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// okResponse builds a valid response for read with payloadMarker in it.
func okResponse(device string, gen uint64, read pb.NetDeviceRead) *pb.ReadNetDeviceResponse {
	r := &pb.ReadNetDeviceResponse{DeviceId: device, TrustGeneration: gen, ObservedAtUnix: pollStart.Unix()}
	switch read {
	case pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION:
		r.Payload = &pb.ReadNetDeviceResponse_CbsVersion{CbsVersion: &pb.NetDevCBSVersion{Model: payloadMarker, Firmware: "3.4.0", Serial: "S1"}}
	case pb.NetDeviceRead_NET_DEVICE_READ_CBS_VLANS:
		r.Payload = &pb.ReadNetDeviceResponse_CbsVlans{CbsVlans: &pb.NetDevVLANs{}}
	case pb.NetDeviceRead_NET_DEVICE_READ_CBS_INTERFACES:
		r.Payload = &pb.ReadNetDeviceResponse_CbsInterfaces{CbsInterfaces: &pb.NetDevPorts{}}
	case pb.NetDeviceRead_NET_DEVICE_READ_CBS_MAC_TABLE:
		r.Payload = &pb.ReadNetDeviceResponse_CbsMacTable{CbsMacTable: &pb.NetDevMACTable{}}
	case pb.NetDeviceRead_NET_DEVICE_READ_CBS_LLDP:
		r.Payload = &pb.ReadNetDeviceResponse_CbsLldp{CbsLldp: &pb.NetDevLLDPNeighbors{}}
	case pb.NetDeviceRead_NET_DEVICE_READ_PANOS_ZONES:
		r.Payload = &pb.ReadNetDeviceResponse_PanosZones{PanosZones: &pb.NetDevZones{}}
	case pb.NetDeviceRead_NET_DEVICE_READ_PANOS_OBJECTS:
		r.Payload = &pb.ReadNetDeviceResponse_PanosObjects{PanosObjects: &pb.NetDevObjects{}}
	case pb.NetDeviceRead_NET_DEVICE_READ_PANOS_SECURITY_RULES:
		r.Payload = &pb.ReadNetDeviceResponse_PanosSecurityRules{PanosSecurityRules: &pb.NetDevSecurityRules{}}
	case pb.NetDeviceRead_NET_DEVICE_READ_PANOS_NAT_RULES:
		r.Payload = &pb.ReadNetDeviceResponse_PanosNatRules{PanosNatRules: &pb.NetDevNATRules{}}
	case pb.NetDeviceRead_NET_DEVICE_READ_PANOS_RULE_HIT_COUNTS:
		r.Payload = &pb.ReadNetDeviceResponse_PanosRuleHitCounts{PanosRuleHitCounts: &pb.NetDevRuleHitCounts{}}
	}
	return r
}

// spooled is one record the fake spool accepted.
type spooled struct {
	device     string
	read       string
	gen        uint64
	incomplete bool
	payload    []byte
}

// fakeSpool records writes in memory.
type fakeSpool struct {
	mu     sync.Mutex
	writes []spooled
	err    error
}

func (s *fakeSpool) Write(_ context.Context, deviceID, read string, gen uint64, incomplete bool, payload []byte) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return "", s.err
	}
	s.writes = append(s.writes, spooled{device: deviceID, read: read, gen: gen, incomplete: incomplete, payload: append([]byte(nil), payload...)})
	return deviceID + "-" + read, nil
}

func (s *fakeSpool) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.writes)
}

func (s *fakeSpool) all() []spooled {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]spooled(nil), s.writes...)
}

func cbsDevice(id string) *pb.NetDeviceInfo {
	return &pb.NetDeviceInfo{DeviceId: id, Family: "cbs", TrustGeneration: 3, CredentialVersion: 1}
}

func panosDevice(id string) *pb.NetDeviceInfo {
	return &pb.NetDeviceInfo{DeviceId: id, Family: "panos", TrustGeneration: 5, CredentialVersion: 2}
}

// constRand returns a Rand that always yields r.
func constRand(r float64) func() float64 { return func() float64 { return r } }

func newTestPoller(c *fakeClient, s SpoolWriter, clock *fakeClock, r func() float64) *Poller {
	return &Poller{Client: c, Spool: s, Now: clock.Now, Rand: r}
}

// cycle runs one cycle and waits for its reads.
func cycle(t *testing.T, p *Poller) CycleReport {
	t.Helper()
	rep, err := p.Cycle(context.Background())
	if err != nil {
		t.Fatalf("Cycle: %v", err)
	}
	p.Wait()
	return rep
}

const (
	cbsVersion = pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION
	cbsVLANs   = pb.NetDeviceRead_NET_DEVICE_READ_CBS_VLANS
)

func TestFirstCycleSpoolsEveryFamilyRead(t *testing.T) {
	clock := newClock()
	c := newFakeClient(clock, cbsDevice("core-sw-01"), panosDevice("edge-fw-01"))
	s := &fakeSpool{}
	p := newTestPoller(c, s, clock, constRand(0.5))
	rep := cycle(t, p)
	if rep.Devices != 2 || rep.Dispatched != 10 || rep.Busy != 0 || rep.Skipped != 0 {
		t.Fatalf("report = %+v", rep)
	}
	got := map[string]bool{}
	for _, w := range s.all() {
		got[w.device+"/"+w.read] = true
		if !json.Valid(w.payload) || (w.payload[0] != '{' && w.payload[0] != '[') {
			t.Fatalf("payload of %s/%s is not a JSON object: %s", w.device, w.read, w.payload)
		}
		wantGen := map[string]uint64{"core-sw-01": 3, "edge-fw-01": 5}[w.device]
		if w.gen != wantGen {
			t.Fatalf("%s trust generation = %d, want %d", w.device, w.gen, wantGen)
		}
	}
	for _, want := range []string{
		"core-sw-01/" + ReadCBSVersion, "core-sw-01/" + ReadCBSVLANs, "core-sw-01/" + ReadCBSInterfaces,
		"core-sw-01/" + ReadCBSMACTable, "core-sw-01/" + ReadCBSLLDP,
		"edge-fw-01/" + ReadPANOSZones, "edge-fw-01/" + ReadPANOSObjects, "edge-fw-01/" + ReadPANOSSecurityRules,
		"edge-fw-01/" + ReadPANOSNATRules, "edge-fw-01/" + ReadPANOSRuleHitCounts,
	} {
		if !got[want] {
			t.Fatalf("missing spool record %s; got %v", want, got)
		}
	}
	if len(got) != 10 {
		t.Fatalf("spooled %d distinct reads, want 10: %v", len(got), got)
	}
}

func TestPayloadIsTheTypedReadAsJSON(t *testing.T) {
	clock := newClock()
	c := newFakeClient(clock, cbsDevice("core-sw-01"))
	s := &fakeSpool{}
	cycle(t, newTestPoller(c, s, clock, constRand(0.5)))
	for _, w := range s.all() {
		if w.read != ReadCBSVersion {
			continue
		}
		var v struct {
			Model string `json:"model"`
		}
		if err := json.Unmarshal(w.payload, &v); err != nil || v.Model != payloadMarker {
			t.Fatalf("cbs_version payload = %s (%v)", w.payload, err)
		}
		return
	}
	t.Fatal("no cbs_version record")
}

func TestIncompleteFlagIsSpooled(t *testing.T) {
	clock := newClock()
	c := newFakeClient(clock, cbsDevice("core-sw-01"))
	c.respond = func(device string, read pb.NetDeviceRead) *pb.ReadNetDeviceResponse {
		r := okResponse(device, 3, read)
		r.Incomplete = read == cbsVLANs
		return r
	}
	s := &fakeSpool{}
	cycle(t, newTestPoller(c, s, clock, constRand(0.5)))
	for _, w := range s.all() {
		if w.incomplete != (w.read == ReadCBSVLANs) {
			t.Fatalf("%s incomplete = %v", w.read, w.incomplete)
		}
	}
}

func TestFloorRespectedAtMinimumJitter(t *testing.T) {
	clock := newClock()
	c := newFakeClient(clock, cbsDevice("core-sw-01"))
	s := &fakeSpool{}
	// Rand 0 is the -20 % edge: a 15 min read would come back at 12 min
	// without the floor.
	p := newTestPoller(c, s, clock, constRand(0))
	cycle(t, p)
	if n := c.callCount(); n != 5 {
		t.Fatalf("first cycle calls = %d, want 5", n)
	}
	for _, d := range []time.Duration{12 * time.Minute, 3*time.Minute - time.Nanosecond} {
		clock.Advance(d)
		if rep := cycle(t, p); rep.Dispatched != 0 {
			t.Fatalf("cycle before the floor dispatched %d reads", rep.Dispatched)
		}
	}
	clock.Advance(time.Nanosecond)
	if rep := cycle(t, p); rep.Dispatched != 4 {
		// The four 15 min reads; cbs_version (60 min, -20 % = 48 min) is not due.
		t.Fatalf("cycle at the floor dispatched %d reads, want 4", rep.Dispatched)
	}
	if got := c.callsFor("core-sw-01", cbsVersion); len(got) != 1 {
		t.Fatalf("cbs_version calls = %d, want 1", len(got))
	}
}

func TestFloorAndJitterHoldOverADay(t *testing.T) {
	clock := newClock()
	c := newFakeClient(clock, cbsDevice("core-sw-01"), panosDevice("edge-fw-01"))
	s := &fakeSpool{}
	src := rand.New(rand.NewPCG(1, 2))
	p := newTestPoller(c, s, clock, src.Float64)
	const tick = 30 * time.Second
	for range int(24 * time.Hour / tick) {
		cycle(t, p)
		clock.Advance(tick)
	}
	for dev, reads := range familyReads {
		id := map[string]string{"cbs": "core-sw-01", "panos": "edge-fw-01"}[dev]
		for _, r := range reads {
			cadence := readCadence[r]
			calls := c.callsFor(id, r)
			if len(calls) < 2 {
				t.Fatalf("%s/%v: only %d calls in a day", id, r, len(calls))
			}
			lo := max(time.Duration(float64(cadence)*0.8), MinReadInterval)
			hi := time.Duration(float64(cadence)*1.2) + tick
			for i := 1; i < len(calls); i++ {
				gap := calls[i].Sub(calls[i-1])
				if gap < MinReadInterval {
					t.Fatalf("%s/%v: gap %v below the %v floor", id, r, gap, MinReadInterval)
				}
				if gap < lo || gap > hi {
					t.Fatalf("%s/%v: gap %v outside [%v, %v]", id, r, gap, lo, hi)
				}
			}
		}
	}
}

func TestJitterBounds(t *testing.T) {
	tests := []struct {
		name    string
		cadence time.Duration
		r       float64
		lo, hi  time.Duration
	}{
		{"60m low edge", time.Hour, 0, 48 * time.Minute, 48 * time.Minute},
		{"60m centre", time.Hour, 0.5, time.Hour, time.Hour},
		{"60m high edge", time.Hour, math.Nextafter(1, 0), 72*time.Minute - time.Microsecond, 72 * time.Minute},
		{"15m low edge clamps to floor", 15 * time.Minute, 0, MinReadInterval, MinReadInterval},
		{"15m high edge", 15 * time.Minute, math.Nextafter(1, 0), 18*time.Minute - time.Microsecond, 18 * time.Minute},
		{"cadence below floor is raised", time.Minute, 0.5, MinReadInterval, MinReadInterval},
		{"NaN is centred", time.Hour, math.NaN(), time.Hour, time.Hour},
		{"1 is centred", time.Hour, 1, time.Hour, time.Hour},
		{"negative is centred", time.Hour, -0.3, time.Hour, time.Hour},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Poller{Rand: constRand(tt.r)}
			got := p.nextDelay(tt.cadence, 0)
			if got < tt.lo || got > tt.hi {
				t.Fatalf("nextDelay(%v) = %v, want in [%v, %v]", tt.cadence, got, tt.lo, tt.hi)
			}
		})
	}
}

func TestBackoffNeverBelowFloorOrAboveCap(t *testing.T) {
	for _, r := range []float64{0, 0.25, 0.5, 0.75, math.Nextafter(1, 0)} {
		p := &Poller{Rand: constRand(r)}
		for _, cadence := range []time.Duration{15 * time.Minute, time.Hour} {
			for n := 1; n <= 100; n++ {
				d := p.nextDelay(cadence, n)
				if d < MinReadInterval || d > DefaultMaxBackoff {
					t.Fatalf("r=%v cadence=%v failures=%d: delay %v outside [%v, %v]", r, cadence, n, d, MinReadInterval, DefaultMaxBackoff)
				}
			}
		}
	}
}

// stateOf returns the schedule entry of one device and read.
func stateOf(t *testing.T, p *Poller, device string, read pb.NetDeviceRead) schedState {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	st, ok := p.sched[schedKey{device: device, read: read}]
	if !ok {
		t.Fatalf("no schedule for %s/%v", device, read)
	}
	return *st
}

func TestExecutorRefusalsBackOffAndReset(t *testing.T) {
	refusals := []struct {
		name string
		err  error
	}{
		{"grpc unimplemented", status.Error(codes.Unimplemented, "not yet "+payloadMarker)},
		{"grpc permission denied", status.Error(codes.PermissionDenied, "no lease")},
		{"grpc failed precondition", status.Error(codes.FailedPrecondition, "vault locked")},
		{"executorclient permission denied", executorclient.ErrPermissionDenied},
		{"executorclient precondition", executorclient.ErrPrecondition},
		{"executorclient lease budget", &executorclient.Error{Code: "lease_budget_exhausted"}},
	}
	for _, tt := range refusals {
		t.Run(tt.name, func(t *testing.T) {
			clock := newClock()
			c := newFakeClient(clock, cbsDevice("core-sw-01"))
			c.setReadErr(cbsVLANs, tt.err)
			s := &fakeSpool{}
			// Rand 0.5 is the jitter centre: delays are exact.
			p := newTestPoller(c, s, clock, constRand(0.5))
			want := []time.Duration{15 * time.Minute, 30 * time.Minute, time.Hour, time.Hour, time.Hour}
			for i, d := range want {
				start := clock.Now()
				rep, err := p.Cycle(context.Background())
				if err != nil {
					t.Fatalf("Cycle after %d refusals: %v", i, err)
				}
				p.Wait()
				if rep.Dispatched == 0 {
					t.Fatalf("refused read was not retried when due (step %d)", i)
				}
				st := stateOf(t, p, "core-sw-01", cbsVLANs)
				if st.failures != i+1 || st.next.Sub(start) != d {
					t.Fatalf("after %d refusals: failures=%d delay=%v, want %d, %v", i+1, st.failures, st.next.Sub(start), i+1, d)
				}
				clock.Advance(d - time.Nanosecond)
				cycle(t, p)
				if n := len(c.callsFor("core-sw-01", cbsVLANs)); n != i+1 {
					t.Fatalf("read retried during backoff: %d calls after %d refusals", n, i+1)
				}
				clock.Advance(time.Nanosecond)
			}
			// The other reads of the device kept working meanwhile.
			for _, w := range s.all() {
				if w.read == ReadCBSVLANs {
					t.Fatal("a refused read was spooled")
				}
			}
			if s.count() == 0 {
				t.Fatal("no other read was spooled")
			}
			// Success resets the backoff to the cadence.
			c.setReadErr(cbsVLANs, nil)
			start := clock.Now()
			cycle(t, p)
			st := stateOf(t, p, "core-sw-01", cbsVLANs)
			if st.failures != 0 || st.next.Sub(start) != 15*time.Minute {
				t.Fatalf("after success: failures=%d delay=%v, want 0, 15m", st.failures, st.next.Sub(start))
			}
		})
	}
}

func TestCustomMaxBackoffCapsGrowth(t *testing.T) {
	p := &Poller{Rand: constRand(0.5), MaxBackoff: 20 * time.Minute}
	for n, want := range map[int]time.Duration{1: 15 * time.Minute, 2: 20 * time.Minute, 10: 20 * time.Minute} {
		if got := p.nextDelay(15*time.Minute, n); got != want {
			t.Fatalf("failures=%d: delay %v, want %v", n, got, want)
		}
	}
	// A cap below the floor cannot lower the floor.
	p.MaxBackoff = time.Minute
	if got := p.nextDelay(15*time.Minute, 5); got != MinReadInterval {
		t.Fatalf("cap below floor: delay %v, want %v", got, MinReadInterval)
	}
}

func TestOneRequestInFlightPerDevice(t *testing.T) {
	clock := newClock()
	devs := []*pb.NetDeviceInfo{cbsDevice("sw-a"), cbsDevice("sw-b"), panosDevice("fw-a")}
	c := newFakeClient(clock, devs...)
	c.block = make(chan struct{})
	c.started = make(chan string, 1024)
	s := &fakeSpool{}
	p := newTestPoller(c, s, clock, rand.New(rand.NewPCG(3, 4)).Float64)
	p.MaxConcurrentDevices = 8

	// Many concurrent cycles while every read of every device is due.
	var wg sync.WaitGroup
	var busyMu sync.Mutex
	busy := 0
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 10 {
				clock.Advance(2 * time.Hour)
				rep, err := p.Cycle(context.Background())
				if err != nil {
					t.Errorf("Cycle: %v", err)
					return
				}
				busyMu.Lock()
				busy += rep.Busy
				busyMu.Unlock()
			}
		}()
	}
	wg.Wait()
	// One read per device has started; the rest are queued behind it.
	for range devs {
		<-c.started
	}
	close(c.block)
	p.Wait()
	for _, d := range devs {
		if m := c.maxInflight[d.DeviceId]; m != 1 {
			t.Fatalf("device %s had %d reads in flight at once", d.DeviceId, m)
		}
	}
	if busy == 0 {
		t.Fatal("no cycle found a device busy; the test did not exercise contention")
	}
	if c.totalMax < 2 {
		t.Fatalf("devices were not read in parallel (max %d in flight overall)", c.totalMax)
	}
}

func TestMaxConcurrentDevicesBoundsParallelism(t *testing.T) {
	clock := newClock()
	c := newFakeClient(clock, cbsDevice("sw-a"), cbsDevice("sw-b"), cbsDevice("sw-c"))
	c.block = make(chan struct{})
	c.started = make(chan string, 64)
	p := newTestPoller(c, &fakeSpool{}, clock, constRand(0.5))
	p.MaxConcurrentDevices = 1
	if _, err := p.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	<-c.started
	close(c.block)
	p.Wait()
	if c.totalMax != 1 {
		t.Fatalf("max reads in flight = %d, want 1", c.totalMax)
	}
}

func TestRunShutdownDrainsInFlightRead(t *testing.T) {
	clock := newClock()
	c := newFakeClient(clock, cbsDevice("core-sw-01"))
	c.block = make(chan struct{})
	c.started = make(chan string, 16)
	s := &fakeSpool{}
	p := newTestPoller(c, s, clock, constRand(0.5))
	p.Interval = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()
	<-c.started
	cancel()
	select {
	case err := <-done:
		t.Fatalf("Run returned %v before the in-flight read finished", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(c.block)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after the in-flight read finished")
	}
	// The started read completed and was spooled; no new read began.
	if n := c.callCount(); n != 1 {
		t.Fatalf("calls = %d, want 1 (no new read after shutdown)", n)
	}
	if n := s.count(); n != 1 {
		t.Fatalf("spooled = %d, want the drained read", n)
	}
}

func TestRunKeepsPollingAndSurvivesListErrors(t *testing.T) {
	clock := newClock()
	c := newFakeClient(clock, cbsDevice("core-sw-01"))
	c.listErr = status.Error(codes.Unavailable, "down")
	c.started = make(chan string, 64)
	s := &fakeSpool{}
	p := newTestPoller(c, s, clock, constRand(0.5))
	p.Interval = time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()
	time.Sleep(20 * time.Millisecond)
	c.mu.Lock()
	c.listErr = nil
	c.mu.Unlock()
	<-c.started
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
}

func TestUnusableDevicesAreNotRead(t *testing.T) {
	clock := newClock()
	blocked := cbsDevice("blocked-sw")
	blocked.Blocked = true
	missing := cbsDevice("missing-cred")
	missing.CredentialMissing = true
	noCred := cbsDevice("no-cred")
	noCred.CredentialVersion = 0
	badID := cbsDevice("Bad_ID")
	pfsense := cbsDevice("pf-01")
	pfsense.Family = "pfsense"
	noGen := cbsDevice("no-gen")
	noGen.TrustGeneration = 0
	hugeGen := cbsDevice("huge-gen")
	hugeGen.TrustGeneration = math.MaxUint64
	c := newFakeClient(clock, blocked, missing, noCred, badID, pfsense, noGen, hugeGen, nil)
	p := newTestPoller(c, &fakeSpool{}, clock, constRand(0.5))
	rep := cycle(t, p)
	if rep.Dispatched != 0 || rep.Skipped != 8 {
		t.Fatalf("report = %+v, want 8 skipped, none dispatched", rep)
	}
	if n := c.callCount(); n != 0 {
		t.Fatalf("unusable devices got %d reads", n)
	}
}

func TestDuplicateDeviceIsReadOnce(t *testing.T) {
	clock := newClock()
	c := newFakeClient(clock, cbsDevice("core-sw-01"), cbsDevice("core-sw-01"))
	p := newTestPoller(c, &fakeSpool{}, clock, constRand(0.5))
	rep := cycle(t, p)
	if rep.Dispatched != 5 || rep.Skipped != 1 || c.callCount() != 5 {
		t.Fatalf("report = %+v, calls = %d", rep, c.callCount())
	}
}

func TestBadResponsesAreNotSpooled(t *testing.T) {
	tests := []struct {
		name    string
		respond func(device string, read pb.NetDeviceRead) *pb.ReadNetDeviceResponse
	}{
		{"nil response", func(string, pb.NetDeviceRead) *pb.ReadNetDeviceResponse { return nil }},
		{"other device", func(_ string, read pb.NetDeviceRead) *pb.ReadNetDeviceResponse {
			return okResponse("other-sw", 3, read)
		}},
		{"other trust generation", func(device string, read pb.NetDeviceRead) *pb.ReadNetDeviceResponse {
			return okResponse(device, 4, read)
		}},
		{"payload of another read", func(device string, _ pb.NetDeviceRead) *pb.ReadNetDeviceResponse {
			return okResponse(device, 3, pb.NetDeviceRead_NET_DEVICE_READ_PANOS_ZONES)
		}},
		{"no payload", func(device string, _ pb.NetDeviceRead) *pb.ReadNetDeviceResponse {
			return &pb.ReadNetDeviceResponse{DeviceId: device, TrustGeneration: 3}
		}},
		{"nil payload message", func(device string, _ pb.NetDeviceRead) *pb.ReadNetDeviceResponse {
			return &pb.ReadNetDeviceResponse{DeviceId: device, TrustGeneration: 3, Payload: &pb.ReadNetDeviceResponse_CbsVlans{}}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock := newClock()
			c := newFakeClient(clock, cbsDevice("core-sw-01"))
			c.respond = tt.respond
			s := &fakeSpool{}
			p := newTestPoller(c, s, clock, constRand(0.5))
			cycle(t, p)
			if n := s.count(); n != 0 {
				t.Fatalf("spooled %d bad responses", n)
			}
			if st := stateOf(t, p, "core-sw-01", cbsVLANs); st.failures != 1 {
				t.Fatalf("failures = %d, want 1 (backoff)", st.failures)
			}
		})
	}
}

func TestSpoolFailureBacksOff(t *testing.T) {
	clock := newClock()
	c := newFakeClient(clock, cbsDevice("core-sw-01"))
	s := &fakeSpool{err: ErrOversize}
	p := newTestPoller(c, s, clock, constRand(0.5))
	cycle(t, p)
	if st := stateOf(t, p, "core-sw-01", cbsVLANs); st.failures != 1 {
		t.Fatalf("failures = %d, want 1", st.failures)
	}
}

func TestListErrorsAreReported(t *testing.T) {
	clock := newClock()
	c := newFakeClient(clock)
	c.listErr = status.Error(codes.PermissionDenied, "role")
	p := newTestPoller(c, &fakeSpool{}, clock, constRand(0.5))
	if _, err := p.Cycle(context.Background()); err == nil {
		t.Fatal("Cycle accepted a list error")
	}
	c.listErr = nil
	c.devices = make([]*pb.NetDeviceInfo, MaxDevices+1)
	for i := range c.devices {
		c.devices[i] = cbsDevice("sw")
	}
	if _, err := p.Cycle(context.Background()); !errors.Is(err, ErrTooManyDevices) {
		t.Fatalf("Cycle over the device limit = %v, want ErrTooManyDevices", err)
	}
	if n := c.callCount(); n != 0 {
		t.Fatalf("reads after an oversized list: %d", n)
	}
}

// schedCount counts the schedule entries of device.
func schedCount(p *Poller, device string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for k := range p.sched {
		if k.device == device {
			n++
		}
	}
	return n
}

func TestRemovedDevicesArePruned(t *testing.T) {
	// A removed device's schedule survives the grace period (absent for
	// up to the backoff cap), then it is dropped; its slot goes at once.
	clock := newClock()
	c := newFakeClient(clock, cbsDevice("core-sw-01"), cbsDevice("old-sw"))
	p := newTestPoller(c, &fakeSpool{}, clock, constRand(0.5))
	cycle(t, p)
	reads := len(familyReads["cbs"])
	c.mu.Lock()
	c.devices = c.devices[:1]
	c.mu.Unlock()
	cycle(t, p)
	if n := schedCount(p, "old-sw"); n != reads {
		t.Fatalf("removed device has %d schedules right after removal, want %d kept", n, reads)
	}
	p.mu.Lock()
	_, slot := p.slots["old-sw"]
	p.mu.Unlock()
	if slot {
		t.Fatal("device slot of a removed device was kept")
	}
	clock.Advance(DefaultMaxBackoff)
	cycle(t, p)
	if n := schedCount(p, "old-sw"); n != reads {
		t.Fatalf("removed device has %d schedules at the end of the grace period, want %d", n, reads)
	}
	clock.Advance(time.Nanosecond)
	cycle(t, p)
	if n := schedCount(p, "old-sw"); n != 0 {
		t.Fatalf("schedule of a removed device was kept after the grace period: %d entries", n)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.absent["old-sw"]; ok {
		t.Fatal("absence record of a pruned device was kept")
	}
}

func TestUnlistedThenRelistedDeviceKeepsSchedule(t *testing.T) {
	// A device missing from one device list (partial list, or removed
	// and re-added) must keep its 15 min floor and its running backoff.
	clock := newClock()
	d := cbsDevice("core-sw-01")
	c := newFakeClient(clock, d)
	c.setReadErr(cbsVLANs, status.Error(codes.Unavailable, "down"))
	p := newTestPoller(c, &fakeSpool{}, clock, constRand(0.5))
	cycle(t, p)                     // failure 1, retry in 15m
	clock.Advance(15 * time.Minute) // due again
	cycle(t, p)                     // failure 2, retry in 30m
	before := stateOf(t, p, "core-sw-01", cbsVLANs)
	if before.failures != 2 {
		t.Fatalf("setup: failures=%d, want 2", before.failures)
	}
	calls := c.callCount()

	setDevices := func(ds ...*pb.NetDeviceInfo) {
		c.mu.Lock()
		c.devices = ds
		c.mu.Unlock()
	}
	setDevices()
	clock.Advance(time.Minute)
	cycle(t, p)
	setDevices(d)
	clock.Advance(time.Minute)
	if rep := cycle(t, p); rep.Dispatched != 0 {
		t.Fatalf("relisted device was read %d times before its floor or backoff", rep.Dispatched)
	}
	if c.callCount() != calls {
		t.Fatalf("relisted device got %d reads before its schedule", c.callCount()-calls)
	}
	after := stateOf(t, p, "core-sw-01", cbsVLANs)
	if after != before {
		t.Fatalf("schedule changed across the unlisted cycle: %+v, want %+v", after, before)
	}
	// The backoff keeps growing from where it was.
	clock.Advance(before.next.Sub(clock.Now()))
	start := clock.Now()
	cycle(t, p)
	st := stateOf(t, p, "core-sw-01", cbsVLANs)
	if st.failures != 3 || st.next.Sub(start) != time.Hour {
		t.Fatalf("after relist: failures=%d delay=%v, want 3, 1h", st.failures, st.next.Sub(start))
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.absent) != 0 {
		t.Fatalf("relisted device still recorded as absent: %v", p.absent)
	}
}

func TestAbsentDeviceStateIsBounded(t *testing.T) {
	// Schedules of unlisted devices are kept for the grace period, but
	// never for more than maxAbsentDevices devices; the longest absent go
	// first.
	clock := newClock()
	c := newFakeClient(clock, cbsDevice("core-sw-01"))
	p := newTestPoller(c, &fakeSpool{}, clock, constRand(0.5))
	cycle(t, p)
	far := clock.Now().Add(24 * time.Hour)
	p.mu.Lock()
	p.sched[schedKey{device: "oldest", read: cbsVLANs}] = &schedState{next: far}
	p.absent["oldest"] = clock.Now().Add(-time.Minute)
	for i := range maxAbsentDevices {
		p.sched[schedKey{device: fmt.Sprintf("gone-%04d", i), read: cbsVLANs}] = &schedState{next: far}
	}
	p.mu.Unlock()
	clock.Advance(time.Minute)
	cycle(t, p)
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.absent) != maxAbsentDevices {
		t.Fatalf("%d absent devices tracked, want %d", len(p.absent), maxAbsentDevices)
	}
	if _, ok := p.sched[schedKey{device: "oldest", read: cbsVLANs}]; ok {
		t.Fatal("longest absent device was not evicted over the bound")
	}
	if _, ok := p.absent["oldest"]; ok {
		t.Fatal("absence record of the evicted device was kept")
	}
	if len(p.sched) != maxAbsentDevices+len(familyReads["cbs"]) {
		t.Fatalf("%d schedules, want %d", len(p.sched), maxAbsentDevices+len(familyReads["cbs"]))
	}
}

func TestBlockedDeviceKeepsItsSchedule(t *testing.T) {
	// Blocking and unblocking a device must not reset its floor.
	clock := newClock()
	d := cbsDevice("core-sw-01")
	c := newFakeClient(clock, d)
	p := newTestPoller(c, &fakeSpool{}, clock, constRand(0.5))
	cycle(t, p)
	c.mu.Lock()
	c.devices = []*pb.NetDeviceInfo{{DeviceId: "core-sw-01", Family: "cbs", TrustGeneration: 3, CredentialVersion: 1, Blocked: true}}
	c.mu.Unlock()
	clock.Advance(time.Minute)
	cycle(t, p)
	c.mu.Lock()
	c.devices = []*pb.NetDeviceInfo{d}
	c.mu.Unlock()
	clock.Advance(time.Minute)
	if rep := cycle(t, p); rep.Dispatched != 0 {
		t.Fatalf("unblocked device was read %d times before its floor", rep.Dispatched)
	}
}

func TestLogsNeverContainPayloadsOrDetails(t *testing.T) {
	clock := newClock()
	c := newFakeClient(clock, cbsDevice("core-sw-01"))
	c.setReadErr(cbsVLANs, status.Error(codes.Unimplemented, "detail "+payloadMarker))
	c.setReadErr(pb.NetDeviceRead_NET_DEVICE_READ_CBS_LLDP, &executorclient.Error{Code: "permission_denied", Detail: payloadMarker})
	var buf bytes.Buffer
	p := newTestPoller(c, &fakeSpool{}, clock, constRand(0.5))
	p.Log = slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cycle(t, p)
	c.mu.Lock()
	c.listErr = status.Error(codes.Internal, payloadMarker)
	c.mu.Unlock()
	p.Interval = time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := p.Run(ctx); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if out == "" {
		t.Fatal("no log output; the test checks nothing")
	}
	if strings.Contains(out, payloadMarker) {
		t.Fatalf("log contains device output or executor detail:\n%s", out)
	}
	if !strings.Contains(out, `"code":"grpc:Unimplemented"`) || !strings.Contains(out, `"code":"executor:permission_denied"`) {
		t.Fatalf("log lacks the failure codes:\n%s", out)
	}
}

func TestPollerRequiresItsDependencies(t *testing.T) {
	clock := newClock()
	c := newFakeClient(clock)
	full := Poller{Client: c, Spool: &fakeSpool{}, Now: clock.Now, Rand: constRand(0.5)}
	for name, p := range map[string]*Poller{
		"client": {Spool: full.Spool, Now: full.Now, Rand: full.Rand},
		"spool":  {Client: c, Now: full.Now, Rand: full.Rand},
		"now":    {Client: c, Spool: full.Spool, Rand: full.Rand},
		"rand":   {Client: c, Spool: full.Spool, Now: full.Now},
	} {
		if _, err := p.Cycle(context.Background()); !errors.Is(err, ErrNotConfigured) {
			t.Fatalf("missing %s: Cycle = %v, want ErrNotConfigured", name, err)
		}
		if err := p.Run(context.Background()); !errors.Is(err, ErrNotConfigured) {
			t.Fatalf("missing %s: Run = %v, want ErrNotConfigured", name, err)
		}
	}
}

func TestPollerWritesToTheRealSpool(t *testing.T) {
	clock := newClock()
	c := newFakeClient(clock, cbsDevice("core-sw-01"))
	s := newSpool(t)
	p := newTestPoller(c, s, clock, constRand(0.5))
	cycle(t, p)
	names, err := s.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 5 {
		t.Fatalf("spool has %d files, want 5: %v", len(names), names)
	}
	for _, name := range names {
		taken, err := s.Take(context.Background(), name)
		if err != nil {
			t.Fatalf("Take %s: %v", name, err)
		}
		if taken.Record.DeviceID != "core-sw-01" || taken.Record.TrustGeneration != 3 {
			t.Fatalf("record = %+v", taken.Record)
		}
	}
}
