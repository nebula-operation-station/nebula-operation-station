// SPDX-License-Identifier: AGPL-3.0-or-later

package netdevcollect

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executorclient"
	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Scheduling limits (ADR 0010 D4: the 15-minute floor of ADR 0007 ordinary
// reads, jitter, exponential backoff; one request per device at a time).
const (
	// MinReadInterval is the floor between two starts of the same read of
	// the same device. No cadence, jitter or backoff schedules below it.
	MinReadInterval = 15 * time.Minute
	// DefaultMaxBackoff caps the backoff after failed reads.
	DefaultMaxBackoff = time.Hour
	// DefaultInterval is how often Run looks for due reads.
	DefaultInterval = time.Minute
	// DefaultReadTimeout bounds one read including its spool write. It
	// covers the executor's device budget (10 s connect, 60 s request).
	DefaultReadTimeout = 90 * time.Second
	// DefaultMaxConcurrentDevices bounds how many devices are read at once.
	DefaultMaxConcurrentDevices = 4
	// maxConcurrentDevicesCap bounds MaxConcurrentDevices.
	maxConcurrentDevicesCap = 32
	// MaxDevices bounds the device list the collector accepts per cycle.
	MaxDevices = 1024
	// jitterFraction spreads every delay by ±20 %.
	jitterFraction = 0.2
	// maxTrackedFailures bounds the failure counter; the backoff is capped
	// long before.
	maxTrackedFailures = 64
	// maxAbsentDevices bounds how many unlisted devices keep their
	// schedule during the grace period; the longest absent go first.
	maxAbsentDevices = MaxDevices
)

// Sentinel errors of the poll loop.
var (
	// ErrNotConfigured means a Poller lacks Client, Spool, Now or Rand.
	ErrNotConfigured = errors.New("netdevcollect: poller is not configured")
	// ErrTooManyDevices means the executor listed more than MaxDevices.
	ErrTooManyDevices = errors.New("netdevcollect: device list over the limit")
	// ErrBadResponse means a read response does not match its request.
	ErrBadResponse = errors.New("netdevcollect: read response does not match the request")
)

// errSpoolWrite marks a failed spool write for log classification.
var errSpoolWrite = errors.New("netdevcollect: spool write failed")

// Client is the executor surface the collector uses: the typed netdev
// wrappers of internal/executorclient (netdev.go). The collector has no
// other way to reach a device: no network, no credential, no database.
type Client interface {
	ListNetDeviceInfos(ctx context.Context) ([]*pb.NetDeviceInfo, error)
	ReadNetDeviceByID(ctx context.Context, deviceID string, read pb.NetDeviceRead) (*pb.ReadNetDeviceResponse, error)
}

// SpoolWriter publishes one read result; *Spool implements it.
type SpoolWriter interface {
	Write(ctx context.Context, deviceID, read string, trustGeneration uint64, incomplete bool, payload []byte) (string, error)
}

// readCadence is the default cadence of each typed read (ADR 0010 D4 data
// and cadence table). MinReadInterval raises anything below the floor.
var readCadence = map[pb.NetDeviceRead]time.Duration{
	pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION:           time.Hour,
	pb.NetDeviceRead_NET_DEVICE_READ_CBS_VLANS:             15 * time.Minute,
	pb.NetDeviceRead_NET_DEVICE_READ_CBS_INTERFACES:        15 * time.Minute,
	pb.NetDeviceRead_NET_DEVICE_READ_CBS_MAC_TABLE:         15 * time.Minute,
	pb.NetDeviceRead_NET_DEVICE_READ_CBS_LLDP:              15 * time.Minute,
	pb.NetDeviceRead_NET_DEVICE_READ_PANOS_ZONES:           time.Hour,
	pb.NetDeviceRead_NET_DEVICE_READ_PANOS_OBJECTS:         time.Hour,
	pb.NetDeviceRead_NET_DEVICE_READ_PANOS_SECURITY_RULES:  time.Hour,
	pb.NetDeviceRead_NET_DEVICE_READ_PANOS_NAT_RULES:       time.Hour,
	pb.NetDeviceRead_NET_DEVICE_READ_PANOS_RULE_HIT_COUNTS: time.Hour,
}

// familyReads is the closed set of reads per device family. The executor
// decides per read whether a device read lease covers it; a read without
// one is refused and backs off.
var familyReads = map[string][]pb.NetDeviceRead{
	string(netdevcontract.FamilyCBS): {
		pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION,
		pb.NetDeviceRead_NET_DEVICE_READ_CBS_VLANS,
		pb.NetDeviceRead_NET_DEVICE_READ_CBS_INTERFACES,
		pb.NetDeviceRead_NET_DEVICE_READ_CBS_MAC_TABLE,
		pb.NetDeviceRead_NET_DEVICE_READ_CBS_LLDP,
	},
	string(netdevcontract.FamilyPANOS): {
		pb.NetDeviceRead_NET_DEVICE_READ_PANOS_ZONES,
		pb.NetDeviceRead_NET_DEVICE_READ_PANOS_OBJECTS,
		pb.NetDeviceRead_NET_DEVICE_READ_PANOS_SECURITY_RULES,
		pb.NetDeviceRead_NET_DEVICE_READ_PANOS_NAT_RULES,
		pb.NetDeviceRead_NET_DEVICE_READ_PANOS_RULE_HIT_COUNTS,
	},
}

// spoolReadName maps a typed read to its spool read name.
var spoolReadName = map[pb.NetDeviceRead]string{
	pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION:           ReadCBSVersion,
	pb.NetDeviceRead_NET_DEVICE_READ_CBS_VLANS:             ReadCBSVLANs,
	pb.NetDeviceRead_NET_DEVICE_READ_CBS_INTERFACES:        ReadCBSInterfaces,
	pb.NetDeviceRead_NET_DEVICE_READ_CBS_MAC_TABLE:         ReadCBSMACTable,
	pb.NetDeviceRead_NET_DEVICE_READ_CBS_LLDP:              ReadCBSLLDP,
	pb.NetDeviceRead_NET_DEVICE_READ_PANOS_ZONES:           ReadPANOSZones,
	pb.NetDeviceRead_NET_DEVICE_READ_PANOS_OBJECTS:         ReadPANOSObjects,
	pb.NetDeviceRead_NET_DEVICE_READ_PANOS_SECURITY_RULES:  ReadPANOSSecurityRules,
	pb.NetDeviceRead_NET_DEVICE_READ_PANOS_NAT_RULES:       ReadPANOSNATRules,
	pb.NetDeviceRead_NET_DEVICE_READ_PANOS_RULE_HIT_COUNTS: ReadPANOSRuleHitCounts,
}

// CycleReport summarizes one Cycle.
type CycleReport struct {
	// Devices is the number of devices the executor listed.
	Devices int
	// Skipped counts listed devices that are not read: malformed,
	// duplicate, blocked, of an unknown family or without a credential.
	Skipped int
	// Busy counts devices with due reads that still had a read in flight.
	Busy int
	// Dispatched is the number of reads handed to device workers.
	Dispatched int
}

// Poller schedules typed reads over the executor socket and spools the
// results. Client, Spool, Now and Rand are required; Now and Rand are
// injected so tests control time and jitter. Rand returns a value in
// [0, 1); anything else counts as 0.5. A Poller must not be copied after
// first use. Cycle may run concurrently with itself; Wait must not run
// concurrently with Cycle.
type Poller struct {
	Client Client
	Spool  SpoolWriter
	Now    func() time.Time
	Rand   func() float64
	// Log receives one line per failure and cycle; never a payload or an
	// executor error detail. Nil discards.
	Log *slog.Logger
	// Interval is how often Run starts a cycle (default DefaultInterval).
	Interval time.Duration
	// MaxBackoff caps the backoff (default DefaultMaxBackoff, never below
	// MinReadInterval).
	MaxBackoff time.Duration
	// ReadTimeout bounds one read (default DefaultReadTimeout).
	ReadTimeout time.Duration
	// MaxConcurrentDevices bounds devices read at once (default
	// DefaultMaxConcurrentDevices).
	MaxConcurrentDevices int

	mu    sync.Mutex
	sched map[schedKey]*schedState
	// absent records since when a device with schedule state has been
	// missing from the device list.
	absent map[string]time.Time
	// slots holds one mutex per device; a device worker holds it for its
	// whole run, so at most one request per device is in flight.
	slots map[string]*sync.Mutex
	sem   chan struct{}
	wg    sync.WaitGroup
}

// schedKey identifies one read of one device.
type schedKey struct {
	device string
	read   pb.NetDeviceRead
}

// schedState is the schedule of one read of one device.
type schedState struct {
	next     time.Time
	failures int
}

// device is a listed device that may be read.
type device struct {
	id     string
	family string
	gen    uint64
}

func (p *Poller) check() error {
	if p.Client == nil || p.Spool == nil || p.Now == nil || p.Rand == nil {
		return ErrNotConfigured
	}
	return nil
}

// init sets up the internal state; callers hold p.mu.
func (p *Poller) init() {
	if p.sched != nil {
		return
	}
	p.sched = map[schedKey]*schedState{}
	p.absent = map[string]time.Time{}
	p.slots = map[string]*sync.Mutex{}
	n := p.MaxConcurrentDevices
	if n <= 0 {
		n = DefaultMaxConcurrentDevices
	}
	p.sem = make(chan struct{}, min(n, maxConcurrentDevicesCap))
}

func (p *Poller) log() *slog.Logger {
	if p.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return p.Log
}

// Run starts a cycle every Interval until ctx is done. Then it starts no
// new read, waits for the reads in flight to finish and be spooled, and
// returns nil. A failed cycle is logged and retried at the next tick.
func (p *Poller) Run(ctx context.Context) error {
	if err := p.check(); err != nil {
		return err
	}
	interval := p.Interval
	if interval <= 0 {
		interval = DefaultInterval
	}
	defer p.Wait()
	t := time.NewTimer(0)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
		rep, err := p.Cycle(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			p.log().Warn("netdev cycle failed", "code", errClass(err))
		} else if rep.Dispatched > 0 || rep.Busy > 0 {
			p.log().Info("netdev cycle", "devices", rep.Devices, "skipped", rep.Skipped, "busy", rep.Busy, "dispatched", rep.Dispatched)
		}
		t.Reset(interval)
	}
}

// Wait blocks until every dispatched read has finished.
func (p *Poller) Wait() { p.wg.Wait() }

// Cycle lists the devices and hands each device's due reads to a device
// worker, unless that device still has a read in flight. It returns once
// the work is dispatched; Wait waits for it.
func (p *Poller) Cycle(ctx context.Context) (CycleReport, error) {
	if err := p.check(); err != nil {
		return CycleReport{}, err
	}
	if err := ctx.Err(); err != nil {
		return CycleReport{}, err
	}
	infos, err := p.Client.ListNetDeviceInfos(ctx)
	if err != nil {
		return CycleReport{}, fmt.Errorf("netdevcollect: list devices: %w", err)
	}
	if len(infos) > MaxDevices {
		return CycleReport{}, fmt.Errorf("%w: %d devices, limit %d", ErrTooManyDevices, len(infos), MaxDevices)
	}
	now := p.Now()
	rep := CycleReport{Devices: len(infos)}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.init()
	listed := make(map[string]bool, len(infos))
	for _, info := range infos {
		id := info.GetDeviceId()
		if !netdevcontract.ValidDeviceID(id) || listed[id] {
			rep.Skipped++
			continue
		}
		// A listed but unusable (e.g. blocked) device keeps its schedule.
		listed[id] = true
		dev, ok := usable(info)
		if !ok {
			rep.Skipped++
			continue
		}
		due := p.dueReads(dev, now)
		if len(due) == 0 {
			continue
		}
		slot := p.slots[dev.id]
		if slot == nil {
			slot = &sync.Mutex{}
			p.slots[dev.id] = slot
		}
		if !slot.TryLock() {
			rep.Busy++
			continue
		}
		rep.Dispatched += len(due)
		p.wg.Add(1)
		go p.runDevice(ctx, slot, dev, due)
	}
	p.prune(listed, now)
	return rep, nil
}

// usable reports whether a listed device may be read and returns it.
func usable(info *pb.NetDeviceInfo) (device, bool) {
	d := device{id: info.GetDeviceId(), family: info.GetFamily(), gen: info.GetTrustGeneration()}
	switch {
	case info.GetBlocked(), info.GetCredentialMissing(), info.GetCredentialVersion() <= 0:
		return device{}, false
	case d.gen < 1 || d.gen > netdevcontract.MaxTrustGeneration:
		return device{}, false
	case familyReads[d.family] == nil:
		return device{}, false
	}
	return d, true
}

// dueReads returns the reads of dev due at now; callers hold p.mu.
func (p *Poller) dueReads(dev device, now time.Time) []pb.NetDeviceRead {
	var due []pb.NetDeviceRead
	for _, r := range familyReads[dev.family] {
		st := p.sched[schedKey{device: dev.id, read: r}]
		if st == nil || !now.Before(st.next) {
			due = append(due, r)
		}
	}
	return due
}

// prune drops the state of devices the executor no longer lists. The
// schedule of an unlisted device is kept until the device has been absent
// for longer than the backoff cap and the read is due, so a device that
// drops out of one list (a partial list, or removed and re-added) keeps
// its floor and any running backoff. At most maxAbsentDevices unlisted
// devices keep state; beyond that the longest absent are dropped. A slot
// is only dropped while no worker holds it, so a device never gets two.
// Callers hold p.mu.
func (p *Poller) prune(listed map[string]bool, now time.Time) {
	for id := range listed {
		delete(p.absent, id)
	}
	grace := p.maxBackoff()
	kept := map[string]bool{}
	for k, st := range p.sched {
		if listed[k.device] {
			continue
		}
		since, ok := p.absent[k.device]
		if !ok {
			since = now
			p.absent[k.device] = now
		}
		if now.Sub(since) <= grace || now.Before(st.next) {
			kept[k.device] = true
			continue
		}
		delete(p.sched, k)
	}
	for id := range p.absent {
		if !kept[id] {
			delete(p.absent, id)
		}
	}
	if over := len(p.absent) - maxAbsentDevices; over > 0 {
		ids := make([]string, 0, len(p.absent))
		for id := range p.absent {
			ids = append(ids, id)
		}
		slices.SortFunc(ids, func(a, b string) int {
			if c := p.absent[a].Compare(p.absent[b]); c != 0 {
				return c
			}
			return strings.Compare(a, b)
		})
		evict := make(map[string]bool, over)
		for _, id := range ids[:over] {
			evict[id] = true
			delete(p.absent, id)
		}
		for k := range p.sched {
			if evict[k.device] {
				delete(p.sched, k)
			}
		}
	}
	for id, slot := range p.slots {
		if !listed[id] && slot.TryLock() {
			delete(p.slots, id)
			slot.Unlock()
		}
	}
}

// runDevice reads one device's due reads one after another while holding
// the device slot. After ctx is done it starts no further read.
func (p *Poller) runDevice(ctx context.Context, slot *sync.Mutex, dev device, reads []pb.NetDeviceRead) {
	defer p.wg.Done()
	defer slot.Unlock()
	select {
	case p.sem <- struct{}{}:
	case <-ctx.Done():
		return
	}
	defer func() { <-p.sem }()
	for _, r := range reads {
		if ctx.Err() != nil {
			return
		}
		p.readOne(ctx, dev, r)
	}
}

// readOne runs and spools one read and reschedules it. A read that has
// started is finished even during shutdown, bounded by ReadTimeout.
func (p *Poller) readOne(ctx context.Context, dev device, read pb.NetDeviceRead) {
	timeout := p.ReadTimeout
	if timeout <= 0 {
		timeout = DefaultReadTimeout
	}
	start := p.Now()
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()
	err := p.fetch(rctx, dev, read)

	k := schedKey{device: dev.id, read: read}
	p.mu.Lock()
	st := p.sched[k]
	if st == nil {
		st = &schedState{}
		p.sched[k] = st
	}
	if err == nil {
		st.failures = 0
	} else if st.failures < maxTrackedFailures {
		st.failures++
	}
	delay := p.nextDelay(readCadence[read], st.failures)
	st.next = start.Add(delay)
	failures := st.failures
	p.mu.Unlock()

	if err != nil {
		p.log().Warn("netdev read failed", "device", dev.id, "read", spoolReadName[read],
			"code", errClass(err), "failures", failures, "retry_in", delay.String())
		return
	}
	p.log().Debug("netdev read spooled", "device", dev.id, "read", spoolReadName[read])
}

// fetch runs one read, checks the response against the request and
// spools the typed payload as JSON.
func (p *Poller) fetch(ctx context.Context, dev device, read pb.NetDeviceRead) error {
	resp, err := p.Client.ReadNetDeviceByID(ctx, dev.id, read)
	if err != nil {
		return err
	}
	if resp == nil || resp.GetDeviceId() != dev.id || resp.GetTrustGeneration() != dev.gen {
		return ErrBadResponse
	}
	msg := payloadFor(resp, read)
	if msg == nil {
		return ErrBadResponse
	}
	payload, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(msg)
	if err != nil {
		return fmt.Errorf("%w: encode payload", ErrBadResponse)
	}
	if _, err := p.Spool.Write(ctx, dev.id, spoolReadName[read], dev.gen, resp.GetIncomplete(), payload); err != nil {
		return fmt.Errorf("%w: %w", errSpoolWrite, err)
	}
	return nil
}

// payloadFor returns the payload of resp if it is the one read asked for.
func payloadFor(resp *pb.ReadNetDeviceResponse, read pb.NetDeviceRead) proto.Message {
	var m proto.Message
	switch read {
	case pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION:
		if v := resp.GetCbsVersion(); v != nil {
			m = v
		}
	case pb.NetDeviceRead_NET_DEVICE_READ_CBS_VLANS:
		if v := resp.GetCbsVlans(); v != nil {
			m = v
		}
	case pb.NetDeviceRead_NET_DEVICE_READ_CBS_INTERFACES:
		if v := resp.GetCbsInterfaces(); v != nil {
			m = v
		}
	case pb.NetDeviceRead_NET_DEVICE_READ_CBS_MAC_TABLE:
		if v := resp.GetCbsMacTable(); v != nil {
			m = v
		}
	case pb.NetDeviceRead_NET_DEVICE_READ_CBS_LLDP:
		if v := resp.GetCbsLldp(); v != nil {
			m = v
		}
	case pb.NetDeviceRead_NET_DEVICE_READ_PANOS_ZONES:
		if v := resp.GetPanosZones(); v != nil {
			m = v
		}
	case pb.NetDeviceRead_NET_DEVICE_READ_PANOS_OBJECTS:
		if v := resp.GetPanosObjects(); v != nil {
			m = v
		}
	case pb.NetDeviceRead_NET_DEVICE_READ_PANOS_SECURITY_RULES:
		if v := resp.GetPanosSecurityRules(); v != nil {
			m = v
		}
	case pb.NetDeviceRead_NET_DEVICE_READ_PANOS_NAT_RULES:
		if v := resp.GetPanosNatRules(); v != nil {
			m = v
		}
	case pb.NetDeviceRead_NET_DEVICE_READ_PANOS_RULE_HIT_COUNTS:
		if v := resp.GetPanosRuleHitCounts(); v != nil {
			m = v
		}
	}
	return m
}

// nextDelay is the delay until the next start of a read with the given
// cadence after failures consecutive failures (0 after a success). A
// failure backs off exponentially from MinReadInterval, doubling per
// failure up to MaxBackoff. The delay is spread by ±20 % jitter and never
// below MinReadInterval; a backoff never exceeds MaxBackoff. Callers hold
// p.mu or own p exclusively.
func (p *Poller) nextDelay(cadence time.Duration, failures int) time.Duration {
	maxBackoff := p.maxBackoff()
	base := max(cadence, MinReadInterval)
	if failures > 0 {
		b := MinReadInterval
		for i := 1; i < failures && b < maxBackoff; i++ {
			b *= 2
		}
		base = min(max(base, b), maxBackoff)
	}
	r := p.Rand()
	if !(r >= 0 && r < 1) {
		r = 0.5
	}
	d := time.Duration(float64(base) * (1 - jitterFraction + 2*jitterFraction*r))
	d = max(d, MinReadInterval)
	if failures > 0 {
		d = min(d, maxBackoff)
	}
	return d
}

// maxBackoff is the effective backoff cap: MaxBackoff or its default,
// never below MinReadInterval.
func (p *Poller) maxBackoff() time.Duration {
	b := p.MaxBackoff
	if b <= 0 {
		b = DefaultMaxBackoff
	}
	return max(b, MinReadInterval)
}

// errClass names the kind of a failure for the log: a stable executor
// failure code or gRPC status code, never the error text, which may echo
// device output.
func errClass(err error) string {
	var ee *executorclient.Error
	switch {
	case errors.As(err, &ee):
		return "executor:" + ee.Code
	case errors.Is(err, ErrBadResponse):
		return "bad_response"
	case errors.Is(err, errSpoolWrite):
		return "spool"
	case errors.Is(err, ErrTooManyDevices):
		return "too_many_devices"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, context.Canceled):
		return "canceled"
	}
	if c := status.Code(err); c != codes.Unknown {
		return "grpc:" + c.String()
	}
	return "other"
}
