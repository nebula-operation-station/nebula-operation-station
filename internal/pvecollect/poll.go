// SPDX-License-Identifier: AGPL-3.0-or-later
// Package pvecollect implements the PVE collector (ADR 0006, P1-10): it
// schedules typed read requests over the executor socket, assembles
// sanitized observations and writes them to the spool. It never talks to a
// PVE endpoint itself, opens no network listener, touches no database and
// holds no credentials.
package pvecollect

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

// maxReadWorkers bounds workers and buffered responses even with a large config.
const maxReadWorkers = 16

// Reader is the executor read surface the collector uses. The generated
// executorclient.Client satisfies it; tests substitute a fake. The collector
// only ever issues the two typed read methods, never a generic HTTP call.
type Reader interface {
	ListPVERemotes(ctx context.Context, in *pb.ListPVERemotesRequest, opts ...grpc.CallOption) (*pb.ListPVERemotesResponse, error)
	ReadPVE(ctx context.Context, in *pb.ReadPVERequest, opts ...grpc.CallOption) (*pb.ReadPVEResponse, error)
}

// Config carries the collector's tunables. Zero values fall back to the ADR
// defaults. Now and Jitter are injected so tests are deterministic.
type Config struct {
	// Now returns the current time; defaults to time.Now.
	Now func() time.Time
	// Jitter returns a value in [0,1) used to spread poll and backoff
	// timing; defaults to a source-seeded random.
	Jitter func() float64
	// Interval is the base poll interval per remote (default 60 s).
	Interval time.Duration
	// InitialBackoff is the first backoff delay after a failed poll
	// (default 1 m).
	InitialBackoff time.Duration
	// MaxBackoff caps the exponential backoff (default 15 m).
	MaxBackoff time.Duration
	// MaxConcurrentReads bounds concurrent ReadPVE calls per remote
	// (default 2).
	MaxConcurrentReads int
	// ReadTimeout bounds a single ReadPVE call (default 30 s).
	ReadTimeout time.Duration
}

// withDefaults fills zero fields with the ADR defaults.
func (c Config) withDefaults() Config {
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Jitter == nil {
		src := rand.New(rand.NewSource(time.Now().UnixNano()))
		c.Jitter = src.Float64
	}
	if c.Interval <= 0 {
		c.Interval = 60 * time.Second
	}
	if c.InitialBackoff <= 0 {
		c.InitialBackoff = time.Minute
	}
	if c.MaxBackoff <= 0 {
		c.MaxBackoff = 15 * time.Minute
	}
	if c.MaxConcurrentReads <= 0 {
		c.MaxConcurrentReads = 2
	}
	if c.MaxConcurrentReads > maxReadWorkers {
		c.MaxConcurrentReads = maxReadWorkers
	}
	if c.ReadTimeout <= 0 {
		c.ReadTimeout = 30 * time.Second
	}
	return c
}

// PollReport summarizes one PollOnce pass.
type PollReport struct {
	// Now is the injected time the pass ran at.
	Now time.Time
	// Remotes is the number of remotes the executor reported.
	Remotes int
	// Polled is the number of remotes that produced a spooled observation.
	Polled int
	// Skipped is the number of remotes not polled (inactive or still in
	// backoff).
	Skipped int
	// Failed is the number of remotes whose poll errored.
	Failed int
	// Errors carries one short line per failed remote.
	Errors []string
}

// Collector schedules typed PVE reads and writes the resulting observations
// to a spool. It is safe for use by a single Run loop; PollOnce is
// re-entrant only under the caller's own serialization.
type Collector struct {
	reader Reader
	spool  *Spool
	cfg    Config

	mu       sync.Mutex
	failures map[string]int
	nextPoll map[string]time.Time
}

// New builds a Collector. reader must be non-nil; spool must be non-nil.
func New(reader Reader, spool *Spool, cfg Config) (*Collector, error) {
	if reader == nil {
		return nil, fmt.Errorf("pvecollect: reader is nil")
	}
	if spool == nil {
		return nil, fmt.Errorf("pvecollect: spool is nil")
	}
	return &Collector{
		reader:   reader,
		spool:    spool,
		cfg:      cfg.withDefaults(),
		failures: map[string]int{},
		nextPoll: map[string]time.Time{},
	}, nil
}

// PollOnce runs one collection pass over every remote the executor reports.
// It returns a report; per-remote read failures are recorded in the report
// and do not abort the pass.
func (c *Collector) PollOnce(ctx context.Context) (PollReport, error) {
	now := c.cfg.Now().UTC()
	resp, err := c.reader.ListPVERemotes(ctx, &pb.ListPVERemotesRequest{})
	if err != nil {
		return PollReport{}, fmt.Errorf("pvecollect: list remotes: %w", err)
	}
	rep := PollReport{Now: now, Remotes: len(resp.Remotes)}
	for _, r := range resp.Remotes {
		if r == nil || r.State != pb.PVERemoteState_PVE_REMOTE_STATE_ACTIVE {
			rep.Skipped++
			continue
		}
		if !pvecontract.ValidRemoteID(r.RemoteId) {
			rep.Skipped++
			continue
		}
		if !c.due(r.RemoteId, now) {
			rep.Skipped++
			continue
		}
		if err := c.pollRemote(ctx, r.RemoteId, now); err != nil {
			c.recordFailure(r.RemoteId, now)
			rep.Failed++
			rep.Errors = append(rep.Errors, fmt.Sprintf("%s: %v", r.RemoteId, err))
			continue
		}
		c.recordSuccess(r.RemoteId, now)
		rep.Polled++
	}
	return rep, nil
}

// Run polls on a ticker until ctx is cancelled. The first pass runs
// immediately. It returns nil when ctx is done.
func (c *Collector) Run(ctx context.Context) error {
	for {
		if _, err := c.PollOnce(ctx); err != nil && ctx.Err() == nil {
			// A list-remotes failure is logged via the report path in a
			// full build; here we simply back off and retry.
			c.sleep(ctx, c.cfg.InitialBackoff)
			continue
		}
		if ctx.Err() != nil {
			return nil
		}
		c.sleep(ctx, c.cfg.Interval)
		if ctx.Err() != nil {
			return nil
		}
	}
}

// sleep waits d (with a little jitter) or until ctx is cancelled.
func (c *Collector) sleep(ctx context.Context, d time.Duration) {
	if d > 0 {
		d = d + time.Duration(c.cfg.Jitter()*float64(d)/4)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// due reports whether a remote is due for a poll at now.
func (c *Collector) due(remoteID string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	next, ok := c.nextPoll[remoteID]
	return !ok || !now.Before(next)
}

// pollRemote collects one remote and spools the observation.
func (c *Collector) pollRemote(ctx context.Context, remoteID string, now time.Time) error {
	obs, err := c.readRemote(ctx, remoteID, now)
	if err != nil {
		return err
	}
	gen, err := c.spool.allocateGeneration(ctx, remoteID)
	if err != nil {
		return fmt.Errorf("pvecollect: allocate generation: %w", err)
	}
	obs.CollectionGeneration = gen
	if _, err := c.spool.WriteFile(ctx, *obs); err != nil {
		return fmt.Errorf("pvecollect: spool %s: %w", remoteID, err)
	}
	if !obs.Complete {
		return errors.New("pvecollect: incomplete collection")
	}
	return nil
}

// recordSuccess schedules the next poll at the base interval plus jitter and
// clears the failure counter.
func (c *Collector) recordSuccess(remoteID string, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failures[remoteID] = 0
	c.nextPoll[remoteID] = now.Add(c.cfg.Interval + time.Duration(c.cfg.Jitter()*float64(c.cfg.Interval)/4))
}

// recordFailure applies exponential backoff (capped) plus jitter.
func (c *Collector) recordFailure(remoteID string, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failures[remoteID]++
	delay := c.cfg.InitialBackoff
	for i := 1; i < c.failures[remoteID] && delay < c.cfg.MaxBackoff; i++ {
		if delay > c.cfg.MaxBackoff/2 {
			delay = c.cfg.MaxBackoff
		} else {
			delay *= 2
		}
	}
	if delay > c.cfg.MaxBackoff {
		delay = c.cfg.MaxBackoff
	}
	c.nextPoll[remoteID] = now.Add(delay + time.Duration(c.cfg.Jitter()*float64(delay)/4))
}

// readReq is one typed ReadPVE call.
type readReq struct {
	method pb.PVEReadMethod
	vmid   uint64 // guest methods only
}

// readResult pairs a readReq with its outcome.
type readResult struct {
	req  readReq
	resp *pb.ReadPVEResponse
	err  error
}

// readRemote issues the typed reads for one remote and assembles the
// observation. Node-scoped reads run first; per-guest detail reads run after
// the guest list is known. Concurrency is bounded by MaxConcurrentReads.
func (c *Collector) readRemote(ctx context.Context, remoteID string, now time.Time) (*pvecontract.Observation, error) {
	obs := &pvecontract.Observation{
		RemoteID:   remoteID,
		ObservedAt: now,
		Source:     pvecontract.SourcePVEAPI,
		Complete:   true,
	}

	// Phase 1: node-scoped reads.
	phase1 := []readReq{
		{method: pb.PVEReadMethod_PVE_READ_METHOD_NODES},
		{method: pb.PVEReadMethod_PVE_READ_METHOD_GUESTS},
		{method: pb.PVEReadMethod_PVE_READ_METHOD_STORAGE},
		{method: pb.PVEReadMethod_PVE_READ_METHOD_CLUSTER},
		{method: pb.PVEReadMethod_PVE_READ_METHOD_TASKS},
	}
	var retainedBytes int
	checkBudget := func(res readResult) error {
		retainedBytes += proto.Size(res.resp)
		if retainedBytes > maxSpoolFileBytes {
			return ErrOversize
		}
		return nil
	}
	var guestResult readResult
	err := c.runReads(ctx, remoteID, phase1, func(res readResult) error {
		if err := checkBudget(res); err != nil {
			return err
		}
		switch res.req.method {
		case pb.PVEReadMethod_PVE_READ_METHOD_NODES:
			obs.Nodes = convertNodes(res)
		case pb.PVEReadMethod_PVE_READ_METHOD_GUESTS:
			guestResult = res
		case pb.PVEReadMethod_PVE_READ_METHOD_STORAGE:
			obs.Storages = convertStorages(res)
		case pb.PVEReadMethod_PVE_READ_METHOD_CLUSTER:
			obs.Cluster = convertCluster(res)
		case pb.PVEReadMethod_PVE_READ_METHOD_TASKS:
			obs.Tasks = convertTasks(res)
		}
		if res.err != nil || datasetUnavailable(res) {
			obs.Complete = false
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	// Finish node-scoped reads before rejecting the whole guest list.
	// Validate every identity before conversion or detail scheduling.
	var vmids []uint64
	guests := guestResult.resp.GetGuests()
	if guests != nil {
		if len(guests.Guests) > pvecontract.MaxObjectsPerPage || len(guests.Guests) > pvecontract.MaxGuestsPerRemote {
			return nil, errors.New("pvecollect: guest list exceeds limit")
		}
		seen := make(map[uint64]bool, len(guests.Guests))
		for _, guest := range guests.Guests {
			if guest == nil || guest.Vmid < pvecontract.MinVMID || guest.Vmid > pvecontract.MaxVMID || seen[guest.Vmid] {
				return nil, errors.New("pvecollect: invalid guest identity")
			}
			seen[guest.Vmid] = true
		}
	}
	obs.Guests = convertGuests(guestResult)
	for _, g := range obs.Guests.Value {
		vmids = append(vmids, g.VMID)
	}
	// Validate the complete phase-1 schema before any guest detail work.
	// Generation 1 is a validation placeholder; allocation happens at publish.
	obs.CollectionGeneration = 1
	if !obs.Complete {
		obs.Reason = "one or more datasets were not read"
	}
	if _, err := pvecontract.ValidateObservation(*obs); err != nil {
		return nil, errors.New("pvecollect: invalid collection input")
	}

	// Phase 2: per-guest detail reads, only when the guest list is usable.
	if obs.Guests.IsAvailable() && len(vmids) > 0 {
		var phase2 []readReq
		for _, vmid := range vmids {
			phase2 = append(phase2,
				readReq{method: pb.PVEReadMethod_PVE_READ_METHOD_GUEST_CONFIG, vmid: vmid},
				readReq{method: pb.PVEReadMethod_PVE_READ_METHOD_GUEST_AGENT, vmid: vmid},
				readReq{method: pb.PVEReadMethod_PVE_READ_METHOD_SNAPSHOTS, vmid: vmid},
				readReq{method: pb.PVEReadMethod_PVE_READ_METHOD_BACKUPS, vmid: vmid},
			)
		}
		err := c.runReads(ctx, remoteID, phase2, func(res readResult) error {
			if err := checkBudget(res); err != nil {
				return err
			}
			c.applyGuestDetail(obs, res)
			if res.err != nil || datasetUnavailable(res) {
				obs.Complete = false
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	if !obs.Complete {
		obs.Reason = "one or more datasets were not read"
	}
	return obs, nil
}

// runReads streams results through a fixed worker pool. Each worker holds at
// most one response; the result buffer holds at most one response per worker.
// Consumption errors and cancellation stop scheduling remaining work.
func (c *Collector) runReads(ctx context.Context, remoteID string, reqs []readReq, consume func(readResult) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(reqs) == 0 {
		return nil
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	workers := min(c.cfg.MaxConcurrentReads, len(reqs))
	results := make(chan readResult, workers)
	var next atomic.Int64
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if ctx.Err() != nil {
					return
				}
				i := int(next.Add(1) - 1)
				if i >= len(reqs) {
					return
				}
				r := reqs[i]
				rctx, cancelRead := context.WithTimeout(ctx, c.cfg.ReadTimeout)
				resp, err := c.reader.ReadPVE(rctx, buildReadReq(remoteID, r))
				cancelRead()
				if resp != nil && proto.Size(resp) > maxSpoolFileBytes {
					resp, err = nil, ErrOversize
				}
				select {
				case results <- readResult{req: r, resp: resp, err: err}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(results); close(done) }()
	defer func() { cancel(); <-done }()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case res, ok := <-results:
			if !ok {
				return ctx.Err()
			}
			if err := consume(res); err != nil {
				return err
			}
		}
	}
}

// buildReadReq assembles a ReadPVE request for one readReq, honouring the
// parameter rules from executor.ValidateReadPVERequest.
func buildReadReq(remoteID string, r readReq) *pb.ReadPVERequest {
	req := &pb.ReadPVERequest{RemoteId: remoteID, Method: r.method}
	switch r.method {
	case pb.PVEReadMethod_PVE_READ_METHOD_GUEST_CONFIG,
		pb.PVEReadMethod_PVE_READ_METHOD_GUEST_AGENT,
		pb.PVEReadMethod_PVE_READ_METHOD_SNAPSHOTS,
		pb.PVEReadMethod_PVE_READ_METHOD_BACKUPS:
		req.Params = &pb.ReadPVERequest_Guest{Guest: &pb.PVEReadGuestParams{Vmid: r.vmid}}
	}
	return req
}

// applyGuestDetail folds one per-guest read result into the matching guest.
func (c *Collector) applyGuestDetail(obs *pvecontract.Observation, res readResult) {
	if !obs.Guests.IsAvailable() {
		return
	}
	var guest *pvecontract.GuestObservation
	for i := range obs.Guests.Value {
		if obs.Guests.Value[i].VMID == res.req.vmid {
			guest = &obs.Guests.Value[i]
			break
		}
	}
	if guest == nil {
		return
	}
	switch res.req.method {
	case pb.PVEReadMethod_PVE_READ_METHOD_GUEST_CONFIG:
		guest.Config = convertGuestConfig(res)
	case pb.PVEReadMethod_PVE_READ_METHOD_GUEST_AGENT:
		guest.Agent = convertGuestAgent(res)
	case pb.PVEReadMethod_PVE_READ_METHOD_SNAPSHOTS:
		guest.Snapshots = convertSnapshots(res)
	case pb.PVEReadMethod_PVE_READ_METHOD_BACKUPS:
		guest.Backups = convertBackups(res)
	}
}
