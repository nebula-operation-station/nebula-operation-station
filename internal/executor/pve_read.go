// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveapi"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvetransport"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vault"
)

// Provider read limits (spec 07 "Provider profile", ADR 0006).
const (
	// pveReadConcurrency bounds concurrent API reads per remote.
	pveReadConcurrency = 2
	// pveReadConnectTimeout bounds connect and TLS handshake per endpoint.
	pveReadConnectTimeout = 10 * time.Second
	// pveReadRequestTimeout bounds one API request.
	pveReadRequestTimeout = 30 * time.Second
	// pveReadMaxResponseBytes bounds one transport response; pveapi applies
	// its own, smaller per-endpoint limits on top.
	pveReadMaxResponseBytes = 4 << 20
	// pveReadSource names the executor as the observation source.
	pveReadSource = "executor"
)

// pveReadMethods maps the wired typed methods to their grant method names.
// The remaining methods stay Unimplemented until their mapping lands.
var pveReadMethods = map[pb.PVEReadMethod]string{
	pb.PVEReadMethod_PVE_READ_METHOD_NODES:   permit.ProviderMethodNodes,
	pb.PVEReadMethod_PVE_READ_METHOD_GUESTS:  permit.ProviderMethodGuests,
	pb.PVEReadMethod_PVE_READ_METHOD_STORAGE: permit.ProviderMethodStorage,
	pb.PVEReadMethod_PVE_READ_METHOD_CLUSTER: permit.ProviderMethodCluster,
}

var (
	errPveReadTrust       = errors.New("executor: pve remote no longer presents its pinned trust identity")
	errPveReadUnreachable = errors.New("executor: no pve endpoint reachable")
)

// pveReadState holds per-remote request slots and the verified cluster CA
// certificates. The CA is cached per (remote, pin, generation): its SHA-256
// equals the pin, so it carries no trust beyond the registry.
type pveReadState struct {
	mu    sync.Mutex
	slots map[string]chan struct{}
	cas   map[string]pveCachedCA
}

type pveCachedCA struct {
	pin        string
	generation uint64
	cert       *x509.Certificate
}

// acquire takes one of the remote's request slots, waiting until ctx ends.
func (p *pveReadState) acquire(ctx context.Context, remoteID string) (func(), error) {
	p.mu.Lock()
	if p.slots == nil {
		p.slots = map[string]chan struct{}{}
	}
	ch, ok := p.slots[remoteID]
	if !ok {
		ch = make(chan struct{}, pveReadConcurrency)
		p.slots[remoteID] = ch
	}
	p.mu.Unlock()
	select {
	case ch <- struct{}{}:
		return func() { <-ch }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (p *pveReadState) cachedCA(rm executordb.PveRemote) *x509.Certificate {
	p.mu.Lock()
	defer p.mu.Unlock()
	c, ok := p.cas[rm.RemoteID]
	if !ok || c.pin != rm.TrustPin || c.generation != rm.TrustGeneration {
		return nil
	}
	return c.cert
}

func (p *pveReadState) storeCA(rm executordb.PveRemote, cert *x509.Certificate) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cas == nil {
		p.cas = map[string]pveCachedCA{}
	}
	p.cas[rm.RemoteID] = pveCachedCA{pin: rm.TrustPin, generation: rm.TrustGeneration, cert: cert}
}

// pveTrustWatch records whether any request failed trust verification, which
// pveapi readers flatten into generic transport errors.
type pveTrustWatch struct {
	rt     http.RoundTripper
	failed atomic.Bool
}

func (w *pveTrustWatch) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := w.rt.RoundTrip(r)
	if err != nil && errors.Is(err, pvetransport.ErrTrustMismatch) {
		w.failed.Store(true)
	}
	return resp, err
}

// ReadPVE (ADR 0006 P1-05, ADR 0007 E08) performs one typed read against
// one registered remote under an approved provider read grant:
//
//  1. the request shape is validated (ValidateReadPVERequest);
//  2. the remote must be active in the executor registry and carry its
//     read credential; its current trust pin, generation and credential
//     version must be exactly those an active provider grant names for
//     this method, whose per-method interval and per-remote request
//     budget are reserved durably before any network traffic;
//  3. the token is opened at exactly that credential version and sent only
//     over the pinned transport;
//  4. lock, restart (until local unlock), recovery and revocation are
//     re-checked before the request and again before the result is
//     returned, so a read in flight across one of them is discarded;
//  5. the response is mapped to the pvecontract shape and validated with
//     its rules; values that fail are reported as an unavailable dataset.
//
// A trust failure blocks the remote persistently and revokes its grants.
// Errors carry no token, URL or raw PVE text.
func (s *Service) ReadPVE(ctx context.Context, in *pb.ReadPVERequest) (*pb.ReadPVEResponse, error) {
	if err := ValidateReadPVERequest(in); err != nil {
		return nil, err
	}
	method, ok := pveReadMethods[in.Method]
	if !ok {
		return nil, status.Error(codes.Unimplemented, "read pve: method is not wired yet")
	}
	if err := s.checkNotRecovering(); err != nil {
		return nil, err
	}
	if st, err := s.vault.State(); err != nil || st != vault.StateUnlocked {
		return nil, status.Error(codes.FailedPrecondition, "read pve: the executor vault is locked")
	}
	rm, ok, err := s.db.GetRemote(in.RemoteId)
	if err != nil {
		return nil, status.Error(codes.Internal, "read pve: registry unavailable")
	}
	switch {
	case !ok || rm.State == executordb.StateRemoved:
		return nil, status.Error(codes.NotFound, "read pve: remote not found")
	case rm.State != executordb.StateActive:
		return nil, status.Error(codes.FailedPrecondition, "read pve: remote is blocked until an admin re-pins it")
	case rm.Credentials.ReadRef != PveVaultID(rm.RemoteID, PvePurposeRead) || rm.Credentials.ReadVersion < 1:
		return nil, status.Error(codes.FailedPrecondition, "read pve: remote has no read credential")
	}
	release, err := s.pveRead.acquire(ctx, rm.RemoteID)
	if err != nil {
		return nil, status.FromContextError(err).Err()
	}
	defer release()

	claim, err := s.auth.AuthorizeProviderRead(permit.ProviderRead{
		RemoteID: rm.RemoteID, Method: method, TrustPin: rm.TrustPin,
		TrustGeneration: rm.TrustGeneration, CredentialVersion: rm.Credentials.ReadVersion,
	})
	if err != nil {
		return nil, readGrantStatus(err)
	}
	token, version, err := s.vault.OpenVersion(rm.Credentials.ReadRef)
	if err != nil || version != rm.Credentials.ReadVersion {
		return nil, status.Error(codes.FailedPrecondition, "read pve: read credential is unavailable or changed")
	}
	trust, err := s.pveReadTrust(ctx, rm)
	switch {
	case errors.Is(err, errPveReadTrust):
		return nil, s.blockPveRead(rm.RemoteID)
	case err != nil:
		return nil, status.Error(codes.Unavailable, "read pve: remote unreachable")
	}
	if err := claim.Check(); err != nil {
		return nil, readGrantStatus(err)
	}
	header := "PVEAPIToken=" + string(token)
	clear(token)
	hc, watch, base, err := pveReadHTTP(rm, trust, s.clock)
	if err != nil {
		return nil, status.Error(codes.Internal, "read pve: transport setup failed")
	}
	supplier := func(context.Context) (string, error) { return header, nil }

	out := &pb.ReadPVEResponse{RemoteId: rm.RemoteID, ObservedAtUnix: s.clock().Unix()}
	switch in.Method {
	case pb.PVEReadMethod_PVE_READ_METHOD_NODES:
		out.Payload = &pb.ReadPVEResponse_Nodes{Nodes: readPveNodes(ctx, rm.RemoteID, base, hc, supplier, in.GetNode().GetNode(), s.clock())}
	case pb.PVEReadMethod_PVE_READ_METHOD_GUESTS:
		out.Payload = &pb.ReadPVEResponse_Guests{Guests: readPveGuests(ctx, rm.RemoteID, base, hc, supplier, s.clock())}
	case pb.PVEReadMethod_PVE_READ_METHOD_STORAGE:
		out.Payload = &pb.ReadPVEResponse_Storages{Storages: readPveStorages(ctx, rm.RemoteID, base, hc, supplier, s.clock())}
	case pb.PVEReadMethod_PVE_READ_METHOD_CLUSTER:
		out.Payload = &pb.ReadPVEResponse_Cluster{Cluster: readPveCluster(ctx, rm.RemoteID, base, hc, supplier, s.clock())}
	}
	if watch.failed.Load() {
		return nil, s.blockPveRead(rm.RemoteID)
	}
	if err := ctx.Err(); err != nil {
		return nil, status.FromContextError(err).Err()
	}
	if err := claim.Check(); err != nil {
		return nil, readGrantStatus(err)
	}
	s.log.Info("audit", "kind", "pve_read", "remote", rm.RemoteID, "method", method, "grant", claim.GrantID)
	return out, nil
}

// blockPveRead blocks a remote whose endpoints failed trust verification and
// revokes its provider grants (spec: a changed pin blocks the whole remote
// persistently until an admin re-pins it).
func (s *Service) blockPveRead(remoteID string) error {
	s.pveMu.Lock()
	defer s.pveMu.Unlock()
	if err := s.pveAdmin().blockTrustFailure(remoteID, "executor", errPveReadTrust); !errors.Is(err, errPveReadTrust) {
		s.log.Error("pve remote block failed", "remote", remoteID)
		return status.Error(codes.Internal, "read pve: trust failure could not be recorded")
	}
	return status.Error(codes.FailedPrecondition, "read pve: trust verification failed; the remote is blocked until an admin re-pins it")
}

// pveReadTrust returns the pinned transport trust of rm. A standalone remote
// is pinned to its leaf fingerprint. A cluster is pinned to its CA, whose
// certificate the registry does not store: the executor fetches the
// presented chains credential-free and uses the self-signed certificate
// whose SHA-256 equals the pin. If endpoints answer but none presents it,
// the trust identity changed.
func (s *Service) pveReadTrust(ctx context.Context, rm executordb.PveRemote) (pvetransport.Trust, error) {
	raw, err := hex.DecodeString(rm.TrustPin)
	if err != nil || len(raw) != 32 {
		return pvetransport.Trust{}, errPveReadTrust
	}
	var pin [32]byte
	copy(pin[:], raw)
	switch rm.Kind {
	case pvecontract.KindStandalone:
		return pvetransport.Trust{LeafFingerprint: pin}, nil
	case pvecontract.KindCluster:
	default:
		return pvetransport.Trust{}, errPveReadTrust
	}
	if ca := s.pveRead.cachedCA(rm); ca != nil {
		return pvetransport.Trust{CA: ca}, nil
	}
	presented := false
	for _, ep := range rm.Endpoints {
		certs, err := fetchPresentedChain(ctx, ep.Host, ep.Port)
		if err != nil {
			if ctx.Err() != nil {
				return pvetransport.Trust{}, ctx.Err()
			}
			continue
		}
		presented = true
		for _, c := range certs {
			if bytes.Equal(c.RawIssuer, c.RawSubject) && pvetransport.Fingerprint(c) == pin {
				s.pveRead.storeCA(rm, c)
				return pvetransport.Trust{CA: c}, nil
			}
		}
	}
	if presented {
		return pvetransport.Trust{}, errPveReadTrust
	}
	return pvetransport.Trust{}, errPveReadUnreachable
}

// pveReadHTTP builds the pinned HTTP client for one read. The base URL is
// the first endpoint; the transport substitutes the endpoint on failover.
func pveReadHTTP(rm executordb.PveRemote, trust pvetransport.Trust, now func() time.Time) (*http.Client, *pveTrustWatch, string, error) {
	urls := make([]*url.URL, 0, len(rm.Endpoints))
	for _, ep := range rm.Endpoints {
		u, err := pvetransport.ParseEndpoint("https://" + net.JoinHostPort(ep.Host, strconv.Itoa(int(ep.Port))))
		if err != nil {
			return nil, nil, "", err
		}
		urls = append(urls, u)
	}
	if len(urls) == 0 {
		return nil, nil, "", pvetransport.ErrNoEndpoints
	}
	rt, err := pvetransport.NewRoundTripper(pvetransport.Options{
		Trust: trust, Endpoints: urls, Timeout: pveReadRequestTimeout, DialTimeout: pveReadConnectTimeout,
		MaxResponseBytes: pveReadMaxResponseBytes, Now: now,
	})
	if err != nil {
		return nil, nil, "", err
	}
	watch := &pveTrustWatch{rt: rt}
	hc := &http.Client{Transport: watch, CheckRedirect: func(*http.Request, []*http.Request) error { return pvetransport.ErrRedirect }}
	return hc, watch, "https://" + urls[0].Host, nil
}

// pveReadValid validates one mapped dataset with the pvecontract rules by
// placing it in an otherwise unread observation page.
func pveReadValid(remoteID string, at time.Time, fill func(*pvecontract.Observation)) bool {
	o := pvecontract.Observation{
		RemoteID: remoteID, ObservedAt: at, Source: pveReadSource, CollectionGeneration: 1, Complete: true,
		Nodes:    pvecontract.UnavailableDataset[[]pvecontract.NodeObservation]("not read"),
		Guests:   pvecontract.UnavailableDataset[[]pvecontract.GuestObservation]("not read"),
		Storages: pvecontract.UnavailableDataset[[]pvecontract.StorageObservation]("not read"),
		Cluster:  pvecontract.UnavailableDataset[pvecontract.ClusterObservation]("not read"),
		Tasks:    pvecontract.UnavailableDataset[[]pvecontract.TaskObservation]("not read"),
	}
	fill(&o)
	_, err := pvecontract.ValidateObservation(o)
	return err == nil
}

const (
	pveUnavailable = pb.PVEDatasetState_PVE_DATASET_STATE_UNAVAILABLE
	pveAvailable   = pb.PVEDatasetState_PVE_DATASET_STATE_AVAILABLE
	// Fixed reasons; raw PVE text never reaches the caller.
	pveReasonRead    = "read failed"
	pveReasonInvalid = "response failed validation"
	pveReasonPartial = "not every node could be read"
)

func readPveNodes(ctx context.Context, remoteID, base string, hc *http.Client, token pveapi.TokenSupplier, only string, at time.Time) *pb.PVENodes {
	c, err := pveapi.New(base, hc, token, pveapi.WithTimeout(pveReadRequestTimeout))
	if err != nil {
		return &pb.PVENodes{State: pveUnavailable, Reason: pveReasonRead}
	}
	nodes, err := c.ListNodes(ctx)
	if err != nil {
		return &pb.PVENodes{State: pveUnavailable, Reason: pveReasonRead}
	}
	var obs []pvecontract.NodeObservation
	for _, n := range nodes {
		if only != "" && n.Name != only {
			continue
		}
		st := pvecontract.NodeOffline
		if n.Status == "online" {
			st = pvecontract.NodeOnline
		}
		obs = append(obs, pvecontract.NodeObservation{
			Node: n.Name, Status: st, UptimeSeconds: n.UptimeSeconds, CPUCount: uint32(n.MaxCPU),
			RAMTotalBytes: n.MaxMemory, RAMUsedBytes: n.Memory,
			Details: pvecontract.UnavailableDataset[pvecontract.NodeDetails]("not read"),
		})
	}
	if obs == nil {
		obs = []pvecontract.NodeObservation{}
	}
	if !pveReadValid(remoteID, at, func(o *pvecontract.Observation) { o.Nodes = pvecontract.AvailableDataset(obs) }) {
		return &pb.PVENodes{State: pveUnavailable, Reason: pveReasonInvalid}
	}
	out := &pb.PVENodes{State: pveAvailable}
	for _, n := range obs {
		out.Nodes = append(out.Nodes, &pb.PVENode{
			Node: n.Node, Status: string(n.Status), UptimeSeconds: n.UptimeSeconds, CpuCount: n.CPUCount,
			RamTotalBytes: n.RAMTotalBytes, RamUsedBytes: n.RAMUsedBytes,
			Details: &pb.PVENodeDetails{State: pveUnavailable, Reason: "not read"},
		})
	}
	return out
}

func readPveGuests(ctx context.Context, remoteID, base string, hc *http.Client, token pveapi.TokenSupplier, at time.Time) *pb.PVEGuests {
	c, err := pveapi.New(base, hc, token, pveapi.WithTimeout(pveReadRequestTimeout))
	if err != nil {
		return &pb.PVEGuests{State: pveUnavailable, Reason: pveReasonRead}
	}
	inv, err := c.EnumerateCluster(ctx)
	if err != nil {
		return &pb.PVEGuests{State: pveUnavailable, Reason: pveReasonRead}
	}
	// A partial or truncated list must never look complete: absent guests
	// would be tombstoned downstream.
	if inv.Partial || inv.Truncated {
		return &pb.PVEGuests{State: pveUnavailable, Reason: pveReasonPartial}
	}
	obs := make([]pvecontract.GuestObservation, 0, len(inv.Guests))
	for _, g := range inv.Guests {
		st := pvecontract.GuestStatus(g.Status)
		switch st {
		case pvecontract.GuestRunning, pvecontract.GuestStopped, pvecontract.GuestPaused:
		default:
			st = pvecontract.GuestUnknown
		}
		obs = append(obs, pvecontract.GuestObservation{
			VMID: uint64(max(g.VMID, 0)), Kind: pvecontract.GuestKind(g.Kind), Node: g.Node, Name: g.Name, Status: st,
			Generation: 1, UUID: strings.ToLower(g.UUID),
			Config:     pvecontract.UnavailableDataset[pvecontract.GuestConfig]("not read"),
			Interfaces: pvecontract.UnavailableDataset[[]pvecontract.GuestInterface]("not read"),
			Agent:      pvecontract.UnavailableDataset[pvecontract.GuestAgent]("not read"),
			Snapshots:  pvecontract.UnavailableDataset[[]pvecontract.Snapshot]("not read"),
			Backups:    pvecontract.UnavailableDataset[[]pvecontract.BackupEvidence]("not read"),
		})
	}
	if !pveReadValid(remoteID, at, func(o *pvecontract.Observation) { o.Guests = pvecontract.AvailableDataset(obs) }) {
		return &pb.PVEGuests{State: pveUnavailable, Reason: pveReasonInvalid}
	}
	out := &pb.PVEGuests{State: pveAvailable}
	for _, g := range obs {
		out.Guests = append(out.Guests, &pb.PVEGuest{Vmid: g.VMID, Kind: string(g.Kind), Node: g.Node, Name: g.Name,
			Status: string(g.Status), Generation: g.Generation, Uuid: g.UUID})
	}
	return out
}

// pveStorageContent maps PVE content types to the contract names; unknown
// types are dropped rather than failing the whole dataset.
var pveStorageContent = map[string]string{
	"images": "images", "iso": "iso", "backup": "backup", "vztmpl": "vztmpl",
	"snippets": "snippets", "rootdir": "container", "container": "container",
}

func readPveStorages(ctx context.Context, remoteID, base string, hc *http.Client, token pveapi.TokenSupplier, at time.Time) *pb.PVEStorages {
	inv, err := pveapi.New(base, hc, token, pveapi.WithTimeout(pveReadRequestTimeout))
	if err != nil {
		return &pb.PVEStorages{State: pveUnavailable, Reason: pveReasonRead}
	}
	nodes, err := inv.ListNodes(ctx)
	if err != nil {
		return &pb.PVEStorages{State: pveUnavailable, Reason: pveReasonRead}
	}
	c, err := pveapi.NewClient(hc, base+"/api2/json", token)
	if err != nil {
		return &pb.PVEStorages{State: pveUnavailable, Reason: pveReasonRead}
	}
	// One entry per (node, storage) as each online node reports it, with
	// PVE's shared flag; downstream counts a shared storage once. An
	// inactive storage, or one without a usable capacity pair, carries no
	// capacity (unknown), never a measured zero.
	obs := []pvecontract.StorageObservation{}
	for _, n := range nodes {
		if n.Status != "online" {
			continue
		}
		list, err := c.ListStorages(ctx, n.Name)
		if err != nil || !list.Complete {
			return &pb.PVEStorages{State: pveUnavailable, Reason: pveReasonPartial}
		}
		for _, st := range list.Storages {
			so := pvecontract.StorageObservation{Name: st.ID, Type: st.Type, Format: st.Format, Active: st.Active,
				Content: []string{}, Node: n.Name, Shared: st.Shared}
			if st.Active && st.CapacityKnown && st.UsedBytes <= st.TotalBytes {
				so.SizeBytes, so.FreeBytes = st.TotalBytes, st.TotalBytes-st.UsedBytes
			}
			have := map[string]bool{}
			for _, ct := range st.Content {
				if name, ok := pveStorageContent[ct]; ok && !have[name] {
					have[name] = true
					so.Content = append(so.Content, name)
				}
			}
			obs = append(obs, so)
		}
	}
	if !pveReadValid(remoteID, at, func(o *pvecontract.Observation) { o.Storages = pvecontract.AvailableDataset(obs) }) {
		return &pb.PVEStorages{State: pveUnavailable, Reason: pveReasonInvalid}
	}
	out := &pb.PVEStorages{State: pveAvailable}
	for _, so := range obs {
		out.Storages = append(out.Storages, &pb.PVEStorage{Name: so.Name, Type: so.Type, Format: so.Format, Content: so.Content,
			Active: so.Active, SizeBytes: so.SizeBytes, FreeBytes: so.FreeBytes, Node: so.Node, Shared: so.Shared})
	}
	return out
}

func readPveCluster(ctx context.Context, remoteID, base string, hc *http.Client, token pveapi.TokenSupplier, at time.Time) *pb.PVECluster {
	c := &pveapi.Client{HTTP: hc, BaseURL: base + "/api2/json", Token: token, Timeout: pveReadRequestTimeout}
	cs, err := c.ClusterStatus(ctx)
	if err != nil {
		return &pb.PVECluster{State: pveUnavailable, Reason: pveReasonRead}
	}
	if !cs.Available {
		reason := pveReasonRead
		if strings.HasPrefix(cs.Reason, "standalone") {
			reason = "standalone host: no cluster configured"
		}
		return &pb.PVECluster{State: pveUnavailable, Reason: reason}
	}
	ha, err := c.HAStatus(ctx)
	if err != nil {
		return &pb.PVECluster{State: pveUnavailable, Reason: pveReasonRead}
	}
	obs := pvecontract.ClusterObservation{Quorum: "not-quorate", Nodes: []pvecontract.ClusterNode{}, HAResources: []pvecontract.HAResource{}}
	if cs.Quorum {
		obs.Quorum = "quorate"
	}
	for _, m := range cs.Members {
		st := pvecontract.NodeOffline
		if m.Online {
			st = pvecontract.NodeOnline
		}
		obs.Nodes = append(obs.Nodes, pvecontract.ClusterNode{Node: m.Name, Status: st})
	}
	if ha.Available {
		for _, r := range ha.Resources {
			kind, prefix := pvecontract.GuestQEMU, "vm"
			if r.Type == "ct" {
				kind, prefix = pvecontract.GuestLXC, "ct"
			}
			obs.HAResources = append(obs.HAResources, pvecontract.HAResource{
				ID: prefix + "-" + strconv.Itoa(r.VMID), Kind: kind, VMID: uint64(max(r.VMID, 0)),
				Desired: pveHAState(r.DesiredState), Observed: pveHAState(r.State), Node: r.Node,
			})
		}
	}
	if !pveReadValid(remoteID, at, func(o *pvecontract.Observation) { o.Cluster = pvecontract.AvailableDataset(obs) }) {
		return &pb.PVECluster{State: pveUnavailable, Reason: pveReasonInvalid}
	}
	out := &pb.PVECluster{State: pveAvailable, Quorum: obs.Quorum}
	for _, n := range obs.Nodes {
		out.Nodes = append(out.Nodes, &pb.PVEClusterNode{Node: n.Node, Status: string(n.Status)})
	}
	for _, h := range obs.HAResources {
		out.HaResources = append(out.HaResources, &pb.PVEHAResource{Id: h.ID, Kind: string(h.Kind), Vmid: h.VMID,
			Desired: h.Desired, Observed: h.Observed, Node: h.Node})
	}
	return out
}

// pveHAState maps PVE HA states onto the contract's four states.
func pveHAState(s string) string {
	switch s {
	case "started", "stopped", "migrating":
		return s
	case "relocate":
		return "migrating"
	case "disabled", "ignored":
		return "stopped"
	default:
		return "unknown"
	}
}
