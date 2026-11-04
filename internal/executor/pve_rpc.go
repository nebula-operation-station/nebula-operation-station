// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/keyring"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveapi"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/riskpolicy"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vault"
)

const pveRepinAction = "nebula.pve.repin"

var pveRepinArtifact = []byte("nebula.pve.repin 1.0.0\nReplace the approved remote trust fingerprint and invalidate dependent authority.\n")

// pveMutations returns the executor's single PVE mutation engine. Every
// mutation run and every PveAdmin must use this instance: its in-flight
// set is what keeps Reconcile and PveAdmin.CloseOpenJobs off the steps of
// a running execution. It is built on first use, from the service state at
// that time. Its Client is the production pveMutationClient over the
// remote's pinned trust (pveReadTrust) and approved endpoints: writes
// carry only the action token, reads only the read token, and a write is
// never failed over or resent once it may have reached an endpoint. The
// client dispatches the guest power, provisioning and image steps
// (DispatchGuestPowerStep, DispatchProvisionStep, DispatchImageStep) and
// names their task types and IDs. A pin or trust failure seen by any of
// its calls blocks the remote persistently (blockPveRead), so further
// mutations are refused. When the executor has a state directory
// (SetBackupDirs, called before serving), TaskIDs is the executor's one
// PveProvisioner (pveProvisioner), so provisioning steps are identified
// and reconciled also after a restart; without one, provisioning is
// unavailable and its steps are never identified.
func (s *Service) pveMutations() *PveMutations {
	s.pveMutOnce.Do(func() {
		client := &pveMutationClient{trust: s.pveReadTrust, secrets: s.vault, now: s.clock,
			// A trust failure on the mutation path blocks the remote as
			// on the read path; the step itself already fails closed.
			block: func(remoteID string) { _ = s.blockPveRead(remoteID) }}
		m := &PveMutations{DB: s.db, Auth: s.auth, Vault: s.vault, Client: client, Now: s.clock, Log: s.log}
		if p := s.newPveProvisioner(m); p != nil {
			m.TaskIDs = p
		}
		s.pveMut = m
	})
	return s.pveMut
}

// Fixed identity of the provisioning and template actions the executor
// proposes itself.
const (
	pveGuestProvisionVersion = "1.0.0"
	pveImagePrepareVersion   = "1.0.0"
	// pveGuestProvisionLifetime is how long a proposed provisioning permit
	// (and its VMID reservation) can be approved and run.
	pveGuestProvisionLifetime = 30 * time.Minute
	// State files of provisioning in the executor's data directory.
	pveTemplatesFile    = "pve-templates.json"
	pveVMIDsFile        = "pve-vmids.json"
	pveCatalogStateFile = "pve-catalog.json"
)

var (
	pveGuestProvisionArtifact = []byte(PveGuestProvisionAction + " " + pveGuestProvisionVersion + "\nProvision one guest from a prepared template.\n")
	pveImagePrepareArtifact   = []byte(PveImagePrepareAction + " " + pveImagePrepareVersion + "\nPrepare a PVE template from a catalog image.\n")
	// pveGuestProvisionStagePlan is the stage plan hash of a provisioning
	// (one node, the fixed step plan in the parameters).
	pveGuestProvisionStagePlan = func() string {
		s, _ := canonical.HashParameters([]byte(`{"plan":"pve-guest-provision-v1"}`))
		return s
	}()
)

// newPveProvisioner builds the executor's one provisioner on m, with its
// state in the data directory: template records, VMID reservations and the
// image catalog rollback state. The NOS automation key is the public key
// of the keyring credential a request names; the reader uses the read
// token over the remote's pinned transport (pveProvisionReaderAPI). It
// returns nil when the executor has no data directory.
func (s *Service) newPveProvisioner(m *PveMutations) *PveProvisioner {
	if s.dataDir == "" {
		return nil
	}
	imgs := &PveImages{Mutations: m,
		Catalog:   &PveImageCatalog{State: &FilePveCatalogState{Path: filepath.Join(s.dataDir, pveCatalogStateFile)}},
		Templates: &FilePveTemplateStore{Path: filepath.Join(s.dataDir, pveTemplatesFile)},
		Artifact:  pveImagePrepareArtifact, ModuleVersion: pveImagePrepareVersion}
	return &PveProvisioner{Mutations: m, Images: imgs, Reader: pveProvisionReaderAPI{agent: pveGuestAgentAPI{s: s}},
		VMIDs: &FilePveVMIDStore{Path: filepath.Join(s.dataDir, pveVMIDsFile)}, Passwords: s.vault,
		AutomationKeys: s.automationKey, Artifact: pveGuestProvisionArtifact, ModuleVersion: pveGuestProvisionVersion}
}

// PveAutomationCredentialRef is the keyring credential reference designated
// as the NOS automation key (ADR 0008 section 3, "Access and password": one
// NOS automation key; the keyring file nos-automation.key). Provisioning
// installs only this credential's public key; a request naming any other
// keyring credential is refused, so the key of an unrelated host credential
// never reaches a new guest.
const PveAutomationCredentialRef = "nos-automation"

var (
	// ErrPveAutomationCredential is returned for an AutomationCredentialRef
	// that does not name the designated NOS automation credential
	// (PveAutomationCredentialRef). Nothing is read from the keyring.
	ErrPveAutomationCredential = errors.New("executor: credential is not the designated nos automation key")
	// errNoKeyring is returned when the executor has no keyring; it counts
	// as a locked keyring.
	errNoKeyring = fmt.Errorf("executor: no keyring: %w", keyring.ErrLocked)
)

// automationKey returns the authorized_keys form of the public key of the
// keyring credential ref, which must be the designated NOS automation
// credential (ErrPveAutomationCredential). It fails with keyring.ErrLocked
// while the keyring is locked and keyring.ErrUnknownRef when the keyring
// does not hold the credential.
func (s *Service) automationKey(ref string) (string, error) {
	if ref != PveAutomationCredentialRef {
		return "", ErrPveAutomationCredential
	}
	if s.keys == nil {
		return "", errNoKeyring
	}
	signer, err := s.keys.Signer(ref)
	if err != nil {
		return "", fmt.Errorf("automation credential: %w", err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))), nil
}

// pveProvisioner returns the executor's one provisioner (the TaskIDs of
// its one mutation engine), or nil when provisioning is unavailable.
func (s *Service) pveProvisioner() *PveProvisioner {
	p, _ := s.pveMutations().TaskIDs.(*PveProvisioner)
	return p
}

// pveProvisionReaderAPI is the production PveProvisionReader: typed pveapi
// reads with the read token over the remote's pinned TLS channel (the
// trust and transport of ReadPVE), with the read slots and trust blocking
// of every provider read.
type pveProvisionReaderAPI struct {
	agent pveGuestAgentAPI
}

// conn builds the pinned HTTP client of rm and returns it with its trust
// watch, base URL and the release of the remote's request slot.
func (r pveProvisionReaderAPI) conn(ctx context.Context, rm executordb.PveRemote, read pveapi.TokenSupplier) (*http.Client, *pveTrustWatch, string, func(), error) {
	s := r.agent.s
	if read == nil {
		return nil, nil, "", nil, errors.New("executor: provisioning read: no read token")
	}
	release, err := s.pveRead.acquire(ctx, rm.RemoteID)
	if err != nil {
		return nil, nil, "", nil, err
	}
	trust, err := s.pveReadTrust(ctx, rm)
	if errors.Is(err, errPveReadTrust) {
		release()
		return nil, nil, "", nil, s.blockPveRead(rm.RemoteID)
	}
	if err != nil {
		release()
		return nil, nil, "", nil, err
	}
	hc, watch, base, err := pveReadHTTP(rm, trust, s.clock)
	if err != nil {
		release()
		return nil, nil, "", nil, err
	}
	return hc, watch, base, release, nil
}

// ClusterInventory implements PveProvisionReader.
func (r pveProvisionReaderAPI) ClusterInventory(ctx context.Context, rm executordb.PveRemote, read pveapi.TokenSupplier) (pveapi.ClusterInventory, error) {
	hc, watch, base, release, err := r.conn(ctx, rm, read)
	if err != nil {
		return pveapi.ClusterInventory{}, err
	}
	defer release()
	c, err := pveapi.New(base, hc, read, pveapi.WithTimeout(pveReadRequestTimeout))
	if err != nil {
		return pveapi.ClusterInventory{}, err
	}
	inv, err := c.EnumerateCluster(ctx)
	if terr := r.agent.checkTrust(rm, watch); terr != nil {
		return pveapi.ClusterInventory{}, terr
	}
	return inv, err
}

// NodeStorage implements PveProvisionReader.
func (r pveProvisionReaderAPI) NodeStorage(ctx context.Context, rm executordb.PveRemote, node, storage string, read pveapi.TokenSupplier) (pveapi.Storage, error) {
	hc, watch, base, release, err := r.conn(ctx, rm, read)
	if err != nil {
		return pveapi.Storage{}, err
	}
	defer release()
	c, err := pveapi.NewClient(hc, base+"/api2/json", read)
	if err != nil {
		return pveapi.Storage{}, err
	}
	c.Timeout = pveReadRequestTimeout
	st, err := c.GetStorage(ctx, node, storage)
	if terr := r.agent.checkTrust(rm, watch); terr != nil {
		return pveapi.Storage{}, terr
	}
	return st, err
}

// ReconcilePVEMutations observes open PVE mutation steps until ctx ends:
// once per interval while the vault is unlocked, also those left open by
// an earlier process. It only reads (task status and task list with the
// read token); nothing is ever dispatched.
func (s *Service) ReconcilePVEMutations(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if err := s.pveMutations().Reconcile(ctx); err != nil && !errors.Is(err, vault.ErrLocked) && ctx.Err() == nil {
			s.log.Error("audit", "kind", "pve_reconcile_failed")
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Service) pveAdmin() *PveAdmin {
	return &PveAdmin{DB: s.db, Vault: s.vault, Now: s.clock, Log: s.log, AuthorizeRepin: s.authorizePVERepin,
		Mutations: s.pveMutations(),
		RevokeGrants: func(remoteID, reason string) error {
			// Trust, credential and state changes also void every mutation
			// permit of the remote, including one whose job is in flight.
			s.auth.RevokeProviderMutations(remoteID, reason)
			_, err := s.auth.RevokeProviderGrants(remoteID, reason)
			return err
		}}
}

func pveAdminProto(r executordb.PveRemote) *pb.PVEAdminRemote {
	out := &pb.PVEAdminRemote{RemoteId: r.RemoteID, Name: r.Name, Kind: string(r.Kind), TrustPin: r.TrustPin, TrustGeneration: r.TrustGeneration, State: string(r.State), ReadRef: r.Credentials.ReadRef, ReadVersion: r.Credentials.ReadVersion, ActionRef: r.Credentials.ActionRef, ActionVersion: r.Credentials.ActionVersion, UpdatedAtUnix: r.UpdatedAt.Unix(), Site: r.Site}
	for _, ep := range r.Endpoints {
		out.Endpoints = append(out.Endpoints, &pb.PVEEndpoint{Host: ep.Host, Port: uint32(ep.Port)})
	}
	return out
}

func pveEndpointsFromProto(in []*pb.PVEEndpoint) ([]pvecontract.Endpoint, error) {
	if len(in) == 0 || len(in) > pvecontract.MaxEndpointsPerRemote {
		return nil, status.Error(codes.InvalidArgument, "invalid pve endpoint count")
	}
	out := make([]pvecontract.Endpoint, 0, len(in))
	for _, ep := range in {
		if ep.GetPort() == 0 || ep.GetPort() > 65535 {
			return nil, status.Error(codes.InvalidArgument, "invalid pve endpoint port")
		}
		out = append(out, pvecontract.Endpoint{Host: ep.GetHost(), Port: uint16(ep.GetPort())})
	}
	return out, nil
}

func pveRPCError(err error) error {
	switch {
	case errors.Is(err, vault.ErrLocked), errors.Is(err, ErrPveApprovalRequired), errors.Is(err, executordb.ErrRemoteState):
		return status.Error(codes.FailedPrecondition, "pve operation requires an unlocked vault and valid remote state or approval")
	case errors.Is(err, executordb.ErrRemoteNotFound):
		return status.Error(codes.NotFound, "pve remote not found")
	case errors.Is(err, executordb.ErrSecretVersion), errors.Is(err, vault.ErrConcurrentChange):
		return status.Error(codes.Aborted, "pve remote changed; retry")
	case errors.Is(err, ErrPveTokenFormat), errors.Is(err, ErrPveTokenRejected), errors.Is(err, ErrPveTokenInvalid), errors.Is(err, ErrPvePurpose), errors.Is(err, ErrPvePinMismatch), errors.Is(err, pvecontract.ErrInvalid), errors.Is(err, executordb.ErrInvalid):
		return status.Error(codes.InvalidArgument, "pve token, profile, trust confirmation or remote is invalid")
	default:
		return status.Error(codes.Internal, "pve operation failed")
	}
}

// ProbePVERemote probes validated endpoints inside the unlocked executor.
func (s *Service) ProbePVERemote(ctx context.Context, in *pb.ProbePVERemoteRequest) (*pb.ProbePVERemoteResponse, error) {
	s.pveMu.Lock()
	defer s.pveMu.Unlock()
	a := s.pveAdmin()
	if err := a.checkDeps(); err != nil {
		return nil, pveRPCError(err)
	}
	eps, err := pveEndpointsFromProto(in.GetEndpoints())
	if err != nil {
		return nil, err
	}
	// Apply the same kind, host, duplicate and endpoint limits as AddRemote.
	r, err := pvecontract.ValidateRemote(pvecontract.Remote{RemoteID: "probe", Kind: pvecontract.Kind(in.GetKind()), Endpoints: eps, TrustPin: strings.Repeat("0", 64), TrustGeneration: 1})
	if err != nil {
		return nil, pveRPCError(err)
	}
	res, err := a.probeFn()(ctx, r.Endpoints)
	if err != nil {
		return nil, pveRPCError(err)
	}
	pin, _, err := res.TrustIdentity(r.Kind)
	if err != nil {
		return nil, pveRPCError(err)
	}
	out := &pb.ProbePVERemoteResponse{TrustPin: pin}
	for _, ep := range res.Endpoints {
		out.Endpoints = append(out.Endpoints, &pb.PVEProbeEndpoint{Host: ep.Host, Port: uint32(ep.Port), LeafFingerprint: ep.LeafFingerprint, CaFingerprint: ep.CAFingerprint})
	}
	return out, nil
}

// AddPVERemote stores tokens only in the executor and records the peer UID.
func (s *Service) AddPVERemote(ctx context.Context, in *pb.AddPVERemoteRequest) (*pb.AddPVERemoteResponse, error) {
	s.pveMu.Lock()
	defer s.pveMu.Unlock()
	defer clear(in.GetReadToken())
	defer clear(in.GetActionToken())
	eps, err := pveEndpointsFromProto(in.GetEndpoints())
	if err != nil {
		return nil, err
	}
	r, err := s.pveAdmin().AddRemote(ctx, PveAddRemote{RemoteID: in.GetRemoteId(), Name: in.GetName(), Kind: pvecontract.Kind(in.GetKind()), Endpoints: eps, ConfirmedPin: in.GetConfirmedPin(), ReadToken: in.GetReadToken(), ActionToken: in.GetActionToken(), By: callerName(ctx)})
	if err != nil {
		return nil, pveRPCError(err)
	}
	return &pb.AddPVERemoteResponse{Remote: pveAdminProto(r)}, nil
}

// RotatePVEToken atomically replaces a purpose's encrypted credential.
func (s *Service) RotatePVEToken(ctx context.Context, in *pb.RotatePVETokenRequest) (*pb.RotatePVETokenResponse, error) {
	s.pveMu.Lock()
	defer s.pveMu.Unlock()
	defer clear(in.GetToken())
	r, err := s.pveAdmin().RotateToken(ctx, PveRotateToken{RemoteID: in.GetRemoteId(), Purpose: in.GetPurpose(), Token: in.GetToken(), By: callerName(ctx)})
	if err != nil {
		return nil, pveRPCError(err)
	}
	return &pb.RotatePVETokenResponse{Remote: pveAdminProto(r)}, nil
}

// RemovePVERemote disables and tombstones a remote after removing custody.
func (s *Service) RemovePVERemote(ctx context.Context, in *pb.RemovePVERemoteRequest) (*pb.RemovePVERemoteResponse, error) {
	s.pveMu.Lock()
	defer s.pveMu.Unlock()
	r, err := s.pveAdmin().RemoveRemote(ctx, PveRemove{RemoteID: in.GetRemoteId(), By: callerName(ctx)})
	if err != nil {
		return nil, pveRPCError(err)
	}
	return &pb.RemovePVERemoteResponse{Remote: pveAdminProto(r)}, nil
}

// SetPVERemoteSite records the admin-set site marker of a remote.
func (s *Service) SetPVERemoteSite(ctx context.Context, in *pb.SetPVERemoteSiteRequest) (*pb.SetPVERemoteSiteResponse, error) {
	s.pveMu.Lock()
	defer s.pveMu.Unlock()
	r, err := s.pveAdmin().SetSite(ctx, PveSetSite{RemoteID: in.GetRemoteId(), Site: in.GetSite(), By: callerName(ctx)})
	if err != nil {
		return nil, pveRPCError(err)
	}
	return &pb.SetPVERemoteSiteResponse{Remote: pveAdminProto(r)}, nil
}

// ListPVEAdminRemotes lists credential references, never their values.
func (s *Service) ListPVEAdminRemotes(ctx context.Context, _ *pb.ListPVEAdminRemotesRequest) (*pb.ListPVEAdminRemotesResponse, error) {
	s.pveMu.Lock()
	defer s.pveMu.Unlock()
	rows, err := s.pveAdmin().ListRemotes(ctx)
	if err != nil {
		return nil, pveRPCError(err)
	}
	out := &pb.ListPVEAdminRemotesResponse{}
	for _, r := range rows {
		out.Remotes = append(out.Remotes, pveAdminProto(r))
	}
	return out, nil
}

func pveRepinBinding(r executordb.PveRemote, newPin string) ([]byte, canonical.Target, error) {
	params, err := json.Marshal(struct {
		Remote executordb.PveRemote `json:"remote"`
		NewPin string               `json:"new_pin"`
	}{r, newPin})
	// The permit target uses the same 32-byte fingerprint encoding as the
	// existing authority; the parameters retain its PVE identity and kind.
	fp, decodeErr := hex.DecodeString(r.TrustPin)
	if err != nil || decodeErr != nil {
		return nil, canonical.Target{}, ErrPveApprovalRequired
	}
	target := canonical.Target{HostID: PveVaultID(r.RemoteID, "trust"), HostKeyFingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(fp)}
	return params, target, nil
}

// ProposePVERepin creates an exact HIGH approval; probing sends no token.
func (s *Service) ProposePVERepin(ctx context.Context, in *pb.ProposePVERepinRequest) (*pb.ProposePVERepinResponse, error) {
	s.pveMu.Lock()
	defer s.pveMu.Unlock()
	a := s.pveAdmin()
	if err := a.checkDeps(); err != nil {
		return nil, pveRPCError(err)
	}
	r, ok, err := s.db.GetRemote(in.GetRemoteId())
	if err != nil {
		return nil, pveRPCError(err)
	}
	if !ok || r.State == executordb.StateRemoved {
		return nil, pveRPCError(executordb.ErrRemoteNotFound)
	}
	if r.TrustPin != in.GetOldPin() || !pvecontract.ValidTrustPin(in.GetConfirmedNewPin()) || r.TrustPin == in.GetConfirmedNewPin() {
		return nil, pveRPCError(ErrPvePinMismatch)
	}
	probe, err := a.probeFn()(ctx, r.Endpoints)
	if err != nil {
		return nil, pveRPCError(err)
	}
	pin, _, err := probe.TrustIdentity(r.Kind)
	if err != nil || pin != in.GetConfirmedNewPin() {
		return nil, pveRPCError(ErrPvePinMismatch)
	}
	params, target, err := pveRepinBinding(r, pin)
	if err != nil {
		return nil, pveRPCError(err)
	}
	ph, err := canonical.HashParameters(params)
	if err != nil {
		return nil, pveRPCError(err)
	}
	id, err := newExecutionID()
	if err != nil {
		return nil, pveRPCError(err)
	}
	rq := canonical.Request{ExecutionID: id, ActionID: pveRepinAction, ModuleVersion: repinVersion, ArtifactSHA256: sha256Hex(pveRepinArtifact), ParametersHash: ph, CredentialRefs: []string{r.Credentials.ReadRef}, RiskClass: canonical.RiskHigh, StagePlanHash: stagePlanRepin, ExpiryUnix: s.clock().Add(repinLifetime).Unix(), ResolvedTargets: []canonical.Target{target}}
	res, err := s.auth.ProposeAtLeastMinimum(rq, params)
	if err != nil {
		return nil, toStatus(err)
	}
	out, err := s.permitResponse(res.Permit)
	if err != nil {
		return nil, err
	}
	return &pb.ProposePVERepinResponse{Permit: out}, nil
}

func (s *Service) authorizePVERepin(_ context.Context, r executordb.PveRemote, in PveRepin) error {
	d, err := canonical.ParseDigest(in.ApprovalDigest)
	if err != nil {
		return ErrPveApprovalRequired
	}
	params, target, err := pveRepinBinding(r, in.ConfirmedNewPin)
	if err != nil {
		return err
	}
	_, err = s.auth.AuthorizeGrant(d, permit.Run{HostID: target.HostID, HostKeyFingerprint: target.HostKeyFingerprint, ActionID: pveRepinAction, ModuleVersion: repinVersion, Artifact: pveRepinArtifact, ParametersJSON: params, CredentialRef: r.Credentials.ReadRef})
	if err != nil {
		return ErrPveApprovalRequired
	}
	return nil
}

// CommitPVERepin consumes the approved binding before changing trust.
func (s *Service) CommitPVERepin(ctx context.Context, in *pb.CommitPVERepinRequest) (*pb.CommitPVERepinResponse, error) {
	s.pveMu.Lock()
	defer s.pveMu.Unlock()
	r, err := s.pveAdmin().Repin(ctx, PveRepin{RemoteID: in.GetRemoteId(), OldPin: in.GetOldPin(), ConfirmedNewPin: in.GetConfirmedNewPin(), ApprovalDigest: in.GetExecutionDigest(), By: callerName(ctx)})
	if err != nil {
		return nil, pveRPCError(err)
	}
	return &pb.CommitPVERepinResponse{Remote: pveAdminProto(r)}, nil
}

// pveGuestPowerLifetime is how long a proposed guest power permit can be
// approved and run.
const pveGuestPowerLifetime = 15 * time.Minute

// pveGuestPower returns the guest power actions on the executor's single
// mutation engine. The proposal evaluates the full executor floor itself
// (NewGuestPowerRiskFloor over the executor's criticality records and
// registry links); the authority re-evaluates it on approval and run
// authorization when its risk policy reads the same bindings
// (SetPveGuestPowerBindings).
func (s *Service) pveGuestPower() (*PveGuestPower, error) {
	m := s.pveMutations()
	next, err := riskpolicy.New(s.db)
	if err != nil {
		return nil, err
	}
	b := s.pveGuestPowerBindings
	if b == nil {
		b = &m.powerBindings
	}
	return &PveGuestPower{Mutations: m, Bindings: b, Floor: NewGuestPowerRiskFloor(next, s.db, b)}, nil
}

func guestPowerRequestFromProto(in *pb.PVEGuestPowerTarget) (PveGuestPowerRequest, error) {
	if in == nil || in.GetTimeoutSec() > pveapi.MaxPowerTimeoutSec {
		return PveGuestPowerRequest{}, ErrPveGuestPowerVerb
	}
	return PveGuestPowerRequest{RemoteID: in.GetRemoteId(), Kind: in.GetKind(), Node: in.GetNode(), VMID: in.GetVmid(),
		Verb: in.GetVerb(), TimeoutSec: int(in.GetTimeoutSec())}, nil
}

// pveGuestPowerRPCError maps guest power errors to fixed status texts; no
// remote text reaches the caller.
func pveGuestPowerRPCError(err error) error {
	switch {
	case errors.Is(err, ErrPveGuestPowerVerb), errors.Is(err, ErrPveMutationRequest):
		return status.Error(codes.InvalidArgument, "pve guest power: unsupported verb, kind, timeout or target")
	case errors.Is(err, ErrPveGuestState):
		return status.Error(codes.FailedPrecondition, "pve guest power: the guest is not running")
	case errors.Is(err, ErrPveTargetChanged), errors.Is(err, ErrPveRemoteChanged):
		return status.Error(codes.FailedPrecondition, "pve guest power: the guest or remote changed; propose again")
	case errors.Is(err, ErrPveReadOnly):
		return status.Error(codes.FailedPrecondition, "pve guest power: the remote has no action credential")
	case errors.Is(err, ErrPveGuestPowerRisk):
		return status.Error(codes.Internal, "pve guest power: risk floor unavailable")
	case errors.Is(err, ErrPveTargetBusy), errors.Is(err, ErrPveGuestPowerBusy):
		return status.Error(codes.Unavailable, "pve guest power: another mutation of the guest is in progress")
	case errors.Is(err, ErrPveMutationDenied):
		return status.Error(codes.PermissionDenied, "pve guest power: no approved permit covers this action")
	case errors.Is(err, vault.ErrLocked):
		return status.Error(codes.FailedPrecondition, "pve guest power requires an unlocked vault")
	case errors.Is(err, executordb.ErrRemoteNotFound):
		return status.Error(codes.NotFound, "pve remote not found")
	default:
		return status.Error(codes.Internal, "pve guest power failed")
	}
}

// ProposePVEGuestPower proposes one typed power action on one exact,
// running guest. The risk is the executor's floor; the caller's input
// cannot lower it.
func (s *Service) ProposePVEGuestPower(ctx context.Context, in *pb.ProposePVEGuestPowerRequest) (*pb.ProposePVEGuestPowerResponse, error) {
	req, err := guestPowerRequestFromProto(in.GetTarget())
	if err != nil {
		return nil, pveGuestPowerRPCError(err)
	}
	g, err := s.pveGuestPower()
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "pve guest power: pve mutations are not available")
	}
	if g.Mutations.Client == nil {
		// Defensive: pveMutations always wires the production client.
		return nil, status.Error(codes.FailedPrecondition, "pve guest power: PVE mutation client not configured")
	}
	id, err := newExecutionID()
	if err != nil {
		return nil, status.Error(codes.Internal, "execution id")
	}
	p, err := g.Propose(ctx, req, id, s.clock().Add(pveGuestPowerLifetime))
	if err != nil {
		if permit.CodeOf(err) != "" {
			return nil, toStatus(err)
		}
		return nil, pveGuestPowerRPCError(err)
	}
	out, err := s.permitResponse(p)
	if err != nil {
		return nil, err
	}
	return &pb.ProposePVEGuestPowerResponse{Permit: out}, nil
}

// pveGuestSnapshot returns the guest snapshot actions on the executor's
// single mutation engine. The proposal evaluates the full executor floor
// itself (GuestSnapshotRiskFloor over the executor's criticality records
// and registry links); the authority re-evaluates it on approval and run
// authorization when its risk policy (NewExecutorRiskPolicy) reads the
// same bindings (SetPveGuestPowerBindings), exactly like guest power.
func (s *Service) pveGuestSnapshot() (*PveGuestSnapshot, error) {
	m := s.pveMutations()
	next, err := riskpolicy.New(s.db)
	if err != nil {
		return nil, err
	}
	b := s.pveGuestPowerBindings
	if b == nil {
		b = &m.powerBindings
	}
	floor := NewGuestSnapshotRiskFloor(next, s.db, b)
	return &PveGuestSnapshot{Mutations: m, Bindings: b, Floor: floor}, nil
}

func guestSnapshotRequestFromProto(in *pb.PVEGuestSnapshotTarget) (PveGuestSnapshotRequest, error) {
	if in == nil {
		return PveGuestSnapshotRequest{}, ErrPveSnapshotRequest
	}
	r := PveGuestSnapshotRequest{RemoteID: in.GetRemoteId(), Kind: in.GetKind(), Node: in.GetNode(), VMID: in.GetVmid(),
		Op: in.GetOp(), Name: in.GetName(), VMState: in.GetVmstate(), Start: in.GetStart()}
	if e := in.GetExpect(); e != nil {
		r.Expect = &PveSnapshotIdentity{Name: e.GetName(), SnapTimeUnix: e.GetSnaptimeUnix(), Parent: e.GetParent(), VMState: e.GetVmstate()}
	}
	return r, nil
}

// pveGuestSnapshotRPCError maps guest snapshot errors to fixed status
// texts; no remote text reaches the caller.
func pveGuestSnapshotRPCError(err error) error {
	switch {
	case errors.Is(err, ErrPveSnapshotRequest), errors.Is(err, ErrPveMutationRequest):
		return status.Error(codes.InvalidArgument, "pve guest snapshot: unsupported op, name, flag, identity or target")
	case errors.Is(err, ErrPveSnapshotStorage):
		return status.Error(codes.FailedPrecondition, "pve guest snapshot: a disk is not on verified snapshot-capable storage")
	case errors.Is(err, ErrPveSnapshotChanged):
		return status.Error(codes.FailedPrecondition, "pve guest snapshot: the snapshot, disk set or guest state changed; propose again")
	case errors.Is(err, ErrPveSnapshotState):
		return status.Error(codes.FailedPrecondition, "pve guest snapshot: the guest is locked, not running for RAM, or its lists are unreadable")
	case errors.Is(err, ErrPveSnapshotUnavailable):
		return status.Error(codes.FailedPrecondition, "pve guest snapshot: not available")
	case errors.Is(err, ErrPveSnapshotRisk):
		return status.Error(codes.Internal, "pve guest snapshot: risk floor unavailable")
	case errors.Is(err, ErrPveTargetChanged), errors.Is(err, ErrPveRemoteChanged):
		return status.Error(codes.FailedPrecondition, "pve guest snapshot: the guest or remote changed; propose again")
	case errors.Is(err, ErrPveReadOnly):
		return status.Error(codes.FailedPrecondition, "pve guest snapshot: the remote has no action credential")
	case errors.Is(err, ErrPveTargetBusy), errors.Is(err, ErrPveGuestPowerBusy):
		return status.Error(codes.Unavailable, "pve guest snapshot: another mutation of the guest is in progress")
	case errors.Is(err, ErrPveMutationDenied):
		return status.Error(codes.PermissionDenied, "pve guest snapshot: no approved permit covers this action")
	case errors.Is(err, vault.ErrLocked):
		return status.Error(codes.FailedPrecondition, "pve guest snapshot requires an unlocked vault")
	case errors.Is(err, executordb.ErrRemoteNotFound):
		return status.Error(codes.NotFound, "pve remote not found")
	default:
		return status.Error(codes.Internal, "pve guest snapshot failed")
	}
}

// ProposePVEGuestSnapshot proposes one typed snapshot action on one exact
// guest. The executor binds the disk set (create) or the exact snapshot
// and rollback side effects (delete, rollback) and sets the risk; the
// caller's input cannot lower it.
func (s *Service) ProposePVEGuestSnapshot(ctx context.Context, in *pb.ProposePVEGuestSnapshotRequest) (*pb.ProposePVEGuestSnapshotResponse, error) {
	req, err := guestSnapshotRequestFromProto(in.GetTarget())
	if err != nil {
		return nil, pveGuestSnapshotRPCError(err)
	}
	g, err := s.pveGuestSnapshot()
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "pve guest snapshot: pve mutations are not available")
	}
	id, err := newExecutionID()
	if err != nil {
		return nil, status.Error(codes.Internal, "execution id")
	}
	p, err := g.Propose(ctx, req, id, s.clock().Add(pveGuestPowerLifetime))
	if err != nil {
		if permit.CodeOf(err) != "" {
			return nil, toStatus(err)
		}
		return nil, pveGuestSnapshotRPCError(err)
	}
	out, err := s.permitResponse(p)
	if err != nil {
		return nil, err
	}
	resp := &pb.ProposePVEGuestSnapshotResponse{Permit: out}
	var doc struct {
		Parameters pveSnapshotParams `json:"parameters"`
	}
	if err := json.Unmarshal(p.Parameters, &doc); err != nil {
		return nil, status.Error(codes.Internal, "pve guest snapshot: bound parameters unreadable")
	}
	if sn := doc.Parameters.Snapshot; sn != nil {
		resp.Snapshot = &pb.PVESnapshotIdentity{Name: sn.Name, SnaptimeUnix: sn.SnapTimeUnix, Parent: sn.Parent, Vmstate: sn.VMState}
	}
	if rb := doc.Parameters.Rollback; rb != nil {
		resp.GuestRunsAfter = rb.GuestRunsAfter
	}
	return resp, nil
}

// CommitPVEGuestSnapshot runs the approved snapshot action. The bound
// snapshot, disk set and guest state are checked again before the step is
// sent. Once a step is recorded the response carries its durable state;
// an uncertain step is reconciled, never resent.
func (s *Service) CommitPVEGuestSnapshot(ctx context.Context, in *pb.CommitPVEGuestSnapshotRequest) (*pb.CommitPVEGuestSnapshotResponse, error) {
	req, err := guestSnapshotRequestFromProto(in.GetTarget())
	if err != nil {
		return nil, pveGuestSnapshotRPCError(err)
	}
	d, err := canonical.ParseDigest(in.GetExecutionDigest())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "pve guest snapshot: malformed execution digest")
	}
	req.Digest = d
	g, err := s.pveGuestSnapshot()
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "pve guest snapshot: pve mutations are not available")
	}
	res, err := g.Run(ctx, req)
	if len(res.Steps) == 0 || errors.Is(err, ErrPveJobStore) {
		if err == nil {
			err = ErrPveJobStore
		}
		return nil, pveGuestSnapshotRPCError(err)
	}
	out := &pb.CommitPVEGuestSnapshotResponse{ExecutionId: res.ExecutionID}
	for _, st := range res.Steps {
		out.Steps = append(out.Steps, &pb.PVEGuestPowerStep{State: st.State, Upid: st.UPID, TaskType: st.TaskType})
	}
	return out, nil
}

// CommitPVEGuestPower runs the approved power action. The guest's identity
// and running state are checked again before the step is sent. Once a step
// is recorded the response carries its durable state (succeeded, failed,
// running or reconciling); an uncertain step is reconciled, never resent.
func (s *Service) CommitPVEGuestPower(ctx context.Context, in *pb.CommitPVEGuestPowerRequest) (*pb.CommitPVEGuestPowerResponse, error) {
	req, err := guestPowerRequestFromProto(in.GetTarget())
	if err != nil {
		return nil, pveGuestPowerRPCError(err)
	}
	d, err := canonical.ParseDigest(in.GetExecutionDigest())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "pve guest power: malformed execution digest")
	}
	req.Digest = d
	g, err := s.pveGuestPower()
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "pve guest power: pve mutations are not available")
	}
	if g.Mutations.Client == nil {
		// Defensive: pveMutations always wires the production client.
		return nil, status.Error(codes.FailedPrecondition, "pve guest power: PVE mutation client not configured")
	}
	res, err := g.Run(ctx, req)
	if len(res.Steps) == 0 || errors.Is(err, ErrPveJobStore) {
		if err == nil {
			err = ErrPveJobStore
		}
		return nil, pveGuestPowerRPCError(err)
	}
	out := &pb.CommitPVEGuestPowerResponse{ExecutionId: res.ExecutionID}
	for _, st := range res.Steps {
		out.Steps = append(out.Steps, &pb.PVEGuestPowerStep{State: st.State, Upid: st.UPID, TaskType: st.TaskType})
	}
	return out, nil
}

// Limits of a provisioning spec from the RPC, checked before parsing; the
// provisioner validates every field again (PveProvisioner.config).
const (
	// maxPveProvisionSSHKeys bounds the further keys (the automation key
	// takes one of pveapi.MaxSSHKeys).
	maxPveProvisionSSHKeys = pveapi.MaxSSHKeys - 1
	// maxPveProvisionAddrBytes bounds one textual address or prefix.
	maxPveProvisionAddrBytes = 64
)

// errPveProvisionSpec is a malformed provisioning spec from the RPC.
var errPveProvisionSpec = fmt.Errorf("%w: malformed spec", ErrPveProvisionInvalid)

func parsePveAddr(s string) (netip.Addr, error) {
	if len(s) > maxPveProvisionAddrBytes {
		return netip.Addr{}, errPveProvisionSpec
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, errPveProvisionSpec
	}
	return a, nil
}

// provisionRequestFromProto converts an untrusted spec. Counts and numeric
// ranges are checked before conversion; everything else is validated by
// the provisioner.
func provisionRequestFromProto(in *pb.PVEGuestProvisionSpec) (PveProvisionRequest, error) {
	if in == nil || in.GetTemplate() == nil || in.GetNic() == nil {
		return PveProvisionRequest{}, errPveProvisionSpec
	}
	if len(in.GetSshKeys()) > maxPveProvisionSSHKeys || len(in.GetNameservers()) > pveapi.MaxNameservers ||
		len(in.GetSearchDomains()) > pveapi.MaxSearchDomains ||
		in.GetCores() > pveapi.MaxCores || in.GetMemoryMib() > pveapi.MaxMemoryMiB || in.GetDiskGib() > pveapi.MaxDiskGiB ||
		in.GetNic().GetVlan() > pveapi.MaxVLANTag {
		return PveProvisionRequest{}, errPveProvisionSpec
	}
	t, nic := in.GetTemplate(), in.GetNic()
	req := PveProvisionRequest{
		RemoteID: in.GetRemoteId(), Node: in.GetNode(), Storage: in.GetStorage(),
		Template: PveTemplateBinding{
			PveTemplateKey: PveTemplateKey{RemoteID: t.GetRemoteId(), Node: t.GetNode(), Storage: t.GetStorage(), ImageID: t.GetImageId()},
			VMID:           t.GetVmid(), Generation: t.GetGeneration(), SourceSHA256: t.GetSourceSha256(),
		},
		VMID: in.GetVmid(), Name: in.GetName(), Cores: int(in.GetCores()), MemoryMiB: int(in.GetMemoryMib()),
		Disk: in.GetDisk(), DiskGiB: int64(in.GetDiskGib()),
		NIC:    PveProvisionNIC{Model: nic.GetModel(), Bridge: nic.GetBridge(), VLAN: int(nic.GetVlan()), MAC: nic.GetMac()},
		CIUser: in.GetCiUser(), SSHKeys: append([]string(nil), in.GetSshKeys()...),
		SearchDomains: append([]string(nil), in.GetSearchDomains()...),
		PasswordID:    in.GetPasswordId(), Start: in.GetStart(), AutomationCredentialRef: in.GetAutomationCredentialRef(),
	}
	for _, s := range in.GetNameservers() {
		a, err := parsePveAddr(s)
		if err != nil {
			return PveProvisionRequest{}, err
		}
		req.Nameservers = append(req.Nameservers, a)
	}
	if b := in.GetIpam(); b != nil {
		if b.GetVlan() > pveapi.MaxVLANTag || len(b.GetPrefix()) > maxPveProvisionAddrBytes {
			return PveProvisionRequest{}, errPveProvisionSpec
		}
		prefix, err := netip.ParsePrefix(b.GetPrefix())
		if err != nil {
			return PveProvisionRequest{}, errPveProvisionSpec
		}
		addr, err := parsePveAddr(b.GetAddress())
		if err != nil {
			return PveProvisionRequest{}, err
		}
		var gw netip.Addr
		if b.GetGateway() != "" {
			if gw, err = parsePveAddr(b.GetGateway()); err != nil {
				return PveProvisionRequest{}, err
			}
		}
		req.IPAM = &PveIPAMBinding{NetworkID: b.GetNetworkId(), Pool: b.GetPool(), Prefix: prefix, Gateway: gw,
			VLAN: int(b.GetVlan()), Address: addr, ReservedBy: b.GetReservedBy(), ReservedAtUnix: b.GetReservedAtUnix()}
	}
	return req, nil
}

// pveGuestProvisionRPCError maps provisioning errors to fixed status
// texts; no remote text reaches the caller.
func pveGuestProvisionRPCError(err error) error {
	switch {
	case permit.CodeOf(err) != "":
		return toStatus(err)
	// The automation credential refusals come before the generic spec
	// error they are wrapped in, so the caller can tell them apart.
	case errors.Is(err, ErrPveAutomationCredential):
		return status.Error(codes.PermissionDenied, "pve guest provision: the automation credential ref does not name the designated NOS automation key")
	case errors.Is(err, keyring.ErrLocked):
		return status.Error(codes.FailedPrecondition, "pve guest provision: keyring locked; unlock the executor")
	case errors.Is(err, keyring.ErrUnknownRef):
		return status.Error(codes.NotFound, "pve guest provision: the NOS automation credential is not in the keyring")
	case errors.Is(err, ErrPveProvisionInvalid), errors.Is(err, ErrPveProvisionUnsupported), errors.Is(err, ErrPveMutationRequest):
		return status.Error(codes.InvalidArgument, "pve guest provision: invalid or unsupported spec, template, network, key or password id")
	case errors.Is(err, ErrPveTemplateNotPrepared), errors.Is(err, ErrPveTemplateChanged):
		return status.Error(codes.FailedPrecondition, "pve guest provision: the template is not prepared or changed; prepare it again")
	case errors.Is(err, ErrPveVMIDTaken):
		return status.Error(codes.FailedPrecondition, "pve guest provision: the vmid is in use or not reserved for this execution")
	case errors.Is(err, ErrPveInventoryIncomplete):
		return status.Error(codes.FailedPrecondition, "pve guest provision: the cluster guest list is incomplete; a free vmid cannot be proven")
	case errors.Is(err, ErrPveGuestPassword):
		return status.Error(codes.FailedPrecondition, "pve guest provision: the guest password is missing or changed")
	case errors.Is(err, ErrPveTargetChanged), errors.Is(err, ErrPveRemoteChanged):
		return status.Error(codes.FailedPrecondition, "pve guest provision: the node, storage or remote changed; propose again")
	case errors.Is(err, ErrPveReadOnly):
		return status.Error(codes.FailedPrecondition, "pve guest provision: the remote has no action credential")
	case errors.Is(err, ErrPveTargetBusy):
		return status.Error(codes.Unavailable, "pve guest provision: another mutation of the node is in progress")
	case errors.Is(err, ErrPveMutationDenied), errors.Is(err, ErrPvePermitFinal), errors.Is(err, ErrPveMutationAlreadyRun):
		return status.Error(codes.PermissionDenied, "pve guest provision: no approved permit covers this provisioning")
	case errors.Is(err, vault.ErrLocked):
		return status.Error(codes.FailedPrecondition, "pve guest provision requires an unlocked vault")
	case errors.Is(err, executordb.ErrRemoteNotFound):
		return status.Error(codes.NotFound, "pve remote not found")
	default:
		return status.Error(codes.Internal, "pve guest provision failed")
	}
}

// pveProvisionRunOutcome reports whether err is the outcome of steps this
// run dispatched (reported with their durable states), not a refusal.
func pveProvisionRunOutcome(err error) bool {
	if errors.Is(err, ErrPveMutationDenied) || errors.Is(err, ErrPveJobStore) || permit.CodeOf(err) != "" {
		return false
	}
	return errors.Is(err, ErrPveStepFailed) || errors.Is(err, ErrPveStepRunning) || errors.Is(err, ErrPveDispatchUncertain)
}

// errPveProvisionUnavailable is returned when the executor has no
// provisioner (no data directory).
var errPveProvisionUnavailable = status.Error(codes.FailedPrecondition, "pve guest provision: provisioning is not available on this executor")

// ProposePVEGuestProvision proposes one pve.guest.provision (ADR 0008
// section 3; roles server and admin). The executor binds the template
// record, reserves the VMID against the live guest list and registers the
// permit at its own floor (base MEDIUM; the authority's risk policy raises
// it for criticality). The caller's input cannot lower it.
func (s *Service) ProposePVEGuestProvision(ctx context.Context, in *pb.ProposePVEGuestProvisionRequest) (*pb.ProposePVEGuestProvisionResponse, error) {
	req, err := provisionRequestFromProto(in.GetSpec())
	if err != nil {
		return nil, pveGuestProvisionRPCError(err)
	}
	p := s.pveProvisioner()
	if p == nil {
		return nil, errPveProvisionUnavailable
	}
	id, err := newExecutionID()
	if err != nil {
		return nil, status.Error(codes.Internal, "execution id")
	}
	pp, err := p.ProposalRequest(ctx, req, id, canonical.RiskMedium, pveGuestProvisionStagePlan, s.clock().Add(pveGuestProvisionLifetime))
	if err != nil {
		return nil, pveGuestProvisionRPCError(err)
	}
	res, err := s.auth.ProposeAtLeastMinimum(pp.Request, pp.Parameters)
	if err != nil {
		// No permit: the reservation would only block the VMID.
		_ = p.VMIDs.ReleaseVMID(req.RemoteID, pp.VMID, id)
		return nil, pveGuestProvisionRPCError(err)
	}
	out, err := s.permitResponse(res.Permit)
	if err != nil {
		return nil, err
	}
	return &pb.ProposePVEGuestProvisionResponse{Permit: out, ExecutionId: id, Vmid: pp.VMID, CapacityWarnings: pp.Capacity.Warnings()}, nil
}

// CommitPVEGuestProvision runs an approved pve.guest.provision (roles
// server and admin). It runs only with the permit approved for exactly
// this spec, execution and VMID under the normal approval semantics; the
// provisioner rebuilds the parameters from fresh reads, so anything that
// changed refuses the permit. Once a step is recorded the response carries
// the durable step states; an uncertain step is reconciled, never resent.
// A failed run leaves the guest for inspection (guest_kept).
func (s *Service) CommitPVEGuestProvision(ctx context.Context, in *pb.CommitPVEGuestProvisionRequest) (*pb.CommitPVEGuestProvisionResponse, error) {
	req, err := provisionRequestFromProto(in.GetSpec())
	if err != nil {
		return nil, pveGuestProvisionRPCError(err)
	}
	d, err := canonical.ParseDigest(in.GetExecutionDigest())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "pve guest provision: malformed execution digest")
	}
	req.Digest, req.ExecutionID = d, in.GetExecutionId()
	p := s.pveProvisioner()
	if p == nil {
		return nil, errPveProvisionUnavailable
	}
	res, err := p.Provision(ctx, req)
	// Only this run's outcome is reported as step states: success, or a
	// step that failed, is still running or is uncertain. Any other error
	// (no approved permit, the permit already used, a changed spec) is
	// refused as such, even when the execution has steps from an earlier
	// run, so a replay never reads like a run.
	if len(res.Steps) == 0 || (err != nil && !pveProvisionRunOutcome(err)) {
		if err == nil {
			err = ErrPveJobStore
		}
		return nil, pveGuestProvisionRPCError(err)
	}
	out := &pb.CommitPVEGuestProvisionResponse{ExecutionId: res.ExecutionID, Vmid: res.VMID,
		GuestConfigDigest: res.GuestConfigDigest, GuestKept: res.GuestKept}
	for _, st := range res.Steps {
		out.Steps = append(out.Steps, &pb.PVEGuestPowerStep{State: string(st.State), Upid: st.UPID, TaskType: st.TaskType})
	}
	return out, nil
}
