// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
)

// leaseCallAs runs fn behind the real peercred interceptor for method, as a
// peer that holds exactly role. It returns the interceptor's error when
// the role table refuses the call before fn runs.
func leaseCallAs(t *testing.T, role peercred.Role, method string, fn func(ctx context.Context) (any, error)) (any, error) {
	t.Helper()
	const uid uint32 = 41001
	policy := peercred.NewPolicy(map[uint32][]peercred.Role{uid: {role}}, MethodRoles())
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: peercred.AuthInfo{UID: uid}})
	return policy.UnaryInterceptor(nil)(ctx, nil, &grpc.UnaryServerInfo{FullMethod: method},
		func(ctx context.Context, _ any) (any, error) { return fn(ctx) })
}

// proposeAs proposes raw through the interceptor as role.
func (e *netDevGrantEnv) proposeAs(role peercred.Role, raw []byte) (*pb.ProposeReadGrantResponse, error) {
	e.t.Helper()
	out, err := leaseCallAs(e.t, role, pb.ExecutorService_ProposeReadGrant_FullMethodName, func(ctx context.Context) (any, error) {
		return e.svc.ProposeReadGrant(ctx, &pb.ProposeReadGrantRequest{GrantJson: raw})
	})
	if err != nil {
		return nil, err
	}
	return out.(*pb.ProposeReadGrantResponse), nil
}

// TestProposeReadGrantRolesIncludeAdmin (A1-5): ProposeReadGrant is the
// one role change of A1-5: {server, admin}. Side effect recorded here: the
// admin may now propose host and provider leases through the same RPC too
// (see TestAdminMayProposeHostLease). No other role reaches it.
func TestProposeReadGrantRolesIncludeAdmin(t *testing.T) {
	got := MethodRoles()[pb.ExecutorService_ProposeReadGrant_FullMethodName]
	if want := []peercred.Role{peercred.RoleServer, peercred.RoleAdmin}; !slices.Equal(got, want) {
		t.Fatalf("ProposeReadGrant roles %v, want %v", got, want)
	}
	for _, r := range []peercred.Role{peercred.RolePVECollector, peercred.RoleNetDevCollector} {
		_, err := leaseCallAs(t, r, pb.ExecutorService_ProposeReadGrant_FullMethodName, func(context.Context) (any, error) {
			t.Fatalf("%s reached ProposeReadGrant", r)
			return nil, nil
		})
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("%s: %v, want PermissionDenied", r, err)
		}
	}
	// The approval, commit and revocation paths are unchanged.
	for m, want := range map[string][]peercred.Role{
		pb.ExecutorService_CommitReadGrant_FullMethodName:     {peercred.RoleServer},
		pb.ExecutorService_ApproveReadGrantCLI_FullMethodName: {peercred.RoleAdmin},
		pb.ExecutorService_RevokeReadGrant_FullMethodName:     {peercred.RoleServer, peercred.RoleAdmin},
	} {
		if got := MethodRoles()[m]; !slices.Equal(got, want) {
			t.Errorf("%s roles %v, want %v", m, got, want)
		}
	}
}

// TestNetDeviceLeaseAdminOnlyProposal (A1-5, "admin-only proposal"): the
// admin proposes a device read lease and gets a pending grant that needs
// CLI approval; the same proposal from the server role is refused with
// PermissionDenied, before any registry lookup, and leaves nothing pending.
// A call without an authenticated caller is refused the same way.
func TestNetDeviceLeaseAdminOnlyProposal(t *testing.T) {
	e := newNetDevGrantEnv(t)
	raw := e.leaseDoc(e.target(netDevGrantDevice, schedgrant.NetDeviceReadCBSVersion))

	_, err := e.proposeAs(peercred.RoleServer, raw)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("server proposal: %v, want PermissionDenied", err)
	}
	if msg := status.Convert(err).Message(); strings.Contains(msg, netDevGrantDevice) || strings.Contains(msg, testNetDevPin) {
		t.Errorf("refusal %q carries device data", msg)
	}
	if _, err := e.svc.ProposeReadGrant(context.Background(), &pb.ProposeReadGrantRequest{GrantJson: raw}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("proposal without caller: %v, want PermissionDenied", err)
	}
	if p := e.svc.auth.PendingReadGrants(); len(p) != 0 {
		t.Fatalf("refused proposals left %d pending grants", len(p))
	}

	// The role check runs before the registry check: an unknown device
	// gives the server the same answer (no registry oracle).
	ghost := e.target(netDevGrantDevice, schedgrant.NetDeviceReadCBSVersion)
	ghost.DeviceID = "ghost-sw"
	if _, err := e.proposeAs(peercred.RoleServer, e.leaseDoc(ghost)); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("server proposal for unknown device: %v, want PermissionDenied", err)
	}

	pg, err := e.proposeAs(peercred.RoleAdmin, raw)
	if err != nil {
		t.Fatalf("admin proposal: %v", err)
	}
	if pg.GetApprovalRequirement() != pb.ApprovalRequirement_APPROVAL_REQUIREMENT_CLI_ONLY || len(pg.GetChallenge()) != 0 {
		t.Fatalf("admin device lease requirement %v challenge %d bytes, want CLI only", pg.GetApprovalRequirement(), len(pg.GetChallenge()))
	}
	p := e.svc.auth.PendingReadGrants()
	if len(p) != 1 || p[0].Digest != pg.GetGrantDigest() {
		t.Fatalf("pending grants %d, want the admin's lease", len(p))
	}

	// The server cannot approve it; the admin approves on the CLI path.
	if _, err := leaseCallAs(t, peercred.RoleServer, pb.ExecutorService_CommitReadGrant_FullMethodName, func(ctx context.Context) (any, error) {
		return e.svc.CommitReadGrant(ctx, &pb.CommitReadGrantRequest{GrantDigest: pg.GetGrantDigest(), AssertionJson: []byte(`{}`)})
	}); status.Code(err) == codes.OK {
		t.Fatal("server committed an admin-proposed device lease")
	}
	if _, err := leaseCallAs(t, peercred.RoleAdmin, pb.ExecutorService_ApproveReadGrantCLI_FullMethodName, func(ctx context.Context) (any, error) {
		return e.svc.ApproveReadGrantCLI(ctx, &pb.ApproveReadGrantCLIRequest{GrantDigest: pg.GetGrantDigest()})
	}); err != nil {
		t.Fatalf("admin CLI approval: %v", err)
	}
}

// TestServerRoleProposesHostAndProviderLeasesAsBefore: the device rule
// does not touch host or PVE leases; the server role proposes both as
// before (host: assertion-verified approval).
func TestServerRoleProposesHostAndProviderLeasesAsBefore(t *testing.T) {
	t.Run("host", func(t *testing.T) {
		e, _, raw := readRPCEnv(t, permit.ModeStandard)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		pg, err := readRPCClient(t, e.svc, peercred.RoleServer).ProposeReadGrant(ctx, &pb.ProposeReadGrantRequest{GrantJson: raw})
		if err != nil {
			t.Fatalf("server host lease: %v", err)
		}
		if pg.GetApprovalRequirement() != pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_VERIFIED || len(pg.GetChallenge()) == 0 {
			t.Fatalf("server host lease requirement %v, want assertion verified", pg.GetApprovalRequirement())
		}
	})
	t.Run("pve", func(t *testing.T) {
		e := newPveReadEnv(t, pvecontract.KindStandalone)
		raw := e.grantDoc("00000000-0000-4000-8000-0000000a1501", 2, "nodes")
		out, err := leaseCallAs(t, peercred.RoleServer, pb.ExecutorService_ProposeReadGrant_FullMethodName, func(ctx context.Context) (any, error) {
			return e.svc.ProposeReadGrant(ctx, &pb.ProposeReadGrantRequest{GrantJson: raw})
		})
		if err != nil {
			t.Fatalf("server PVE lease: %v", err)
		}
		if p := e.svc.auth.PendingReadGrants(); len(p) != 1 || p[0].Digest != out.(*pb.ProposeReadGrantResponse).GetGrantDigest() {
			t.Fatalf("pending grants %+v, want the server's PVE lease", p)
		}
	})
}

// TestAdminMayProposeHostLease records the side effect of the role change
// (decisions §5 B1): the admin reaches ProposeReadGrant for a host lease
// too, with the same approval requirement the server would get.
func TestAdminMayProposeHostLease(t *testing.T) {
	e, _, raw := readRPCEnv(t, permit.ModeStandard)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pg, err := readRPCClient(t, e.svc, peercred.RoleAdmin).ProposeReadGrant(ctx, &pb.ProposeReadGrantRequest{GrantJson: raw})
	if err != nil {
		t.Fatalf("admin host lease: %v", err)
	}
	if pg.GetApprovalRequirement() != pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_VERIFIED {
		t.Fatalf("admin host lease requirement %v", pg.GetApprovalRequirement())
	}
}

// TestNetDeviceLeaseOverThirtyDaysRefused: a device lease document whose
// lifetime exceeds 30 days is refused at proposal, also for the admin.
func TestNetDeviceLeaseOverThirtyDaysRefused(t *testing.T) {
	e := newNetDevGrantEnv(t)
	now := e.clock.Now()
	d := permit.ReadGrantDoc{
		Grant: permit.ReadGrantFormat, ID: roNetDevLeaseID, Issuer: "admin", CreatedUnix: now.Unix(),
		ExpiryUnix: now.Add(permit.ReadGrantMaxLifetime + time.Second).Unix(), Trigger: permit.TriggerScheduled,
		Actions: []permit.ReadGrantAction{}, MinIntervalS: 900, RunBudget: schedgrant.NetDeviceDefaultRunBudget,
		RateProfile:      schedgrant.NetDeviceReadProfile,
		NetDeviceTargets: []permit.NetDeviceTarget{e.target(netDevGrantDevice, schedgrant.NetDeviceReadCBSVersion)},
	}
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.proposeAs(peercred.RoleAdmin, raw); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("31-day lease: %v, want InvalidArgument", err)
	}
	if p := e.svc.auth.PendingReadGrants(); len(p) != 0 {
		t.Fatalf("refused lease left %d pending grants", len(p))
	}
}

// TestNetDevLeaseDocumentFromRegistry (A1-5): the admin helper builds the
// lease document from the registry's current pin, trust generation and
// credential version, with the device profile, 7 days by default and at
// most 30 days; the document is accepted by the admin's proposal.
func TestNetDevLeaseDocumentFromRegistry(t *testing.T) {
	e := newNetDevGrantEnv(t)
	a := e.svc.netDevAdmin()
	reads := []string{schedgrant.NetDeviceReadCBSVLANs, schedgrant.NetDeviceReadCBSVersion}
	lease, err := a.LeaseDocument(context.Background(), NetDevLeaseRequest{DeviceID: netDevGrantDevice, Reads: reads})
	if err != nil {
		t.Fatalf("lease document: %v", err)
	}
	want := e.target(netDevGrantDevice, schedgrant.NetDeviceReadCBSVLANs, schedgrant.NetDeviceReadCBSVersion)
	slices.Sort(want.Reads)
	d := lease.Doc
	switch {
	case d.RateProfile != schedgrant.NetDeviceReadProfile || d.Grant != permit.ReadGrantFormat:
		t.Errorf("profile %q format %q", d.RateProfile, d.Grant)
	case len(d.NetDeviceTargets) != 1:
		t.Fatalf("targets %+v", d.NetDeviceTargets)
	case d.ExpiryUnix-d.CreatedUnix != int64(permit.DefaultReadGrantLifetime/time.Second):
		t.Errorf("lifetime %ds, want 7 days", d.ExpiryUnix-d.CreatedUnix)
	case d.CreatedUnix != e.clock.Now().Unix():
		t.Errorf("created %d, want now", d.CreatedUnix)
	case len(d.Actions) != 0 || len(d.Targets) != 0 || len(d.ProviderTargets) != 0 || len(d.Credentials) != 0:
		t.Errorf("device lease binds other scope: %+v", d)
	}
	got := d.NetDeviceTargets[0]
	if got.DeviceID != want.DeviceID || got.TrustPin != want.TrustPin || got.TrustGeneration != want.TrustGeneration ||
		got.CredentialVersion != want.CredentialVersion || !slices.Equal(got.Reads, want.Reads) {
		t.Fatalf("target %+v, want the registry identity %+v", got, want)
	}
	if _, canon, digest, err := permit.ParseReadGrant(lease.JSON, e.clock.Now()); err != nil || digest != lease.Digest || string(canon) != string(lease.JSON) {
		t.Fatalf("lease JSON is not the canonical document: %v", err)
	}
	pg, err := e.proposeAs(peercred.RoleAdmin, lease.JSON)
	if err != nil || pg.GetGrantDigest() != lease.Digest {
		t.Fatalf("admin proposal of the built lease: %v", err)
	}

	// The lease follows the registry: after a re-pin the new document has
	// the new pin and trust generation.
	if _, err := e.db.BumpTrustGeneration(netDevGrantDevice, testNetDevPin2); err != nil {
		t.Fatal(err)
	}
	again, err := a.LeaseDocument(context.Background(), NetDevLeaseRequest{DeviceID: netDevGrantDevice, Reads: reads, Lifetime: 30 * 24 * time.Hour})
	if err != nil {
		t.Fatalf("lease after re-pin: %v", err)
	}
	if tg := again.Doc.NetDeviceTargets[0]; tg.TrustPin != testNetDevPin2 || tg.TrustGeneration != want.TrustGeneration+1 {
		t.Fatalf("target after re-pin %+v", tg)
	}
	if again.Doc.ExpiryUnix-again.Doc.CreatedUnix != int64(permit.ReadGrantMaxLifetime/time.Second) {
		t.Fatalf("30-day lifetime not kept")
	}
	if again.Doc.ID == d.ID {
		t.Fatal("two leases share an id")
	}
}

// TestNetDevLeaseDocumentRefusals: the helper refuses what the registry
// does not back and what ADR 0010 D4 does not allow.
func TestNetDevLeaseDocumentRefusals(t *testing.T) {
	cbs := schedgrant.NetDeviceReadCBSVersion
	for _, tc := range []struct {
		name  string
		setup func(*netDevGrantEnv)
		in    NetDevLeaseRequest
		want  error
	}{
		{name: "over 30 days", in: NetDevLeaseRequest{DeviceID: netDevGrantDevice, Reads: []string{cbs}, Lifetime: permit.ReadGrantMaxLifetime + time.Second}, want: ErrNetDevLeaseRequest},
		{name: "under 1 hour", in: NetDevLeaseRequest{DeviceID: netDevGrantDevice, Reads: []string{cbs}, Lifetime: time.Minute}, want: ErrNetDevLeaseRequest},
		{name: "negative lifetime", in: NetDevLeaseRequest{DeviceID: netDevGrantDevice, Reads: []string{cbs}, Lifetime: -time.Hour}, want: ErrNetDevLeaseRequest},
		{name: "no reads", in: NetDevLeaseRequest{DeviceID: netDevGrantDevice}, want: ErrNetDevLeaseRequest},
		{name: "unknown read", in: NetDevLeaseRequest{DeviceID: netDevGrantDevice, Reads: []string{"cbs_config"}}, want: ErrNetDevLeaseRequest},
		{name: "duplicate read", in: NetDevLeaseRequest{DeviceID: netDevGrantDevice, Reads: []string{cbs, cbs}}, want: ErrNetDevLeaseRequest},
		{name: "read of another family", in: NetDevLeaseRequest{DeviceID: netDevGrantDevice, Reads: []string{schedgrant.NetDeviceReadPANOSZones}}, want: ErrNetDevLeaseRequest},
		{name: "bad issuer", in: NetDevLeaseRequest{DeviceID: netDevGrantDevice, Reads: []string{cbs}, Issuer: "Root User"}, want: ErrNetDevLeaseRequest},
		{name: "malformed device id", in: NetDevLeaseRequest{DeviceID: "../x", Reads: []string{cbs}}, want: ErrNetDeviceRequest},
		{name: "unknown device", in: NetDevLeaseRequest{DeviceID: "ghost-sw", Reads: []string{cbs}}, want: executordb.ErrNetDeviceNotFound},
		{name: "removed device", in: NetDevLeaseRequest{DeviceID: netDevGrantDevice, Reads: []string{cbs}}, want: executordb.ErrNetDeviceTombstoned, setup: func(e *netDevGrantEnv) {
			if _, err := e.db.TombstoneNetDevice(netDevGrantDevice); err != nil {
				e.t.Fatal(err)
			}
		}},
		{name: "blocked device", in: NetDevLeaseRequest{DeviceID: netDevGrantDevice, Reads: []string{cbs}}, want: ErrNetDevReadBlocked, setup: func(e *netDevGrantEnv) {
			if _, err := e.db.BlockNetDevice(netDevGrantDevice, "test"); err != nil {
				e.t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newNetDevGrantEnv(t)
			if tc.setup != nil {
				tc.setup(e)
			}
			_, err := e.svc.netDevAdmin().LeaseDocument(context.Background(), tc.in)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err %v, want %v", err, tc.want)
			}
		})
	}

	t.Run("no read credential", func(t *testing.T) {
		e := newNetDevGrantEnvWithCredentials(t, netDevGrantFW)
		_, err := e.svc.netDevAdmin().LeaseDocument(context.Background(), NetDevLeaseRequest{DeviceID: netDevGrantDevice, Reads: []string{cbs}})
		if !errors.Is(err, ErrNetDevReadNoCredential) {
			t.Fatalf("err %v, want ErrNetDevReadNoCredential", err)
		}
	})
}

// TestNetDevLeaseFromInfo: the pure builder takes the registry row the
// executor returns (ListNetDevices) and refuses a blocked row or one
// without read credential; nothing outside that row enters the target.
func TestNetDevLeaseFromInfo(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	info := &pb.NetDeviceInfo{DeviceId: netDevGrantDevice, Family: "cbs", TrustPin: testNetDevPin, TrustGeneration: 3, CredentialVersion: 5}
	l, err := NetDevLeaseFromInfo(info, NetDevLeaseRequest{DeviceID: netDevGrantDevice, Reads: []string{schedgrant.NetDeviceReadCBSLLDP}}, now)
	if err != nil {
		t.Fatal(err)
	}
	tg := l.Doc.NetDeviceTargets[0]
	if tg.DeviceID != netDevGrantDevice || tg.TrustPin != testNetDevPin || tg.TrustGeneration != 3 || tg.CredentialVersion != 5 {
		t.Fatalf("target %+v", tg)
	}
	for name, mut := range map[string]func(*pb.NetDeviceInfo){
		"blocked":         func(i *pb.NetDeviceInfo) { i.Blocked = true },
		"no credential":   func(i *pb.NetDeviceInfo) { i.CredentialVersion = 0 },
		"other device":    func(i *pb.NetDeviceInfo) { i.DeviceId = netDevGrantFW },
		"no generation":   func(i *pb.NetDeviceInfo) { i.TrustGeneration = 0 },
		"malformed pin":   func(i *pb.NetDeviceInfo) { i.TrustPin = "zz" },
		"unknown family":  func(i *pb.NetDeviceInfo) { i.Family = "ios" },
		"nil device info": nil,
	} {
		t.Run(name, func(t *testing.T) {
			var in *pb.NetDeviceInfo
			if mut != nil {
				in = &pb.NetDeviceInfo{DeviceId: info.DeviceId, Family: info.Family, TrustPin: info.TrustPin, TrustGeneration: info.TrustGeneration, CredentialVersion: info.CredentialVersion}
				mut(in)
			}
			if _, err := NetDevLeaseFromInfo(in, NetDevLeaseRequest{DeviceID: netDevGrantDevice, Reads: []string{schedgrant.NetDeviceReadCBSLLDP}}, now); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}
