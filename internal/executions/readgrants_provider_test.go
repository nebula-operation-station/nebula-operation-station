// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

var (
	testPinA = strings.Repeat("a1", 32)
	testPinB = strings.Repeat("b2", 32)
)

// providerFake is a read-grant executor that also lists PVE remote
// metadata, as the executor's ListPVERemotes reports it. It says nothing
// about who may call that method; cmd/nebula-server's
// TestProviderReadLeaseThroughRoleTable covers the executor's role table.
type providerFake struct {
	*proposeFake
	remotes      []*pb.PVERemoteInfo
	remoteErr    error
	remoteCalls  int
	proposeCalls int
}

func (f *providerFake) ListPVERemotes(_ context.Context, _ *pb.ListPVERemotesRequest, _ ...grpc.CallOption) (*pb.ListPVERemotesResponse, error) {
	f.remoteCalls++
	if f.remoteErr != nil {
		return nil, f.remoteErr
	}
	return &pb.ListPVERemotesResponse{Remotes: f.remotes}, nil
}

func (f *providerFake) ProposeReadGrant(ctx context.Context, in *pb.ProposeReadGrantRequest, opts ...grpc.CallOption) (*pb.ProposeReadGrantResponse, error) {
	f.proposeCalls++
	f.sent = permit.ReadGrantDoc{}
	return f.proposeFake.ProposeReadGrant(ctx, in, opts...)
}

func newProviderFake() *providerFake {
	const (
		cluster    = pb.PVERemoteKind_PVE_REMOTE_KIND_CLUSTER
		standalone = pb.PVERemoteKind_PVE_REMOTE_KIND_STANDALONE
		active     = pb.PVERemoteState_PVE_REMOTE_STATE_ACTIVE
		blocked    = pb.PVERemoteState_PVE_REMOTE_STATE_BLOCKED
	)
	return &providerFake{proposeFake: newProposeFake(), remotes: []*pb.PVERemoteInfo{
		{RemoteId: "proxmoxbai", Name: "bai", Kind: cluster, TrustPin: testPinA, TrustGeneration: 3, State: active, ReadCredentialVersion: 7},
		{RemoteId: "pve-lab", Name: "lab", Kind: standalone, TrustPin: testPinB, TrustGeneration: 1, State: active, ReadCredentialVersion: 1},
		{RemoteId: "pve-blocked", Name: "blocked", Kind: standalone, TrustPin: testPinB, TrustGeneration: 2, State: blocked, ReadCredentialVersion: 4},
		{RemoteId: "pve-noread", Name: "noread", Kind: standalone, TrustPin: testPinB, TrustGeneration: 2, State: active},
	}}
}

func providerService(t *testing.T, f Executor) *Service {
	t.Helper()
	s, _ := proposeService(t, f, testInventory())
	now := time.Unix(1_800_000_000, 0)
	s.now = func() time.Time { return now }
	return s
}

// TestProposeProviderReadGrantBuildsExactDoc pins every member of the built
// provider document and that the executor's own parser accepts it.
func TestProposeProviderReadGrantBuildsExactDoc(t *testing.T) {
	f := newProviderFake()
	s, audit := proposeService(t, f, testInventory())
	now := time.Unix(1_800_000_000, 0)
	s.now = func() time.Time { return now }
	v, err := s.ProposeProviderReadGrant(context.Background(), "alice", ProviderReadGrantRequest{
		RemoteIDs: []string{"pve-lab", "proxmoxbai"}, Days: ReadGrantLongDays})
	if err != nil {
		t.Fatal(err)
	}
	d := f.sent
	if d.Grant != permit.ReadGrantFormat || d.Issuer != readGrantIssuer || !readGrantIDRe.MatchString(d.ID) ||
		d.CreatedUnix != now.Unix() || d.ExpiryUnix != now.Add(30*24*time.Hour).Unix() ||
		d.Trigger != permit.TriggerBoth || d.RateProfile != permit.ProviderReadProfile ||
		d.MinIntervalS != int64(permit.ProviderMinInterval/time.Second) || d.RunBudget != 600 {
		t.Fatalf("sent document %+v", d)
	}
	if len(d.Actions) != 0 || len(d.Targets) != 0 || len(d.Credentials) != 0 {
		t.Fatalf("a provider grant carries SSH members: %+v", d)
	}
	want := []permit.ProviderTarget{
		{RemoteID: "proxmoxbai", TrustPin: testPinA, TrustGeneration: 3, CredentialVersion: 7, Methods: DefaultProviderReadMethods()},
		{RemoteID: "pve-lab", TrustPin: testPinB, TrustGeneration: 1, CredentialVersion: 1, Methods: DefaultProviderReadMethods()},
	}
	if !sameProviderTargets(d.ProviderTargets, want) {
		t.Fatalf("provider targets %+v, want %+v", d.ProviderTargets, want)
	}
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, member := range []string{`"credentials"`, `"host_id"`, `"credential_ref"`, `"metrics_targets"`} {
		if strings.Contains(string(raw), member) {
			t.Errorf("provider document carries %s: %s", member, raw)
		}
	}
	if _, _, _, err := permit.ParseReadGrant(raw, now); err != nil {
		t.Fatalf("the executor's parser refuses the built document: %v", err)
	}
	if v.ID != d.ID || v.Digest != testDigest || v.RateProfile != permit.ProviderReadProfile || v.RunBudget != 600 ||
		v.MinInterval != time.Minute || len(v.Targets) != 0 || len(v.Actions) != 0 {
		t.Fatalf("preview %+v", v)
	}
	if len(v.Providers) != 2 || v.Providers[0].RemoteID != "proxmoxbai" || v.Providers[0].TrustPin != testPinA ||
		v.Providers[0].TrustGeneration != 3 || v.Providers[0].CredentialVersion != 7 ||
		!sameStrings(v.Providers[0].Methods, DefaultProviderReadMethods()) {
		t.Fatalf("preview providers %+v", v.Providers)
	}
	if !strings.Contains(audit.String(), "provider_read_grant_proposed") || !strings.Contains(audit.String(), "user=alice") {
		t.Errorf("no audit line: %s", audit)
	}
}

// TestProposeProviderReadGrantMethods pins the default methods (what the
// collector reads) and an explicit choice, and the budget for each.
func TestProposeProviderReadGrantMethods(t *testing.T) {
	for _, tc := range []struct {
		name    string
		methods []string
		want    []string
		budget  int64
	}{
		{"default", nil, []string{"cluster", "guests", "nodes", "storage", "tasks"}, 600},
		{"explicit", []string{"tasks", "nodes"}, []string{"nodes", "tasks"}, 240},
		{"per-guest method", []string{"guests", "guest_config"}, []string{"guest_config", "guests"}, permit.MaxProviderRequestBudget},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newProviderFake()
			s := providerService(t, f)
			if _, err := s.ProposeProviderReadGrant(context.Background(), "alice", ProviderReadGrantRequest{
				RemoteIDs: []string{"proxmoxbai"}, Methods: tc.methods, Days: ReadGrantShortDays}); err != nil {
				t.Fatal(err)
			}
			if len(f.sent.ProviderTargets) != 1 || !sameStrings(f.sent.ProviderTargets[0].Methods, tc.want) {
				t.Fatalf("methods %+v, want %v", f.sent.ProviderTargets, tc.want)
			}
			if f.sent.RunBudget != tc.budget || f.sent.ExpiryUnix-f.sent.CreatedUnix != 7*24*3600 {
				t.Fatalf("budget %d lifetime %d", f.sent.RunBudget, f.sent.ExpiryUnix-f.sent.CreatedUnix)
			}
		})
	}
	if got := DefaultProviderReadMethods(); !sameStrings(got, []string{"cluster", "guests", "nodes", "storage", "tasks"}) {
		t.Fatalf("default methods %v", got)
	}
}

// TestProposeProviderReadGrantRefusesInput pins the request checks: nothing
// reaches the executor for an unusable request.
func TestProposeProviderReadGrantRefusesInput(t *testing.T) {
	many := make([]string, permit.MaxProviderTargets+1)
	for i := range many {
		many[i] = "pve-" + strings.Repeat("x", i+1)
	}
	for name, in := range map[string]ProviderReadGrantRequest{
		"no remote":         {Days: ReadGrantShortDays},
		"too many remotes":  {RemoteIDs: many, Days: ReadGrantShortDays},
		"duplicate remote":  {RemoteIDs: []string{"proxmoxbai", "proxmoxbai"}, Days: ReadGrantShortDays},
		"malformed remote":  {RemoteIDs: []string{"PVE A"}, Days: ReadGrantShortDays},
		"unknown method":    {RemoteIDs: []string{"proxmoxbai"}, Methods: []string{"nodes", "exec"}, Days: ReadGrantShortDays},
		"metrics method":    {RemoteIDs: []string{"proxmoxbai"}, Methods: []string{permit.ProviderMethodMetrics}, Days: ReadGrantShortDays},
		"duplicate method":  {RemoteIDs: []string{"proxmoxbai"}, Methods: []string{"nodes", "nodes"}, Days: ReadGrantShortDays},
		"zero days":         {RemoteIDs: []string{"proxmoxbai"}},
		"fourteen days":     {RemoteIDs: []string{"proxmoxbai"}, Days: 14},
		"thirty-one days":   {RemoteIDs: []string{"proxmoxbai"}, Days: 31},
		"negative days":     {RemoteIDs: []string{"proxmoxbai"}, Days: -7},
		"empty method name": {RemoteIDs: []string{"proxmoxbai"}, Methods: []string{""}, Days: ReadGrantShortDays},
	} {
		f := newProviderFake()
		s := providerService(t, f)
		_, err := s.ProposeProviderReadGrant(context.Background(), "alice", in)
		var ie *ReadGrantInputError
		if !errors.As(err, &ie) {
			t.Errorf("%s: err %v, want an input error", name, err)
		}
		if f.proposeCalls != 0 || f.remoteCalls != 0 {
			t.Errorf("%s: reached the executor", name)
		}
	}
}

// TestProposeProviderReadGrantRefusesRemotes pins that only active remotes
// with a pin, a trust generation and a read credential are proposed.
func TestProposeProviderReadGrantRefusesRemotes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		remote string
		mutate func(*pb.PVERemoteInfo)
	}{
		{"unknown", "pve-gone", nil},
		{"blocked", "pve-blocked", nil},
		{"no read credential", "pve-noread", nil},
		// The executor maps a tombstoned remote to the unspecified state.
		{"removed", "pve-lab", func(r *pb.PVERemoteInfo) { r.State = pb.PVERemoteState_PVE_REMOTE_STATE_UNSPECIFIED }},
		{"unknown state", "pve-lab", func(r *pb.PVERemoteInfo) { r.State = pb.PVERemoteState(99) }},
		{"malformed pin", "pve-lab", func(r *pb.PVERemoteInfo) { r.TrustPin = "SHA256:abc" }},
		{"zero generation", "pve-lab", func(r *pb.PVERemoteInfo) { r.TrustGeneration = 0 }},
		{"zero credential version", "pve-lab", func(r *pb.PVERemoteInfo) { r.ReadCredentialVersion = 0 }},
		{"negative credential version", "pve-lab", func(r *pb.PVERemoteInfo) { r.ReadCredentialVersion = -1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newProviderFake()
			if tc.mutate != nil {
				for _, r := range f.remotes {
					if r.RemoteId == tc.remote {
						tc.mutate(r)
					}
				}
			}
			s := providerService(t, f)
			_, err := s.ProposeProviderReadGrant(context.Background(), "alice", ProviderReadGrantRequest{
				RemoteIDs: []string{"proxmoxbai", tc.remote}, Days: ReadGrantShortDays})
			var ie *ReadGrantInputError
			if !errors.As(err, &ie) {
				t.Fatalf("err %v, want an input error", err)
			}
			if f.proposeCalls != 0 {
				t.Fatal("the proposal reached the executor")
			}
		})
	}
	// An executor listing that names one remote twice is ambiguous.
	f := newProviderFake()
	dup := proto.Clone(f.remotes[0]).(*pb.PVERemoteInfo)
	dup.TrustGeneration = 4
	f.remotes = append(f.remotes, dup)
	s := providerService(t, f)
	if _, err := s.ProposeProviderReadGrant(context.Background(), "alice", ProviderReadGrantRequest{
		RemoteIDs: []string{"proxmoxbai"}, Days: ReadGrantShortDays}); !errors.Is(err, ErrProviderRemotesUnavailable) || f.proposeCalls != 0 {
		t.Fatalf("duplicate remote in the listing: err %v, proposals %d", err, f.proposeCalls)
	}
	// A listing failure is reported without the executor's text.
	f = newProviderFake()
	f.remoteErr = status.Error(codes.Unavailable, "secret detail")
	s = providerService(t, f)
	if _, err := s.ProposeProviderReadGrant(context.Background(), "alice", ProviderReadGrantRequest{
		RemoteIDs: []string{"proxmoxbai"}, Days: ReadGrantShortDays}); !errors.Is(err, ErrProviderRemotesUnavailable) || strings.Contains(err.Error(), "secret") {
		t.Fatalf("listing failure: err %v", err)
	}
}

// providerOnlyExec is an executor without the PVE remote listing.
type providerOnlyExec struct{ *proposeFake }

// TestProposeProviderReadGrantExecutorRefusal pins the mapping of the
// executor's answers to fixed errors.
func TestProposeProviderReadGrantExecutorRefusal(t *testing.T) {
	for _, tc := range []struct {
		code codes.Code
		want error
	}{
		{codes.InvalidArgument, ErrReadGrantProposeFailed},
		{codes.FailedPrecondition, ErrReadGrantProposeFailed},
		{codes.Unimplemented, ErrReadGrantProposeUnsupported},
		{codes.Unavailable, ErrReadGrantProposeFailed},
	} {
		f := newProviderFake()
		f.proposeErr = status.Error(tc.code, "read grant: remote is not active with the approved trust and credential version")
		s := providerService(t, f)
		_, err := s.ProposeProviderReadGrant(context.Background(), "alice", ProviderReadGrantRequest{
			RemoteIDs: []string{"proxmoxbai"}, Days: ReadGrantShortDays})
		if !errors.Is(err, tc.want) || strings.Contains(err.Error(), "approved trust") {
			t.Errorf("%v: err %v, want %v", tc.code, err, tc.want)
		}
	}
	s := providerService(t, &providerOnlyExec{newProposeFake()})
	if _, err := s.ProposeProviderReadGrant(context.Background(), "alice", ProviderReadGrantRequest{
		RemoteIDs: []string{"proxmoxbai"}, Days: ReadGrantShortDays}); !errors.Is(err, ErrReadGrantProposeUnsupported) {
		t.Fatalf("executor without remote listing: err %v", err)
	}
}

// TestProposeProviderReadGrantRejectsTamperedAnswer pins that the preview
// comparison is exact for every provider target member.
func TestProposeProviderReadGrantRejectsTamperedAnswer(t *testing.T) {
	cases := map[string]func(*permit.ReadGrantDoc){
		"remote id":          func(d *permit.ReadGrantDoc) { d.ProviderTargets[0].RemoteID = "pve-other" },
		"trust pin":          func(d *permit.ReadGrantDoc) { d.ProviderTargets[0].TrustPin = testPinB },
		"trust generation":   func(d *permit.ReadGrantDoc) { d.ProviderTargets[0].TrustGeneration++ },
		"credential version": func(d *permit.ReadGrantDoc) { d.ProviderTargets[1].CredentialVersion++ },
		"method added": func(d *permit.ReadGrantDoc) {
			d.ProviderTargets[0].Methods = append(d.ProviderTargets[0].Methods, permit.ProviderMethodBackups)
		},
		"method dropped": func(d *permit.ReadGrantDoc) { d.ProviderTargets[1].Methods = d.ProviderTargets[1].Methods[1:] },
		"method replaced": func(d *permit.ReadGrantDoc) {
			d.ProviderTargets[0].Methods = append([]string{permit.ProviderMethodGuestAgent}, d.ProviderTargets[0].Methods[1:]...)
		},
		"method repeated": func(d *permit.ReadGrantDoc) {
			m := d.ProviderTargets[0].Methods
			d.ProviderTargets[0].Methods = append(append([]string{}, m...), m[0])
		},
		"remote added": func(d *permit.ReadGrantDoc) {
			d.ProviderTargets = append(d.ProviderTargets, permit.ProviderTarget{RemoteID: "pve-x", TrustPin: testPinA,
				TrustGeneration: 1, CredentialVersion: 1, Methods: []string{"nodes"}})
		},
		"remote dropped": func(d *permit.ReadGrantDoc) { d.ProviderTargets = d.ProviderTargets[:1] },
		"remotes swapped": func(d *permit.ReadGrantDoc) {
			d.ProviderTargets[0], d.ProviderTargets[1] = d.ProviderTargets[1], d.ProviderTargets[0]
		},
		"metrics targets": func(d *permit.ReadGrantDoc) {
			d.ProviderTargets[0].MetricsTargets = []permit.ProviderMetricsTarget{{}}
		},
		"ssh target":   func(d *permit.ReadGrantDoc) { d.Targets = validDoc().Targets },
		"ssh action":   func(d *permit.ReadGrantDoc) { d.Actions = validDoc().Actions },
		"rate profile": func(d *permit.ReadGrantDoc) { d.RateProfile = "ordinary" },
		"run budget":   func(d *permit.ReadGrantDoc) { d.RunBudget = permit.MaxProviderRequestBudget },
		"min interval": func(d *permit.ReadGrantDoc) { d.MinIntervalS++ },
		"no providers": func(d *permit.ReadGrantDoc) { d.ProviderTargets = nil },
		"expiry":       func(d *permit.ReadGrantDoc) { d.ExpiryUnix++ },
		"trigger":      func(d *permit.ReadGrantDoc) { d.Trigger = permit.TriggerScheduled },
		"grant id":     func(d *permit.ReadGrantDoc) { d.ID = testGrantID },
		"issuer":       func(d *permit.ReadGrantDoc) { d.Issuer = "someone" },
		"ssh credential": func(d *permit.ReadGrantDoc) {
			d.Credentials = []permit.ReadGrantCredential{{HostID: "web", CredentialRef: "default"}}
		},
	}
	for name, alter := range cases {
		f := newProviderFake()
		f.alter = func(d *permit.ReadGrantDoc) {
			// Deep-copy the provider targets so the alteration never
			// reaches the recorded proposal.
			pts := make([]permit.ProviderTarget, len(d.ProviderTargets))
			for i, p := range d.ProviderTargets {
				p.Methods = append([]string{}, p.Methods...)
				pts[i] = p
			}
			d.ProviderTargets = pts
			alter(d)
		}
		s := providerService(t, f)
		if _, err := s.ProposeProviderReadGrant(context.Background(), "alice", ProviderReadGrantRequest{
			RemoteIDs: []string{"proxmoxbai", "pve-lab"}, Days: ReadGrantShortDays}); !errors.Is(err, ErrReadGrantProposalMismatch) {
			t.Errorf("%s: err %v, want mismatch", name, err)
		}
	}
	// The untampered answer is accepted (control).
	f := newProviderFake()
	s := providerService(t, f)
	if _, err := s.ProposeProviderReadGrant(context.Background(), "alice", ProviderReadGrantRequest{
		RemoteIDs: []string{"proxmoxbai", "pve-lab"}, Days: ReadGrantShortDays}); err != nil {
		t.Fatalf("control: %v", err)
	}
}

// TestSameReadGrantSSHUnchanged pins that SSH documents still compare as
// before and that a provider target on either side of an SSH comparison is
// a mismatch.
func TestSameReadGrantSSHUnchanged(t *testing.T) {
	a := validDoc()
	if !sameReadGrant(a, validDoc()) {
		t.Fatal("identical SSH documents differ")
	}
	b := validDoc()
	b.ProviderTargets = []permit.ProviderTarget{{RemoteID: "pve-a"}}
	if sameReadGrant(a, b) || sameReadGrant(b, a) {
		t.Fatal("an SSH document with provider targets compares equal")
	}
}

// TestReadGrantsListsProviderLeases pins that a provider lease is listed
// with every remote's ID, pin prefix, trust generation, credential version
// and methods, and its expiry, and that it can be revoked.
func TestReadGrantsListsProviderLeases(t *testing.T) {
	f := newProviderFake()
	f.grants = []*pb.ReadGrant{pbGrant(decodeStored, decodeExpiry, time.Time{}, marshalDoc(t, providerDoc()))}
	s := providerService(t, f)
	s.now = func() time.Time { return decodeNow }
	views, err := s.ReadGrants(context.Background())
	if err != nil || len(views) != 1 {
		t.Fatalf("views %+v err %v", views, err)
	}
	v := views[0]
	if v.State != "active" || v.ScopeKind != ScopeProvider || v.RateProfile != permit.ProviderReadProfile ||
		!v.Expiry.Equal(decodeExpiry) || len(v.Hosts) != 0 || len(v.Actions) != 0 {
		t.Fatalf("view %+v", v)
	}
	want := []ReadGrantProviderView{
		{RemoteID: "pve-a", PinPrefix: strings.Repeat("a1", 8), TrustGeneration: 1, CredentialVersion: 3, Methods: []string{"guests"}},
		{RemoteID: "pve-b", PinPrefix: strings.Repeat("b2", 8), TrustGeneration: 2, CredentialVersion: 5, Methods: []string{"nodes", "tasks"}},
	}
	if len(v.Providers) != len(want) {
		t.Fatalf("providers %+v", v.Providers)
	}
	for i, p := range v.Providers {
		w := want[i]
		if p.RemoteID != w.RemoteID || p.PinPrefix != w.PinPrefix || p.TrustGeneration != w.TrustGeneration ||
			p.CredentialVersion != w.CredentialVersion || !sameStrings(p.Methods, w.Methods) {
			t.Errorf("provider %d: %+v, want %+v", i, p, w)
		}
	}
	if err := s.RevokeReadGrant(context.Background(), "alice", v.ID); err != nil || f.revokeID != testGrantID {
		t.Fatalf("revoke: err %v id %q", err, f.revokeID)
	}
}

// TestDecodeReadGrantRejectsMalformedProviderTarget pins that every
// rendered provider member is checked; a bad one marks the grant invalid.
func TestDecodeReadGrantRejectsMalformedProviderTarget(t *testing.T) {
	cases := map[string]func(*permit.ProviderTarget){
		"pin empty":           func(p *permit.ProviderTarget) { p.TrustPin = "" },
		"pin uppercase":       func(p *permit.ProviderTarget) { p.TrustPin = strings.ToUpper(p.TrustPin) },
		"pin short":           func(p *permit.ProviderTarget) { p.TrustPin = p.TrustPin[:10] },
		"pin with newline":    func(p *permit.ProviderTarget) { p.TrustPin = "\n" + p.TrustPin[1:] },
		"generation zero":     func(p *permit.ProviderTarget) { p.TrustGeneration = 0 },
		"credential zero":     func(p *permit.ProviderTarget) { p.CredentialVersion = 0 },
		"credential negative": func(p *permit.ProviderTarget) { p.CredentialVersion = -1 },
		"no methods":          func(p *permit.ProviderTarget) { p.Methods = nil },
		"unknown method":      func(p *permit.ProviderTarget) { p.Methods = []string{"nodes", "<b>x</b>"} },
		"duplicate method":    func(p *permit.ProviderTarget) { p.Methods = []string{"nodes", "nodes"} },
	}
	for name, mutate := range cases {
		d := providerDoc()
		mutate(&d.ProviderTargets[0])
		wantInvalid(t, name, decodeRaw(marshalDoc(t, d)))
		if v := decodeRaw(marshalDoc(t, d)); len(v.Providers) != 0 || v.RateProfile != "" {
			t.Errorf("%s: invalid grant still shows providers %+v", name, v.Providers)
		}
	}
	// A provider telemetry grant lists its metrics method.
	d := providerDoc()
	d.RateProfile = permit.ProviderTelemetryProfile
	d.ProviderTargets[0].Methods = []string{permit.ProviderMethodMetrics}
	if v := decodeRaw(marshalDoc(t, d)); v.State != "active" || len(v.Providers) != 2 {
		t.Fatalf("provider telemetry grant: %+v", v)
	}
}

// TestProviderRefreshPrefillsRemotesAndMethods pins the refresh data of a
// provider lease.
func TestProviderRefreshPrefillsRemotesAndMethods(t *testing.T) {
	v := decodeRaw(marshalDoc(t, providerDoc()))
	in, ok := v.ProviderRefresh()
	if !ok || !sameStrings(in.RemoteIDs, []string{"pve-a", "pve-b"}) || !sameStrings(in.Methods, []string{"guests", "nodes", "tasks"}) ||
		in.Days != ReadGrantShortDays {
		t.Fatalf("refresh %+v ok %v", in, ok)
	}
	long := providerDoc()
	long.ExpiryUnix = decodeStored.Add(30 * 24 * time.Hour).Unix()
	lv := decodeReadGrant(pbGrant(decodeStored, time.Unix(long.ExpiryUnix, 0), time.Time{}, marshalDoc(t, long)), nil, false, decodeNow)
	if in, ok := lv.ProviderRefresh(); !ok || in.Days != ReadGrantLongDays {
		t.Fatalf("30-day lease refresh %+v ok %v (state %q)", in, ok, lv.State)
	}
	expired := decodeReadGrant(pbGrant(decodeStored, decodeExpiry, time.Time{}, marshalDoc(t, providerDoc())), nil, false, decodeExpiry)
	if _, ok := expired.ProviderRefresh(); !ok {
		t.Fatal("an expired provider lease cannot be refreshed")
	}
	revoked := decodeReadGrant(pbGrant(decodeStored, decodeExpiry, decodeNow, marshalDoc(t, providerDoc())), nil, false, decodeNow)
	if _, ok := revoked.ProviderRefresh(); ok {
		t.Fatal("a revoked provider lease offers a refresh")
	}
	if _, ok := decodeRaw(marshalDoc(t, validDoc())).ProviderRefresh(); ok {
		t.Fatal("an SSH lease offers a provider refresh")
	}
	tel := providerDoc()
	tel.RateProfile = permit.ProviderTelemetryProfile
	if _, ok := decodeRaw(marshalDoc(t, tel)).ProviderRefresh(); ok {
		t.Fatal("a provider telemetry lease offers a provider read refresh")
	}
	// The pre-filled request is accepted by the proposal checks.
	if _, _, err := checkProviderReadGrantRequest(in); err != nil {
		t.Fatalf("refresh request refused: %v", err)
	}
}
