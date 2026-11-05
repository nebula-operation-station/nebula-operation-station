// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
)

// readGrantFake is a fakeExec that serves read grants and records revokes.
type readGrantFake struct {
	*fakeExec
	grants    []*pb.ReadGrant
	listErr   error
	revokeErr error
	revokeID  string
}

func (f *readGrantFake) ListReadGrants(ctx context.Context, in *pb.ListReadGrantsRequest, _ ...grpc.CallOption) (*pb.ListReadGrantsResponse, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return &pb.ListReadGrantsResponse{Grants: f.grants}, nil
}

func (f *readGrantFake) RevokeReadGrant(ctx context.Context, in *pb.RevokeReadGrantRequest, _ ...grpc.CallOption) (*pb.RevokeReadGrantResponse, error) {
	f.revokeID = in.GetGrantId()
	if f.revokeErr != nil {
		return nil, f.revokeErr
	}
	return &pb.RevokeReadGrantResponse{}, nil
}

// readGrantHosts is a fakeHosts that also lists the whole inventory, so the
// scope label can be derived from the frozen list.
type readGrantHosts struct {
	fakeHosts
	all []inventory.Host
}

func (h readGrantHosts) List(_ context.Context) ([]inventory.Host, error) { return h.all, nil }

// testInventory is the inventory the scope-label tests run against:
//
//	prod: web (tier=front), db (tier=back)
//	dev:  dev (tier=front)
//
// so {web,db,dev} is "all", {web,db} is environment "prod", and {web,dev} is
// tag "tier=front" (no environment matches that set).
func testInventory() []inventory.Host {
	return []inventory.Host{
		{ID: "web", Environment: "prod", Tags: map[string]string{"tier": "front"}},
		{ID: "db", Environment: "prod", Tags: map[string]string{"tier": "back"}},
		{ID: "dev", Environment: "dev", Tags: map[string]string{"tier": "front"}},
	}
}

func readGrantHostsFrom(inv []inventory.Host) readGrantHosts {
	m := fakeHosts{}
	for _, h := range inv {
		m[h.ID] = h
	}
	return readGrantHosts{fakeHosts: m, all: inv}
}

// testGrantID, testDigest and testApprover are registry values in the
// executor's real forms.
const (
	testGrantID  = "6f1c2a3b-4d5e-4f60-8a71-92b3c4d5e6f7"
	testApprover = "cli:alice"
)

var testDigest = strings.Repeat("ab", 32)

// grantDoc marshals a read-grant document with the given format, targets and
// times, carrying testGrantID. Older formats carry only their own members.
func grantDoc(t *testing.T, format string, targets []string, created, expiry, _ time.Time) []byte {
	t.Helper()
	return marshalDoc(t, grantDocValue(format, targets, created, expiry))
}

// grantDocValue is grantDoc before marshalling, for tests that alter it.
func grantDocValue(format string, targets []string, created, expiry time.Time) permit.ReadGrantDoc {
	var tg []canonical.Target
	for _, id := range targets {
		tg = append(tg, canonical.Target{HostID: id, HostKeyFingerprint: "fp"})
	}
	doc := permit.ReadGrantDoc{
		Grant:       format,
		ID:          testGrantID,
		Issuer:      "test",
		CreatedUnix: created.Unix(),
		ExpiryUnix:  expiry.Unix(),
		Trigger:     permit.TriggerBoth,
		Actions: []permit.ReadGrantAction{{
			ActionID: "core.facts", ModuleVersion: "1.0.0",
			ArtifactSHA256: "sha", ParametersHash: "ph",
		}},
		Targets:      tg,
		MinIntervalS: 900,
		RunBudget:    5,
		RateProfile:  "ordinary",
	}
	switch format {
	case "read-grant-v1":
		doc.RateProfile = ""
	case schedgrant.Format:
		doc.RateProfile, doc.Issuer, doc.CreatedUnix, doc.Trigger, doc.RunBudget = "", "", 0, "", 0
	}
	return doc
}

func marshalDoc(t *testing.T, doc permit.ReadGrantDoc) []byte {
	t.Helper()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// pbGrant is the registry entry the executor sends for doc.
func pbGrant(created, expiry, revoked time.Time, doc []byte) *pb.ReadGrant {
	return &pb.ReadGrant{
		GrantId: testGrantID, GrantDigest: testDigest, CanonicalGrant: doc,
		ApprovedBy: testApprover, CreatedUnix: created.Unix(),
		ExpiryUnix: expiry.Unix(), RevokedUnix: revokedUnix(revoked),
	}
}

func TestReadGrantsDecode(t *testing.T) {
	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	inv := testInventory()
	zero := time.Time{}

	cases := []struct {
		name       string
		doc        []byte
		created    time.Time
		expiry     time.Time
		revoked    time.Time
		wantState  string
		wantScope  string
		wantValue  string
		wantHosts  []string
		wantLegacy bool
	}{
		{
			name:    "active all",
			doc:     grantDoc(t, schedgrant.ReadFormat, []string{"web", "db", "dev"}, now.Add(-time.Hour), now.Add(time.Hour), zero),
			created: now.Add(-time.Hour), expiry: now.Add(time.Hour),
			wantState: "active", wantScope: "all", wantHosts: []string{"db", "dev", "web"},
		},
		{
			name:    "expired environment",
			doc:     grantDoc(t, schedgrant.ReadFormat, []string{"web", "db"}, now.Add(-2*time.Hour), now.Add(-time.Hour), zero),
			created: now.Add(-2 * time.Hour), expiry: now.Add(-time.Hour),
			wantState: "expired", wantScope: "environment", wantValue: "prod", wantHosts: []string{"db", "web"},
		},
		{
			name:    "revoked tag",
			doc:     grantDoc(t, schedgrant.ReadFormat, []string{"web", "dev"}, now.Add(-2*time.Hour), now.Add(time.Hour), now.Add(-30*time.Minute)),
			created: now.Add(-2 * time.Hour), expiry: now.Add(time.Hour), revoked: now.Add(-30 * time.Minute),
			wantState: "revoked", wantScope: "tag", wantValue: "tier=front", wantHosts: []string{"dev", "web"},
		},
		{
			name:    "legacy schedule",
			doc:     grantDoc(t, schedgrant.Format, []string{"dev"}, now.Add(-time.Hour), now.Add(time.Hour), zero),
			created: now.Add(-time.Hour), expiry: now.Add(time.Hour),
			wantState: "legacy", wantScope: "environment", wantValue: "dev", wantHosts: []string{"dev"},
			wantLegacy: true,
		},
		{
			name:    "invalid json",
			doc:     []byte("not a document"),
			created: now.Add(-time.Hour), expiry: now.Add(time.Hour),
			wantState: "invalid", wantHosts: nil,
		},
		{
			name:    "wrong format",
			doc:     grantDoc(t, "bogus-format", []string{"web"}, now.Add(-time.Hour), now.Add(time.Hour), zero),
			created: now.Add(-time.Hour), expiry: now.Add(time.Hour),
			wantState: "invalid", wantHosts: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &readGrantFake{fakeExec: &fakeExec{}, grants: []*pb.ReadGrant{
				pbGrant(tc.created, tc.expiry, tc.revoked, tc.doc),
			}}
			s := newReadGrantService(t, f, readGrantHostsFrom(inv))
			s.now = func() time.Time { return now }

			views, err := s.ReadGrants(context.Background())
			if err != nil {
				t.Fatalf("ReadGrants: %v", err)
			}
			if len(views) != 1 {
				t.Fatalf("want 1 view, got %d", len(views))
			}
			got := views[0]
			if got.State != tc.wantState {
				t.Errorf("state = %q, want %q", got.State, tc.wantState)
			}
			if got.ScopeKind != tc.wantScope {
				t.Errorf("scope kind = %q, want %q", got.ScopeKind, tc.wantScope)
			}
			if got.ScopeValue != tc.wantValue {
				t.Errorf("scope value = %q, want %q", got.ScopeValue, tc.wantValue)
			}
			if !sameStrings(got.Hosts, tc.wantHosts) {
				t.Errorf("hosts = %v, want %v", got.Hosts, tc.wantHosts)
			}
			if got.Legacy != tc.wantLegacy {
				t.Errorf("legacy = %v, want %v", got.Legacy, tc.wantLegacy)
			}
			if got.ID != testGrantID || got.Digest != testDigest || got.ApprovedBy != testApprover {
				t.Errorf("identity = %+v", got)
			}
			if tc.wantState == "invalid" {
				if len(got.Hosts) != 0 || len(got.Actions) != 0 {
					t.Errorf("invalid grant must have no hosts/actions, got %v %v", got.Hosts, got.Actions)
				}
			}
		})
	}
}

func TestReadGrantsListError(t *testing.T) {
	f := &readGrantFake{fakeExec: &fakeExec{}, listErr: status.Error(codes.Unavailable, "boom")}
	s := newReadGrantService(t, f, readGrantHostsFrom(testInventory()))
	if _, err := s.ReadGrants(context.Background()); err != ErrReadGrantsUnavailable {
		t.Fatalf("want ErrReadGrantsUnavailable, got %v", err)
	}
}

func TestRevokeReadGrant(t *testing.T) {
	var audit bytes.Buffer
	f := &readGrantFake{fakeExec: &fakeExec{}}
	log := slog.New(slog.NewTextHandler(&audit, nil))
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s := New(context.Background(), f, db, readGrantHostsFrom(testInventory()), log)

	if err := s.RevokeReadGrant(context.Background(), "alice", testGrantID); err != nil {
		t.Fatalf("RevokeReadGrant: %v", err)
	}
	if f.revokeID != testGrantID {
		t.Errorf("revoke id = %q, want %s", f.revokeID, testGrantID)
	}
	if !strings.Contains(audit.String(), "read_grant_revoked") || !strings.Contains(audit.String(), testGrantID) {
		t.Errorf("audit missing read_grant_revoked/%s: %s", testGrantID, audit.String())
	}
}

func TestRevokeReadGrantNotFound(t *testing.T) {
	f := &readGrantFake{fakeExec: &fakeExec{}, revokeErr: status.Error(codes.NotFound, "nope")}
	s := newReadGrantService(t, f, readGrantHostsFrom(testInventory()))
	if err := s.RevokeReadGrant(context.Background(), "alice", "0a1b2c3d-4e5f-4a6b-9c7d-8e9f0a1b2c3d"); err != ErrReadGrantNotFound {
		t.Fatalf("want ErrReadGrantNotFound, got %v", err)
	}
}

func TestRevokeReadGrantFailed(t *testing.T) {
	f := &readGrantFake{fakeExec: &fakeExec{}, revokeErr: status.Error(codes.Internal, "boom")}
	s := newReadGrantService(t, f, readGrantHostsFrom(testInventory()))
	if err := s.RevokeReadGrant(context.Background(), "alice", testGrantID); err != ErrReadGrantRevokeFailed {
		t.Fatalf("want ErrReadGrantRevokeFailed, got %v", err)
	}
}

// TestRevokeReadGrantRejectsBadID pins that an id not in the executor's
// lowercase UUIDv4 form is neither sent to the executor nor audited.
func TestRevokeReadGrantRejectsBadID(t *testing.T) {
	var audit bytes.Buffer
	f := &readGrantFake{fakeExec: &fakeExec{}}
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s := New(context.Background(), f, db, readGrantHostsFrom(testInventory()), slog.New(slog.NewTextHandler(&audit, nil)))
	for name, id := range map[string]string{
		"empty":             "",
		"not a uuid":        "grant-1",
		"uppercase":         strings.ToUpper(testGrantID),
		"trailing newline":  testGrantID + "\n",
		"embedded newline":  testGrantID[:8] + "\n" + testGrantID[9:],
		"control character": testGrantID + "\x1b",
		"not version 4":     "6f1c2a3b-4d5e-1f60-8a71-92b3c4d5e6f7",
		"oversize":          testGrantID + strings.Repeat("a", 300),
		"bad utf8":          testGrantID[:35] + "\xff",
	} {
		f.revokeID = "unset"
		if err := s.RevokeReadGrant(context.Background(), "alice", id); err != ErrReadGrantNotFound {
			t.Errorf("%s: err %v, want ErrReadGrantNotFound", name, err)
		}
		if f.revokeID != "unset" {
			t.Errorf("%s: id was sent to the executor", name)
		}
	}
	if strings.Contains(audit.String(), "read_grant_revoked") {
		t.Errorf("a rejected id was audited: %s", audit.String())
	}
}

// newReadGrantService builds a service over a fresh temp database.
func newReadGrantService(t *testing.T, f Executor, hosts Hosts) *Service {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return New(context.Background(), f, db, hosts, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// revokedUnix mirrors the executor: RevokedUnix is 0 when not revoked.
func revokedUnix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// decodeTimes are the document and registry times of the decode tests: the
// document is created an hour before the executor approved it.
var (
	decodeNow     = time.Unix(1_800_000_000, 0)
	decodeCreated = decodeNow.Add(-2 * time.Hour)
	decodeStored  = decodeNow.Add(-time.Hour)
	decodeExpiry  = decodeNow.Add(time.Hour)
)

// decodeRaw decodes raw as the registry entry for testGrantID.
func decodeRaw(raw []byte) ReadGrantView {
	return decodeReadGrant(pbGrant(decodeStored, decodeExpiry, time.Time{}, raw), nil, false, decodeNow)
}

// validDoc is an active SSH grant for host "web" at the decode times.
func validDoc() permit.ReadGrantDoc {
	return grantDocValue(schedgrant.ReadFormat, []string{"web"}, decodeCreated, decodeExpiry)
}

// wantInvalid fails unless v is invalid with nothing shown.
func wantInvalid(t *testing.T, name string, v ReadGrantView) {
	t.Helper()
	if v.State != "invalid" || v.Hosts != nil || v.Actions != nil || v.Remotes != nil {
		t.Errorf("%s: state %q hosts %v actions %v remotes %v, want invalid with nothing shown", name, v.State, v.Hosts, v.Actions, v.Remotes)
	}
}

// TestDecodeReadGrantExecutorEncoding pins what the real executor sends:
// RevokedUnix 0 is "not revoked" and expiry is exclusive.
func TestDecodeReadGrantExecutorEncoding(t *testing.T) {
	g := pbGrant(decodeStored, decodeExpiry, time.Time{}, marshalDoc(t, validDoc()))
	if g.RevokedUnix != 0 {
		t.Fatalf("helper sends RevokedUnix %d, want 0", g.RevokedUnix)
	}
	if v := decodeReadGrant(g, nil, false, decodeNow); v.State != "active" || !v.Revoked.IsZero() {
		t.Fatalf("RevokedUnix 0: state %q revoked %v, want active and zero", v.State, v.Revoked)
	}
	if v := decodeReadGrant(g, nil, false, decodeExpiry); v.State != "expired" {
		t.Fatalf("at the expiry second: state %q, want expired", v.State)
	}
	if v := decodeReadGrant(g, nil, false, decodeExpiry.Add(-time.Second)); v.State != "active" {
		t.Fatalf("one second before expiry: state %q, want active", v.State)
	}
	g.RevokedUnix = decodeNow.Add(-time.Minute).Unix()
	if v := decodeReadGrant(g, nil, false, decodeNow); v.State != "revoked" {
		t.Fatalf("revoked grant: state %q, want revoked", v.State)
	}
}

// TestDecodeReadGrantLimits pins each size and count limit with a document
// that is otherwise valid, so each case fails only on its own check.
func TestDecodeReadGrantLimits(t *testing.T) {
	oversize := validDoc()
	oversize.Issuer = strings.Repeat("a", permit.MaxReadGrantDocSize)
	targets := validDoc()
	targets.Targets = nil
	for i := 0; i <= permit.MaxReadGrantTargets; i++ {
		targets.Targets = append(targets.Targets, canonical.Target{HostID: "h" + strconv.Itoa(i), HostKeyFingerprint: "fp"})
	}
	actions := validDoc()
	actions.Actions = nil
	for i := 0; i <= permit.MaxReadGrantActions; i++ {
		actions.Actions = append(actions.Actions, permit.ReadGrantAction{ActionID: "core.a" + strconv.Itoa(i), ModuleVersion: "1.0.0"})
	}
	remotes := providerDoc()
	remotes.ProviderTargets = nil
	for i := 0; i <= permit.MaxProviderTargets; i++ {
		remotes.ProviderTargets = append(remotes.ProviderTargets, permit.ProviderTarget{RemoteID: "pve-" + strconv.Itoa(i)})
	}
	cases := map[string][]byte{
		"oversize":         marshalDoc(t, oversize),
		"bad utf8":         bytes.Replace(marshalDoc(t, validDoc()), []byte(`"issuer":"test"`), []byte("\"issuer\":\"te\xffst\""), 1),
		"empty":            nil,
		"too many targets": marshalDoc(t, targets),
		"too many actions": marshalDoc(t, actions),
		"too many remotes": marshalDoc(t, remotes),
	}
	for name, raw := range cases {
		wantInvalid(t, name, decodeRaw(raw))
	}
	if v := decodeRaw(marshalDoc(t, validDoc())); v.State != "active" {
		t.Fatalf("control document: state %q, want active", v.State)
	}
	if v := decodeRaw(marshalDoc(t, providerDoc())); v.State != "active" {
		t.Fatalf("control provider document: state %q, want active", v.State)
	}
}

// TestRejectDuplicateMembersDepth pins the nesting bound of the member scan
// (no document member accepts arbitrary values, so it is tested directly).
func TestRejectDuplicateMembersDepth(t *testing.T) {
	deep := []byte(`{"a":` + strings.Repeat("[", maxViewJSONDepth+1) + strings.Repeat("]", maxViewJSONDepth+1) + `}`)
	if err := rejectDuplicateMembers(deep); !errors.Is(err, errJSONTooDeep) {
		t.Fatalf("deep document: err %v, want errJSONTooDeep", err)
	}
	ok := []byte(`{"a":` + strings.Repeat("[", maxViewJSONDepth-1) + strings.Repeat("]", maxViewJSONDepth-1) + `}`)
	if err := rejectDuplicateMembers(ok); err != nil {
		t.Fatalf("document within the bound: %v", err)
	}
}

// TestDecodeReadGrantRejectsAmbiguousMembers pins that a member cannot be
// repeated or spelled in another case: encoding/json matches names
// case-insensitively, so either would let a hidden member win.
func TestDecodeReadGrantRejectsAmbiguousMembers(t *testing.T) {
	valid := marshalDoc(t, validDoc())
	cases := map[string][]byte{
		"duplicate member":    append([]byte(`{"grant":"read-grant-v2",`), valid[1:]...),
		"duplicate nested":    bytes.Replace(valid, []byte(`"host_id":"web"`), []byte(`"host_id":"web","host_id":"db"`), 1),
		"case duplicate":      bytes.Replace(valid, []byte(`"issuer":"test"`), []byte(`"issuer":"test","ISSUER":"x"`), 1),
		"case duplicate host": bytes.Replace(valid, []byte(`"host_id":"web"`), []byte(`"host_id":"web","Host_ID":"db"`), 1),
		"uppercase name":      bytes.Replace(valid, []byte(`"issuer":`), []byte(`"Issuer":`), 1),
		"unicode-folded name": bytes.Replace(valid, []byte(`"host_key_fingerprint":`), []byte("\"host_\u212aey_fingerprint\":"), 1),
		"trailing data":       append(append([]byte{}, valid...), []byte(` {}`)...),
		"top-level array":     []byte(`[1]`),
		"invalid json":        []byte("not a document"),
		"unknown member":      bytes.Replace(valid, []byte(`"issuer":"test"`), []byte(`"issuer":"test","extra":1`), 1),
	}
	for name, raw := range cases {
		wantInvalid(t, name, decodeRaw(raw))
	}
}

// TestDecodeReadGrantRejectsMalformedScope pins that invalid or repeated
// identifiers mark the grant invalid, never a silently repaired scope.
func TestDecodeReadGrantRejectsMalformedScope(t *testing.T) {
	withHosts := func(ids ...string) []byte {
		d := validDoc()
		d.Targets = nil
		for _, id := range ids {
			d.Targets = append(d.Targets, canonical.Target{HostID: id, HostKeyFingerprint: "fp"})
		}
		return marshalDoc(t, d)
	}
	withActions := func(ids ...string) []byte {
		d := validDoc()
		d.Actions = nil
		for _, id := range ids {
			d.Actions = append(d.Actions, permit.ReadGrantAction{ActionID: id, ModuleVersion: "1.0.0"})
		}
		return marshalDoc(t, d)
	}
	withRemotes := func(ids ...string) []byte {
		d := providerDoc()
		d.ProviderTargets = nil
		for _, id := range ids {
			d.ProviderTargets = append(d.ProviderTargets, permit.ProviderTarget{RemoteID: id})
		}
		return marshalDoc(t, d)
	}
	cases := map[string][]byte{
		"duplicate host":   withHosts("web", "web"),
		"empty host":       withHosts(""),
		"uppercase host":   withHosts("WEB"),
		"overlong host":    withHosts(strings.Repeat("a", 64)),
		"non-ascii host":   withHosts("wéb"),
		"duplicate action": withActions("core.facts", "core.facts"),
		"empty action":     withActions(""),
		"malformed action": withActions("Core Facts"),
		"duplicate remote": withRemotes("pve-a", "pve-a"),
		"malformed remote": withRemotes("PVE A"),
	}
	for name, raw := range cases {
		wantInvalid(t, name, decodeRaw(raw))
	}
}

// TestDecodeReadGrantRejectsImpossibleStructure pins that documents no
// executor could have approved are invalid.
func TestDecodeReadGrantRejectsImpossibleStructure(t *testing.T) {
	alter := func(base permit.ReadGrantDoc, f func(*permit.ReadGrantDoc)) []byte {
		f(&base)
		return marshalDoc(t, base)
	}
	remote := []permit.ProviderTarget{{RemoteID: "pve-a"}}
	cases := map[string][]byte{
		"ssh without targets":        alter(validDoc(), func(d *permit.ReadGrantDoc) { d.Targets = nil }),
		"ssh without actions":        alter(validDoc(), func(d *permit.ReadGrantDoc) { d.Actions = nil }),
		"ssh with provider targets":  alter(validDoc(), func(d *permit.ReadGrantDoc) { d.ProviderTargets = remote }),
		"unknown rate profile":       alter(validDoc(), func(d *permit.ReadGrantDoc) { d.RateProfile = "fast" }),
		"provider without remotes":   alter(providerDoc(), func(d *permit.ReadGrantDoc) { d.ProviderTargets = nil }),
		"provider with ssh targets":  alter(providerDoc(), func(d *permit.ReadGrantDoc) { d.Targets = []canonical.Target{{HostID: "web"}} }),
		"provider with actions":      alter(providerDoc(), func(d *permit.ReadGrantDoc) { d.Actions = validDoc().Actions }),
		"provider on read-grant-v1":  alter(providerDoc(), func(d *permit.ReadGrantDoc) { d.Grant = "read-grant-v1" }),
		"read-grant-v1 with profile": alter(grantDocValue("read-grant-v1", []string{"web"}, decodeCreated, decodeExpiry), func(d *permit.ReadGrantDoc) { d.RateProfile = "ordinary" }),
		"schedule with remotes":      alter(grantDocValue(schedgrant.Format, []string{"web"}, decodeCreated, decodeExpiry), func(d *permit.ReadGrantDoc) { d.ProviderTargets = remote }),
		"schedule with v2 members":   alter(grantDocValue(schedgrant.Format, []string{"web"}, decodeCreated, decodeExpiry), func(d *permit.ReadGrantDoc) { d.Issuer = "test" }),
		"schedule with provider kind": alter(grantDocValue(schedgrant.Format, nil, decodeCreated, decodeExpiry), func(d *permit.ReadGrantDoc) {
			d.Actions = nil
			d.RateProfile = permit.ProviderReadProfile
			d.ProviderTargets = remote
		}),
	}
	for name, raw := range cases {
		wantInvalid(t, name, decodeRaw(raw))
	}
}

// TestDecodeReadGrantChecksRegistry pins that the registry fields are
// validated and must agree with the document they carry.
func TestDecodeReadGrantChecksRegistry(t *testing.T) {
	raw := marshalDoc(t, validDoc())
	cases := map[string]func(*pb.ReadGrant){
		"id differs from doc":     func(g *pb.ReadGrant) { g.GrantId = "0a1b2c3d-4e5f-4a6b-9c7d-8e9f0a1b2c3d" },
		"expiry differs from doc": func(g *pb.ReadGrant) { g.ExpiryUnix++ },
		"stored before created":   func(g *pb.ReadGrant) { g.CreatedUnix = decodeCreated.Unix() - 1 },
		"digest not hex":          func(g *pb.ReadGrant) { g.GrantDigest = "digest-g1" },
		"digest uppercase":        func(g *pb.ReadGrant) { g.GrantDigest = strings.ToUpper(testDigest) },
		"approver empty":          func(g *pb.ReadGrant) { g.ApprovedBy = "" },
		"approver oversize":       func(g *pb.ReadGrant) { g.ApprovedBy = "cli:" + strings.Repeat("a", maxApprovedByLen) },
		"approver bad utf8":       func(g *pb.ReadGrant) { g.ApprovedBy = "cli:\xff" },
		"approver newline":        func(g *pb.ReadGrant) { g.ApprovedBy = "cli:alice\nwebauthn:x" },
		"approver bidi override":  func(g *pb.ReadGrant) { g.ApprovedBy = "cli:\u202eecila" },
	}
	for name, mutate := range cases {
		g := pbGrant(decodeStored, decodeExpiry, time.Time{}, raw)
		mutate(g)
		wantInvalid(t, name, decodeReadGrant(g, nil, false, decodeNow))
	}
	// A malformed registry id is invalid even when the document agrees.
	for name, id := range map[string]string{"id not a uuid": "g1", "uppercase id": strings.ToUpper(testGrantID), "id with newline": testGrantID + "\n"} {
		d := validDoc()
		d.ID = id
		g := pbGrant(decodeStored, decodeExpiry, time.Time{}, marshalDoc(t, d))
		g.GrantId = id
		v := decodeReadGrant(g, nil, false, decodeNow)
		wantInvalid(t, name, v)
		if v.ID != "" {
			t.Errorf("%s: malformed id %q is shown", name, v.ID)
		}
	}
	// One bad registry field must not leave another unvalidated field in
	// the view: a bad id or digest next to a hostile approver clears both.
	for name, mutate := range map[string]func(*pb.ReadGrant){
		"bad id":     func(g *pb.ReadGrant) { g.GrantId = "g1" },
		"bad digest": func(g *pb.ReadGrant) { g.GrantDigest = "digest-g1" },
	} {
		g := pbGrant(decodeStored, decodeExpiry, time.Time{}, raw)
		mutate(g)
		g.ApprovedBy = "cli:\u202eecila\nwebauthn:x"
		v := decodeReadGrant(g, nil, false, decodeNow)
		wantInvalid(t, name, v)
		if v.ApprovedBy != "" {
			t.Errorf("%s: hostile approver %q is shown", name, v.ApprovedBy)
		}
	}
	g := pbGrant(decodeStored, decodeExpiry, time.Time{}, raw)
	g.GrantId = "g1"
	g.GrantDigest = "digest-g1"
	if v := decodeReadGrant(g, nil, false, decodeNow); v.ID != "" || v.Digest != "" {
		t.Errorf("bad id and digest: shown as %q / %q", v.ID, v.Digest)
	}
	g = pbGrant(decodeCreated, decodeExpiry, time.Time{}, raw)
	if v := decodeReadGrant(g, nil, false, decodeNow); v.State != "active" {
		t.Fatalf("stored at the creation second: state %q, want active", v.State)
	}
}

// TestDecodeReadGrantStateOrder pins the state precedence: revoked over
// expired over legacy.
func TestDecodeReadGrantStateOrder(t *testing.T) {
	revoked := decodeNow.Add(-time.Minute)
	g := pbGrant(decodeStored, decodeExpiry, revoked, marshalDoc(t, validDoc()))
	if v := decodeReadGrant(g, nil, false, decodeExpiry.Add(time.Hour)); v.State != "revoked" {
		t.Errorf("revoked and expired: state %q, want revoked", v.State)
	}
	legacy := grantDoc(t, schedgrant.Format, []string{"web"}, decodeCreated, decodeExpiry, time.Time{})
	if v := decodeReadGrant(pbGrant(decodeStored, decodeExpiry, revoked, legacy), nil, false, decodeNow); v.State != "revoked" {
		t.Errorf("revoked and legacy: state %q, want revoked", v.State)
	}
	if v := decodeReadGrant(pbGrant(decodeStored, decodeExpiry, time.Time{}, legacy), nil, false, decodeExpiry); v.State != "expired" {
		t.Errorf("expired and legacy: state %q, want expired", v.State)
	}
}

// TestDecodeReadGrantFormats pins the formats the executor registry holds:
// the stored read-grant-v1 is a normal grant, and a legacy read-schedule-v1
// document is never shown as active, whatever its times.
func TestDecodeReadGrantFormats(t *testing.T) {
	v1 := grantDoc(t, "read-grant-v1", []string{"web"}, decodeCreated, decodeExpiry, time.Time{})
	if v := decodeRaw(v1); v.State != "active" || v.Legacy {
		t.Errorf("read-grant-v1: state %q legacy %v, want active and not legacy", v.State, v.Legacy)
	}
	for exp, want := range map[time.Time]string{decodeExpiry: "legacy", decodeNow.Add(-time.Minute): "expired"} {
		doc := grantDoc(t, schedgrant.Format, []string{"web"}, decodeCreated, exp, time.Time{})
		v := decodeReadGrant(pbGrant(decodeStored, exp, time.Time{}, doc), nil, false, decodeNow)
		if v.State != want || !v.Legacy {
			t.Errorf("read-schedule-v1 expiring %v: state %q legacy %v, want %s and legacy", exp, v.State, v.Legacy, want)
		}
	}
}

// providerDoc is a valid provider grant over two PVE remotes.
func providerDoc() permit.ReadGrantDoc {
	return permit.ReadGrantDoc{Grant: schedgrant.ReadFormat, ID: testGrantID, Issuer: "test", CreatedUnix: decodeCreated.Unix(),
		ExpiryUnix: decodeExpiry.Unix(), Trigger: permit.TriggerBoth, MinIntervalS: 900, RunBudget: 5,
		RateProfile: permit.ProviderReadProfile,
		ProviderTargets: []permit.ProviderTarget{
			{RemoteID: "pve-b", TrustPin: strings.Repeat("b2", 32), TrustGeneration: 2, CredentialVersion: 5, Methods: []string{"nodes", "tasks"}},
			{RemoteID: "pve-a", TrustPin: strings.Repeat("a1", 32), TrustGeneration: 1, CredentialVersion: 3, Methods: []string{"guests"}},
		}}
}

// TestDecodeReadGrantProviderScope pins that a provider grant shows its PVE
// remotes instead of an empty SSH host list.
func TestDecodeReadGrantProviderScope(t *testing.T) {
	g := pbGrant(decodeStored, decodeExpiry, time.Time{}, marshalDoc(t, providerDoc()))
	v := decodeReadGrant(g, testInventory(), true, decodeNow)
	if v.State != "active" || v.ScopeKind != "provider" || !sameStrings(v.Remotes, []string{"pve-a", "pve-b"}) || len(v.Hosts) != 0 {
		t.Fatalf("provider grant: state %q scope %q remotes %v hosts %v", v.State, v.ScopeKind, v.Remotes, v.Hosts)
	}
}
