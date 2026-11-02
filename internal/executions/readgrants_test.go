// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
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

// grantDoc marshals a read-grant document with the given format, targets and
// times (the times are also what the executor registry reports).
func grantDoc(t *testing.T, format string, targets []string, created, expiry, revoked time.Time) []byte {
	t.Helper()
	var tg []canonical.Target
	for _, id := range targets {
		tg = append(tg, canonical.Target{HostID: id, HostKeyFingerprint: "fp"})
	}
	doc := permit.ReadGrantDoc{
		Grant:       format,
		ID:          "g1",
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
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func pbGrant(id string, created, expiry, revoked time.Time, doc []byte) *pb.ReadGrant {
	return &pb.ReadGrant{
		GrantId: id, GrantDigest: "digest-" + id, CanonicalGrant: doc,
		ApprovedBy: "alice", CreatedUnix: created.Unix(),
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
				pbGrant("g1", tc.created, tc.expiry, tc.revoked, tc.doc),
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
			if got.ID != "g1" || got.Digest != "digest-g1" || got.ApprovedBy != "alice" {
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

	if err := s.RevokeReadGrant(context.Background(), "alice", "grant-1"); err != nil {
		t.Fatalf("RevokeReadGrant: %v", err)
	}
	if f.revokeID != "grant-1" {
		t.Errorf("revoke id = %q, want grant-1", f.revokeID)
	}
	if !strings.Contains(audit.String(), "read_grant_revoked") || !strings.Contains(audit.String(), "grant-1") {
		t.Errorf("audit missing read_grant_revoked/grant-1: %s", audit.String())
	}
}

func TestRevokeReadGrantNotFound(t *testing.T) {
	f := &readGrantFake{fakeExec: &fakeExec{}, revokeErr: status.Error(codes.NotFound, "nope")}
	s := newReadGrantService(t, f, readGrantHostsFrom(testInventory()))
	if err := s.RevokeReadGrant(context.Background(), "alice", "missing"); err != ErrReadGrantNotFound {
		t.Fatalf("want ErrReadGrantNotFound, got %v", err)
	}
}

func TestRevokeReadGrantFailed(t *testing.T) {
	f := &readGrantFake{fakeExec: &fakeExec{}, revokeErr: status.Error(codes.Internal, "boom")}
	s := newReadGrantService(t, f, readGrantHostsFrom(testInventory()))
	if err := s.RevokeReadGrant(context.Background(), "alice", "g1"); err != ErrReadGrantRevokeFailed {
		t.Fatalf("want ErrReadGrantRevokeFailed, got %v", err)
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

// TestDecodeReadGrantExecutorEncoding pins what the real executor sends:
// RevokedUnix 0 is "not revoked", expiry is exclusive, and oversized or
// malformed documents are invalid.
func TestDecodeReadGrantExecutorEncoding(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	var zero time.Time
	doc := grantDoc(t, schedgrant.ReadFormat, []string{"web"}, now.Add(-time.Hour), now.Add(time.Hour), zero)
	g := &pb.ReadGrant{GrantId: "g", CreatedUnix: now.Add(-time.Hour).Unix(), ExpiryUnix: now.Add(time.Hour).Unix(), RevokedUnix: 0, CanonicalGrant: doc}
	if v := decodeReadGrant(g, nil, false, now); v.State != "active" || !v.Revoked.IsZero() {
		t.Fatalf("RevokedUnix 0: state %q revoked %v, want active and zero", v.State, v.Revoked)
	}
	g.ExpiryUnix = now.Unix()
	if v := decodeReadGrant(g, nil, false, now); v.State != "expired" {
		t.Fatalf("at the expiry second: state %q, want expired", v.State)
	}
	g.ExpiryUnix = now.Add(time.Hour).Unix()
	for name, raw := range map[string][]byte{
		"oversize": append(append([]byte{}, doc...), make([]byte, permit.MaxReadGrantDocSize)...),
		"bad utf8": {0xff, 0xfe},
		"empty":    nil,
	} {
		g.CanonicalGrant = raw
		if v := decodeReadGrant(g, nil, false, now); v.State != "invalid" || v.Hosts != nil {
			t.Errorf("%s: state %q hosts %v, want invalid with no hosts", name, v.State, v.Hosts)
		}
	}
	g.CanonicalGrant = grantDoc(t, schedgrant.ReadFormat, []string{""}, now.Add(-time.Hour), now.Add(time.Hour), zero)
	if v := decodeReadGrant(g, nil, false, now); v.State != "invalid" {
		t.Errorf("empty host id: state %q, want invalid", v.State)
	}
}
