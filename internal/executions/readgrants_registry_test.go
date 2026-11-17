// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
)

// registryLeaseDoc is a read-grant-v2 registry read lease for one registry
// ("corp"), created at created and expiring at expiry. The mutate hook
// alters it before it is marshalled.
func registryLeaseDoc(created, expiry time.Time, mutate func(*permit.ReadGrantDoc)) permit.ReadGrantDoc {
	doc := permit.ReadGrantDoc{
		Grant:        permit.ReadGrantFormat,
		ID:           testGrantID,
		Issuer:       "nebula-server",
		CreatedUnix:  created.Unix(),
		ExpiryUnix:   expiry.Unix(),
		Trigger:      permit.TriggerOnDemand,
		Actions:      []permit.ReadGrantAction{},
		MinIntervalS: int64(schedgrant.RegistryMinInterval / time.Second),
		RunBudget:    schedgrant.RegistryDefaultRunBudget,
		RateProfile:  schedgrant.RegistryReadProfile,
		RegistryTargets: []permit.RegistryTarget{{
			RegistryID:        "corp",
			ConfigDigest:      strings.Repeat("c", 64),
			ConfigVersion:     1,
			CredentialID:      strings.Repeat("d", 32),
			CredentialVersion: 1,
			Repositories:      []string{"team/app"},
			Methods:           []string{schedgrant.RegistryReadTagDigest},
		}},
	}
	if mutate != nil {
		mutate(&doc)
	}
	return doc
}

// registryLeaseGrant is the executor's registry entry for doc. The digest is
// the one permit computes for a document it accepts; for one it rejects, the
// placeholder testDigest is used (the lease must then be invalid anyway).
func registryLeaseGrant(t *testing.T, doc permit.ReadGrantDoc, created time.Time, revoked time.Time) *pb.ReadGrant {
	t.Helper()
	raw := marshalDoc(t, doc)
	digest := testDigest
	if _, _, d, err := permit.ParseReadGrant(raw, created); err == nil {
		digest = d
	}
	return &pb.ReadGrant{
		GrantId: testGrantID, GrantDigest: digest, CanonicalGrant: raw,
		ApprovedBy: testApprover, CreatedUnix: created.Unix(),
		ExpiryUnix: doc.ExpiryUnix, RevokedUnix: revokedUnix(revoked),
	}
}

// TestDecodeReadGrantRegistryLeaseStates: a verified registry read lease
// is a lease view with its registry as the scope, and its state is active,
// expired or revoked (the same rule the lease pages use). It is never
// "invalid" and it carries no hosts or actions.
func TestDecodeReadGrantRegistryLeaseStates(t *testing.T) {
	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name      string
		created   time.Time
		expiry    time.Time
		revoked   time.Time
		wantState string
	}{
		{"valid active", now.Add(-time.Hour), now.Add(time.Hour), time.Time{}, "active"},
		{"expired", now.Add(-2 * time.Hour), now.Add(-time.Hour), time.Time{}, "expired"},
		{"revoked before expiry", now.Add(-2 * time.Hour), now.Add(time.Hour), now.Add(-30 * time.Minute), "revoked"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := registryLeaseDoc(tc.created, tc.expiry, nil)
			g := registryLeaseGrant(t, doc, tc.created, tc.revoked)
			v := decodeReadGrant(g, nil, false, now)
			if v.State != tc.wantState {
				t.Fatalf("state = %q, want %q", v.State, tc.wantState)
			}
			if v.ScopeKind != ScopeRegistry || v.ScopeValue != "corp" {
				t.Fatalf("scope = %q %q, want registry corp", v.ScopeKind, v.ScopeValue)
			}
			if v.RateProfile != schedgrant.RegistryReadProfile || v.Legacy {
				t.Fatalf("profile = %q legacy=%v", v.RateProfile, v.Legacy)
			}
			if len(v.Hosts) != 0 || len(v.Actions) != 0 || len(v.Remotes) != 0 || len(v.Providers) != 0 {
				t.Fatalf("registry lease carries host, action or remote scope: %+v", v)
			}
			if v.Digest != g.GetGrantDigest() || v.ApprovedBy != testApprover || v.ID != testGrantID {
				t.Fatalf("identity = %q %q %q", v.ID, v.Digest, v.ApprovedBy)
			}
		})
	}
}

// TestDecodeReadGrantRegistryLeaseTooWideIsInvalid: a registry lease that
// exceeds the registry limits (lifetime, budget, registry count) does not
// verify, so it is "invalid", as the lease pages show it.
func TestDecodeReadGrantRegistryLeaseTooWideIsInvalid(t *testing.T) {
	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	created := now.Add(-time.Hour)
	long := created.Add(schedgrant.RegistryReadMaxLifetime + time.Hour)
	manyRegistries := make([]permit.RegistryTarget, permit.MaxRegistryTargets+1)
	for i := range manyRegistries {
		manyRegistries[i] = permit.RegistryTarget{
			RegistryID: "r" + string(rune('a'+i)), ConfigDigest: strings.Repeat("c", 64), ConfigVersion: 1,
			CredentialID: strings.Repeat("d", 32), CredentialVersion: 1,
			Repositories: []string{"team/app"}, Methods: []string{schedgrant.RegistryReadTagDigest},
		}
	}
	cases := []struct {
		name   string
		expiry time.Time
		mutate func(*permit.ReadGrantDoc)
	}{
		{"lifetime beyond seven days", long, nil},
		{"budget above the maximum", now.Add(time.Hour), func(d *permit.ReadGrantDoc) {
			d.RunBudget = schedgrant.RegistryMaxRunBudget + 1
		}},
		{"more registries than one lease may name", now.Add(time.Hour), func(d *permit.ReadGrantDoc) {
			d.RegistryTargets = manyRegistries
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := registryLeaseDoc(created, tc.expiry, tc.mutate)
			g := registryLeaseGrant(t, doc, created, time.Time{})
			if v := decodeReadGrant(g, nil, false, now); v.State != "invalid" {
				t.Fatalf("state = %q, want invalid", v.State)
			}
		})
	}
}

// TestDecodeReadGrantRegistryLeaseTamperedIsInvalid: a registry-profile
// document whose stored identity, digest or approval time does not match
// what permit verifies is "invalid", never a lease view.
func TestDecodeReadGrantRegistryLeaseTamperedIsInvalid(t *testing.T) {
	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	created := now.Add(-time.Hour)
	expiry := now.Add(time.Hour)
	valid := registryLeaseDoc(created, expiry, nil)

	t.Run("digest not the one permit computes", func(t *testing.T) {
		g := registryLeaseGrant(t, valid, created, time.Time{})
		g.GrantDigest = strings.Repeat("e", 64)
		if v := decodeReadGrant(g, nil, false, now); v.State != "invalid" {
			t.Fatalf("state = %q, want invalid", v.State)
		}
	})
	t.Run("stored id differs from the document", func(t *testing.T) {
		g := registryLeaseGrant(t, valid, created, time.Time{})
		g.GrantId = "0a1b2c3d-4e5f-4a60-8b71-92c3d4e5f6a7"
		if v := decodeReadGrant(g, nil, false, now); v.State != "invalid" {
			t.Fatalf("state = %q, want invalid", v.State)
		}
	})
	t.Run("approved before the document was created", func(t *testing.T) {
		g := registryLeaseGrant(t, valid, created, time.Time{})
		g.CreatedUnix = created.Add(-time.Minute).Unix()
		if v := decodeReadGrant(g, nil, false, now); v.State != "invalid" {
			t.Fatalf("state = %q, want invalid", v.State)
		}
	})
	t.Run("stored expiry differs from the document", func(t *testing.T) {
		g := registryLeaseGrant(t, valid, created, time.Time{})
		g.ExpiryUnix = expiry.Add(time.Hour).Unix()
		if v := decodeReadGrant(g, nil, false, now); v.State != "invalid" {
			t.Fatalf("state = %q, want invalid", v.State)
		}
	})
	t.Run("registry profile mixed with host targets", func(t *testing.T) {
		doc := registryLeaseDoc(created, expiry, func(d *permit.ReadGrantDoc) {
			d.Targets = []canonical.Target{{HostID: "web", HostKeyFingerprint: "fp"}}
		})
		g := registryLeaseGrant(t, doc, created, time.Time{})
		if v := decodeReadGrant(g, nil, false, now); v.State != "invalid" {
			t.Fatalf("state = %q, want invalid", v.State)
		}
	})
}

// TestDecodeReadGrantRegistryLeaseUnlistedRegistry: a lease names a
// registry the executor does not currently list. The lease itself verifies
// (the executor checks registry records on every read, not at view time),
// so it is shown with its state like the lease pages show it, not invalid.
func TestDecodeReadGrantRegistryLeaseUnlistedRegistry(t *testing.T) {
	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	created := now.Add(-time.Hour)
	doc := registryLeaseDoc(created, now.Add(time.Hour), func(d *permit.ReadGrantDoc) {
		d.RegistryTargets[0].RegistryID = "retired"
	})
	g := registryLeaseGrant(t, doc, created, time.Time{})
	v := decodeReadGrant(g, nil, false, now)
	if v.State != "active" || v.ScopeKind != ScopeRegistry || v.ScopeValue != "retired" {
		t.Fatalf("view = state %q scope %q %q, want active registry retired", v.State, v.ScopeKind, v.ScopeValue)
	}
}

// TestDecodeReadGrantOrdinaryWithRegistryTargetsIsInvalid: a host grant that
// also carries registry targets is impossible (permit refuses it), so it is
// invalid, and the other lease kinds are otherwise decoded as before.
func TestDecodeReadGrantOrdinaryWithRegistryTargetsIsInvalid(t *testing.T) {
	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	created := now.Add(-time.Hour)
	doc := grantDocValue(schedgrant.ReadFormat, []string{"web"}, created, now.Add(time.Hour))
	doc.RegistryTargets = registryLeaseDoc(created, now.Add(time.Hour), nil).RegistryTargets
	if v := decodeReadGrant(pbGrant(created, now.Add(time.Hour), time.Time{}, marshalDoc(t, doc)), nil, false, now); v.State != "invalid" {
		t.Fatalf("state = %q, want invalid", v.State)
	}
}
