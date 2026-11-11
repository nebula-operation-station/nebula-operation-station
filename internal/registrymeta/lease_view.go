// SPDX-License-Identifier: AGPL-3.0-or-later

package registrymeta

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"time"
	"unicode"
	"unicode/utf8"

	"google.golang.org/grpc"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
)

// Registry read leases as the lease pages show them. The executor's grant
// list is untrusted input: a document is a registry lease view only when it
// re-verifies exactly like the executor's own check (permit.ParseReadGrant
// at its creation time, the same digest, id and expiry) and has the
// registry rate profile. It names registries, repositories and methods,
// never a credential.

// ErrLeaseListFailed: the executor's read grants could not be listed.
var ErrLeaseListFailed = errors.New("registrymeta: the executor's read leases could not be listed")

// maxLeaseApprovedByLen bounds the executor-reported approver.
const maxLeaseApprovedByLen = 256

var leaseIDRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// LeaseView is one executor-held registry read lease.
type LeaseView struct {
	ID, Digest, ApprovedBy   string
	Created, Expiry, Revoked time.Time
	// State is "active", "expired" or "revoked".
	State string
	// Registries are the frozen registry targets in document order.
	Registries  []permit.RegistryTarget
	RunBudget   int64
	MinInterval time.Duration
}

// ReadGrantLister is the read-grant list subset of the executor API.
type ReadGrantLister interface {
	ListReadGrants(ctx context.Context, in *pb.ListReadGrantsRequest, opts ...grpc.CallOption) (*pb.ListReadGrantsResponse, error)
}

// ListRegistryLeases lists the executor's registry read leases; every other
// grant (and any that does not verify) is left out.
func ListRegistryLeases(ctx context.Context, exec ReadGrantLister, now time.Time) ([]LeaseView, error) {
	r, err := exec.ListReadGrants(ctx, &pb.ListReadGrantsRequest{})
	if err != nil {
		return nil, ErrLeaseListFailed
	}
	var out []LeaseView
	for _, g := range r.GetGrants() {
		if v, ok := DecodeRegistryLease(g, now); ok {
			out = append(out, v)
		}
	}
	return out, nil
}

// DecodeRegistryLease decodes one executor-held grant as a registry read
// lease. ok is false for any other grant and for one that does not verify.
func DecodeRegistryLease(g *pb.ReadGrant, now time.Time) (LeaseView, bool) {
	raw := g.GetCanonicalGrant()
	if !leaseIDRe.MatchString(g.GetGrantId()) || !canonical.ValidSHA256Hex(g.GetGrantDigest()) ||
		!validApprover(g.GetApprovedBy()) || g.GetCreatedUnix() <= 0 || g.GetRevokedUnix() < 0 {
		return LeaseView{}, false
	}
	created := time.Unix(g.GetCreatedUnix(), 0).UTC()
	doc, _, digest, err := permit.ParseReadGrant(raw, created)
	if err != nil || digest != g.GetGrantDigest() || doc.ID != g.GetGrantId() || doc.ExpiryUnix != g.GetExpiryUnix() ||
		doc.CreatedUnix != g.GetCreatedUnix() || doc.Grant != permit.ReadGrantFormat ||
		doc.RateProfile != schedgrant.RegistryReadProfile || len(doc.RegistryTargets) == 0 ||
		len(doc.Targets) != 0 || len(doc.ProviderTargets) != 0 {
		return LeaseView{}, false
	}
	v := LeaseView{ID: doc.ID, Digest: digest, ApprovedBy: g.GetApprovedBy(), Created: created,
		Expiry: time.Unix(doc.ExpiryUnix, 0).UTC(), RunBudget: doc.RunBudget,
		MinInterval: time.Duration(doc.MinIntervalS) * time.Second}
	for _, t := range doc.RegistryTargets {
		t.Repositories, t.Methods = slices.Clone(t.Repositories), slices.Clone(t.Methods)
		v.Registries = append(v.Registries, t)
	}
	switch {
	case g.GetRevokedUnix() != 0:
		v.Revoked, v.State = time.Unix(g.GetRevokedUnix(), 0).UTC(), "revoked"
	case !now.Before(v.Expiry):
		v.State = "expired"
	default:
		v.State = "active"
	}
	return v, true
}

// validApprover reports whether the executor-reported approver is
// non-empty, bounded, UTF-8 and printable.
func validApprover(s string) bool {
	if s == "" || len(s) > maxLeaseApprovedByLen || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}
