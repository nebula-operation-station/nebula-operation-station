// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecollect

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/trafficstore"
)

// GuestNetStoreSink is the GuestNetSink of the server: it stores each
// remote's guest NIC snapshot as provider-tier guest links in the traffic
// store (ADR 0009 D1 tier 2, TM14). The links keep their own source
// (trafficstore.SourceProvider), carry no address and are matched to
// observed endpoints by MAC on the server only; nothing is written into
// the observed tiers.
type GuestNetStoreSink struct {
	store *trafficstore.Store
}

// NewGuestNetStoreSink returns a sink over store, which must not be nil.
func NewGuestNetStoreSink(store *trafficstore.Store) (*GuestNetStoreSink, error) {
	if store == nil {
		return nil, errors.New("pvecollect: traffic store is nil")
	}
	return &GuestNetStoreSink{store: store}, nil
}

// ImportGuestNet revalidates rec and replaces the remote's stored guest
// NICs with it. A record the store holds a newer snapshot for, or one
// older than the store's retention, is reported as ErrGuestNetStale; one
// the store refuses as malformed as ErrGuestNetInvalid. Other errors
// (limits, database) leave the record for a later pass.
func (s *GuestNetStoreSink) ImportGuestNet(ctx context.Context, rec GuestNetRecord) error {
	v, err := ValidateGuestNet(rec)
	if err != nil {
		return err
	}
	snap := trafficstore.GuestNICSnapshot{
		Remote:     v.Remote,
		ObservedAt: time.Unix(v.ObservedUnix, 0),
		NICs:       make([]trafficstore.GuestNIC, len(v.NICs)),
	}
	for i, n := range v.NICs {
		snap.NICs[i] = trafficstore.GuestNIC{
			VMID: n.VMID, Kind: n.Kind, Index: n.Index,
			Bridge: n.Bridge, VLAN: n.VLAN, MAC: n.MAC,
		}
	}
	err = s.store.ReplaceGuestNICs(ctx, snap)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, trafficstore.ErrStaleSnapshot), errors.Is(err, trafficstore.ErrOutOfRange):
		return fmt.Errorf("%w: %w", ErrGuestNetStale, err)
	case errors.Is(err, trafficstore.ErrInvalidGuestNIC):
		return fmt.Errorf("%w: %w", ErrGuestNetInvalid, err)
	default:
		return fmt.Errorf("pvecollect: store guest nics of %s: %w", v.Remote, err)
	}
}
