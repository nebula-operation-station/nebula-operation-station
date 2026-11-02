// SPDX-License-Identifier: AGPL-3.0-or-later

package ipam

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// ErrAddressTaken is returned by Reserve for an address that is not FREE
// (reserved, excluded, assigned, the gateway, discovered, in conflict) or
// that another reservation took first.
var ErrAddressTaken = errors.New("ipam: address is not free")

// Reservation is an address Reserve took for one consumer (for example a
// guest provisioning). It carries what a consumer binds: the network with
// its prefix, gateway and VLAN, the pool, the address and who reserved it
// when.
type Reservation struct {
	NetworkID string
	Pool      string
	Prefix    netip.Prefix
	Gateway   netip.Addr // invalid when the network has none
	VLAN      int
	Address   netip.Addr
	Note      string
	By        string
	At        time.Time
}

// Reserve atomically reserves one FREE IPv4 address of a network (and of
// pool, if set). Unlike SetEntry it never replaces an existing entry: the
// insert fails when any reservation or exclusion of the address exists, so
// of two concurrent reservations exactly one succeeds. An address that is
// not FREE, including one discovery saw at any time, is refused with
// ErrAddressTaken; a suggestion is not a reservation.
func (s *Store) Reserve(ctx context.Context, user, networkID, pool string, ad netip.Addr, note string) (Reservation, error) {
	switch {
	case !userRe.MatchString(user):
		return Reservation{}, errors.New("ipam: invalid user")
	case !ad.IsValid() || ad.Zone() != "" || !ad.Unmap().Is4():
		return Reservation{}, invalid("a reservation needs an IPv4 address")
	case !plain(note, maxNote, false):
		return Reservation{}, invalid("the note must be at most %d characters of plain text", maxNote)
	}
	ad = ad.Unmap()
	n, err := s.Network(ctx, networkID)
	if err != nil {
		return Reservation{}, fmt.Errorf("reserve %s: %w", ad, err)
	}
	if !n.Prefix.Contains(ad) {
		return Reservation{}, invalid("the address is not in network %s", n.ID)
	}
	if pool != "" {
		found := false
		for _, p := range n.Pools {
			if p.Name == pool {
				found = true
				if ad.Less(p.First) || p.Last.Less(ad) {
					return Reservation{}, invalid("the address is not in pool %s", pool)
				}
			}
		}
		if !found {
			return Reservation{}, fmt.Errorf("reserve %s: pool: %w", ad, ErrNotFound)
		}
	}
	c, err := s.claims(ctx)
	if err != nil {
		return Reservation{}, fmt.Errorf("reserve %s: %w", ad, err)
	}
	now := s.now()
	if v := c.view(n, ad, now); v.Status != Free {
		return Reservation{}, fmt.Errorf("reserve %s (%s): %w", ad, v.Status, ErrAddressTaken)
	}
	// No upsert: the primary key on address makes the reservation atomic
	// against every other entry, including a concurrent Reserve.
	_, err = s.db.ExecContext(ctx, `INSERT INTO ip_entries (address, kind, note, by_user, at) VALUES (?, ?, ?, ?, ?)`,
		ad.String(), EntryReserved, note, user, now.Unix())
	if err != nil {
		var exists int
		if qerr := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM ip_entries WHERE address = ?`, ad.String()).Scan(&exists); qerr == nil && exists > 0 {
			return Reservation{}, fmt.Errorf("reserve %s: %w", ad, ErrAddressTaken)
		}
		return Reservation{}, fmt.Errorf("reserve %s: %w", ad, err)
	}
	return Reservation{NetworkID: n.ID, Pool: pool, Prefix: n.Prefix, Gateway: n.Gateway, VLAN: n.VLAN, Address: ad,
		Note: note, By: user, At: time.Unix(now.Unix(), 0)}, nil
}
