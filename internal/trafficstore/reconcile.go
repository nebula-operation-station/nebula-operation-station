// SPDX-License-Identifier: AGPL-3.0-or-later

package trafficstore

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"strings"
)

// SQL of ReconcileIdentities; package-level (or built from the number of
// placeholders) so the tests can check the query plans. The owner
// conditions repeat the partial index's condition (a non-empty owner), so
// SQLite can use idx_net_endpoints_owner.
const (
	// listOwnersSQL lists the distinct endpoint owners from the owner
	// index.
	listOwnersSQL = `SELECT DISTINCT owner FROM net_endpoints WHERE owner != '' ORDER BY owner`
	// releaseMACLessOwnerSQL drops the ownership of the MAC-less
	// endpoints of an owner that have no address attested by it.
	// Argument: the owner.
	releaseMACLessOwnerSQL = `
		UPDATE net_endpoints SET owner = ''
		WHERE owner = ? AND owner != '' AND mac = '' AND NOT EXISTS (
			SELECT 1 FROM net_endpoint_addresses a
			WHERE a.endpoint_id = net_endpoints.id AND a.reporter = net_endpoints.owner)`
)

// reconcileAddrsSQL deletes an owner's attested addresses on the
// endpoints it owns that are not in a list. Arguments: the owner twice,
// the addresses.
func reconcileAddrsSQL(addrPlaceholders string) string {
	return `
		DELETE FROM net_endpoint_addresses
		WHERE reporter = ? AND endpoint_id IN (SELECT id FROM net_endpoints WHERE owner = ? AND owner != '')
		  AND address NOT IN (` + addrPlaceholders + `)`
}

// releaseMACOwnerSQL drops the ownership of an owner's endpoints whose
// MAC is not in a list. Arguments: the owner, the MACs.
func releaseMACOwnerSQL(macPlaceholders string) string {
	return `
		UPDATE net_endpoints SET owner = ''
		WHERE owner = ? AND owner != '' AND mac != '' AND mac NOT IN (` + macPlaceholders + `)`
}

// ReconcileIdentities re-evaluates every endpoint's ownership and
// owner-attested addresses against the server's current records, so a
// host that no longer reports an endpoint cannot keep stale ownership or
// attestations until the retention removes them.
//
// current maps every managed host ID to its Identity, built as for
// UpsertEndpoint (MACs and addresses more than one host claims left
// out); an owner missing from current has no records. For every owner:
// its attested addresses that are no longer in its Identity.Addrs are
// removed, it loses the endpoints whose MAC is no longer in its
// Identity.MACs, and it loses the MAC-less endpoints left without an
// attested address. Ownership is never granted here; a holder becomes
// owner with its next report. Reporters' own observations (seen-by rows
// and non-owner addresses) are kept.
//
// The work is bounded: one indexed read of the owners, then three
// indexed statements per owner, each owner in its own short write
// transaction. It returns the number of endpoints that lost their owner.
// Callers run it whenever host records change, and periodically (with
// Prune).
func (s *Store) ReconcileIdentities(ctx context.Context, current map[string]Identity) (int64, error) {
	type record struct {
		macs  []string
		addrs []netip.Addr
	}
	records := make(map[string]record, len(current))
	for host, own := range current {
		addrs, err := validateIdentity(own)
		if err != nil {
			return 0, fmt.Errorf("host %s: %w", host, err)
		}
		records[host] = record{macs: own.MACs, addrs: addrs}
	}
	owners, err := s.listOwners(ctx)
	if err != nil {
		return 0, err
	}
	var released int64
	for _, owner := range owners {
		rec := records[owner]
		err := s.writeTx(ctx, "reconcile owner", func(tx *sql.Tx) error {
			addrPlaceholders, addrArgsList := addrArgs(rec.addrs)
			if _, err := tx.ExecContext(ctx, reconcileAddrsSQL(addrPlaceholders),
				append([]any{owner, owner}, addrArgsList...)...); err != nil {
				return fmt.Errorf("trafficstore: reconcile addresses of %s: %w", owner, err)
			}
			macPlaceholders := strings.TrimSuffix(strings.Repeat("?,", len(rec.macs)), ",")
			args := make([]any, 0, 1+len(rec.macs))
			args = append(args, owner)
			for _, m := range rec.macs {
				args = append(args, m)
			}
			res, err := tx.ExecContext(ctx, releaseMACOwnerSQL(macPlaceholders), args...)
			if err != nil {
				return fmt.Errorf("trafficstore: reconcile MAC endpoints of %s: %w", owner, err)
			}
			n, err := res.RowsAffected()
			if err != nil {
				return fmt.Errorf("trafficstore: reconcile MAC endpoints of %s: %w", owner, err)
			}
			released += n
			res, err = tx.ExecContext(ctx, releaseMACLessOwnerSQL, owner)
			if err != nil {
				return fmt.Errorf("trafficstore: reconcile MAC-less endpoints of %s: %w", owner, err)
			}
			if n, err = res.RowsAffected(); err != nil {
				return fmt.Errorf("trafficstore: reconcile MAC-less endpoints of %s: %w", owner, err)
			}
			released += n
			return nil
		})
		if err != nil {
			return released, err
		}
	}
	return released, nil
}

// listOwners returns the distinct endpoint owners.
func (s *Store) listOwners(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, listOwnersSQL)
	if err != nil {
		return nil, fmt.Errorf("trafficstore: list endpoint owners: %w", err)
	}
	defer rows.Close()
	var owners []string
	for rows.Next() {
		var o string
		if err := rows.Scan(&o); err != nil {
			return nil, fmt.Errorf("trafficstore: list endpoint owners: %w", err)
		}
		owners = append(owners, o)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("trafficstore: list endpoint owners: %w", err)
	}
	return owners, nil
}
