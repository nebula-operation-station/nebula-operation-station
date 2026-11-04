// SPDX-License-Identifier: AGPL-3.0-or-later

package trafficstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/flowagg"
)

// Endpoint is one observed endpoint.
type Endpoint struct {
	// ID is the stable identity: "mac:"+mac when a MAC is known,
	// "addr:"+address (the first-seen address) otherwise. It is assigned
	// by the store; callers leave it empty on upsert.
	ID string
	// MAC is the lowercase aa:bb:cc:dd:ee:ff MAC, or "" when unknown.
	MAC string
	// Addresses are the observed addresses (normalized). At least one is
	// required.
	Addresses []netip.Addr
	// VLAN is the observed VLAN, 0 when unknown.
	VLAN int
	// OUI is the vendor OUI (six lowercase hex digits). When the MAC is
	// known the store derives it from the MAC and ignores this field;
	// without a MAC it is accepted as given.
	OUI string
	// Hostname is the observed hostname, bounded.
	Hostname string
	// FirstSeen is the first observation time; zero means LastSeen.
	FirstSeen time.Time
	// LastSeen is the most recent observation time.
	LastSeen time.Time
	// Tier is the source tier (flowagg.TierSocket, TierConntrack or
	// TierSensor).
	Tier string
	// Reporter is the host that last reported the endpoint.
	Reporter string
	// IPAMAssetID links the endpoint to the matching IPAM asset, "" when
	// unmatched.
	IPAMAssetID string
	// HostID links the endpoint to the matching managed host, "" when
	// unmatched.
	HostID string
}

var (
	macRE = regexp.MustCompile(`^([0-9a-f]{2}:){5}[0-9a-f]{2}$`)
	ouiRE = regexp.MustCompile(`^[0-9a-f]{6}$`)
)

// validName checks an identifier: bounded, valid UTF-8 and free of
// control characters. allowEmpty permits the empty string.
func validName(s string, maxLen int, allowEmpty bool) error {
	if s == "" {
		if allowEmpty {
			return nil
		}
		return errors.New("empty")
	}
	if len(s) > maxLen {
		return fmt.Errorf("longer than %d bytes", maxLen)
	}
	if !utf8.ValidString(s) {
		return errors.New("not valid UTF-8")
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return errors.New("contains control characters")
		}
	}
	return nil
}

// validTier reports whether t is one of the fixed source tiers.
func validTier(t string) bool {
	return t == flowagg.TierSocket || t == flowagg.TierConntrack || t == flowagg.TierSensor
}

// validAddress reports whether a belongs on the traffic map: valid,
// normalized, not unspecified and not loopback.
func validAddress(a netip.Addr) error {
	n := a.Unmap().WithZone("")
	switch {
	case !n.IsValid():
		return errors.New("invalid address")
	case n.IsUnspecified():
		return errors.New("unspecified address")
	case n.IsLoopback():
		return errors.New("loopback address")
	}
	return nil
}

// deriveOUI returns the vendor OUI (first three octets) of mac, or ""
// when mac is empty.
func deriveOUI(mac string) string {
	if mac == "" {
		return ""
	}
	return strings.ReplaceAll(mac[:8], ":", "")
}

// normalizeAddresses normalizes (unmap, drop zone) and deduplicates
// addresses, keeping the first occurrence of each.
func normalizeAddresses(addrs []netip.Addr) []netip.Addr {
	seen := make(map[netip.Addr]struct{}, len(addrs))
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		n := a.Unmap().WithZone("")
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	return out
}

func validateEndpoint(e *Endpoint) error {
	if e.MAC != "" && !macRE.MatchString(e.MAC) {
		return fmt.Errorf("%w: mac %q", ErrInvalidEndpoint, e.MAC)
	}
	if len(e.Addresses) == 0 {
		return fmt.Errorf("%w: no addresses", ErrInvalidEndpoint)
	}
	if len(e.Addresses) > MaxAddressesPerEndpoint {
		return fmt.Errorf("%w: %d addresses exceed limit %d", ErrInvalidEndpoint, len(e.Addresses), MaxAddressesPerEndpoint)
	}
	for _, a := range e.Addresses {
		if err := validAddress(a); err != nil {
			return fmt.Errorf("%w: address %s: %v", ErrInvalidEndpoint, a, err)
		}
	}
	if e.VLAN < 0 || e.VLAN > 4094 {
		return fmt.Errorf("%w: vlan %d outside [0,4094]", ErrInvalidEndpoint, e.VLAN)
	}
	if e.MAC == "" && e.OUI != "" && !ouiRE.MatchString(e.OUI) {
		return fmt.Errorf("%w: oui %q", ErrInvalidEndpoint, e.OUI)
	}
	if err := validName(e.Hostname, maxHostnameLen, true); err != nil {
		return fmt.Errorf("%w: hostname: %v", ErrInvalidEndpoint, err)
	}
	if err := validName(e.Tier, flowagg.MaxTierLen, false); err != nil || !validTier(e.Tier) {
		return fmt.Errorf("%w: tier %q", ErrInvalidEndpoint, e.Tier)
	}
	if err := validName(e.Reporter, flowagg.MaxHostIDLen, false); err != nil {
		return fmt.Errorf("%w: reporter: %v", ErrInvalidEndpoint, err)
	}
	if err := validName(e.IPAMAssetID, maxIDLen, true); err != nil {
		return fmt.Errorf("%w: ipam asset id: %v", ErrInvalidEndpoint, err)
	}
	if err := validName(e.HostID, maxIDLen, true); err != nil {
		return fmt.Errorf("%w: host id: %v", ErrInvalidEndpoint, err)
	}
	if e.LastSeen.IsZero() {
		return fmt.Errorf("%w: zero last_seen", ErrInvalidEndpoint)
	}
	return nil
}

// UpsertEndpoint stores or updates one observed endpoint.
//
// The endpoint is matched by MAC first, then by any of its addresses, so
// an endpoint first seen by address is merged with the later observation
// that carries its MAC (and vice versa). On update, last_seen advances to
// the maximum, first_seen keeps the minimum, new addresses are added
// (bounded by MaxAddressesPerEndpoint), and non-empty fields of the new
// observation fill empty stored fields.
//
// A new endpoint is refused with ErrLimit when it would exceed
// MaxEndpoints in total or MaxEndpointsPerReporter for its reporter
// (ADR 0009 D7): existing rows of other reporters are never evicted.
//
// LastSeen must lie within the retention window and at most
// maxClockSkew in the future.
func (s *Store) UpsertEndpoint(ctx context.Context, e Endpoint) error {
	if err := validateEndpoint(&e); err != nil {
		return err
	}
	now := s.now()
	if e.LastSeen.Before(now.Add(-s.retention)) {
		return fmt.Errorf("%w: last_seen %s is older than the retention", ErrOutOfRange, e.LastSeen.UTC().Format(time.RFC3339))
	}
	if e.LastSeen.After(now.Add(maxClockSkew)) {
		return fmt.Errorf("%w: last_seen %s is in the future", ErrOutOfRange, e.LastSeen.UTC().Format(time.RFC3339))
	}
	e.Addresses = normalizeAddresses(e.Addresses)
	if e.FirstSeen.IsZero() || e.FirstSeen.After(e.LastSeen) {
		e.FirstSeen = e.LastSeen
	}
	oui := deriveOUI(e.MAC)
	if e.MAC == "" {
		oui = e.OUI
	}

	s.autoPrune(ctx)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("trafficstore: begin upsert endpoint: %w", err)
	}
	defer tx.Rollback()

	id, err := s.findEndpointID(ctx, tx, e.MAC, e.Addresses)
	if err != nil {
		return err
	}

	if id != "" {
		if _, err := tx.ExecContext(ctx, `
			UPDATE net_endpoints SET
				last_seen       = MAX(last_seen, ?),
				hostname        = CASE WHEN hostname = '' AND ? != '' THEN ? ELSE hostname END,
				vlan            = CASE WHEN vlan = 0 AND ? > 0 THEN ? ELSE vlan END,
				tier            = ?,
				reporter        = ?,
				ipam_asset_id   = CASE WHEN ipam_asset_id = '' AND ? != '' THEN ? ELSE ipam_asset_id END,
				host_id         = CASE WHEN host_id = '' AND ? != '' THEN ? ELSE host_id END,
				mac             = CASE WHEN mac = '' AND ? != '' THEN ? ELSE mac END,
				oui             = CASE WHEN ? != '' THEN ? ELSE oui END
			WHERE id = ?`,
			e.LastSeen.Unix(), e.Hostname, e.Hostname, e.VLAN, e.VLAN,
			e.Tier, e.Reporter,
			e.IPAMAssetID, e.IPAMAssetID, e.HostID, e.HostID,
			e.MAC, e.MAC, oui, oui, id); err != nil {
			return fmt.Errorf("trafficstore: update endpoint %s: %w", id, err)
		}
		if err := s.addEndpointAddresses(ctx, tx, id, e.Addresses); err != nil {
			return err
		}
		return tx.Commit()
	}

	// New endpoint: enforce the caps (ADR 0009 D7) before inserting.
	var total, perReporter int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM net_endpoints`).Scan(&total); err != nil {
		return fmt.Errorf("trafficstore: count endpoints: %w", err)
	}
	if total >= s.endpointCap {
		return fmt.Errorf("%w: %d endpoints held, limit %d", ErrLimit, total, s.endpointCap)
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM net_endpoints WHERE reporter = ?`, e.Reporter).Scan(&perReporter); err != nil {
		return fmt.Errorf("trafficstore: count endpoints of reporter %s: %w", e.Reporter, err)
	}
	if perReporter >= s.endpointCapReporter {
		return fmt.Errorf("%w: reporter %s already has %d endpoints, limit %d", ErrLimit, e.Reporter, perReporter, s.endpointCapReporter)
	}

	if e.MAC != "" {
		id = "mac:" + e.MAC
	} else {
		id = "addr:" + e.Addresses[0].String()
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO net_endpoints (id, mac, vlan, oui, hostname, first_seen, last_seen, tier, reporter, ipam_asset_id, host_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, e.MAC, e.VLAN, oui, e.Hostname, e.FirstSeen.Unix(), e.LastSeen.Unix(),
		e.Tier, e.Reporter, e.IPAMAssetID, e.HostID); err != nil {
		return fmt.Errorf("trafficstore: insert endpoint %s: %w", id, err)
	}
	if err := s.addEndpointAddresses(ctx, tx, id, e.Addresses); err != nil {
		return err
	}
	return tx.Commit()
}

// findEndpointID returns the id of the stored endpoint that matches mac
// (when non-empty) or any of addrs, or "" when there is no match.
func (s *Store) findEndpointID(ctx context.Context, tx *sql.Tx, mac string, addrs []netip.Addr) (string, error) {
	if mac != "" {
		var id string
		err := tx.QueryRowContext(ctx, `SELECT id FROM net_endpoints WHERE mac = ?`, mac).Scan(&id)
		if err == nil {
			return id, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return "", fmt.Errorf("trafficstore: look up endpoint by mac: %w", err)
		}
	}
	if len(addrs) == 0 {
		return "", nil
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(addrs)), ",")
	args := make([]any, len(addrs))
	for i, a := range addrs {
		args[i] = a.String()
	}
	var id string
	err := tx.QueryRowContext(ctx,
		`SELECT endpoint_id FROM net_endpoint_addresses WHERE address IN (`+placeholders+`) LIMIT 1`,
		args...).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("trafficstore: look up endpoint by address: %w", err)
	}
	return "", nil
}

// addEndpointAddresses adds addrs to the endpoint, refusing with ErrLimit
// when the endpoint would exceed MaxAddressesPerEndpoint addresses.
func (s *Store) addEndpointAddresses(ctx context.Context, tx *sql.Tx, id string, addrs []netip.Addr) error {
	rows, err := tx.QueryContext(ctx, `SELECT address FROM net_endpoint_addresses WHERE endpoint_id = ?`, id)
	if err != nil {
		return fmt.Errorf("trafficstore: list addresses of endpoint %s: %w", id, err)
	}
	var have int
	known := make(map[string]struct{})
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			rows.Close()
			return fmt.Errorf("trafficstore: list addresses of endpoint %s: %w", id, err)
		}
		have++
		known[a] = struct{}{}
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("trafficstore: list addresses of endpoint %s: %w", id, err)
	}
	var missing []string
	for _, a := range addrs {
		if _, ok := known[a.String()]; !ok {
			missing = append(missing, a.String())
		}
	}
	if have+len(missing) > MaxAddressesPerEndpoint {
		return fmt.Errorf("%w: endpoint %s would hold %d addresses, limit %d", ErrLimit, id, have+len(missing), MaxAddressesPerEndpoint)
	}
	for _, a := range missing {
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO net_endpoint_addresses (endpoint_id, address) VALUES (?, ?)`, id, a); err != nil {
			return fmt.Errorf("trafficstore: add address %s to endpoint %s: %w", a, id, err)
		}
	}
	return nil
}

// Endpoint returns the endpoint with the given store-assigned ID. It
// returns ErrNotFound when there is no such endpoint.
func (s *Store) Endpoint(ctx context.Context, id string) (Endpoint, error) {
	var e Endpoint
	var first, last int64
	err := s.db.QueryRowContext(ctx, `
		SELECT id, mac, vlan, oui, hostname, first_seen, last_seen, tier, reporter, ipam_asset_id, host_id
		FROM net_endpoints WHERE id = ?`, id).
		Scan(&e.ID, &e.MAC, &e.VLAN, &e.OUI, &e.Hostname, &first, &last, &e.Tier, &e.Reporter, &e.IPAMAssetID, &e.HostID)
	if errors.Is(err, sql.ErrNoRows) {
		return Endpoint{}, fmt.Errorf("trafficstore: endpoint %s: %w", id, ErrNotFound)
	}
	if err != nil {
		return Endpoint{}, fmt.Errorf("trafficstore: read endpoint %s: %w", id, err)
	}
	e.FirstSeen = time.Unix(first, 0).UTC()
	e.LastSeen = time.Unix(last, 0).UTC()
	e.Addresses, err = s.endpointAddresses(ctx, id)
	if err != nil {
		return Endpoint{}, err
	}
	return e, nil
}

// LookupEndpoint finds the endpoint by MAC (when mac is non-empty) or by
// address and reports whether one was found.
func (s *Store) LookupEndpoint(ctx context.Context, mac string, addr netip.Addr) (Endpoint, bool, error) {
	var id string
	var err error
	if mac != "" {
		err = s.db.QueryRowContext(ctx, `SELECT id FROM net_endpoints WHERE mac = ?`, mac).Scan(&id)
	} else {
		addr = addr.Unmap().WithZone("")
		err = s.db.QueryRowContext(ctx, `SELECT endpoint_id FROM net_endpoint_addresses WHERE address = ?`, addr.String()).Scan(&id)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return Endpoint{}, false, nil
	}
	if err != nil {
		return Endpoint{}, false, fmt.Errorf("trafficstore: look up endpoint: %w", err)
	}
	e, err := s.Endpoint(ctx, id)
	if err != nil {
		return Endpoint{}, false, err
	}
	return e, true, nil
}

func (s *Store) endpointAddresses(ctx context.Context, id string) ([]netip.Addr, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT address FROM net_endpoint_addresses WHERE endpoint_id = ? ORDER BY address`, id)
	if err != nil {
		return nil, fmt.Errorf("trafficstore: list addresses of endpoint %s: %w", id, err)
	}
	defer rows.Close()
	var out []netip.Addr
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			return nil, fmt.Errorf("trafficstore: list addresses of endpoint %s: %w", id, err)
		}
		addr, err := netip.ParseAddr(a)
		if err != nil {
			// The database is written only by this package's validated
			// writers; an unparsable address is a corruption, not
			// untrusted input.
			return nil, fmt.Errorf("trafficstore: endpoint %s: stored address %q: %w", id, a, err)
		}
		out = append(out, addr)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("trafficstore: list addresses of endpoint %s: %w", id, err)
	}
	return out, nil
}

// CountEndpoints returns the number of stored endpoints.
func (s *Store) CountEndpoints(ctx context.Context) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM net_endpoints`).Scan(&n); err != nil {
		return 0, fmt.Errorf("trafficstore: count endpoints: %w", err)
	}
	return n, nil
}
