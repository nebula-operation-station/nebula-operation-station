// SPDX-License-Identifier: AGPL-3.0-or-later

package trafficstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/flowagg"
)

// Endpoint is one observed endpoint.
type Endpoint struct {
	// ID is the opaque, store-assigned identity ("ep-" plus a random
	// suffix). It never changes, also not when a MAC is learned later.
	// Callers leave it empty on upsert.
	ID string
	// MAC is the lowercase aa:bb:cc:dd:ee:ff MAC, or "" when unknown.
	MAC string
	// Addresses are the observed addresses. On upsert at least one is
	// required; IPv4-mapped addresses are unmapped and the zone of a
	// link-local address is dropped (it names the reporter's interface),
	// a zone on any other address is refused. On read they are the
	// distinct addresses all reporters attached, sorted.
	Addresses []netip.Addr
	// VLAN is the observed VLAN, 0 when unknown.
	VLAN int
	// OUI is the vendor OUI (six lowercase hex digits). When the MAC is
	// known the store derives it from the MAC and ignores this field;
	// without a MAC it is accepted as given.
	OUI string
	// Hostname is the observed hostname, bounded.
	Hostname string
	// FirstSeen is the first observation time; zero means LastSeen. On
	// read it is the earliest of all reporters.
	FirstSeen time.Time
	// LastSeen is the most recent observation time. On read it is the
	// latest of all reporters.
	LastSeen time.Time
	// Tier is the source tier (flowagg.TierSocket, TierConntrack or
	// TierSensor); on read, the owner's latest tier.
	Tier string
	// Reporter is, on upsert, the host that reports the observation; on
	// read, the owner: the reporter that created the endpoint (or the
	// earliest remaining reporter after the owner's observation expired).
	Reporter string
	// SeenBy lists, on read, every reporter that currently sees the
	// endpoint, sorted. It is ignored on upsert.
	SeenBy []string
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

// endpointIDPrefix starts every store-assigned endpoint ID.
const endpointIDPrefix = "ep-"

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

// normalizeAddress returns a in the stored form: unmapped, and without
// the zone of a link-local address. A zone on any other address makes no
// sense and is refused, as are invalid, unspecified and loopback
// addresses.
func normalizeAddress(a netip.Addr) (netip.Addr, error) {
	if !a.IsValid() {
		return netip.Addr{}, errors.New("invalid address")
	}
	n := a.Unmap()
	if n.Zone() != "" {
		if !n.IsLinkLocalUnicast() && !n.IsLinkLocalMulticast() {
			return netip.Addr{}, errors.New("zone on a non-link-local address")
		}
		n = n.WithZone("")
	}
	switch {
	case n.IsUnspecified():
		return netip.Addr{}, errors.New("unspecified address")
	case n.IsLoopback():
		return netip.Addr{}, errors.New("loopback address")
	}
	return n, nil
}

// deriveOUI returns the vendor OUI (first three octets) of mac, or ""
// when mac is empty.
func deriveOUI(mac string) string {
	if mac == "" {
		return ""
	}
	return strings.ReplaceAll(mac[:8], ":", "")
}

// validateEndpoint checks e and normalizes and deduplicates its
// addresses in place.
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
	addrs := make([]netip.Addr, 0, len(e.Addresses))
	for _, a := range e.Addresses {
		n, err := normalizeAddress(a)
		if err != nil {
			return fmt.Errorf("%w: address %s: %v", ErrInvalidEndpoint, a, err)
		}
		if !slices.Contains(addrs, n) {
			addrs = append(addrs, n)
		}
	}
	e.Addresses = addrs
	if e.VLAN < 0 || e.VLAN > 4094 {
		return fmt.Errorf("%w: vlan %d outside [0,4094]", ErrInvalidEndpoint, e.VLAN)
	}
	if e.MAC == "" && e.OUI != "" && !ouiRE.MatchString(e.OUI) {
		return fmt.Errorf("%w: oui %q", ErrInvalidEndpoint, e.OUI)
	}
	if err := validName(e.Hostname, maxHostnameLen, true); err != nil {
		return fmt.Errorf("%w: hostname: %v", ErrInvalidEndpoint, err)
	}
	if !validTier(e.Tier) {
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
// Matching (deterministic):
//   - an observation with a MAC matches the endpoint with that MAC; if
//     there is none, it matches a MAC-less endpoint the same reporter
//     owns and that has one of its addresses (the owner learns the MAC);
//     otherwise it creates a new endpoint. An address never merges a
//     different or new MAC into another endpoint, so a device that gets
//     a reused DHCP address gets its own endpoint.
//   - an observation without a MAC matches an endpoint with one of its
//     addresses, preferring one the reporter owns, then one whose owner
//     attached the address, then the most recently seen, then the
//     smallest ID; otherwise it creates one.
//
// The reporter is added to the endpoint's seen-by set (its own tier and
// first/last seen) and its new addresses are attached under its name,
// bounded by MaxAddressesPerEndpoint per reporter. The endpoint's
// last_seen advances to the maximum and first_seen keeps the minimum of
// all observations. Only the owner changes the descriptive fields: its
// tier replaces the stored one, a learned MAC sets the MAC and its OUI,
// and non-empty VLAN, OUI (without MAC), hostname and links fill empty
// stored fields. Other reporters never change them, so they cannot take
// over an endpoint, use up the owner's address slots or make its writes
// fail.
//
// A new endpoint is refused with ErrLimit when it would exceed
// MaxEndpoints in total; joining or creating an endpoint is refused when
// the reporter already sees MaxEndpointsPerReporter endpoints or the
// endpoint has MaxReportersPerEndpoint reporters (ADR 0009 D7). The
// counts are per reporter, so other reporters' rows are never evicted.
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
	if e.FirstSeen.IsZero() || e.FirstSeen.After(e.LastSeen) {
		e.FirstSeen = e.LastSeen
	}
	oui := deriveOUI(e.MAC)
	if e.MAC == "" {
		oui = e.OUI
	}

	s.autoPrune(ctx)

	return s.writeTx(ctx, "upsert endpoint", func(tx *sql.Tx) error {
		id, owner, err := findEndpoint(ctx, tx, e.MAC, e.Reporter, e.Addresses)
		if err != nil {
			return err
		}
		if id == "" {
			return s.insertEndpoint(ctx, tx, &e, oui)
		}
		if err := s.joinEndpoint(ctx, tx, id, &e); err != nil {
			return err
		}
		if owner == e.Reporter {
			if _, err := tx.ExecContext(ctx, `
				UPDATE net_endpoints SET
					tier          = ?1,
					oui           = CASE WHEN mac = '' AND ?2 != '' THEN ?3
					                     WHEN mac = '' AND oui = '' THEN ?3 ELSE oui END,
					mac           = CASE WHEN mac = '' AND ?2 != '' THEN ?2 ELSE mac END,
					vlan          = CASE WHEN vlan = 0 THEN ?4 ELSE vlan END,
					hostname      = CASE WHEN hostname = '' THEN ?5 ELSE hostname END,
					ipam_asset_id = CASE WHEN ipam_asset_id = '' THEN ?6 ELSE ipam_asset_id END,
					host_id       = CASE WHEN host_id = '' THEN ?7 ELSE host_id END
				WHERE id = ?8`,
				e.Tier, e.MAC, oui, e.VLAN, e.Hostname, e.IPAMAssetID, e.HostID, id); err != nil {
				return fmt.Errorf("trafficstore: update endpoint %s: %w", id, err)
			}
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE net_endpoints SET first_seen = MIN(first_seen, ?), last_seen = MAX(last_seen, ?)
			WHERE id = ?`, e.FirstSeen.Unix(), e.LastSeen.Unix(), id); err != nil {
			return fmt.Errorf("trafficstore: update endpoint %s: %w", id, err)
		}
		return nil
	})
}

// newEndpointID returns a fresh opaque endpoint ID.
func newEndpointID() string {
	return endpointIDPrefix + strings.ToLower(rand.Text())
}

// insertEndpoint creates a new endpoint owned by e.Reporter.
func (s *Store) insertEndpoint(ctx context.Context, tx *sql.Tx, e *Endpoint, oui string) error {
	total, err := readCount(ctx, tx, countEndpoints, countTotal)
	if err != nil {
		return err
	}
	if total >= s.endpointCap {
		return fmt.Errorf("%w: %d endpoints held, limit %d", ErrLimit, total, s.endpointCap)
	}
	if err := s.checkReporterCap(ctx, tx, e.Reporter); err != nil {
		return err
	}
	id := newEndpointID()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO net_endpoints (id, mac, vlan, oui, hostname, first_seen, last_seen, tier, owner, ipam_asset_id, host_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, e.MAC, e.VLAN, oui, e.Hostname, e.FirstSeen.Unix(), e.LastSeen.Unix(),
		e.Tier, e.Reporter, e.IPAMAssetID, e.HostID); err != nil {
		return fmt.Errorf("trafficstore: insert endpoint %s: %w", id, err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO net_endpoint_reporters (endpoint_id, reporter, tier, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?)`, id, e.Reporter, e.Tier, e.FirstSeen.Unix(), e.LastSeen.Unix()); err != nil {
		return fmt.Errorf("trafficstore: insert endpoint %s reporter: %w", id, err)
	}
	return addEndpointAddresses(ctx, tx, id, e.Reporter, e.Addresses)
}

// checkReporterCap refuses a new seen-by row for reporter at
// MaxEndpointsPerReporter.
func (s *Store) checkReporterCap(ctx context.Context, tx *sql.Tx, reporter string) error {
	n, err := readCount(ctx, tx, countEndpointSeen, reporter)
	if err != nil {
		return err
	}
	if n >= s.endpointCapReporter {
		return fmt.Errorf("%w: reporter %s already sees %d endpoints, limit %d", ErrLimit, reporter, n, s.endpointCapReporter)
	}
	return nil
}

// joinEndpoint records e.Reporter's observation of endpoint id: it adds
// or updates the reporter's seen-by row and attaches its addresses.
func (s *Store) joinEndpoint(ctx context.Context, tx *sql.Tx, id string, e *Endpoint) error {
	res, err := tx.ExecContext(ctx, `
		UPDATE net_endpoint_reporters SET
			tier = ?, first_seen = MIN(first_seen, ?), last_seen = MAX(last_seen, ?)
		WHERE endpoint_id = ? AND reporter = ?`,
		e.Tier, e.FirstSeen.Unix(), e.LastSeen.Unix(), id, e.Reporter)
	if err != nil {
		return fmt.Errorf("trafficstore: update endpoint %s reporter: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("trafficstore: update endpoint %s reporter: %w", id, err)
	}
	if n == 0 {
		var reporters int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM net_endpoint_reporters WHERE endpoint_id = ?`, id).Scan(&reporters); err != nil {
			return fmt.Errorf("trafficstore: count reporters of endpoint %s: %w", id, err)
		}
		if reporters >= MaxReportersPerEndpoint {
			return fmt.Errorf("%w: endpoint %s already has %d reporters, limit %d", ErrLimit, id, reporters, MaxReportersPerEndpoint)
		}
		if err := s.checkReporterCap(ctx, tx, e.Reporter); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO net_endpoint_reporters (endpoint_id, reporter, tier, first_seen, last_seen)
			VALUES (?, ?, ?, ?, ?)`, id, e.Reporter, e.Tier, e.FirstSeen.Unix(), e.LastSeen.Unix()); err != nil {
			return fmt.Errorf("trafficstore: insert endpoint %s reporter: %w", id, err)
		}
	}
	return addEndpointAddresses(ctx, tx, id, e.Reporter, e.Addresses)
}

// addrArgs returns the SQL placeholders and arguments for addrs.
func addrArgs(addrs []netip.Addr) (string, []any) {
	args := make([]any, len(addrs))
	for i, a := range addrs {
		args[i] = a.String()
	}
	return strings.TrimSuffix(strings.Repeat("?,", len(addrs)), ","), args
}

// findEndpoint returns the id and owner of the stored endpoint an
// observation by reporter with mac (may be "") and addrs belongs to, or
// "" when it needs a new endpoint. See UpsertEndpoint for the rules.
func findEndpoint(ctx context.Context, tx *sql.Tx, mac, reporter string, addrs []netip.Addr) (id, owner string, err error) {
	if mac != "" {
		err := tx.QueryRowContext(ctx, `SELECT id, owner FROM net_endpoints WHERE mac = ?`, mac).Scan(&id, &owner)
		if err == nil {
			return id, owner, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return "", "", fmt.Errorf("trafficstore: look up endpoint by mac: %w", err)
		}
	}
	placeholders, args := addrArgs(addrs)
	var row *sql.Row
	if mac != "" {
		// Only the reporter's own MAC-less endpoint may learn the MAC.
		row = tx.QueryRowContext(ctx, `
			SELECT e.id, e.owner FROM net_endpoint_addresses a
			JOIN net_endpoints e ON e.id = a.endpoint_id
			WHERE a.address IN (`+placeholders+`) AND e.mac = '' AND e.owner = ?
			GROUP BY e.id ORDER BY e.last_seen DESC, e.id LIMIT 1`,
			append(args, reporter)...)
	} else {
		row = tx.QueryRowContext(ctx, `
			SELECT e.id, e.owner FROM net_endpoint_addresses a
			JOIN net_endpoints e ON e.id = a.endpoint_id
			WHERE a.address IN (`+placeholders+`)
			GROUP BY e.id
			ORDER BY MAX(e.owner = ?) DESC, MAX(a.reporter = e.owner) DESC, e.last_seen DESC, e.id
			LIMIT 1`,
			append(args, reporter)...)
	}
	err = row.Scan(&id, &owner)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", nil
	}
	if err != nil {
		return "", "", fmt.Errorf("trafficstore: look up endpoint by address: %w", err)
	}
	return id, owner, nil
}

// addEndpointAddresses attaches addrs to the endpoint under reporter,
// refusing with ErrLimit when the reporter would attach more than
// MaxAddressesPerEndpoint addresses to it.
func addEndpointAddresses(ctx context.Context, tx *sql.Tx, id, reporter string, addrs []netip.Addr) error {
	placeholders, args := addrArgs(addrs)
	var known, have int
	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*), COUNT(CASE WHEN address IN (`+placeholders+`) THEN 1 END)
		FROM net_endpoint_addresses WHERE endpoint_id = ? AND reporter = ?`,
		append(args, id, reporter)...).Scan(&have, &known); err != nil {
		return fmt.Errorf("trafficstore: count addresses of endpoint %s: %w", id, err)
	}
	if n := have + len(addrs) - known; n > MaxAddressesPerEndpoint {
		return fmt.Errorf("%w: reporter %s would attach %d addresses to endpoint %s, limit %d", ErrLimit, reporter, n, id, MaxAddressesPerEndpoint)
	}
	for _, a := range addrs {
		if _, err := tx.ExecContext(ctx, `
			INSERT OR IGNORE INTO net_endpoint_addresses (endpoint_id, reporter, address) VALUES (?, ?, ?)`,
			id, reporter, a.String()); err != nil {
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
		SELECT id, mac, vlan, oui, hostname, first_seen, last_seen, tier, owner, ipam_asset_id, host_id
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
	if e.Addresses, err = s.endpointAddresses(ctx, id); err != nil {
		return Endpoint{}, err
	}
	if e.SeenBy, err = s.endpointReporters(ctx, id); err != nil {
		return Endpoint{}, err
	}
	return e, nil
}

// LookupEndpoint finds the endpoint by MAC (when mac is non-empty) or by
// address and reports whether one was found. Several endpoints can share
// an address (a reused DHCP lease); an endpoint whose owner attached the
// address comes first, then the most recently seen one, then the
// smallest ID.
func (s *Store) LookupEndpoint(ctx context.Context, mac string, addr netip.Addr) (Endpoint, bool, error) {
	var id string
	var err error
	if mac != "" {
		err = s.db.QueryRowContext(ctx, `SELECT id FROM net_endpoints WHERE mac = ?`, mac).Scan(&id)
	} else {
		n, nerr := normalizeAddress(addr)
		if nerr != nil {
			return Endpoint{}, false, fmt.Errorf("%w: address %s: %v", ErrInvalidEndpoint, addr, nerr)
		}
		err = s.db.QueryRowContext(ctx, `
			SELECT e.id FROM net_endpoint_addresses a JOIN net_endpoints e ON e.id = a.endpoint_id
			WHERE a.address = ? GROUP BY e.id
			ORDER BY MAX(a.reporter = e.owner) DESC, e.last_seen DESC, e.id LIMIT 1`, n.String()).Scan(&id)
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

// endpointAddresses returns the distinct addresses of the endpoint, at
// most MaxReportersPerEndpoint*MaxAddressesPerEndpoint, sorted.
func (s *Store) endpointAddresses(ctx context.Context, id string) ([]netip.Addr, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT address FROM net_endpoint_addresses WHERE endpoint_id = ?`, id)
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
			return nil, fmt.Errorf("trafficstore: endpoint %s: stored address %q: %w", id, a, err)
		}
		out = append(out, addr)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("trafficstore: list addresses of endpoint %s: %w", id, err)
	}
	slices.SortFunc(out, netip.Addr.Compare)
	return out, nil
}

// endpointReporters returns the seen-by set of the endpoint, sorted.
func (s *Store) endpointReporters(ctx context.Context, id string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT reporter FROM net_endpoint_reporters WHERE endpoint_id = ? ORDER BY reporter`, id)
	if err != nil {
		return nil, fmt.Errorf("trafficstore: list reporters of endpoint %s: %w", id, err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			return nil, fmt.Errorf("trafficstore: list reporters of endpoint %s: %w", id, err)
		}
		out = append(out, r)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("trafficstore: list reporters of endpoint %s: %w", id, err)
	}
	return out, nil
}

// CountEndpoints returns the number of stored endpoints, as maintained
// for the caps.
func (s *Store) CountEndpoints(ctx context.Context) (int, error) {
	return readCount(ctx, s.db, countEndpoints, countTotal)
}
