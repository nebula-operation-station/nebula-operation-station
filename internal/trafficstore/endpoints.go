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
//
// On upsert it is one reporter's observation; on read it is the merged
// view of all reporters. Values a reporter supplies (addresses, VLAN,
// hostname, OUI without MAC, tier, first/last seen) are kept per
// reporter (Observations). The displayed values come from the
// endpoint's authoritative owner when there is one (Owner: the managed
// host that has the endpoint's MAC on its own interface, by the
// server's own records); without an owner, values the reporters agree
// on are shown and fields they disagree on are left empty and named in
// Conflicts. Identity links (HostID, IPAMAssetID) come only from the
// server: from the owner or SetEndpointLinks, never from a report.
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
	// owner's addresses when the endpoint has an owner, otherwise the
	// distinct addresses of all reporters; sorted. Observations
	// attributes every address to its reporter.
	Addresses []netip.Addr
	// VLAN is the observed VLAN, 0 when unknown (or, on read, in
	// conflict).
	VLAN int
	// OUI is the vendor OUI (six lowercase hex digits). When the MAC is
	// known the store derives it from the MAC and ignores this field;
	// without a MAC it is the reporter's claim.
	OUI string
	// Hostname is the observed hostname, bounded.
	Hostname string
	// FirstSeen is the first observation time; zero means LastSeen. The
	// store clamps it to no earlier than MaxFirstSeenLead before the
	// server's first receipt of that reporter's report for the endpoint.
	// On read it is the owner's when there is one, otherwise the
	// earliest of all reporters.
	FirstSeen time.Time
	// LastSeen is the most recent observation time. On read it is the
	// latest of all reporters.
	LastSeen time.Time
	// Tier is the source tier (flowagg.TierSocket, TierConntrack or
	// TierSensor). On read it is the owner's latest tier, without an
	// owner the tier of the most recently seen reporter.
	Tier string
	// Reporter is the host that reports the observation (upsert only;
	// empty on read).
	Reporter string
	// Owner is, on read, the authoritative owner ("" when none): the
	// reporter whose own MAC (or, for a MAC-less endpoint, whose own
	// addresses) the endpoint is, per the server's records passed to
	// UpsertEndpoint with its latest report. It is ignored on upsert.
	Owner string
	// SeenBy lists, on read, every reporter that currently sees the
	// endpoint, sorted. It is ignored on upsert.
	SeenBy []string
	// Observations holds, on read, each reporter's own values, sorted by
	// reporter. It is ignored on upsert.
	Observations []Observation
	// Conflicts names, on read, the fields ("hostname", "oui", "vlan")
	// on which reporters of an endpoint without owner disagree; those
	// fields are left empty. It is ignored on upsert.
	Conflicts []string
	// IPAMAssetID links the endpoint to the matching IPAM asset, "" when
	// unmatched. Read only: set by SetEndpointLinks; an upsert with a
	// non-empty value is refused.
	IPAMAssetID string
	// HostID links the endpoint to the matching managed host, "" when
	// unmatched. Read only: set by SetEndpointLinks, otherwise the
	// owner; an upsert with a non-empty value is refused.
	HostID string
}

// Observation is one reporter's view of an endpoint (read only).
type Observation struct {
	Reporter  string
	Tier      string
	VLAN      int
	OUI       string
	Hostname  string
	FirstSeen time.Time
	LastSeen  time.Time
	// Addresses are the addresses this reporter attached, sorted.
	Addresses []netip.Addr
}

// Identity is the server's own record of a reporting managed host:
// the MACs of its interfaces and its addresses. As for
// flowagg.Aggregator.Ingest, the caller takes them from the server's
// records, never from the report, and leaves out MACs and addresses
// more than one host claims. A zero Identity (unknown host) is valid and
// never makes the reporter an owner.
type Identity struct {
	// MACs are the reporter's own interface MACs, lowercase
	// aa:bb:cc:dd:ee:ff, at most MaxIdentityMACs.
	MACs []string
	// Addrs are the reporter's own addresses, at most
	// flowagg.MaxHostAddrs.
	Addrs []netip.Addr
}

// MaxIdentityMACs bounds Identity.MACs.
const MaxIdentityMACs = 256

// MaxFirstSeenLead bounds how far before the server's first receipt of a
// reporter's report for an endpoint that reporter's first_seen may lie
// (further bounded by the retention).
const MaxFirstSeenLead = 24 * time.Hour

// Conflict field names in Endpoint.Conflicts.
const (
	ConflictHostname = "hostname"
	ConflictOUI      = "oui"
	ConflictVLAN     = "vlan"
)

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
	if e.IPAMAssetID != "" || e.HostID != "" {
		return fmt.Errorf("%w: ipam asset and host links are set by server-side matching only", ErrInvalidEndpoint)
	}
	if e.LastSeen.IsZero() {
		return fmt.Errorf("%w: zero last_seen", ErrInvalidEndpoint)
	}
	return nil
}

// validateIdentity checks own and returns its addresses normalized.
func validateIdentity(own Identity) ([]netip.Addr, error) {
	if len(own.MACs) > MaxIdentityMACs {
		return nil, fmt.Errorf("%w: %d reporter MACs exceed limit %d", ErrInvalidEndpoint, len(own.MACs), MaxIdentityMACs)
	}
	for i, m := range own.MACs {
		if !macRE.MatchString(m) {
			return nil, fmt.Errorf("%w: reporter mac %d invalid", ErrInvalidEndpoint, i)
		}
	}
	if len(own.Addrs) > flowagg.MaxHostAddrs {
		return nil, fmt.Errorf("%w: %d reporter addresses exceed limit %d", ErrInvalidEndpoint, len(own.Addrs), flowagg.MaxHostAddrs)
	}
	addrs := make([]netip.Addr, 0, len(own.Addrs))
	for i, a := range own.Addrs {
		a = a.Unmap().WithZone("")
		if !a.IsValid() || a.IsUnspecified() {
			return nil, fmt.Errorf("%w: reporter address %d invalid", ErrInvalidEndpoint, i)
		}
		addrs = append(addrs, a)
	}
	return addrs, nil
}

// authoritative reports whether the observation e is about the
// reporter's own interface according to the server's records: its MAC
// is one of the reporter's MACs, or, without a MAC, every address is one
// of the reporter's addresses.
func authoritative(e *Endpoint, own Identity, ownAddrs []netip.Addr) bool {
	if e.MAC != "" {
		return slices.Contains(own.MACs, e.MAC)
	}
	for _, a := range e.Addresses {
		if !slices.Contains(ownAddrs, a) {
			return false
		}
	}
	return len(e.Addresses) > 0
}

// UpsertEndpoint stores or updates one reporter's observation of an
// endpoint.
//
// own is the server's record of the reporting host e.Reporter (see
// Identity). The observation is authoritative when its MAC is one of
// own.MACs, or, without a MAC, all its addresses are in own.Addrs.
// Ownership is never taken from reported values; it follows the
// server's current records and is re-evaluated on every report:
//   - an endpoint with a MAC is owned by the reporter whose own.MACs hold
//     it: such a reporter becomes the owner (also taking over from a
//     former owner, whose records no longer hold the MAC: the caller
//     leaves out MACs more than one host claims), and the owner loses
//     ownership when its records no longer hold the MAC;
//   - a MAC-less endpoint is owned by an authoritative reporter (taking
//     over likewise); its owner keeps it while it still holds one of the
//     endpoint's addresses by its records, and loses it otherwise.
//
// When the owner's observation expires, the endpoint has no owner until
// an authoritative report arrives.
//
// The owner's attributed addresses are the endpoint's owner-attested
// addresses: only addresses in own.Addrs are attached under the owner,
// and on every report of the owner the addresses it attached earlier
// that are no longer in own.Addrs are removed. Other addresses the owner
// observes are not stored (the schema has no unattested owner
// attribution); non-owners' addresses are stored under their names and
// never count as attested.
//
// Matching (deterministic):
//   - an observation with a MAC matches the endpoint with that MAC; if
//     there is none, it matches a MAC-less endpoint with one of its
//     addresses, attached by this reporter, that the reporter owns (and
//     the observation is authoritative) or that has no owner and no
//     other reporter (the MAC is learned); otherwise it creates a new
//     endpoint. An address never merges a different or new MAC into
//     another endpoint, so a device that gets a reused DHCP address gets
//     its own endpoint.
//   - an observation without a MAC matches an endpoint with one of its
//     addresses through owner-attested addresses only when the endpoint
//     has an owner (addresses non-owners attached to an owned endpoint
//     never match), through any reporter's addresses otherwise. An
//     authoritative observation only matches a MAC-less endpoint or one
//     whose MAC is in own.MACs. It prefers one the reporter owns, then
//     one another reporter owns, then one without owner; then one this
//     reporter attached the address to, then the most recently seen,
//     then the smallest ID; otherwise it creates one.
//
// The reporter's own values (tier, VLAN, hostname, OUI without MAC,
// first/last seen) are stored in its seen-by row; a non-empty value
// replaces its earlier one. Its addresses are attached under its name,
// bounded by MaxAddressesPerEndpoint per reporter. An observation
// without a MAC by a non-owner attaches no new address to an endpoint
// that has a MAC or an owner: only addresses the endpoint already has
// (owner-attested, when it has an owner) are attached, the rest are
// dropped. First_seen is clamped to no earlier than MaxFirstSeenLead
// (at most the retention) before the server's first receipt of this
// reporter's report for the endpoint.
//
// An address is held by one host at a time (the caller leaves out
// addresses more than one host claims), so when the owner attests an
// address, other owners' attestations of it are stale: they are removed,
// and a MAC-less endpoint left without an attested address loses its
// owner. Lookups therefore never see an address attested by two
// different owners. Owners that stop reporting are reconciled by
// ReconcileIdentities.
//
// An authoritative MAC observation whose addresses are all outside
// own.Addrs still creates (or keeps) the owned endpoint, with no attested
// address: the MAC alone attests it, it resolves by MAC, never by
// address, and non-owners' addresses do not attach to it. There is at
// most one such endpoint per MAC in own.MACs (MaxIdentityMACs), within
// the endpoint caps.
//
// A new endpoint is refused with ErrLimit when it would exceed
// MaxEndpoints in total; joining or creating an endpoint is refused when
// the reporter already sees MaxEndpointsPerReporter endpoints (ADR 0009
// D7). The seen-by set holds at most MaxReportersPerEndpoint reporters
// besides the owner: a non-owner is refused beyond that, and one slot is
// reserved for the owner, which is always admitted. Other reporters'
// rows are never evicted (a former owner keeps its row as an ordinary
// reporter; until such rows expire, further non-owners are refused).
//
// LastSeen must lie within the retention window and at most
// maxClockSkew in the future. e.HostID and e.IPAMAssetID must be empty:
// they are set by server-side matching (SetEndpointLinks) only.
func (s *Store) UpsertEndpoint(ctx context.Context, e Endpoint, own Identity) error {
	if err := validateEndpoint(&e); err != nil {
		return err
	}
	ownAddrs, err := validateIdentity(own)
	if err != nil {
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
	auth := authoritative(&e, own, ownAddrs)
	attested := make([]netip.Addr, 0, len(e.Addresses))
	for _, a := range e.Addresses {
		if slices.Contains(ownAddrs, a) {
			attested = append(attested, a)
		}
	}
	reporterOUI := ""
	if e.MAC == "" {
		reporterOUI = e.OUI
	}
	obs := reporterObs{
		tier: e.Tier, vlan: e.VLAN, oui: reporterOUI, hostname: e.Hostname,
		first: e.FirstSeen.Unix(), last: e.LastSeen.Unix(),
		now: now.Unix(), lead: int64(min(MaxFirstSeenLead, s.retention) / time.Second),
	}

	s.autoPrune(ctx)

	return s.writeTx(ctx, "upsert endpoint", func(tx *sql.Tx) error {
		m, err := findEndpoint(ctx, tx, &e, auth, own.MACs)
		if err != nil {
			return err
		}
		if m.id == "" {
			owner, addrs := "", e.Addresses
			if auth {
				owner, addrs = e.Reporter, attested
			}
			return s.insertEndpoint(ctx, tx, &e, owner, obs, addrs)
		}
		learn := e.MAC != "" && m.mac == ""
		mac := m.mac
		if learn {
			mac = e.MAC
		}
		// Ownership is re-evaluated from the server's current records on
		// every report: the holder of the endpoint's MAC (or, without a
		// MAC, of the observed addresses) owns it, a former owner whose
		// records no longer hold it loses it.
		var holds, dropped bool
		switch {
		case mac != "":
			holds = slices.Contains(own.MACs, mac)
		case auth:
			holds = true
		case m.owner == e.Reporter:
			// A MAC-less endpoint stays owned while its owner still holds
			// one of its addresses by the records.
			if err := dropUnattested(ctx, tx, m.id, e.Reporter, ownAddrs); err != nil {
				return err
			}
			dropped = true
			n, err := countReporterAddresses(ctx, tx, m.id, e.Reporter)
			if err != nil {
				return err
			}
			holds = n > 0 || len(attested) > 0
		}
		owner := m.owner
		switch {
		case holds:
			owner = e.Reporter
		case owner == e.Reporter:
			owner = ""
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE net_endpoints SET
				mac       = CASE WHEN ?1 THEN ?2 ELSE mac END,
				oui       = CASE WHEN ?1 THEN ?3 ELSE oui END,
				owner     = ?4,
				last_seen = MAX(last_seen, ?5)
			WHERE id = ?6`,
			learn, e.MAC, deriveOUI(e.MAC), owner, obs.last, m.id); err != nil {
			return fmt.Errorf("trafficstore: update endpoint %s: %w", m.id, err)
		}
		addrs := e.Addresses
		switch {
		case owner == e.Reporter:
			// The owner's attributions are the endpoint's attested
			// addresses: only those in its current records.
			if !dropped {
				if err := dropUnattested(ctx, tx, m.id, e.Reporter, ownAddrs); err != nil {
					return err
				}
			}
			addrs = attested
			if err := releaseAttested(ctx, tx, m.id, e.Reporter, attested); err != nil {
				return err
			}
		case e.MAC == "" && (mac != "" || owner != ""):
			if addrs, err = knownAddresses(ctx, tx, m.id, owner, addrs); err != nil {
				return err
			}
		}
		return s.joinEndpoint(ctx, tx, m.id, e.Reporter, owner, obs, addrs)
	})
}

// dropUnattested removes the addresses reporter attached to endpoint id
// that are not in ownAddrs, its addresses by the server's records.
func dropUnattested(ctx context.Context, tx *sql.Tx, id, reporter string, ownAddrs []netip.Addr) error {
	placeholders, args := addrArgs(ownAddrs)
	if _, err := tx.ExecContext(ctx, dropUnattestedSQL(placeholders),
		append([]any{id, reporter}, args...)...); err != nil {
		return fmt.Errorf("trafficstore: drop unattested addresses of endpoint %s: %w", id, err)
	}
	return nil
}

// countReporterAddresses returns the number of addresses reporter
// attached to endpoint id.
func countReporterAddresses(ctx context.Context, tx *sql.Tx, id, reporter string) (int, error) {
	var n int
	if err := tx.QueryRowContext(ctx, countReporterAddressesSQL, id, reporter).Scan(&n); err != nil {
		return 0, fmt.Errorf("trafficstore: count addresses of endpoint %s: %w", id, err)
	}
	return n, nil
}

// reporterObs is the per-reporter part of an observation, in the stored
// form, with the server's ingest time and the first_seen lead bound.
type reporterObs struct {
	tier, oui, hostname string
	vlan                int
	first, last         int64
	now, lead           int64
}

// clampedFirst returns the first_seen of a new seen-by row: no earlier
// than lead before now (the first receipt), and never after last.
func (o reporterObs) clampedFirst() int64 {
	return max(o.first, min(o.now-o.lead, o.last))
}

// newEndpointID returns a fresh opaque endpoint ID.
func newEndpointID() string {
	return endpointIDPrefix + strings.ToLower(rand.Text())
}

// insertEndpoint creates a new endpoint seen by e.Reporter with the
// given owner ("" or e.Reporter) and attaches addrs under e.Reporter.
func (s *Store) insertEndpoint(ctx context.Context, tx *sql.Tx, e *Endpoint, owner string, obs reporterObs, addrs []netip.Addr) error {
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
		INSERT INTO net_endpoints (id, mac, oui, last_seen, owner) VALUES (?, ?, ?, ?, ?)`,
		id, e.MAC, deriveOUI(e.MAC), obs.last, owner); err != nil {
		return fmt.Errorf("trafficstore: insert endpoint %s: %w", id, err)
	}
	if err := insertReporter(ctx, tx, id, e.Reporter, obs); err != nil {
		return err
	}
	if owner != "" {
		if err := releaseAttested(ctx, tx, id, owner, addrs); err != nil {
			return err
		}
	}
	return addEndpointAddresses(ctx, tx, id, e.Reporter, addrs)
}

// releaseAttested removes the attestations of addrs by the owners of
// endpoints other than id and other than owner: owner holds them by the
// server's current records, which give an address to one host only, so
// those attestations are stale. A MAC-less endpoint left without any
// address attested by its owner loses its owner.
func releaseAttested(ctx context.Context, tx *sql.Tx, id, owner string, addrs []netip.Addr) error {
	if len(addrs) == 0 {
		return nil
	}
	placeholders, args := addrArgs(addrs)
	rows, err := tx.QueryContext(ctx, releaseAttestedSQL(placeholders),
		append(args, id, owner)...)
	if err != nil {
		return fmt.Errorf("trafficstore: release stale attestations: %w", err)
	}
	defer rows.Close()
	var released []string
	for rows.Next() {
		var eid string
		if err := rows.Scan(&eid); err != nil {
			return fmt.Errorf("trafficstore: release stale attestations: %w", err)
		}
		if !slices.Contains(released, eid) {
			released = append(released, eid)
		}
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("trafficstore: release stale attestations: %w", err)
	}
	for _, eid := range released {
		if _, err := tx.ExecContext(ctx, clearUnattestedOwnerSQL, eid); err != nil {
			return fmt.Errorf("trafficstore: clear owner of endpoint %s: %w", eid, err)
		}
	}
	return nil
}

// insertReporter adds reporter's seen-by row to endpoint id.
func insertReporter(ctx context.Context, tx *sql.Tx, id, reporter string, obs reporterObs) error {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO net_endpoint_reporters
			(endpoint_id, reporter, tier, vlan, oui, hostname, first_seen, first_ingest, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, reporter, obs.tier, obs.vlan, obs.oui, obs.hostname, obs.clampedFirst(), obs.now, obs.last); err != nil {
		return fmt.Errorf("trafficstore: insert endpoint %s reporter: %w", id, err)
	}
	return nil
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

// joinEndpoint records reporter's observation of endpoint id: it adds or
// updates the reporter's seen-by row and attaches addrs. owner is the
// endpoint's owner ("" when none): a non-owner is refused when the
// endpoint already has MaxReportersPerEndpoint reporters besides the
// owner; the owner has a reserved slot and is always admitted. No row is
// ever evicted.
func (s *Store) joinEndpoint(ctx context.Context, tx *sql.Tx, id, reporter, owner string, obs reporterObs, addrs []netip.Addr) error {
	// first_seen keeps the minimum, bounded below by lead before the
	// server's first receipt (first_ingest), or the reported last_seen
	// when that is earlier.
	res, err := tx.ExecContext(ctx, `
		UPDATE net_endpoint_reporters SET
			tier       = ?1,
			vlan       = CASE WHEN ?2 != 0 THEN ?2 ELSE vlan END,
			oui        = CASE WHEN ?3 != '' THEN ?3 ELSE oui END,
			hostname   = CASE WHEN ?4 != '' THEN ?4 ELSE hostname END,
			first_seen = MAX(MIN(first_seen, ?5), MIN(first_ingest - ?6, ?7)),
			last_seen  = MAX(last_seen, ?7)
		WHERE endpoint_id = ?8 AND reporter = ?9`,
		obs.tier, obs.vlan, obs.oui, obs.hostname, obs.first, obs.lead, obs.last, id, reporter)
	if err != nil {
		return fmt.Errorf("trafficstore: update endpoint %s reporter: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("trafficstore: update endpoint %s reporter: %w", id, err)
	}
	if n == 0 {
		if reporter != owner {
			var others int
			if err := tx.QueryRowContext(ctx, countNonOwnersSQL, id, owner).Scan(&others); err != nil {
				return fmt.Errorf("trafficstore: count reporters of endpoint %s: %w", id, err)
			}
			if others >= MaxReportersPerEndpoint {
				return fmt.Errorf("%w: endpoint %s already has %d reporters besides its owner, limit %d", ErrLimit, id, others, MaxReportersPerEndpoint)
			}
		}
		if err := s.checkReporterCap(ctx, tx, reporter); err != nil {
			return err
		}
		if err := insertReporter(ctx, tx, id, reporter, obs); err != nil {
			return err
		}
	}
	if len(addrs) == 0 {
		return nil
	}
	return addEndpointAddresses(ctx, tx, id, reporter, addrs)
}

// addrArgs returns the SQL placeholders and arguments for addrs.
func addrArgs(addrs []netip.Addr) (string, []any) {
	args := make([]any, len(addrs))
	for i, a := range addrs {
		args[i] = a.String()
	}
	return strings.TrimSuffix(strings.Repeat("?,", len(addrs)), ","), args
}

// endpointMatch is the stored endpoint an observation belongs to; id is
// "" when it needs a new endpoint.
type endpointMatch struct {
	id, mac, owner string
}

// SQL of the endpoint write path; package-level (or built from the
// number of placeholders) so the tests can check the query plans.
const (
	// findByMACSQL and lookupByMACSQL repeat the partial index's
	// condition (mac != ''), so SQLite can use idx_net_endpoints_mac.
	findByMACSQL   = `SELECT id, mac, owner FROM net_endpoints WHERE mac = ? AND mac != ''`
	lookupByMACSQL = `SELECT id FROM net_endpoints WHERE mac = ? AND mac != ''`
	// countNonOwnersSQL counts the seen-by rows of one endpoint other
	// than its owner's (all of them for owner '').
	countNonOwnersSQL = `
		SELECT COUNT(*) FROM net_endpoint_reporters WHERE endpoint_id = ? AND reporter != ?`
	// countReporterAddressesSQL counts one reporter's addresses on one
	// endpoint.
	countReporterAddressesSQL = `
		SELECT COUNT(*) FROM net_endpoint_addresses WHERE endpoint_id = ? AND reporter = ?`
	// clearUnattestedOwnerSQL drops the owner of a MAC-less endpoint
	// that has no address attested by its owner. Argument: id.
	clearUnattestedOwnerSQL = `
		UPDATE net_endpoints SET owner = ''
		WHERE id = ? AND mac = '' AND owner != '' AND NOT EXISTS (
			SELECT 1 FROM net_endpoint_addresses a
			WHERE a.endpoint_id = net_endpoints.id AND a.reporter = net_endpoints.owner)`
)

// releaseAttestedSQL deletes the attestations of a list of addresses by
// the owners of endpoints other than the given one and other than the
// given owner, returning the affected endpoints. Arguments: the
// addresses, the endpoint id, the owner.
func releaseAttestedSQL(addrPlaceholders string) string {
	return `
		DELETE FROM net_endpoint_addresses
		WHERE address IN (` + addrPlaceholders + `) AND endpoint_id != ? AND reporter != ?
		  AND reporter = (SELECT e.owner FROM net_endpoints e WHERE e.id = net_endpoint_addresses.endpoint_id)
		RETURNING endpoint_id`
}

// learnMACSQL selects the MAC-less endpoint a MAC observation learns its
// MAC into: one this reporter attached one of the addresses to and that
// it owns (authoritatively) or that has no owner and no other reporter.
// Arguments: the addresses, the reporter, auth.
func learnMACSQL(addrPlaceholders string) string {
	return `
		SELECT e.id, e.mac, e.owner FROM net_endpoint_addresses a
		JOIN net_endpoints e ON e.id = a.endpoint_id
		WHERE a.address IN (` + addrPlaceholders + `) AND a.reporter = ? AND e.mac = ''
		  AND ((e.owner = a.reporter AND ?) OR (e.owner = '' AND NOT EXISTS (
		      SELECT 1 FROM net_endpoint_reporters r
		      WHERE r.endpoint_id = e.id AND r.reporter != a.reporter)))
		GROUP BY e.id ORDER BY e.last_seen DESC, e.id LIMIT 1`
}

// matchAddressSQL selects the endpoint a MAC-less observation joins. An
// owned endpoint matches only through addresses its owner attached
// (owner-attested: the owner's attributions are kept to its records), an
// endpoint without owner through any reporter's. An authoritative
// observation (auth) only joins a MAC-less endpoint or one with one of
// the reporter's own MACs, never another device's. Preference: owned by
// the reporter, owned by another, unowned; then one this reporter
// attached the address to; then the most recently seen; then the
// smallest ID. Arguments: the addresses, auth, the reporter's MACs, the
// reporter twice.
func matchAddressSQL(addrPlaceholders, macPlaceholders string) string {
	return `
		SELECT e.id, e.mac, e.owner FROM net_endpoint_addresses a
		JOIN net_endpoints e ON e.id = a.endpoint_id
		WHERE a.address IN (` + addrPlaceholders + `) AND (e.owner = '' OR a.reporter = e.owner)
		  AND (NOT ? OR e.mac = '' OR e.mac IN (` + macPlaceholders + `))
		GROUP BY e.id
		ORDER BY MAX(e.owner = ?) DESC, MAX(e.owner != '') DESC,
		         MAX(a.reporter = ?) DESC, e.last_seen DESC, e.id
		LIMIT 1`
}

// knownAddressesSQL selects the addresses of a list endpoint id already
// has: attached by the owner when the owner argument is non-empty, by
// any reporter otherwise. Arguments: id, owner twice, the addresses.
func knownAddressesSQL(addrPlaceholders string) string {
	return `
		SELECT DISTINCT address FROM net_endpoint_addresses
		WHERE endpoint_id = ? AND (? = '' OR reporter = ?) AND address IN (` + addrPlaceholders + `)`
}

// countAddressesSQL counts a reporter's addresses on an endpoint and how
// many of a list it already has. Arguments: the addresses, id, reporter.
func countAddressesSQL(addrPlaceholders string) string {
	return `
		SELECT COUNT(*), COUNT(CASE WHEN address IN (` + addrPlaceholders + `) THEN 1 END)
		FROM net_endpoint_addresses WHERE endpoint_id = ? AND reporter = ?`
}

// dropUnattestedSQL deletes a reporter's addresses on an endpoint that
// are not in a list. Arguments: id, reporter, the addresses.
func dropUnattestedSQL(addrPlaceholders string) string {
	return `
		DELETE FROM net_endpoint_addresses
		WHERE endpoint_id = ? AND reporter = ? AND address NOT IN (` + addrPlaceholders + `)`
}

// findEndpoint returns the stored endpoint the observation e belongs to.
// auth reports whether e is authoritative, ownMACs are the reporter's
// MACs by the server's records. See UpsertEndpoint for the rules.
func findEndpoint(ctx context.Context, tx *sql.Tx, e *Endpoint, auth bool, ownMACs []string) (endpointMatch, error) {
	var m endpointMatch
	if e.MAC != "" {
		err := tx.QueryRowContext(ctx, findByMACSQL, e.MAC).Scan(&m.id, &m.mac, &m.owner)
		if err == nil {
			return m, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return endpointMatch{}, fmt.Errorf("trafficstore: look up endpoint by mac: %w", err)
		}
	}
	placeholders, args := addrArgs(e.Addresses)
	var row *sql.Row
	if e.MAC != "" {
		row = tx.QueryRowContext(ctx, learnMACSQL(placeholders), append(args, e.Reporter, auth)...)
	} else {
		macPlaceholders := strings.TrimSuffix(strings.Repeat("?,", len(ownMACs)), ",")
		args = append(args, auth)
		for _, mac := range ownMACs {
			args = append(args, mac)
		}
		row = tx.QueryRowContext(ctx, matchAddressSQL(placeholders, macPlaceholders),
			append(args, e.Reporter, e.Reporter)...)
	}
	err := row.Scan(&m.id, &m.mac, &m.owner)
	if errors.Is(err, sql.ErrNoRows) {
		return endpointMatch{}, nil
	}
	if err != nil {
		return endpointMatch{}, fmt.Errorf("trafficstore: look up endpoint by address: %w", err)
	}
	return m, nil
}

// knownAddresses returns the addresses of addrs that endpoint id already
// has: attached by owner when owner is non-empty, by any reporter
// otherwise.
func knownAddresses(ctx context.Context, tx *sql.Tx, id, owner string, addrs []netip.Addr) ([]netip.Addr, error) {
	placeholders, args := addrArgs(addrs)
	rows, err := tx.QueryContext(ctx, knownAddressesSQL(placeholders),
		append([]any{id, owner, owner}, args...)...)
	if err != nil {
		return nil, fmt.Errorf("trafficstore: known addresses of endpoint %s: %w", id, err)
	}
	defer rows.Close()
	known := make(map[string]bool)
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			return nil, fmt.Errorf("trafficstore: known addresses of endpoint %s: %w", id, err)
		}
		known[a] = true
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("trafficstore: known addresses of endpoint %s: %w", id, err)
	}
	var out []netip.Addr
	for _, a := range addrs {
		if known[a.String()] {
			out = append(out, a)
		}
	}
	return out, nil
}

// addEndpointAddresses attaches addrs to the endpoint under reporter,
// refusing with ErrLimit when the reporter would attach more than
// MaxAddressesPerEndpoint addresses to it.
func addEndpointAddresses(ctx context.Context, tx *sql.Tx, id, reporter string, addrs []netip.Addr) error {
	if len(addrs) == 0 {
		return nil
	}
	placeholders, args := addrArgs(addrs)
	var known, have int
	if err := tx.QueryRowContext(ctx, countAddressesSQL(placeholders),
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

// SetEndpointLinks sets the endpoint's IPAM asset and managed host
// links from server-side matching ("" clears a link; an empty host link
// falls back to the owner on read). Reporters never set them. It returns
// ErrNotFound when there is no such endpoint.
func (s *Store) SetEndpointLinks(ctx context.Context, id, ipamAssetID, hostID string) error {
	if err := validName(ipamAssetID, maxIDLen, true); err != nil {
		return fmt.Errorf("%w: ipam asset id: %v", ErrInvalidEndpoint, err)
	}
	if err := validName(hostID, maxIDLen, true); err != nil {
		return fmt.Errorf("%w: host id: %v", ErrInvalidEndpoint, err)
	}
	return s.writeTx(ctx, "set endpoint links", func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx,
			`UPDATE net_endpoints SET ipam_asset_id = ?, host_id = ? WHERE id = ?`, ipamAssetID, hostID, id)
		if err != nil {
			return fmt.Errorf("trafficstore: set links of endpoint %s: %w", id, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("trafficstore: set links of endpoint %s: %w", id, err)
		}
		if n == 0 {
			return fmt.Errorf("trafficstore: endpoint %s: %w", id, ErrNotFound)
		}
		return nil
	})
}

// Endpoint returns the endpoint with the given store-assigned ID,
// merged as described on Endpoint. It returns ErrNotFound when there is
// no such endpoint.
func (s *Store) Endpoint(ctx context.Context, id string) (Endpoint, error) {
	var e Endpoint
	var last int64
	err := s.db.QueryRowContext(ctx, `
		SELECT id, mac, oui, last_seen, owner, ipam_asset_id, host_id
		FROM net_endpoints WHERE id = ?`, id).
		Scan(&e.ID, &e.MAC, &e.OUI, &last, &e.Owner, &e.IPAMAssetID, &e.HostID)
	if errors.Is(err, sql.ErrNoRows) {
		return Endpoint{}, fmt.Errorf("trafficstore: endpoint %s: %w", id, ErrNotFound)
	}
	if err != nil {
		return Endpoint{}, fmt.Errorf("trafficstore: read endpoint %s: %w", id, err)
	}
	e.LastSeen = time.Unix(last, 0).UTC()
	if e.Observations, err = s.endpointObservations(ctx, id); err != nil {
		return Endpoint{}, err
	}
	resolveEndpoint(&e)
	return e, nil
}

// resolveEndpoint fills the displayed values of e from its owner's
// observation, or, without an owner, from the values all reporters
// agree on, flagging the rest in Conflicts.
func resolveEndpoint(e *Endpoint) {
	var owner *Observation
	for i := range e.Observations {
		o := &e.Observations[i]
		e.SeenBy = append(e.SeenBy, o.Reporter)
		if o.Reporter == e.Owner {
			owner = o
		}
	}
	if owner == nil {
		// The owner's observation is gone (pruned): no owner.
		e.Owner = ""
	}
	if e.HostID == "" {
		e.HostID = e.Owner
	}
	if owner != nil {
		e.Addresses = slices.Clone(owner.Addresses)
		e.VLAN, e.Hostname, e.Tier, e.FirstSeen = owner.VLAN, owner.Hostname, owner.Tier, owner.FirstSeen
		if e.MAC == "" {
			e.OUI = owner.OUI
		}
		return
	}
	var latest *Observation
	vlans := make(map[int]bool)
	ouis := make(map[string]bool)
	hostnames := make(map[string]bool)
	for i := range e.Observations {
		o := &e.Observations[i]
		e.Addresses = append(e.Addresses, o.Addresses...)
		if e.FirstSeen.IsZero() || o.FirstSeen.Before(e.FirstSeen) {
			e.FirstSeen = o.FirstSeen
		}
		// Observations are sorted by reporter: ties keep the smallest.
		if latest == nil || o.LastSeen.After(latest.LastSeen) {
			latest = o
		}
		if o.VLAN != 0 {
			vlans[o.VLAN] = true
		}
		if o.OUI != "" {
			ouis[o.OUI] = true
		}
		if o.Hostname != "" {
			hostnames[o.Hostname] = true
		}
	}
	slices.SortFunc(e.Addresses, netip.Addr.Compare)
	e.Addresses = slices.Compact(e.Addresses)
	if latest != nil {
		e.Tier = latest.Tier
	}
	e.VLAN = agreed(vlans, ConflictVLAN, &e.Conflicts)
	e.Hostname = agreed(hostnames, ConflictHostname, &e.Conflicts)
	if e.MAC == "" {
		e.OUI = agreed(ouis, ConflictOUI, &e.Conflicts)
	}
	slices.Sort(e.Conflicts)
}

// agreed returns the single value in set, or the zero value when set is
// empty or holds several values; then it appends field to conflicts.
func agreed[T comparable](set map[T]bool, field string, conflicts *[]string) T {
	var zero T
	if len(set) > 1 {
		*conflicts = append(*conflicts, field)
		return zero
	}
	for v := range set {
		return v
	}
	return zero
}

// endpointObservations returns every reporter's observation of the
// endpoint with its attributed addresses, sorted by reporter.
func (s *Store) endpointObservations(ctx context.Context, id string) ([]Observation, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT reporter, tier, vlan, oui, hostname, first_seen, last_seen
		FROM net_endpoint_reporters WHERE endpoint_id = ? ORDER BY reporter`, id)
	if err != nil {
		return nil, fmt.Errorf("trafficstore: list reporters of endpoint %s: %w", id, err)
	}
	defer rows.Close()
	var out []Observation
	index := make(map[string]int)
	for rows.Next() {
		var o Observation
		var first, last int64
		if err := rows.Scan(&o.Reporter, &o.Tier, &o.VLAN, &o.OUI, &o.Hostname, &first, &last); err != nil {
			return nil, fmt.Errorf("trafficstore: list reporters of endpoint %s: %w", id, err)
		}
		o.FirstSeen = time.Unix(first, 0).UTC()
		o.LastSeen = time.Unix(last, 0).UTC()
		index[o.Reporter] = len(out)
		out = append(out, o)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("trafficstore: list reporters of endpoint %s: %w", id, err)
	}

	rows, err = s.db.QueryContext(ctx,
		`SELECT reporter, address FROM net_endpoint_addresses WHERE endpoint_id = ?`, id)
	if err != nil {
		return nil, fmt.Errorf("trafficstore: list addresses of endpoint %s: %w", id, err)
	}
	defer rows.Close()
	for rows.Next() {
		var r, a string
		if err := rows.Scan(&r, &a); err != nil {
			return nil, fmt.Errorf("trafficstore: list addresses of endpoint %s: %w", id, err)
		}
		addr, err := netip.ParseAddr(a)
		if err != nil {
			return nil, fmt.Errorf("trafficstore: endpoint %s: stored address %q: %w", id, a, err)
		}
		i, ok := index[r]
		if !ok {
			return nil, fmt.Errorf("trafficstore: endpoint %s: address %s of unknown reporter %s", id, a, r)
		}
		out[i].Addresses = append(out[i].Addresses, addr)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("trafficstore: list addresses of endpoint %s: %w", id, err)
	}
	for i := range out {
		slices.SortFunc(out[i].Addresses, netip.Addr.Compare)
	}
	return out, nil
}

// LookupEndpoint finds the endpoint by MAC (when mac is non-empty) or by
// address and reports whether one was found.
//
// By address it resolves only through attributions that cannot be
// forged against another reporter's endpoint: an endpoint whose owner
// attached the address (owner-attested: the owner's attributions are
// kept to its server records) wins; addresses that non-owners attached
// to an owned endpoint are ignored. Without such an endpoint, the endpoints
// without owner that have the address are considered. When more than
// one endpoint qualifies at that level (a reused DHCP lease, or
// conflicting reports) it returns ErrAmbiguous instead of picking one.
func (s *Store) LookupEndpoint(ctx context.Context, mac string, addr netip.Addr) (Endpoint, bool, error) {
	var id string
	if mac != "" {
		err := s.db.QueryRowContext(ctx, lookupByMACSQL, mac).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return Endpoint{}, false, nil
		}
		if err != nil {
			return Endpoint{}, false, fmt.Errorf("trafficstore: look up endpoint: %w", err)
		}
	} else {
		n, err := normalizeAddress(addr)
		if err != nil {
			return Endpoint{}, false, fmt.Errorf("%w: address %s: %v", ErrInvalidEndpoint, addr, err)
		}
		for _, q := range []string{lookupOwnedSQL, lookupUnownedSQL} {
			ids, err := s.lookupIDs(ctx, q, n)
			if err != nil {
				return Endpoint{}, false, err
			}
			if len(ids) > 1 {
				return Endpoint{}, false, fmt.Errorf("%w: address %s matches several endpoints", ErrAmbiguous, n)
			}
			if len(ids) == 1 {
				id = ids[0]
				break
			}
		}
		if id == "" {
			return Endpoint{}, false, nil
		}
	}
	e, err := s.Endpoint(ctx, id)
	if err != nil {
		return Endpoint{}, false, err
	}
	return e, true, nil
}

// Address lookup levels of LookupEndpoint; at most two IDs are needed to
// detect ambiguity.
const (
	lookupOwnedSQL = `
		SELECT DISTINCT e.id FROM net_endpoint_addresses a JOIN net_endpoints e ON e.id = a.endpoint_id
		WHERE a.address = ? AND e.owner != '' AND a.reporter = e.owner ORDER BY e.id LIMIT 2`
	lookupUnownedSQL = `
		SELECT DISTINCT e.id FROM net_endpoint_addresses a JOIN net_endpoints e ON e.id = a.endpoint_id
		WHERE a.address = ? AND e.owner = '' ORDER BY e.id LIMIT 2`
)

// lookupIDs runs one address lookup level.
func (s *Store) lookupIDs(ctx context.Context, query string, addr netip.Addr) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, query, addr.String())
	if err != nil {
		return nil, fmt.Errorf("trafficstore: look up endpoint: %w", err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("trafficstore: look up endpoint: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("trafficstore: look up endpoint: %w", err)
	}
	return ids, nil
}

// CountEndpoints returns the number of stored endpoints, as maintained
// for the caps.
func (s *Store) CountEndpoints(ctx context.Context) (int, error) {
	return readCount(ctx, s.db, countEndpoints, countTotal)
}
