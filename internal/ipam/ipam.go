// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ipam keeps network assets and IPAM-light (spec 12, M9-1):
// networks with pools, reservations and exclusions, and assets with their
// addresses. The status of an address is computed from what claims it,
// never stored; a free-address suggestion is only a suggestion.
package ipam

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
)

// Kind of an asset.
type Kind string

// Asset kinds (spec 12).
const (
	KindServer   Kind = "server"
	KindNAS      Kind = "nas"
	KindFirewall Kind = "firewall"
	KindSwitch   Kind = "switch"
	KindPrinter  Kind = "printer"
	KindIoT      Kind = "iot"
	KindUnknown  Kind = "unknown"
)

// Kinds lists the asset kinds in display order.
var Kinds = []Kind{KindServer, KindNAS, KindFirewall, KindSwitch, KindPrinter, KindIoT, KindUnknown}

// Status of an address (spec 12).
type Status string

// Statuses.
const (
	Free       Status = "FREE"
	Reserved   Status = "RESERVED"
	Assigned   Status = "ASSIGNED"
	Discovered Status = "DISCOVERED"
	Conflict   Status = "CONFLICT"
	Excluded   Status = "EXCLUDED"
	Unknown    Status = "UNKNOWN"
)

// Entry kinds.
const (
	EntryReserved = "reserved"
	EntryExcluded = "excluded"
)

// Limits.
const (
	MaxListed       = 1024 // addresses listed per network (IPv4 /22)
	MaxAddresses    = 16   // per asset
	MaxPools        = 16   // per network
	SuggestStale    = 30 * 24 * time.Hour
	maxName         = 128
	maxNotes        = 2000
	maxNote         = 200
	maxSuggestCount = 20
)

// Asset is a network asset.
type Asset struct {
	ID, Name  string
	Kind      Kind
	Hostname  string
	MAC       string // lowercase aa:bb:cc:dd:ee:ff, or ""
	Notes     string
	HostID    string // the managed host it became, or ""
	Addresses []netip.Addr
	UpdatedAt time.Time
}

// Pool is a range of addresses in a network.
type Pool struct {
	Name        string
	First, Last netip.Addr
}

// Network is a subnet.
type Network struct {
	ID, Name string
	Prefix   netip.Prefix
	VLAN     int
	Gateway  netip.Addr // invalid when none
	Notes    string
	Pools    []Pool
}

// Entry is a reservation or exclusion of one address.
type Entry struct {
	Address netip.Addr
	Kind    string
	Note    string
	By      string
	At      time.Time
}

// Seen is what discovery last saw at an address.
type Seen struct {
	MAC, Hostname string
	At            time.Time
}

// AddressView is one address with its status and why.
type AddressView struct {
	Address netip.Addr
	Status  Status
	Why     string
	Assets  []string // asset IDs claiming it
	Hosts   []string // managed host IDs with it as an endpoint
	Entry   *Entry
	Seen    *Seen
}

// HostAddresses returns the managed hosts' endpoint addresses (literal
// IPs only) by address.
type HostAddresses func(ctx context.Context) (map[netip.Addr][]string, error)

// ValidationError says what is wrong; its text is safe to show.
type ValidationError struct{ Reason string }

func (e *ValidationError) Error() string { return e.Reason }

func invalid(format string, a ...any) error {
	return &ValidationError{Reason: fmt.Sprintf(format, a...)}
}

// Errors.
var ErrNotFound = errors.New("ipam: not found")

var (
	idRe       = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	hostnameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
	userRe     = regexp.MustCompile(`^[\x21-\x7e]{1,64}$`)
)

// plain reports whether s is printable text (newlines and tabs only where
// multiline), without control or invisible formatting characters.
func plain(s string, max int, multiline bool) bool {
	if len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if multiline && (r == '\n' || r == '\t') {
			continue
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == ' ' || r == ' ' {
			return false
		}
	}
	return true
}

// NormalizeMAC returns the lowercase colon form of a 6-byte MAC address.
func NormalizeMAC(s string) (string, bool) {
	if s == "" {
		return "", true
	}
	hw, err := net.ParseMAC(strings.TrimSpace(s))
	if err != nil || len(hw) != 6 {
		return "", false
	}
	return hw.String(), true
}

// Store keeps assets and networks in the server database.
type Store struct {
	db    *sql.DB
	hosts HostAddresses
	now   func() time.Time
}

// New returns a store; hosts may be nil (no managed hosts are known).
func New(db *sql.DB, hosts HostAddresses) *Store { return &Store{db: db, hosts: hosts, now: time.Now} }

// --- assets ---

func (a *Asset) check() error {
	mac, ok := NormalizeMAC(a.MAC)
	switch {
	case !idRe.MatchString(a.ID):
		return invalid("the asset ID must be 1 to 63 lowercase letters, digits, . _ or -")
	case a.Name == "" || !plain(a.Name, maxName, false):
		return invalid("the name must be 1 to %d characters of plain text", maxName)
	case !validKind(a.Kind):
		return invalid("the kind must be one of server, nas, firewall, switch, printer, iot, unknown")
	case a.Hostname != "" && (len(a.Hostname) > 253 || !hostnameRe.MatchString(a.Hostname)):
		return invalid("the hostname is not a valid DNS name (lowercase)")
	case !ok:
		return invalid("the MAC address must look like aa:bb:cc:dd:ee:ff")
	case !plain(a.Notes, maxNotes, true):
		return invalid("the notes must be at most %d characters of plain text", maxNotes)
	case a.HostID != "" && !idRe.MatchString(a.HostID):
		return invalid("the managed host ID is not valid")
	case len(a.Addresses) > MaxAddresses:
		return invalid("at most %d addresses", MaxAddresses)
	}
	a.MAC = mac
	seen := map[netip.Addr]bool{}
	for i, ad := range a.Addresses {
		if !ad.IsValid() || ad.Zone() != "" {
			return invalid("an address is not valid")
		}
		ad = ad.Unmap()
		a.Addresses[i] = ad
		if seen[ad] {
			return invalid("address %s appears twice", ad)
		}
		seen[ad] = true
	}
	return nil
}

func validKind(k Kind) bool {
	for _, x := range Kinds {
		if x == k {
			return true
		}
	}
	return false
}

// SaveAsset creates or replaces an asset. The managed-host link is kept
// on an update: LinkHost changes it.
func (s *Store) SaveAsset(ctx context.Context, a Asset) error {
	if err := a.check(); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `INSERT INTO assets (id, name, kind, hostname, mac, notes, host_id, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET name = excluded.name, kind = excluded.kind, hostname = excluded.hostname, mac = excluded.mac,
		notes = excluded.notes, updated_at = excluded.updated_at`,
		a.ID, a.Name, string(a.Kind), a.Hostname, a.MAC, a.Notes, a.HostID, s.now().Unix()); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM asset_addresses WHERE asset_id = ?`, a.ID); err != nil {
		return err
	}
	for _, ad := range a.Addresses {
		if _, err := tx.ExecContext(ctx, `INSERT INTO asset_addresses (asset_id, address) VALUES (?, ?)`, a.ID, ad.String()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// DeleteAsset removes an asset.
func (s *Store) DeleteAsset(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM assets WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Assets lists all assets by ID.
func (s *Store) Assets(ctx context.Context) ([]Asset, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, kind, hostname, mac, notes, host_id, updated_at FROM assets ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Asset
	idx := map[string]int{}
	for rows.Next() {
		var a Asset
		var kind string
		var at int64
		if err := rows.Scan(&a.ID, &a.Name, &kind, &a.Hostname, &a.MAC, &a.Notes, &a.HostID, &at); err != nil {
			return nil, err
		}
		a.Kind, a.UpdatedAt = Kind(kind), time.Unix(at, 0)
		idx[a.ID] = len(out)
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	ar, err := s.db.QueryContext(ctx, `SELECT asset_id, address FROM asset_addresses ORDER BY asset_id, address`)
	if err != nil {
		return nil, err
	}
	defer ar.Close()
	for ar.Next() {
		var id, ad string
		if err := ar.Scan(&id, &ad); err != nil {
			return nil, err
		}
		if p, err := netip.ParseAddr(ad); err == nil {
			if i, ok := idx[id]; ok {
				out[i].Addresses = append(out[i].Addresses, p)
			}
		}
	}
	for i := range out {
		sort.Slice(out[i].Addresses, func(x, y int) bool { return out[i].Addresses[x].Less(out[i].Addresses[y]) })
	}
	return out, ar.Err()
}

// Asset returns one asset.
func (s *Store) Asset(ctx context.Context, id string) (Asset, error) {
	all, err := s.Assets(ctx)
	if err != nil {
		return Asset{}, err
	}
	for _, a := range all {
		if a.ID == id {
			return a, nil
		}
	}
	return Asset{}, ErrNotFound
}

// --- networks ---

func (n *Network) check() error {
	switch {
	case !idRe.MatchString(n.ID):
		return invalid("the network ID must be 1 to 63 lowercase letters, digits, . _ or -")
	case n.Name == "" || !plain(n.Name, maxName, false):
		return invalid("the name must be 1 to %d characters of plain text", maxName)
	case !n.Prefix.IsValid() || n.Prefix.Addr().Zone() != "" || n.Prefix.Addr().Is4In6():
		return invalid("the network must be a prefix such as 192.168.10.0/24")
	case n.Prefix.Addr().Is4() && n.Prefix.Bits() < 8, n.Prefix.Addr().Is6() && n.Prefix.Bits() < 32:
		return invalid("the network is too large (at most /8 for IPv4, /32 for IPv6)")
	case n.VLAN < 0 || n.VLAN > 4094:
		return invalid("the VLAN must be 0 (none) to 4094")
	case !plain(n.Notes, maxNotes, true):
		return invalid("the notes must be at most %d characters of plain text", maxNotes)
	case len(n.Pools) > MaxPools:
		return invalid("at most %d pools", MaxPools)
	}
	n.Prefix = n.Prefix.Masked()
	if n.Gateway.IsValid() && !n.Prefix.Contains(n.Gateway.Unmap()) {
		return invalid("the gateway must be inside the network")
	}
	names := map[string]bool{}
	for _, p := range n.Pools {
		if p.Name == "" || !plain(p.Name, 64, false) || names[p.Name] {
			return invalid("pools need distinct names of 1 to 64 characters")
		}
		names[p.Name] = true
		if !n.Prefix.Contains(p.First) || !n.Prefix.Contains(p.Last) || p.Last.Less(p.First) {
			return invalid("pool %s must be a range inside the network (first ≤ last)", p.Name)
		}
	}
	return nil
}

// SaveNetwork creates or replaces a network and its pools.
func (s *Store) SaveNetwork(ctx context.Context, n Network) error {
	if err := n.check(); err != nil {
		return err
	}
	all, err := s.Networks(ctx)
	if err != nil {
		return err
	}
	for _, o := range all {
		if o.ID != n.ID && o.Prefix.Overlaps(n.Prefix) && o.Prefix.Bits() == n.Prefix.Bits() {
			return invalid("network %s already covers %s", o.ID, n.Prefix)
		}
	}
	gw := ""
	if n.Gateway.IsValid() {
		gw = n.Gateway.Unmap().String()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `INSERT INTO networks (id, name, prefix, vlan, gateway, notes) VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET name = excluded.name, prefix = excluded.prefix, vlan = excluded.vlan, gateway = excluded.gateway,
		notes = excluded.notes`, n.ID, n.Name, n.Prefix.String(), n.VLAN, gw, n.Notes); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return invalid("another network has the prefix %s", n.Prefix)
		}
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM pools WHERE network_id = ?`, n.ID); err != nil {
		return err
	}
	for _, p := range n.Pools {
		if _, err := tx.ExecContext(ctx, `INSERT INTO pools (network_id, name, first, last) VALUES (?, ?, ?, ?)`,
			n.ID, p.Name, p.First.String(), p.Last.String()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// DeleteNetwork removes a network (its entries stay: they are by address).
func (s *Store) DeleteNetwork(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM networks WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Networks lists all networks by prefix.
func (s *Store) Networks(ctx context.Context) ([]Network, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, prefix, vlan, gateway, notes FROM networks`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Network
	idx := map[string]int{}
	for rows.Next() {
		var n Network
		var prefix, gw string
		if err := rows.Scan(&n.ID, &n.Name, &prefix, &n.VLAN, &gw, &n.Notes); err != nil {
			return nil, err
		}
		if n.Prefix, err = netip.ParsePrefix(prefix); err != nil {
			return nil, fmt.Errorf("ipam: stored prefix %q: %w", prefix, err)
		}
		if gw != "" {
			n.Gateway, _ = netip.ParseAddr(gw)
		}
		idx[n.ID] = len(out)
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	pr, err := s.db.QueryContext(ctx, `SELECT network_id, name, first, last FROM pools ORDER BY network_id, first`)
	if err != nil {
		return nil, err
	}
	defer pr.Close()
	for pr.Next() {
		var id, name, first, last string
		if err := pr.Scan(&id, &name, &first, &last); err != nil {
			return nil, err
		}
		f, err1 := netip.ParseAddr(first)
		l, err2 := netip.ParseAddr(last)
		if i, ok := idx[id]; ok && err1 == nil && err2 == nil {
			out[i].Pools = append(out[i].Pools, Pool{Name: name, First: f, Last: l})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Prefix.Addr() != out[j].Prefix.Addr() {
			return out[i].Prefix.Addr().Less(out[j].Prefix.Addr())
		}
		return out[i].Prefix.Bits() < out[j].Prefix.Bits()
	})
	return out, pr.Err()
}

// Network returns one network.
func (s *Store) Network(ctx context.Context, id string) (Network, error) {
	all, err := s.Networks(ctx)
	if err != nil {
		return Network{}, err
	}
	for _, n := range all {
		if n.ID == id {
			return n, nil
		}
	}
	return Network{}, ErrNotFound
}

// --- entries ---

// SetEntry reserves or excludes an address.
func (s *Store) SetEntry(ctx context.Context, user string, ad netip.Addr, kind, note string) error {
	switch {
	case !userRe.MatchString(user):
		return errors.New("ipam: invalid user")
	case !ad.IsValid() || ad.Zone() != "":
		return invalid("the address is not valid")
	case kind != EntryReserved && kind != EntryExcluded:
		return invalid("an entry is reserved or excluded")
	case !plain(note, maxNote, false):
		return invalid("the note must be at most %d characters of plain text", maxNote)
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO ip_entries (address, kind, note, by_user, at) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (address) DO UPDATE SET kind = excluded.kind, note = excluded.note, by_user = excluded.by_user, at = excluded.at`,
		ad.Unmap().String(), kind, note, user, s.now().Unix())
	return err
}

// ClearEntry removes a reservation or exclusion.
func (s *Store) ClearEntry(ctx context.Context, ad netip.Addr) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM ip_entries WHERE address = ?`, ad.Unmap().String())
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// --- status ---

type claims struct {
	assets  map[netip.Addr][]string
	macs    map[netip.Addr][]string // asset MACs per address
	linked  map[string]string       // asset ID → managed host ID
	hosts   map[netip.Addr][]string
	entries map[netip.Addr]Entry
	seen    map[netip.Addr]Seen
}

func (s *Store) claims(ctx context.Context) (*claims, error) {
	c := &claims{assets: map[netip.Addr][]string{}, macs: map[netip.Addr][]string{}, linked: map[string]string{}, hosts: map[netip.Addr][]string{},
		entries: map[netip.Addr]Entry{}, seen: map[netip.Addr]Seen{}}
	assets, err := s.Assets(ctx)
	if err != nil {
		return nil, err
	}
	for _, a := range assets {
		if a.HostID != "" {
			c.linked[a.ID] = a.HostID
		}
		for _, ad := range a.Addresses {
			c.assets[ad] = append(c.assets[ad], a.ID)
			c.macs[ad] = append(c.macs[ad], a.MAC)
		}
	}
	if s.hosts != nil {
		h, err := s.hosts(ctx)
		if err != nil {
			return nil, err
		}
		for ad, ids := range h {
			c.hosts[ad.Unmap()] = append(c.hosts[ad.Unmap()], ids...)
		}
	}
	rows, err := s.db.QueryContext(ctx, `SELECT address, kind, note, by_user, at FROM ip_entries`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var e Entry
		var ad string
		var at int64
		if err := rows.Scan(&ad, &e.Kind, &e.Note, &e.By, &at); err != nil {
			return nil, err
		}
		if p, err := netip.ParseAddr(ad); err == nil {
			e.Address, e.At = p, time.Unix(at, 0)
			c.entries[p] = e
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	dr, err := s.db.QueryContext(ctx, `SELECT address, mac, hostname, seen_at FROM discovered_addresses`)
	if err != nil {
		return nil, err
	}
	defer dr.Close()
	for dr.Next() {
		var ad, mac, hn string
		var at int64
		if err := dr.Scan(&ad, &mac, &hn, &at); err != nil {
			return nil, err
		}
		if p, err := netip.ParseAddr(ad); err == nil {
			c.seen[p] = Seen{MAC: mac, Hostname: hn, At: time.Unix(at, 0)}
		}
	}
	return c, dr.Err()
}

func (c *claims) view(n Network, ad netip.Addr, now time.Time) AddressView {
	v := AddressView{Address: ad, Assets: c.assets[ad], Hosts: c.hosts[ad]}
	if e, ok := c.entries[ad]; ok {
		v.Entry = &e
	}
	if sn, ok := c.seen[ad]; ok {
		v.Seen = &sn
	}
	owners := c.owners(v.Assets, v.Hosts)
	switch {
	case v.Entry != nil && v.Entry.Kind == EntryExcluded:
		v.Status, v.Why = Excluded, "excluded: "+v.Entry.Note
	case ad.Is4() && n.Prefix.Bits() <= 30 && (ad == n.Prefix.Addr() || ad == lastAddr(n.Prefix)):
		v.Status, v.Why = Excluded, "network or broadcast address"
	case owners > 1:
		v.Status, v.Why = Conflict, "claimed by several assets or hosts"
	case v.Seen != nil && v.Seen.MAC != "" && len(v.Assets) == 1 && c.macs[ad][0] != "" && c.macs[ad][0] != v.Seen.MAC:
		v.Status, v.Why = Conflict, "discovery saw MAC "+v.Seen.MAC+", the asset has "+c.macs[ad][0]
	case v.Entry != nil && v.Entry.Kind == EntryReserved && v.Seen != nil && owners == 0 && now.Sub(v.Seen.At) < SuggestStale:
		v.Status, v.Why = Conflict, "reserved, but discovery saw a device"
	case owners > 0:
		v.Status, v.Why = Assigned, ""
	case ad == n.Gateway:
		v.Status, v.Why = Assigned, "gateway"
	case v.Entry != nil:
		v.Status, v.Why = Reserved, v.Entry.Note
	case v.Seen != nil:
		v.Status, v.Why = Discovered, "seen "+v.Seen.At.UTC().Format("2006-01-02")
	default:
		v.Status = Free
	}
	return v
}

// owners counts who claims an address: each asset, and each managed host
// not linked to one of those assets (an asset and the host it became are
// one owner).
func (c *claims) owners(assets, hosts []string) int {
	linked := map[string]bool{}
	for _, a := range assets {
		if h := c.linked[a]; h != "" {
			linked[h] = true
		}
	}
	n := len(assets)
	seen := map[string]bool{}
	for _, h := range hosts {
		if !linked[h] && !seen[h] {
			seen[h] = true
			n++
		}
	}
	return n
}

func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().As16()
	bits := p.Bits()
	if p.Addr().Is4() {
		bits += 96
	}
	for i := bits; i < 128; i++ {
		a[i/8] |= 1 << (7 - uint(i%8))
	}
	r := netip.AddrFrom16(a)
	if p.Addr().Is4() {
		return r.Unmap()
	}
	return r
}

// size is the number of addresses of p, capped above MaxListed.
func size(p netip.Prefix) int {
	host := p.Addr().BitLen() - p.Bits()
	if host > 20 {
		return MaxListed + 1
	}
	return 1 << host
}

// Status returns the addresses of a network with their status: every
// address for a network of at most MaxListed addresses, otherwise only
// the addresses something claims (listed is then false).
func (s *Store) Status(ctx context.Context, networkID string) ([]AddressView, bool, error) {
	n, err := s.Network(ctx, networkID)
	if err != nil {
		return nil, false, err
	}
	c, err := s.claims(ctx)
	if err != nil {
		return nil, false, err
	}
	now := s.now()
	var out []AddressView
	if size(n.Prefix) <= MaxListed {
		for ad, i := n.Prefix.Addr(), 0; i < size(n.Prefix) && n.Prefix.Contains(ad); ad, i = ad.Next(), i+1 {
			out = append(out, c.view(n, ad, now))
		}
		return out, true, nil
	}
	known := map[netip.Addr]bool{}
	for _, m := range []map[netip.Addr][]string{c.assets, c.hosts} {
		for ad := range m {
			known[ad] = true
		}
	}
	for ad := range c.entries {
		known[ad] = true
	}
	for ad := range c.seen {
		known[ad] = true
	}
	if n.Gateway.IsValid() {
		known[n.Gateway] = true
	}
	for ad := range known {
		if n.Prefix.Contains(ad) {
			out = append(out, c.view(n, ad, now))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Address.Less(out[j].Address) })
	return out, false, nil
}

// Suggest returns up to count FREE addresses of a network (or of one of
// its pools) that discovery has not seen within SuggestStale. It is a
// suggestion, never a certainty: a device may be off or filtered.
func (s *Store) Suggest(ctx context.Context, networkID, pool string, count int) ([]netip.Addr, error) {
	if count < 1 || count > maxSuggestCount {
		count = 5
	}
	n, err := s.Network(ctx, networkID)
	if err != nil {
		return nil, err
	}
	first, last := n.Prefix.Addr(), lastAddr(n.Prefix)
	if pool != "" {
		found := false
		for _, p := range n.Pools {
			if p.Name == pool {
				first, last, found = p.First, p.Last, true
			}
		}
		if !found {
			return nil, ErrNotFound
		}
	}
	c, err := s.claims(ctx)
	if err != nil {
		return nil, err
	}
	now := s.now()
	var out []netip.Addr
	for ad, tried := first, 0; len(out) < count && tried < 65536 && !last.Less(ad) && ad.IsValid(); ad, tried = ad.Next(), tried+1 {
		v := c.view(n, ad, now)
		if v.Status == Free || v.Status == Discovered && now.Sub(v.Seen.At) >= SuggestStale {
			out = append(out, ad)
		}
	}
	return out, nil
}

// LinkHost records that an asset became a managed host (or clears the
// link with ""). The caller checks that the host exists.
func (s *Store) LinkHost(ctx context.Context, assetID, hostID string) error {
	if hostID != "" && !idRe.MatchString(hostID) {
		return invalid("the managed host ID is not valid")
	}
	res, err := s.db.ExecContext(ctx, `UPDATE assets SET host_id = ?, updated_at = ? WHERE id = ?`, hostID, s.now().Unix(), assetID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Entries lists the reservations and exclusions inside a prefix.
func (s *Store) Entries(ctx context.Context, p netip.Prefix) ([]Entry, error) {
	c, err := s.claims(ctx)
	if err != nil {
		return nil, err
	}
	var out []Entry
	for ad, e := range c.entries {
		if p.Contains(ad) {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Address.Less(out[j].Address) })
	return out, nil
}

// FromInventory returns the managed hosts' literal IP endpoints from a
// host list (hostnames are not resolved: IPAM never does DNS).
func FromInventory(list func(ctx context.Context) ([]inventory.Host, error)) HostAddresses {
	return func(ctx context.Context) (map[netip.Addr][]string, error) {
		hosts, err := list(ctx)
		if err != nil {
			return nil, err
		}
		out := map[netip.Addr][]string{}
		for _, h := range hosts {
			seen := map[netip.Addr]bool{}
			for _, e := range h.Endpoints {
				ad, err := netip.ParseAddr(strings.Trim(e.Address, "[]"))
				if err != nil || ad.Zone() != "" {
					continue
				}
				ad = ad.Unmap()
				if !seen[ad] {
					seen[ad] = true
					out[ad] = append(out[ad], h.ID)
				}
			}
		}
		return out, nil
	}
}
