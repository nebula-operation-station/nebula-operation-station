// SPDX-License-Identifier: AGPL-3.0-or-later
package pveinventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/ipam"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
)

// Sentinel errors callers branch on.
var (
	// ErrLinkNotFound is returned when no active link exists for the
	// guest incarnation.
	ErrLinkNotFound = errors.New("pveinventory: link not found")
	// ErrLinkExists is returned when the guest incarnation is already
	// actively linked.
	ErrLinkExists = errors.New("pveinventory: incarnation already linked")
	// ErrHostAlreadyLinked is returned when the managed host is already
	// actively linked to a different guest incarnation. The conflict is
	// surfaced, never resolved silently.
	ErrHostAlreadyLinked = errors.New("pveinventory: host already linked to another guest")
	// ErrManagedHostNotFound is returned when the referenced inventory
	// host does not exist.
	ErrManagedHostNotFound = errors.New("pveinventory: managed host not found")
)

// Link match kinds (Candidate.Match).
const (
	// MatchMAC is a MAC address match via an IPAM asset.
	MatchMAC = "mac"
	// MatchAgentIP is an IP reported by the guest agent (qemu-agent).
	MatchAgentIP = "agent-ip"
	// MatchIP is an IP match from an interface or cloud-init record.
	MatchIP = "ip"
)

// Limits for the linking surface.
const (
	// MaxActorLen is the maximum length of an actor (user) string.
	MaxActorLen = 64
	// MaxUnlinkReasonLen is the maximum length of an unlink reason.
	MaxUnlinkReasonLen = 200
	// MaxLinksQuery caps a ListLinks result.
	MaxLinksQuery = 1000
)

var actorRe = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)

// Link is an explicit, reviewed link between a PVE guest incarnation and
// a managed inventory host. Links are created only by an explicit
// import/confirm call, never automatically, and preserve the existing
// asset id of the managed host.
type Link struct {
	// RemoteID is the PVE remote the guest belongs to.
	RemoteID string
	// VMID is the PVE guest ID.
	VMID uint64
	// Generation is the incarnation of the VMID.
	Generation uint64
	// HostID is the managed inventory host id (asset id preserved).
	HostID string
	// CreatedBy is the user who created the link.
	CreatedBy string
	// CreatedAt is when the link was created.
	CreatedAt time.Time
	// UnlinkedAt is when the link was unlinked; zero while active.
	UnlinkedAt time.Time
	// UnlinkReason is the reason recorded at unlink time.
	UnlinkReason string
}

// Candidate is a suggestion of which managed host a PVE guest might be.
// Candidates are suggestions only: a link is created only by an explicit
// import/confirm call.
type Candidate struct {
	// HostID is the suggested managed host id.
	HostID string
	// Match is how the candidate was found: MatchMAC, MatchAgentIP or
	// MatchIP.
	Match string
	// Detail is a human-readable explanation built from validated values.
	Detail string
	// Conflict is true when the same identifying value points to more
	// than one managed host (one MAC on two guests, one IP on two hosts).
	// Conflicts are flagged, never resolved silently.
	Conflict bool
}

// ReuseNotice is a visible notice that a VMID was reused (new
// incarnation) and the old explicit link no longer applies.
type ReuseNotice struct {
	// RemoteID is the PVE remote.
	RemoteID string
	// VMID is the reused guest ID.
	VMID uint64
	// OldGeneration is the tombstoned incarnation the link pointed at.
	OldGeneration uint64
	// OldHostID is the host the old link pointed at.
	OldHostID string
	// NewGeneration is the current active incarnation of the VMID.
	NewGeneration uint64
	// Notice is a human-readable message safe to display.
	Notice string
}

func validActor(actor string) error {
	if !actorRe.MatchString(actor) {
		return fmt.Errorf("pveinventory: invalid actor %q", actor)
	}
	return nil
}

// hostStore returns an inventory store on the same database.
func (s *Store) hostStore() *inventory.Store {
	return inventory.NewWithNow(s.db, s.now)
}

// ipamStore returns an IPAM store on the same database. Managed-host
// enrichment is not needed for the read-only candidate lookups.
func (s *Store) ipamStore() *ipam.Store {
	return ipam.New(s.db, nil)
}

// CreateLink creates an explicit link between the guest incarnation
// (remoteID, vmid, generation) and the managed host hostID. It is the
// only way a link is created: candidate matching never links
// automatically. The existing asset id of the managed host is preserved.
// The "at most one active link per incarnation" and "one host, one
// guest" invariants are checked and inserted in a single transaction.
func (s *Store) CreateLink(ctx context.Context, remoteID string, vmid, generation uint64, hostID, actor string) (Link, error) {
	if err := validActor(actor); err != nil {
		return Link{}, err
	}
	if _, err := s.getIncarnation(ctx, remoteID, vmid, generation); err != nil {
		return Link{}, err
	}
	if _, err := s.hostStore().Get(ctx, hostID); err != nil {
		if errors.Is(err, inventory.ErrHostNotFound) {
			return Link{}, fmt.Errorf("%w: %s", ErrManagedHostNotFound, hostID)
		}
		return Link{}, fmt.Errorf("pveinventory: get managed host %s: %w", hostID, err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Link{}, fmt.Errorf("pveinventory: begin create link: %w", err)
	}
	defer tx.Rollback()

	if l, err := scanLinkRow(tx.QueryRowContext(ctx, linkByIncarnationSQL, remoteID, vmid, generation)); err == nil {
		return Link{}, fmt.Errorf("%w: %s/%d/%d -> %s", ErrLinkExists, remoteID, vmid, generation, l.HostID)
	} else if !errors.Is(err, ErrLinkNotFound) {
		return Link{}, err
	}
	if l, err := scanLinkRow(tx.QueryRowContext(ctx, linkByHostSQL, hostID)); err == nil {
		return Link{}, fmt.Errorf("%w: %s -> %s/%d/%d", ErrHostAlreadyLinked, hostID, l.RemoteID, l.VMID, l.Generation)
	} else if !errors.Is(err, ErrLinkNotFound) {
		return Link{}, err
	}

	now := s.formatTime(s.now())
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO pve_host_links (remote_id, vmid, generation, host_id, created_by, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		remoteID, vmid, generation, hostID, actor, now); err != nil {
		return Link{}, fmt.Errorf("pveinventory: create link %s/%d/%d -> %s: %w", remoteID, vmid, generation, hostID, err)
	}
	if err := tx.Commit(); err != nil {
		return Link{}, fmt.Errorf("pveinventory: commit create link: %w", err)
	}
	createdAt, _ := time.Parse(time.RFC3339, now)
	return Link{RemoteID: remoteID, VMID: vmid, Generation: generation, HostID: hostID, CreatedBy: actor, CreatedAt: createdAt}, nil
}

// GetLink returns the active link for the guest incarnation.
func (s *Store) GetLink(ctx context.Context, remoteID string, vmid, generation uint64) (Link, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT remote_id, vmid, generation, host_id, created_by, created_at, unlinked_at, unlink_reason
		FROM pve_host_links
		WHERE remote_id = ? AND vmid = ? AND generation = ? AND unlinked_at = ''`,
		remoteID, vmid, generation)
	return scanLinkRow(row)
}

// LinkHistory returns all link rows (active and unlinked) for the guest
// incarnation, newest first, so the explicit link history stays visible.
func (s *Store) LinkHistory(ctx context.Context, remoteID string, vmid, generation uint64) ([]Link, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT remote_id, vmid, generation, host_id, created_by, created_at, unlinked_at, unlink_reason
		FROM pve_host_links
		WHERE remote_id = ? AND vmid = ? AND generation = ?
		ORDER BY created_at DESC, host_id`,
		remoteID, vmid, generation)
	if err != nil {
		return nil, fmt.Errorf("pveinventory: link history %s/%d/%d: %w", remoteID, vmid, generation, err)
	}
	defer rows.Close()
	var out []Link
	for rows.Next() {
		l, err := scanLinkRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// Unlink removes the active link for the guest incarnation. The row is
// tombstoned (unlinked_at, unlink_reason), never deleted, so the
// explicit link history stays visible. The returned link carries the
// notice data for the UI.
func (s *Store) Unlink(ctx context.Context, remoteID string, vmid, generation uint64, actor, reason string) (Link, error) {
	if err := validActor(actor); err != nil {
		return Link{}, err
	}
	if !utf8.ValidString(reason) || len(reason) > MaxUnlinkReasonLen {
		return Link{}, fmt.Errorf("pveinventory: unlink reason must be valid UTF-8 of at most %d bytes", MaxUnlinkReasonLen)
	}
	link, err := s.GetLink(ctx, remoteID, vmid, generation)
	if err != nil {
		return Link{}, err
	}
	now := s.formatTime(s.now())
	res, err := s.db.ExecContext(ctx, `
		UPDATE pve_host_links SET unlinked_at = ?, unlink_reason = ?
		WHERE remote_id = ? AND vmid = ? AND generation = ? AND unlinked_at = ''`,
		now, reason, remoteID, vmid, generation)
	if err != nil {
		return Link{}, fmt.Errorf("pveinventory: unlink %s/%d/%d: %w", remoteID, vmid, generation, err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return Link{}, fmt.Errorf("%w: %s/%d/%d", ErrLinkNotFound, remoteID, vmid, generation)
	}
	link.UnlinkedAt, _ = time.Parse(time.RFC3339, now)
	link.UnlinkReason = reason
	return link, nil
}

// LinksForHost returns the active links pointing at the managed host.
func (s *Store) LinksForHost(ctx context.Context, hostID string) ([]Link, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT remote_id, vmid, generation, host_id, created_by, created_at, unlinked_at, unlink_reason
		FROM pve_host_links
		WHERE host_id = ? AND unlinked_at = ''
		ORDER BY remote_id, vmid, generation`, hostID)
	if err != nil {
		return nil, fmt.Errorf("pveinventory: links for host %s: %w", hostID, err)
	}
	defer rows.Close()
	var out []Link
	for rows.Next() {
		l, err := scanLinkRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// ListLinks returns the active links of one remote, bounded.
func (s *Store) ListLinks(ctx context.Context, remoteID string, limit int) ([]Link, error) {
	limit, err := checkLimit(limit, MaxLinksQuery)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT remote_id, vmid, generation, host_id, created_by, created_at, unlinked_at, unlink_reason
		FROM pve_host_links
		WHERE remote_id = ? AND unlinked_at = ''
		ORDER BY vmid, generation
		LIMIT ?`, remoteID, limit)
	if err != nil {
		return nil, fmt.Errorf("pveinventory: list links %s: %w", remoteID, err)
	}
	defer rows.Close()
	var out []Link
	for rows.Next() {
		l, err := scanLinkRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// SweepVMIDReuse detects active links whose incarnation was tombstoned
// by a VMID reuse (a newer active incarnation of the same VMID exists),
// unlinks them with the reason "vmid reused" and returns one visible
// notice per unlinked link. The new incarnation is never linked
// automatically.
func (s *Store) SweepVMIDReuse(ctx context.Context, remoteID string) ([]ReuseNotice, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("pveinventory: begin vmid reuse sweep: %w", err)
	}
	defer tx.Rollback()

	rows, err := tx.QueryContext(ctx, `
		SELECT l.vmid, l.generation, l.host_id,
		       (SELECT MAX(n.generation) FROM pve_guests n
		        WHERE n.remote_id = l.remote_id AND n.vmid = l.vmid AND n.tombstoned = 0)
		FROM pve_host_links l
		JOIN pve_guests g ON g.remote_id = l.remote_id AND g.vmid = l.vmid AND g.generation = l.generation
		WHERE l.remote_id = ? AND l.unlinked_at = '' AND g.tombstoned = 1
		  AND EXISTS (SELECT 1 FROM pve_guests n
		           WHERE n.remote_id = l.remote_id AND n.vmid = l.vmid
		                 AND n.generation > l.generation AND n.tombstoned = 0)
		ORDER BY l.vmid, l.generation`, remoteID)
	if err != nil {
		return nil, fmt.Errorf("pveinventory: vmid reuse sweep %s: %w", remoteID, err)
	}
	defer rows.Close()

	type item struct {
		vmid, generation, newGeneration uint64
		hostID                          string
	}
	var items []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.vmid, &it.generation, &it.hostID, &it.newGeneration); err != nil {
			return nil, fmt.Errorf("pveinventory: scan vmid reuse sweep: %w", err)
		}
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var notices []ReuseNotice
	now := s.formatTime(s.now())
	for _, it := range items {
		res, err := tx.ExecContext(ctx, `
			UPDATE pve_host_links SET unlinked_at = ?, unlink_reason = 'vmid reused: new incarnation'
			WHERE remote_id = ? AND vmid = ? AND generation = ? AND unlinked_at = ''`,
			now, remoteID, it.vmid, it.generation)
		if err != nil {
			return nil, fmt.Errorf("pveinventory: unlink reused vmid %s/%d/%d: %w", remoteID, it.vmid, it.generation, err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return nil, fmt.Errorf("pveinventory: unlink reused vmid %s/%d/%d: %w", remoteID, it.vmid, it.generation, ErrLinkNotFound)
		}
		notices = append(notices, ReuseNotice{
			RemoteID:      remoteID,
			VMID:          it.vmid,
			OldGeneration: it.generation,
			OldHostID:     it.hostID,
			NewGeneration: it.newGeneration,
			Notice: fmt.Sprintf("VMID %d on %s was reused: the link to host %s (incarnation %d) does not apply to the new guest (incarnation %d)",
				it.vmid, remoteID, it.hostID, it.generation, it.newGeneration),
		})
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("pveinventory: commit vmid reuse sweep: %w", err)
	}
	return notices, nil
}

// guestIPs are the IP addresses observed on one guest incarnation:
// plain interface IPs, guest-agent IPs and the cloud-init IP.
type guestIPs struct {
	agent map[string]bool
	plain map[string]bool
}

// SuggestHosts computes candidate managed hosts for the guest
// incarnation by MAC address (via IPAM assets) and guest IP (interface
// IPs, guest-agent IPs and the cloud-init IP). Candidates are
// suggestions only; they never create a link. Conflicts (one MAC on two
// guests, one IP on two hosts) are flagged in the candidates.
func (s *Store) SuggestHosts(ctx context.Context, remoteID string, vmid, generation uint64) ([]Candidate, error) {
	if _, err := s.getIncarnation(ctx, remoteID, vmid, generation); err != nil {
		return nil, err
	}

	// Guest MACs and IPs.
	macs := map[string]bool{}
	ips := guestIPs{agent: map[string]bool{}, plain: map[string]bool{}}
	ifaces, err := s.ListInterfaces(ctx, remoteID, vmid, generation, 0)
	if err != nil {
		return nil, err
	}
	for _, in := range ifaces {
		if in.MAC != "" {
			macs[in.MAC] = true
		}
		for _, ip := range in.IPs {
			a, ok := parseGuestIP(ip)
			if !ok {
				continue
			}
			if in.Source == pvecontract.SourceQEMUAgent {
				ips.agent[a] = true
			}
			ips.plain[a] = true
		}
	}
	if cfg, err := s.GetGuestConfig(ctx, remoteID, vmid, generation); err == nil && cfg.State == StateAvailable && cfg.CloudInitIP != nil {
		if a, ok := parseGuestIP(cfg.CloudInitIP.IP); ok {
			ips.plain[a] = true
		}
	}

	// Managed hosts: endpoint addresses.
	hosts, err := s.hostStore().List(ctx)
	if err != nil {
		return nil, fmt.Errorf("pveinventory: list managed hosts: %w", err)
	}
	hostByEndpoint := map[string][]string{} // lowercased address -> host ids
	for _, h := range hosts {
		for _, e := range h.Endpoints {
			hostByEndpoint[strings.ToLower(e.Address)] = append(hostByEndpoint[strings.ToLower(e.Address)], h.ID)
		}
	}

	// IPAM assets: MACs and addresses with a managed host.
	assets, err := s.ipamStore().Assets(ctx)
	if err != nil {
		return nil, fmt.Errorf("pveinventory: list ipam assets: %w", err)
	}
	hostsByAssetMAC := map[string][]string{} // normalized mac -> host ids
	hostsByAssetIP := map[string][]string{}  // lowercased ip -> host ids
	for _, a := range assets {
		if a.HostID == "" {
			continue
		}
		if a.MAC != "" {
			hostsByAssetMAC[a.MAC] = append(hostsByAssetMAC[a.MAC], a.HostID)
		}
		for _, addr := range a.Addresses {
			low := strings.ToLower(addr.String())
			hostsByAssetIP[low] = append(hostsByAssetIP[low], a.HostID)
		}
	}

	out := map[string]*Candidate{} // host|match -> candidate
	add := func(hostID, match, detail string, conflict bool) {
		key := hostID + "|" + match
		c, ok := out[key]
		if !ok {
			c = &Candidate{HostID: hostID, Match: match, Detail: detail}
			out[key] = c
		}
		c.Conflict = c.Conflict || conflict
	}

	// MAC matches: a guest MAC present on another guest of the same
	// remote is a conflict (cloned MAC), flagged not resolved.
	for mac := range macs {
		others, err := s.guestsWithMAC(ctx, remoteID, mac, vmid)
		if err != nil {
			return nil, err
		}
		macConflict := len(others) > 0
		for _, hostID := range hostsByAssetMAC[mac] {
			detail := fmt.Sprintf("MAC %s matches an IPAM asset of host %s", mac, hostID)
			if macConflict {
				detail += fmt.Sprintf(" (conflict: MAC also seen on guest %s)", strings.Join(others, ", "))
			}
			add(hostID, MatchMAC, detail, macConflict || len(hostsByAssetMAC[mac]) > 1)
		}
	}

	// IP matches: agent IPs first (stronger), then plain IPs.
	for ip := range ips.agent {
		s.addIPCandidate(ip, MatchAgentIP, hostByEndpoint, hostsByAssetIP, add)
	}
	for ip := range ips.plain {
		if ips.agent[ip] {
			continue
		}
		s.addIPCandidate(ip, MatchIP, hostByEndpoint, hostsByAssetIP, add)
	}

	var candidates []Candidate
	for _, c := range out {
		candidates = append(candidates, *c)
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].HostID != candidates[j].HostID {
			return candidates[i].HostID < candidates[j].HostID
		}
		return candidates[i].Match < candidates[j].Match
	})
	return candidates, nil
}

func (s *Store) addIPCandidate(ip, match string, hostByEndpoint, hostsByAssetIP map[string][]string, add func(hostID, match, detail string, conflict bool)) {
	low := strings.ToLower(ip)
	hostSet := map[string]bool{}
	for _, h := range hostByEndpoint[low] {
		hostSet[h] = true
	}
	for _, h := range hostsByAssetIP[low] {
		hostSet[h] = true
	}
	ipConflict := len(hostSet) > 1
	for h := range hostSet {
		detail := fmt.Sprintf("IP %s matches an endpoint of host %s", ip, h)
		if match == MatchAgentIP {
			detail = fmt.Sprintf("guest agent IP %s matches an endpoint of host %s", ip, h)
		}
		if ipConflict {
			detail += fmt.Sprintf(" (conflict: IP also matches %d other hosts)", len(hostSet)-1)
		}
		add(h, match, detail, ipConflict)
	}
}

// GuestConflicts returns human-readable conflict descriptions for the
// guest incarnation: one MAC present on two guests of the same remote,
// or one guest IP matching more than one managed host. Conflicts are
// flagged, never resolved silently.
func (s *Store) GuestConflicts(ctx context.Context, remoteID string, vmid, generation uint64) ([]string, error) {
	if _, err := s.getIncarnation(ctx, remoteID, vmid, generation); err != nil {
		return nil, err
	}
	var out []string
	ifaces, err := s.ListInterfaces(ctx, remoteID, vmid, generation, 0)
	if err != nil {
		return nil, err
	}
	seenMAC := map[string]bool{}
	for _, in := range ifaces {
		if in.MAC == "" || seenMAC[in.MAC] {
			continue
		}
		seenMAC[in.MAC] = true
		others, err := s.guestsWithMAC(ctx, remoteID, in.MAC, vmid)
		if err != nil {
			return nil, err
		}
		if len(others) > 0 {
			out = append(out, fmt.Sprintf("MAC %s is present on this guest and on guest %s (cloned MAC; link needs review)",
				in.MAC, strings.Join(others, ", ")))
		}
	}
	hosts, err := s.hostStore().List(ctx)
	if err != nil {
		return nil, err
	}
	countByIP := map[string][]string{}
	for _, h := range hosts {
		for _, e := range h.Endpoints {
			countByIP[strings.ToLower(e.Address)] = append(countByIP[strings.ToLower(e.Address)], h.ID)
		}
	}
	seenIP := map[string]bool{}
	for _, in := range ifaces {
		for _, ip := range in.IPs {
			a, ok := parseGuestIP(ip)
			if !ok || seenIP[a] {
				continue
			}
			seenIP[a] = true
			if hs := countByIP[strings.ToLower(a)]; len(hs) > 1 {
				out = append(out, fmt.Sprintf("IP %s is an endpoint of %d managed hosts: %s", a, len(hs), strings.Join(hs, ", ")))
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

// guestsWithMAC returns the "vmid (gen)" labels of other active guests
// of the same remote carrying the MAC.
func (s *Store) guestsWithMAC(ctx context.Context, remoteID, mac string, selfVMID uint64) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT g.vmid, g.generation
		FROM pve_interfaces i
		JOIN pve_guests g ON g.remote_id = i.remote_id AND g.vmid = i.vmid AND g.generation = i.generation
		WHERE i.remote_id = ? AND i.mac = ? AND g.tombstoned = 0
		ORDER BY g.vmid, g.generation`, remoteID, mac)
	if err != nil {
		return nil, fmt.Errorf("pveinventory: guests with mac %s: %w", mac, err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var vmid, gen uint64
		if err := rows.Scan(&vmid, &gen); err != nil {
			return nil, err
		}
		if vmid == selfVMID {
			continue
		}
		out = append(out, fmt.Sprintf("%d (gen %d)", vmid, gen))
	}
	return out, rows.Err()
}

// parseGuestIP parses a stored interface IP ("10.0.0.5" or
// "10.0.0.5/24") into its canonical address string.
func parseGuestIP(ip string) (string, bool) {
	if i := strings.IndexByte(ip, '/'); i >= 0 {
		ip = ip[:i]
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return "", false
	}
	return a.String(), true
}

// getIncarnation loads one active guest incarnation.
func (s *Store) getIncarnation(ctx context.Context, remoteID string, vmid, generation uint64) (Guest, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT remote_id, vmid, generation, kind, node, name, status, uuid,
		       observed_at, source, state, reason, collection_generation,
		       tombstoned, tombstoned_at
		FROM pve_guests
		WHERE remote_id = ? AND vmid = ? AND generation = ? AND tombstoned = 0`,
		remoteID, vmid, generation)
	return scanGuestRow(row, s, fmt.Sprintf("get guest %s/%d/%d", remoteID, vmid, generation))
}

const (
	linkColumns = "remote_id, vmid, generation, host_id, created_by, created_at, unlinked_at, unlink_reason"

	linkByIncarnationSQL = `
		SELECT ` + linkColumns + `
		FROM pve_host_links
		WHERE remote_id = ? AND vmid = ? AND generation = ? AND unlinked_at = ''
		LIMIT 1`

	linkByHostSQL = `
		SELECT ` + linkColumns + `
		FROM pve_host_links
		WHERE host_id = ? AND unlinked_at = ''
		ORDER BY remote_id, vmid, generation
		LIMIT 1`
)

type linkScanner interface {
	Scan(dest ...any) error
}

// scanLinkRow scans one pve_host_links row; sql.ErrNoRows maps to
// ErrLinkNotFound.
func scanLinkRow(row linkScanner) (Link, error) {
	var l Link
	var createdAt, unlinkedAt string
	err := row.Scan(&l.RemoteID, &l.VMID, &l.Generation, &l.HostID, &l.CreatedBy, &createdAt, &unlinkedAt, &l.UnlinkReason)
	if errors.Is(err, sql.ErrNoRows) {
		return Link{}, ErrLinkNotFound
	}
	if err != nil {
		return Link{}, fmt.Errorf("pveinventory: scan link: %w", err)
	}
	l.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	if unlinkedAt != "" {
		l.UnlinkedAt, _ = time.Parse(time.RFC3339, unlinkedAt)
	}
	return l, nil
}
