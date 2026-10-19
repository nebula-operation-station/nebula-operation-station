// SPDX-License-Identifier: AGPL-3.0-or-later

// Package discovery is the server side of network discovery (spec 12,
// M9-2): it queues scan jobs for nebula-discovery, reads their results
// into staging, classifies each staged host against the assets (NEW,
// EXISTING, POSSIBLE MATCH, CONFLICT) and imports what the user selects.
// Scan results are untrusted network data: they are cleaned when read
// and never reach the assets without an import.
package discovery

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/discoveryjob"
	"github.com/nebula-operation-station/nebula-operation-station/internal/ipam"
)

// Class of a staged host (spec 12).
type Class string

// Classes.
const (
	ClassNew      Class = "NEW"
	ClassExisting Class = "EXISTING"
	ClassPossible Class = "POSSIBLE MATCH"
	ClassConflict Class = "CONFLICT"
)

// Job states.
const (
	StateQueued    = "queued"
	StateDone      = "done"
	StateFailed    = "failed"
	StateCancelled = "cancelled"
)

// Limits and timing.
const (
	MinInterval   = time.Hour
	MaxQueued     = 8             // queued scans at a time (review m92 F3)
	resultTimeout = 3 * time.Hour // no result after this: failed
	keepJobs      = 90 * 24 * time.Hour
	tick          = 30 * time.Second
	maxSchedules  = 32
)

// ValidationError says what is wrong with a request; safe to show.
type ValidationError struct{ Reason string }

func (e *ValidationError) Error() string { return e.Reason }

func invalid(format string, a ...any) error {
	return &ValidationError{Reason: fmt.Sprintf(format, a...)}
}

// Errors.
var (
	ErrNotFound    = errors.New("discovery: not found")
	ErrUnavailable = errors.New("discovery: nebula-discovery is not installed")
)

// Request is a scan as the user asks for it.
type Request struct {
	Mode    discoveryjob.Mode    `json:"mode"`
	Targets []string             `json:"targets"`
	Ports   string               `json:"ports"`
	Custom  *discoveryjob.Custom `json:"custom"`
}

// JobRow is a queued or finished job.
type JobRow struct {
	ID, Description, Targets, CreatedBy, State, Error, ScheduleID string
	CreatedAt, FinishedAt                                         time.Time
	Hosts                                                         int
}

// Row is one staged host with its classification against the current
// assets and managed hosts.
type Row struct {
	discoveryjob.Host
	Class         Class
	Reason        string
	MatchAsset    string
	MatchHost     string
	ImportedAsset string
	ImportedBy    string
	ImportedAt    time.Time
	Importable    bool
}

// Schedule is a recurring or one-time scan.
type Schedule struct {
	ID, Name, Description, Targets, CreatedBy string
	Interval                                  time.Duration // 0: once
	NextAt                                    time.Time
	Enabled                                   bool
}

// Store queues jobs and keeps their results.
type Store struct {
	db    *sql.DB
	spool discoveryjob.Spool
	ipam  *ipam.Store
	hosts ipam.HostAddresses
	log   *slog.Logger
	now   func() time.Time
}

// New returns a store; hosts may be nil.
func New(db *sql.DB, spool discoveryjob.Spool, ip *ipam.Store, hosts ipam.HostAddresses, log *slog.Logger) *Store {
	if log == nil {
		log = slog.Default()
	}
	return &Store{db: db, spool: spool, ipam: ip, hosts: hosts, log: log, now: time.Now}
}

// Available reports whether nebula-discovery is installed (its spool
// exists).
func (s *Store) Available() bool { return s.spool.Available() }

func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

var userRe = regexp.MustCompile(`^[\x21-\x7e]{1,64}$`)

// job checks a request against the known networks and builds the job.
func (s *Store) job(ctx context.Context, req Request) (discoveryjob.Job, error) {
	targets, err := discoveryjob.Targets(req.Targets)
	if err != nil {
		return discoveryjob.Job{}, invalid("%s", err.Error())
	}
	nets, err := s.ipam.Networks(ctx)
	if err != nil {
		return discoveryjob.Job{}, err
	}
	var norm []string
	for _, t := range targets {
		known := false
		for _, n := range nets {
			if n.Prefix.Bits() <= t.Bits() && n.Prefix.Contains(t.Addr()) {
				known = true
				break
			}
		}
		if !known {
			return discoveryjob.Job{}, invalid("%s is not inside a known network; add the network first", t)
		}
		if t.IsSingleIP() {
			norm = append(norm, t.Addr().String())
		} else {
			norm = append(norm, t.String())
		}
	}
	j := discoveryjob.Job{Format: discoveryjob.JobFormat, ID: newID(), Mode: req.Mode, Targets: norm, CreatedAt: s.now().Unix()}
	switch req.Mode {
	case discoveryjob.ModePorts:
		if j.Ports, err = discoveryjob.NormalizePorts(req.Ports); err != nil {
			return discoveryjob.Job{}, invalid("%s", err.Error())
		}
	case discoveryjob.ModeCustom:
		if req.Custom == nil {
			return discoveryjob.Job{}, invalid("a custom scan needs its options")
		}
		c := *req.Custom
		if c.Ports != "" {
			if c.Ports, err = discoveryjob.NormalizePorts(c.Ports); err != nil {
				return discoveryjob.Job{}, invalid("%s", err.Error())
			}
		}
		j.Custom = &c
	}
	if err := j.Validate(); err != nil {
		return discoveryjob.Job{}, invalid("%s", err.Error())
	}
	return j, nil
}

// Submit queues a scan now.
func (s *Store) Submit(ctx context.Context, user string, req Request) (JobRow, error) {
	return s.submit(ctx, user, req, "")
}

func (s *Store) submit(ctx context.Context, user string, req Request, scheduleID string) (JobRow, error) {
	if !userRe.MatchString(user) {
		return JobRow{}, errors.New("discovery: invalid user")
	}
	if !s.Available() {
		return JobRow{}, ErrUnavailable
	}
	j, err := s.job(ctx, req)
	if err != nil {
		return JobRow{}, err
	}
	var queued int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM discovery_jobs WHERE state = ?`, StateQueued).Scan(&queued); err != nil {
		return JobRow{}, err
	}
	if queued >= MaxQueued {
		return JobRow{}, invalid("%d scans are waiting already; let them finish or cancel some", queued)
	}
	spec, err := json.Marshal(j)
	if err != nil {
		return JobRow{}, err
	}
	row := JobRow{ID: j.ID, Description: j.Describe(), Targets: strings.Join(j.Targets, ", "), CreatedBy: user, State: StateQueued,
		ScheduleID: scheduleID, CreatedAt: time.Unix(j.CreatedAt, 0)}
	// The row first: a job file without a row would run and never be read.
	if _, err := s.db.ExecContext(ctx, `INSERT INTO discovery_jobs (id, spec, description, targets, created_by, created_at, schedule_id, state)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, j.ID, string(spec), row.Description, row.Targets, user, j.CreatedAt, scheduleID, StateQueued); err != nil {
		return JobRow{}, err
	}
	if err := s.spool.WriteJob(j); err != nil {
		s.finish(ctx, j.ID, StateFailed, "the job could not be queued", 0)
		return JobRow{}, fmt.Errorf("discovery: write job: %w", err)
	}
	return row, nil
}

func (s *Store) finish(ctx context.Context, id, state, msg string, hosts int) {
	if _, err := s.db.ExecContext(ctx, `UPDATE discovery_jobs SET state = ?, error = ?, hosts = ?, finished_at = ? WHERE id = ? AND state = ?`,
		state, discoveryjob.Text(msg), hosts, s.now().Unix(), id, StateQueued); err != nil {
		s.log.Error("discovery: finish job", "job", id, "error", err)
	}
}

// Cancel withdraws a queued job (a scan already running finishes, but its
// result is ignored).
func (s *Store) Cancel(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE discovery_jobs SET state = ?, finished_at = ? WHERE id = ? AND state = ?`,
		StateCancelled, s.now().Unix(), id, StateQueued)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return s.spool.RemoveJob(id)
}

// Poll reads the results of queued jobs into staging.
func (s *Store) Poll(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT id, created_at FROM discovery_jobs WHERE state = ?`, StateQueued)
	if err != nil {
		return err
	}
	type q struct {
		id string
		at int64
	}
	var queued []q
	for rows.Next() {
		var j q
		if err := rows.Scan(&j.id, &j.at); err != nil {
			rows.Close()
			return err
		}
		queued = append(queued, j)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, j := range queued {
		res, err := s.spool.ReadResult(j.id)
		switch {
		case errors.Is(err, os.ErrNotExist):
			if s.now().Sub(time.Unix(j.at, 0)) > resultTimeout {
				s.finish(ctx, j.id, StateFailed, "no result; is the nebula-discovery path unit enabled?", 0)
				_ = s.spool.RemoveJob(j.id)
			}
			continue
		case err != nil:
			s.log.Warn("discovery: bad result", "job", j.id, "error", err)
			s.finish(ctx, j.id, StateFailed, "the result could not be read", 0)
			_ = s.spool.RemoveJob(j.id)
			continue
		}
		if err := s.stage(ctx, j.id, res); err != nil {
			return err
		}
		_ = s.spool.RemoveJob(j.id)
	}
	// Old jobs go, with their staging.
	_, err = s.db.ExecContext(ctx, `DELETE FROM discovery_jobs WHERE state != ? AND created_at < ?`, StateQueued, s.now().Add(-keepJobs).Unix())
	return err
}

func (s *Store) stage(ctx context.Context, id string, res discoveryjob.Result) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if !res.OK {
		msg := res.Error
		if msg == "" {
			msg = "the scan failed"
		}
		if _, err := tx.ExecContext(ctx, `UPDATE discovery_jobs SET state = ?, error = ?, finished_at = ? WHERE id = ? AND state = ?`,
			StateFailed, discoveryjob.Text(msg), s.now().Unix(), id, StateQueued); err != nil {
			return err
		}
		return tx.Commit()
	}
	seen := res.FinishedAt
	if seen <= 0 || seen > s.now().Unix() {
		seen = s.now().Unix()
	}
	for _, h := range res.Hosts {
		ports, err := json.Marshal(h.Ports)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO discovery_staging (job_id, address, mac, vendor, hostname, os, ports) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			id, h.Address, h.MAC, h.Vendor, h.Hostname, h.OS, string(ports)); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO discovered_addresses (address, mac, hostname, seen_at) VALUES (?, ?, ?, ?)
			ON CONFLICT (address) DO UPDATE SET
			mac = CASE WHEN excluded.mac != '' THEN excluded.mac ELSE discovered_addresses.mac END,
			hostname = CASE WHEN excluded.hostname != '' THEN excluded.hostname ELSE discovered_addresses.hostname END,
			seen_at = max(excluded.seen_at, discovered_addresses.seen_at)`, h.Address, h.MAC, h.Hostname, seen); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE discovery_jobs SET state = ?, hosts = ?, finished_at = ? WHERE id = ? AND state = ?`,
		StateDone, len(res.Hosts), s.now().Unix(), id, StateQueued); err != nil {
		return err
	}
	return tx.Commit()
}

// Jobs lists the latest jobs, newest first.
func (s *Store) Jobs(ctx context.Context, limit int) ([]JobRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, description, targets, created_by, created_at, schedule_id, state, finished_at, error, hosts
		FROM discovery_jobs ORDER BY created_at DESC, id LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []JobRow
	for rows.Next() {
		var j JobRow
		var at, fin int64
		if err := rows.Scan(&j.ID, &j.Description, &j.Targets, &j.CreatedBy, &at, &j.ScheduleID, &j.State, &fin, &j.Error, &j.Hosts); err != nil {
			return nil, err
		}
		j.CreatedAt = time.Unix(at, 0)
		if fin > 0 {
			j.FinishedAt = time.Unix(fin, 0)
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// Job returns one job with its staged hosts, classified now.
func (s *Store) Job(ctx context.Context, id string) (JobRow, []Row, error) {
	var j JobRow
	var at, fin int64
	err := s.db.QueryRowContext(ctx, `SELECT id, description, targets, created_by, created_at, schedule_id, state, finished_at, error, hosts
		FROM discovery_jobs WHERE id = ?`, id).Scan(&j.ID, &j.Description, &j.Targets, &j.CreatedBy, &at, &j.ScheduleID, &j.State, &fin, &j.Error, &j.Hosts)
	if errors.Is(err, sql.ErrNoRows) {
		return JobRow{}, nil, ErrNotFound
	}
	if err != nil {
		return JobRow{}, nil, err
	}
	j.CreatedAt = time.Unix(at, 0)
	if fin > 0 {
		j.FinishedAt = time.Unix(fin, 0)
	}
	rows, err := s.staged(ctx, id)
	if err != nil {
		return JobRow{}, nil, err
	}
	m, err := s.matcher(ctx)
	if err != nil {
		return JobRow{}, nil, err
	}
	for i := range rows {
		m.classify(&rows[i])
	}
	return j, rows, nil
}

func (s *Store) staged(ctx context.Context, id string) ([]Row, error) {
	rs, err := s.db.QueryContext(ctx, `SELECT address, mac, vendor, hostname, os, ports, imported_at, imported_by, imported_asset
		FROM discovery_staging WHERE job_id = ?`, id)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	var out []Row
	for rs.Next() {
		var r Row
		var ports string
		var imp int64
		if err := rs.Scan(&r.Address, &r.MAC, &r.Vendor, &r.Hostname, &r.OS, &ports, &imp, &r.ImportedBy, &r.ImportedAsset); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(ports), &r.Ports)
		if imp > 0 {
			r.ImportedAt = time.Unix(imp, 0)
		}
		out = append(out, r)
	}
	if err := rs.Err(); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		a, _ := netip.ParseAddr(out[i].Address)
		b, _ := netip.ParseAddr(out[j].Address)
		return a.Less(b)
	})
	return out, nil
}

// --- classification ---

type matcher struct {
	byMAC  map[string]ipam.Asset
	byAddr map[string][]ipam.Asset
	hosts  map[string][]string // address → managed host IDs
	linked map[string]bool     // host IDs some asset is linked to
	ids    map[string]bool     // asset IDs in use
}

func (s *Store) matcher(ctx context.Context) (*matcher, error) {
	assets, err := s.ipam.Assets(ctx)
	if err != nil {
		return nil, err
	}
	m := &matcher{byMAC: map[string]ipam.Asset{}, byAddr: map[string][]ipam.Asset{}, hosts: map[string][]string{}, linked: map[string]bool{}, ids: map[string]bool{}}
	for _, a := range assets {
		m.ids[a.ID] = true
		if a.MAC != "" {
			m.byMAC[a.MAC] = a
		}
		if a.HostID != "" {
			m.linked[a.HostID] = true
		}
		for _, ad := range a.Addresses {
			m.byAddr[ad.String()] = append(m.byAddr[ad.String()], a)
		}
	}
	if s.hosts != nil {
		h, err := s.hosts(ctx)
		if err != nil {
			return nil, err
		}
		for ad, ids := range h {
			m.hosts[ad.String()] = ids
		}
	}
	return m, nil
}

// classify sets Class, Reason, matches and Importable (spec 12): with a
// MAC (the scanner shares the segment) an asset with that MAC is EXISTING,
// or CONFLICT when the address belongs to another asset; without a MAC an
// asset or managed host at the address is only a POSSIBLE MATCH.
func (m *matcher) classify(r *Row) {
	atAddr := m.byAddr[r.Address]
	var unlinkedHosts []string
	for _, h := range m.hosts[r.Address] {
		if !m.linked[h] {
			unlinkedHosts = append(unlinkedHosts, h)
		}
	}
	if r.MAC != "" {
		if a, ok := m.byMAC[r.MAC]; ok {
			r.MatchAsset = a.ID
			for _, o := range atAddr {
				if o.ID != a.ID {
					r.Class, r.Reason = ClassConflict, "the MAC belongs to asset "+a.ID+", the address to asset "+o.ID
					return
				}
			}
			r.Class, r.Reason = ClassExisting, "same MAC as asset "+a.ID
			if len(atAddr) == 0 {
				// Say it: the import gives the asset a new address (review m92 F2).
				r.Reason += "; importing adds this address to it"
			}
			r.Importable = len(atAddr) == 0 || r.Hostname != "" && a.Hostname == ""
			return
		}
		for _, o := range atAddr {
			if o.MAC != "" {
				r.MatchAsset = o.ID
				r.Class, r.Reason = ClassConflict, "asset "+o.ID+" has this address with MAC "+o.MAC
				return
			}
		}
	}
	switch {
	case len(atAddr) > 1:
		r.Class, r.Reason = ClassConflict, "several assets have this address"
	case len(atAddr) == 1:
		a := atAddr[0]
		r.MatchAsset, r.Class = a.ID, ClassPossible
		r.Reason = "asset " + a.ID + " has this address"
		if r.Hostname != "" && r.Hostname == a.Hostname {
			r.Reason += " and hostname"
		}
		if r.MAC == "" {
			r.Reason += "; no MAC (routed or VPN network)"
		}
		r.Importable = r.MAC != "" && a.MAC == "" || r.Hostname != "" && a.Hostname == ""
	case len(unlinkedHosts) > 1:
		r.Class, r.Reason = ClassConflict, "several managed hosts have this address"
	case len(unlinkedHosts) == 1:
		r.MatchHost, r.Class = unlinkedHosts[0], ClassPossible
		r.Reason = "managed host " + unlinkedHosts[0] + " has this address; import creates an asset linked to it"
		r.Importable = true
	default:
		r.Class, r.Reason, r.Importable = ClassNew, "", true
	}
	if r.ImportedAsset != "" {
		r.Importable = false
	}
}

var idChars = regexp.MustCompile(`[^a-z0-9._-]+`)

// assetID derives a free asset ID from the hostname or the address.
func (m *matcher) assetID(r Row) string {
	base := ""
	if r.Hostname != "" {
		base, _, _ = strings.Cut(r.Hostname, ".")
		base = strings.Trim(idChars.ReplaceAllString(base, "-"), "-._")
	}
	if base == "" {
		base = "ip-" + strings.NewReplacer(".", "-", ":", "-").Replace(r.Address)
	}
	if len(base) > 56 {
		base = strings.TrimRight(base[:56], "-._")
	}
	id := base
	for i := 2; m.ids[id]; i++ {
		id = fmt.Sprintf("%s-%d", base, i)
	}
	m.ids[id] = true
	return id
}

// ImportReport says what an import did per address.
type ImportReport struct {
	Created, Updated []string
	Skipped          map[string]string
}

// Import takes the selected staged hosts of a job into the assets: a NEW
// host becomes an asset (kind unknown), an EXISTING or POSSIBLE MATCH host
// adds what the asset lacks (address, MAC, hostname), a host only matching
// a managed host becomes an asset linked to it. CONFLICT rows are never
// imported. Empty addresses with all=true import every importable row.
func (s *Store) Import(ctx context.Context, user, id string, addresses []string, all bool) (ImportReport, error) {
	rep := ImportReport{Skipped: map[string]string{}}
	if !userRe.MatchString(user) {
		return rep, errors.New("discovery: invalid user")
	}
	j, rows, err := s.Job(ctx, id)
	if err != nil {
		return rep, err
	}
	if j.State != StateDone {
		return rep, invalid("only a finished scan can be imported")
	}
	want := map[string]bool{}
	for _, a := range addresses {
		want[a] = true
	}
	m, err := s.matcher(ctx)
	if err != nil {
		return rep, err
	}
	for _, r := range rows {
		if !all && !want[r.Address] {
			continue
		}
		delete(want, r.Address)
		if !r.Importable {
			if all {
				continue
			}
			reason := "nothing to import"
			switch {
			case r.ImportedAsset != "":
				reason = "already imported"
			case r.Class == ClassConflict:
				reason = "conflict: " + r.Reason
			}
			rep.Skipped[r.Address] = reason
			continue
		}
		ad, err := netip.ParseAddr(r.Address)
		if err != nil {
			rep.Skipped[r.Address] = "invalid address"
			continue
		}
		var asset ipam.Asset
		created := false
		switch {
		case r.MatchAsset != "":
			if asset, err = s.ipam.Asset(ctx, r.MatchAsset); err != nil {
				return rep, err
			}
			if !containsAddr(asset.Addresses, ad) {
				if len(asset.Addresses) >= ipam.MaxAddresses {
					rep.Skipped[r.Address] = "the asset has the most addresses allowed"
					continue
				}
				asset.Addresses = append(asset.Addresses, ad)
			}
			if asset.MAC == "" {
				asset.MAC = r.MAC
			}
			if asset.Hostname == "" {
				asset.Hostname = r.Hostname
			}
		default:
			name := r.Hostname
			if name == "" {
				name = r.Address
			}
			asset = ipam.Asset{ID: m.assetID(r), Name: name, Kind: ipam.KindUnknown, Hostname: r.Hostname, MAC: r.MAC,
				HostID: r.MatchHost, Addresses: []netip.Addr{ad}, Notes: noteFor(r)}
			created = true
		}
		if err := s.ipam.SaveAsset(ctx, asset); err != nil {
			var ve *ipam.ValidationError
			if errors.As(err, &ve) {
				rep.Skipped[r.Address] = ve.Reason
				continue
			}
			return rep, err
		}
		if _, err := s.db.ExecContext(ctx, `UPDATE discovery_staging SET imported_at = ?, imported_by = ?, imported_asset = ? WHERE job_id = ? AND address = ?`,
			s.now().Unix(), user, asset.ID, id, r.Address); err != nil {
			return rep, err
		}
		if created {
			rep.Created = append(rep.Created, asset.ID)
		} else {
			rep.Updated = append(rep.Updated, asset.ID)
		}
		// Later rows see this import.
		if m, err = s.matcher(ctx); err != nil {
			return rep, err
		}
	}
	for a := range want {
		rep.Skipped[a] = "not in this scan"
	}
	return rep, nil
}

func containsAddr(list []netip.Addr, a netip.Addr) bool {
	for _, x := range list {
		if x == a {
			return true
		}
	}
	return false
}

func noteFor(r Row) string {
	var parts []string
	if r.Vendor != "" {
		parts = append(parts, "vendor "+r.Vendor)
	}
	if r.OS != "" {
		parts = append(parts, "OS "+r.OS)
	}
	var open []string
	for _, p := range r.Ports {
		if p.State == "open" && len(open) < 20 {
			open = append(open, fmt.Sprintf("%d/%s", p.Port, p.Protocol))
		}
	}
	if len(open) > 0 {
		parts = append(parts, "open "+strings.Join(open, " "))
	}
	if len(parts) == 0 {
		return "found by discovery"
	}
	return "found by discovery: " + strings.Join(parts, "; ")
}

// --- schedules ---

// CreateSchedule adds a scan that runs once at first (interval 0) or every
// interval (at least an hour) from first on. There is no default schedule.
func (s *Store) CreateSchedule(ctx context.Context, user, name string, req Request, interval time.Duration, first time.Time) (Schedule, error) {
	if !userRe.MatchString(user) {
		return Schedule{}, errors.New("discovery: invalid user")
	}
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 64 || discoveryjob.Text(name) != name {
		return Schedule{}, invalid("the name must be 1 to 64 characters of plain text")
	}
	if interval != 0 && interval < MinInterval {
		return Schedule{}, invalid("the interval must be at least an hour")
	}
	if interval%time.Second != 0 || interval > 366*24*time.Hour {
		return Schedule{}, invalid("the interval is not valid")
	}
	now := s.now()
	if first.IsZero() || first.Before(now) {
		first = now
	}
	if first.After(now.Add(366 * 24 * time.Hour)) {
		return Schedule{}, invalid("the first run is too far ahead")
	}
	j, err := s.job(ctx, req)
	if err != nil {
		return Schedule{}, err
	}
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM discovery_schedules`).Scan(&n); err != nil {
		return Schedule{}, err
	}
	if n >= maxSchedules {
		return Schedule{}, invalid("at most %d schedules", maxSchedules)
	}
	spec, err := json.Marshal(req)
	if err != nil {
		return Schedule{}, err
	}
	sc := Schedule{ID: newID(), Name: name, Description: j.Describe(), Targets: strings.Join(j.Targets, ", "), CreatedBy: user,
		Interval: interval, NextAt: first.Truncate(time.Second), Enabled: true}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO discovery_schedules (id, name, spec, description, targets, interval_s, next_at, created_by, created_at, enabled)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)`, sc.ID, sc.Name, string(spec), sc.Description, sc.Targets, int64(interval/time.Second),
		sc.NextAt.Unix(), user, now.Unix()); err != nil {
		return Schedule{}, err
	}
	return sc, nil
}

// DeleteSchedule removes a schedule.
func (s *Store) DeleteSchedule(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM discovery_schedules WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Schedules lists the schedules by next run.
func (s *Store) Schedules(ctx context.Context) ([]Schedule, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, description, targets, interval_s, next_at, created_by, enabled FROM discovery_schedules ORDER BY next_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Schedule
	for rows.Next() {
		var sc Schedule
		var iv, next int64
		var en int
		if err := rows.Scan(&sc.ID, &sc.Name, &sc.Description, &sc.Targets, &iv, &next, &sc.CreatedBy, &en); err != nil {
			return nil, err
		}
		sc.Interval, sc.NextAt, sc.Enabled = time.Duration(iv)*time.Second, time.Unix(next, 0), en == 1
		out = append(out, sc)
	}
	return out, rows.Err()
}

// RunDue queues the scans of due schedules.
func (s *Store) RunDue(ctx context.Context) error {
	now := s.now()
	rows, err := s.db.QueryContext(ctx, `SELECT id, spec, interval_s, next_at, created_by FROM discovery_schedules WHERE enabled = 1 AND next_at <= ?`, now.Unix())
	if err != nil {
		return err
	}
	type due struct {
		id, spec, by string
		iv, next     int64
	}
	var list []due
	for rows.Next() {
		var d due
		if err := rows.Scan(&d.id, &d.spec, &d.iv, &d.next, &d.by); err != nil {
			rows.Close()
			return err
		}
		list = append(list, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, d := range list {
		// Advance first: a failing scan must not be retried every tick.
		next, enabled := d.next+d.iv, 1
		if d.iv == 0 {
			enabled = 0
		} else if next <= now.Unix() {
			next = now.Unix() + d.iv
		}
		if _, err := s.db.ExecContext(ctx, `UPDATE discovery_schedules SET next_at = ?, enabled = ? WHERE id = ?`, next, enabled, d.id); err != nil {
			return err
		}
		var req Request
		if err := json.Unmarshal([]byte(d.spec), &req); err != nil {
			s.log.Error("discovery: schedule spec", "schedule", d.id, "error", err)
			continue
		}
		if _, err := s.submit(ctx, d.by, req, d.id); err != nil {
			s.log.Warn("discovery: scheduled scan not queued", "schedule", d.id, "error", err)
		}
	}
	return nil
}

// Run polls results and runs due schedules until ctx ends.
func (s *Store) Run(ctx context.Context) {
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		if err := s.RunDue(ctx); err != nil && ctx.Err() == nil {
			s.log.Error("discovery: schedules", "error", err)
		}
		if err := s.Poll(ctx); err != nil && ctx.Err() == nil {
			s.log.Error("discovery: poll", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
