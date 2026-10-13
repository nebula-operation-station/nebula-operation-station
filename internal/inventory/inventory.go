// SPDX-License-Identifier: AGPL-3.0-or-later

// Package inventory implements the host inventory model (spec 12):
// hosts with an ID, a display name, an environment (DEV/QA/PROD), a
// criticality (LOW to CRITICAL, the impact of a disruption), an ordered
// list of endpoints, groups, key=value tags and a credential reference.
//
// Endpoint order is stored explicitly (the priority column of
// host_endpoints) and is never reordered by the inventory: trying
// endpoints in a different order happens at execution time only, and
// only per the failure rules of spec 08.
//
// No credential material lives in the inventory: hosts reference a
// credential by name only (credential_ref).
package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// Environment is the deployment environment of a host (spec 12).
type Environment string

// The three environments of spec 12.
const (
	EnvDev  Environment = "DEV"
	EnvQA   Environment = "QA"
	EnvProd Environment = "PROD"
)

// Criticality is the impact of a disruption of the host (spec 12),
// ordered from lowest to highest.
type Criticality string

// The four criticality classes of spec 12.
const (
	CriticalityLow      Criticality = "LOW"
	CriticalityMedium   Criticality = "MEDIUM"
	CriticalityHigh     Criticality = "HIGH"
	CriticalityCritical Criticality = "CRITICAL"
)

// Endpoint is one reachable address of a host. Port 0 means the default
// SSH port 22; Create and Update store the default explicitly.
type Endpoint struct {
	Address string
	Port    int
}

// Host is a managed host in the inventory.
type Host struct {
	ID            string
	DisplayName   string
	Environment   Environment
	Criticality   Criticality
	Endpoints     []Endpoint
	Groups        []string
	Tags          map[string]string
	CredentialRef string
}

// CreateOptions carries creation hints that are not part of the stored
// host.
type CreateOptions struct {
	// OSHint is a coarse OS hint, for example "proxmox". A Proxmox VE
	// host is created with criticality HIGH when its criticality is
	// left unset (spec 12).
	OSHint string
}

// Limits enforced by Validate.
const (
	maxDisplayNameLen = 128
	maxAddressLen     = 253
	maxTagValueLen    = 256
	maxEndpoints      = 16
	maxGroups         = 32
	maxTags           = 64
	defaultSSHPort    = 22
)

// Patterns. hostIDRe and credRefRe are the same patterns internal/canonical
// applies to host_id and credential_refs in the canonical request, so a
// stored host always produces a valid canonical target.
var (
	hostIDRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	credRefRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	groupRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	tagKeyRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	hostnameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)
)

// Sentinel errors callers branch on.
var (
	// ErrHostExists is returned by Create when the host ID is already
	// taken.
	ErrHostExists = errors.New("inventory: host already exists")
	// ErrHostNotFound is returned by Get, Update and Delete for an
	// unknown host ID.
	ErrHostNotFound = errors.New("inventory: host not found")
)

// ValidationError lists every problem found in a host.
type ValidationError struct{ Problems []string }

// Error implements the error interface.
func (e *ValidationError) Error() string {
	return "invalid host: " + strings.Join(e.Problems, "; ")
}

// Validate checks h and returns a ValidationError listing every problem
// found, or nil if the host is valid. It never mutates h.
func Validate(h Host) error {
	var p []string
	add := func(format string, args ...any) { p = append(p, fmt.Sprintf(format, args...)) }

	if !hostIDRe.MatchString(h.ID) {
		add("id %q must match %s", h.ID, hostIDRe.String())
	}
	if !utf8.ValidString(h.DisplayName) {
		add("display_name is not valid UTF-8")
	} else if len(h.DisplayName) > maxDisplayNameLen {
		add("display_name is longer than %d bytes", maxDisplayNameLen)
	}

	switch {
	case h.Environment == "":
		add("environment must be DEV, QA or PROD")
	case !validEnvironment(h.Environment):
		add("environment %q must be DEV, QA or PROD", h.Environment)
	}
	switch {
	case h.Criticality == "":
		add("criticality must be LOW, MEDIUM, HIGH or CRITICAL")
	case !validCriticality(h.Criticality):
		add("criticality %q must be LOW, MEDIUM, HIGH or CRITICAL", h.Criticality)
	}

	switch {
	case len(h.Endpoints) == 0:
		add("at least one endpoint is required")
	case len(h.Endpoints) > maxEndpoints:
		add("too many endpoints (%d > %d)", len(h.Endpoints), maxEndpoints)
	}
	seenAddr := map[string]int{}
	for i, e := range h.Endpoints {
		if !utf8.ValidString(e.Address) {
			add("endpoint %d: address is not valid UTF-8", i)
		} else if strings.TrimSpace(e.Address) == "" {
			add("endpoint %d: address is empty", i)
		} else if len(e.Address) > maxAddressLen {
			add("endpoint %d: address is longer than %d bytes", i, maxAddressLen)
		} else {
			a := strings.ToLower(e.Address)
			if net.ParseIP(a) == nil && !hostnameRe.MatchString(a) {
				add("endpoint %d: %q is neither an IP address nor a hostname", i, e.Address)
			}
		}
		switch {
		case e.Port == 0:
		case e.Port < 1 || e.Port > 65535:
			add("endpoint %d: port %d out of range", i, e.Port)
		}
		if first, dup := seenAddr[e.Address]; dup {
			add("endpoint %d: %q is duplicated (first at %d)", i, e.Address, first)
		} else {
			seenAddr[e.Address] = i
		}
	}

	if len(h.Groups) > maxGroups {
		add("too many groups (%d > %d)", len(h.Groups), maxGroups)
	}
	seenGroup := map[string]struct{}{}
	for _, g := range h.Groups {
		if !groupRe.MatchString(g) {
			add("group %q is malformed", g)
		}
		if _, dup := seenGroup[g]; dup {
			add("group %q is duplicated", g)
		}
		seenGroup[g] = struct{}{}
	}

	if len(h.Tags) > maxTags {
		add("too many tags (%d > %d)", len(h.Tags), maxTags)
	}
	keys := make([]string, 0, len(h.Tags))
	for k := range h.Tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := h.Tags[k]
		if !utf8.ValidString(k) || !tagKeyRe.MatchString(k) {
			add("tag key %q is malformed", k)
		}
		if !utf8.ValidString(v) {
			add("tag value for %q is not valid UTF-8", k)
		} else if v == "" {
			add("tag value for %q is empty", k)
		} else if len(v) > maxTagValueLen {
			add("tag value for %q is longer than %d bytes", k, maxTagValueLen)
		}
	}

	if h.CredentialRef != "" && !credRefRe.MatchString(h.CredentialRef) {
		add("credential_ref %q is malformed", h.CredentialRef)
	}

	if len(p) > 0 {
		return &ValidationError{Problems: p}
	}
	return nil
}

func validEnvironment(e Environment) bool {
	switch e {
	case EnvDev, EnvQA, EnvProd:
		return true
	}
	return false
}

func validCriticality(c Criticality) bool {
	switch c {
	case CriticalityLow, CriticalityMedium, CriticalityHigh, CriticalityCritical:
		return true
	}
	return false
}

// normalize returns a copy of h with the default SSH port applied to
// endpoints that omit it, and with owned slices and maps. It never
// mutates h.
func normalize(h Host) Host {
	n := h
	n.Endpoints = make([]Endpoint, len(h.Endpoints))
	for i, e := range h.Endpoints {
		if e.Port == 0 {
			e.Port = defaultSSHPort
		}
		n.Endpoints[i] = e
	}
	n.Groups = append([]string(nil), h.Groups...)
	n.Tags = make(map[string]string, len(h.Tags))
	for k, v := range h.Tags {
		n.Tags[k] = v
	}
	return n
}

// Store persists hosts in the server database.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

// New returns a Store for db using time.Now for created_at and
// updated_at.
func New(db *sql.DB) *Store {
	return NewWithNow(db, time.Now)
}

// NewWithNow returns a Store for db that uses now for created_at and
// updated_at. A nil now means time.Now.
func NewWithNow(db *sql.DB, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{db: db, now: now}
}

// Create inserts h and returns the stored host. An empty environment is
// defaulted to DEV and an empty criticality to LOW, or to HIGH when
// opts.OSHint is "proxmox" (Proxmox VE hosts default to HIGH, spec 12).
// A host ID that is already taken is rejected with ErrHostExists.
func (s *Store) Create(ctx context.Context, h Host, opts CreateOptions) (Host, error) {
	h = normalize(h)
	if h.Environment == "" {
		h.Environment = EnvDev
	}
	if h.Criticality == "" {
		h.Criticality = CriticalityLow
		if strings.EqualFold(opts.OSHint, "proxmox") {
			h.Criticality = CriticalityHigh
		}
	}
	if err := Validate(h); err != nil {
		return Host{}, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Host{}, fmt.Errorf("inventory: create host %s: begin: %w", h.ID, err)
	}
	defer tx.Rollback()

	ts := s.now().UTC().Format(time.RFC3339)
	res, err := tx.ExecContext(ctx, `
		INSERT INTO hosts (name, description, credential_ref, display_name, environment, criticality, created_at, updated_at)
		VALUES (?, '', ?, ?, ?, ?, ?, ?)`,
		h.ID, h.CredentialRef, h.DisplayName, string(h.Environment), string(h.Criticality), ts, ts)
	if err != nil {
		if isUniqueViolation(err) {
			return Host{}, fmt.Errorf("inventory: create host %s: %w", h.ID, ErrHostExists)
		}
		return Host{}, fmt.Errorf("inventory: create host %s: %w", h.ID, err)
	}
	hid, err := res.LastInsertId()
	if err != nil {
		return Host{}, fmt.Errorf("inventory: create host %s: last insert id: %w", h.ID, err)
	}
	if err := storeRelations(ctx, tx, hid, h, ts); err != nil {
		return Host{}, fmt.Errorf("inventory: create host %s: %w", h.ID, err)
	}
	if err := tx.Commit(); err != nil {
		return Host{}, fmt.Errorf("inventory: create host %s: commit: %w", h.ID, err)
	}
	return h, nil
}

// Get returns the host with the given ID, with endpoints in their
// stored order, groups sorted by name and tags as a key=value map.
func (s *Store) Get(ctx context.Context, id string) (Host, error) {
	var (
		h    Host
		env  string
		crit string
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT name, credential_ref, display_name, environment, criticality
		FROM hosts WHERE name = ?`, id).
		Scan(&h.ID, &h.CredentialRef, &h.DisplayName, &env, &crit)
	if errors.Is(err, sql.ErrNoRows) {
		return Host{}, fmt.Errorf("inventory: get host %s: %w", id, ErrHostNotFound)
	}
	if err != nil {
		return Host{}, fmt.Errorf("inventory: get host %s: %w", id, err)
	}
	h.Environment = Environment(env)
	h.Criticality = Criticality(crit)

	var hid int64
	if err := s.db.QueryRowContext(ctx, `SELECT id FROM hosts WHERE name = ?`, id).Scan(&hid); err != nil {
		return Host{}, fmt.Errorf("inventory: get host %s: %w", id, err)
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT address, port FROM host_endpoints WHERE host_id = ? ORDER BY priority, id`, hid)
	if err != nil {
		return Host{}, fmt.Errorf("inventory: get host %s: endpoints: %w", id, err)
	}
	h.Endpoints = []Endpoint{}
	for rows.Next() {
		var e Endpoint
		if err := rows.Scan(&e.Address, &e.Port); err != nil {
			rows.Close()
			return Host{}, fmt.Errorf("inventory: get host %s: endpoints: %w", id, err)
		}
		h.Endpoints = append(h.Endpoints, e)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return Host{}, fmt.Errorf("inventory: get host %s: endpoints: %w", id, err)
	}
	rows.Close()

	rows, err = s.db.QueryContext(ctx, `
		SELECT g.name FROM groups g
		JOIN host_groups hg ON hg.group_id = g.id
		WHERE hg.host_id = ? ORDER BY g.name`, hid)
	if err != nil {
		return Host{}, fmt.Errorf("inventory: get host %s: groups: %w", id, err)
	}
	h.Groups = []string{}
	for rows.Next() {
		var g string
		if err := rows.Scan(&g); err != nil {
			rows.Close()
			return Host{}, fmt.Errorf("inventory: get host %s: groups: %w", id, err)
		}
		h.Groups = append(h.Groups, g)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return Host{}, fmt.Errorf("inventory: get host %s: groups: %w", id, err)
	}
	rows.Close()

	rows, err = s.db.QueryContext(ctx,
		`SELECT tag_key, tag_value FROM host_tag_kv WHERE host_id = ? ORDER BY tag_key`, hid)
	if err != nil {
		return Host{}, fmt.Errorf("inventory: get host %s: tags: %w", id, err)
	}
	h.Tags = map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			rows.Close()
			return Host{}, fmt.Errorf("inventory: get host %s: tags: %w", id, err)
		}
		h.Tags[k] = v
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return Host{}, fmt.Errorf("inventory: get host %s: tags: %w", id, err)
	}
	rows.Close()

	return h, nil
}

// List returns all hosts ordered by ID.
func (s *Store) List(ctx context.Context) ([]Host, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name FROM hosts ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("inventory: list hosts: %w", err)
	}
	out := []Host{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, fmt.Errorf("inventory: list hosts: %w", err)
		}
		h, err := s.Get(ctx, id)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("inventory: list hosts: %w", err)
	}
	rows.Close()
	return out, nil
}

// Update replaces the full state of the host with ID h.ID: display
// name, environment, criticality, endpoints (in the given order),
// groups, tags and credential reference. The host ID itself cannot be
// changed. Unknown hosts are rejected with ErrHostNotFound.
func (s *Store) Update(ctx context.Context, h Host) (Host, error) {
	h = normalize(h)
	if err := Validate(h); err != nil {
		return Host{}, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Host{}, fmt.Errorf("inventory: update host %s: begin: %w", h.ID, err)
	}
	defer tx.Rollback()

	ts := s.now().UTC().Format(time.RFC3339)
	res, err := tx.ExecContext(ctx, `
		UPDATE hosts SET credential_ref = ?, display_name = ?, environment = ?, criticality = ?, updated_at = ?
		WHERE name = ?`,
		h.CredentialRef, h.DisplayName, string(h.Environment), string(h.Criticality), ts, h.ID)
	if err != nil {
		return Host{}, fmt.Errorf("inventory: update host %s: %w", h.ID, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return Host{}, fmt.Errorf("inventory: update host %s: %w", h.ID, err)
	}
	if n == 0 {
		return Host{}, fmt.Errorf("inventory: update host %s: %w", h.ID, ErrHostNotFound)
	}

	var hid int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM hosts WHERE name = ?`, h.ID).Scan(&hid); err != nil {
		return Host{}, fmt.Errorf("inventory: update host %s: %w", h.ID, err)
	}
	for _, q := range []string{
		`DELETE FROM host_endpoints WHERE host_id = ?`,
		`DELETE FROM host_groups WHERE host_id = ?`,
		`DELETE FROM host_tag_kv WHERE host_id = ?`,
	} {
		if _, err := tx.ExecContext(ctx, q, hid); err != nil {
			return Host{}, fmt.Errorf("inventory: update host %s: %w", h.ID, err)
		}
	}
	if err := storeRelations(ctx, tx, hid, h, ts); err != nil {
		return Host{}, fmt.Errorf("inventory: update host %s: %w", h.ID, err)
	}
	if err := tx.Commit(); err != nil {
		return Host{}, fmt.Errorf("inventory: update host %s: commit: %w", h.ID, err)
	}
	return s.Get(ctx, h.ID)
}

// Delete removes the host with the given ID and all of its endpoints,
// group links and tags. Unknown hosts are rejected with
// ErrHostNotFound.
func (s *Store) Delete(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM hosts WHERE name = ?`, id)
	if err != nil {
		return fmt.Errorf("inventory: delete host %s: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("inventory: delete host %s: %w", id, err)
	}
	if n == 0 {
		return fmt.Errorf("inventory: delete host %s: %w", id, ErrHostNotFound)
	}
	return nil
}

// storeRelations writes the endpoints (in order), groups and tags of h
// for the host row hid inside tx.
func storeRelations(ctx context.Context, tx *sql.Tx, hid int64, h Host, ts string) error {
	for i, e := range h.Endpoints {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO host_endpoints (host_id, address, port, priority, created_at) VALUES (?, ?, ?, ?, ?)`,
			hid, e.Address, e.Port, i, ts); err != nil {
			return fmt.Errorf("insert endpoint %d: %w", i, err)
		}
	}
	for _, g := range h.Groups {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO groups (name, created_at, updated_at) VALUES (?, ?, ?) ON CONFLICT(name) DO NOTHING`,
			g, ts, ts); err != nil {
			return fmt.Errorf("insert group %q: %w", g, err)
		}
		var gid int64
		if err := tx.QueryRowContext(ctx, `SELECT id FROM groups WHERE name = ?`, g).Scan(&gid); err != nil {
			return fmt.Errorf("look up group %q: %w", g, err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO host_groups (host_id, group_id) VALUES (?, ?)`, hid, gid); err != nil {
			return fmt.Errorf("link group %q: %w", g, err)
		}
	}
	keys := make([]string, 0, len(h.Tags))
	for k := range h.Tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO host_tag_kv (host_id, tag_key, tag_value) VALUES (?, ?, ?)`,
			hid, k, h.Tags[k]); err != nil {
			return fmt.Errorf("insert tag %q: %w", k, err)
		}
	}
	return nil
}

// isUniqueViolation reports whether err is a SQLite UNIQUE constraint
// violation.
func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}
