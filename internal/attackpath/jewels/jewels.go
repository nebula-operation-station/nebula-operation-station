// SPDX-License-Identifier: AGPL-3.0-or-later

// Package jewels keeps the crown jewels of the attack-path search (ADR 0011
// D10, Q7 decided 2026-11-09; plan VU-23) and describes its entry classes.
//
// A crown jewel is an attack-path node (an internal/attackpath node ID of a
// host, PVE node, guest, container or network device) that the admin marks
// with a role and an impact weight 1–10. Marking, changing and unmarking
// are admin actions: each one is written to the crown_jewel_history table
// in the same transaction and, after commit, to the audit log (a log line
// with the message "audit", internal/auditlog).
//
// Roles carry suggested default weights (executor host and firewall 10;
// Proxmox nodes, NAS and Home Assistant host 8). A suggestion is only shown
// to the admin: Mark always needs the weight the admin entered and never
// derives one from a role, a label or a host name. Which subject fills a
// role is the admin's choice; nothing here guesses it.
package jewels

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/attackpath"
)

// Limits, next to the code that enforces them.
const (
	// MaxJewels is the most crown jewels kept; it equals the targets one
	// attack-path computation searches.
	MaxJewels = attackpath.MaxTargets
	// MaxReasonBytes bounds the admin's reason text.
	MaxReasonBytes = 512
	// MaxAdminBytes bounds the admin name.
	MaxAdminBytes = 128
	// MaxHistory bounds the history rows History returns.
	MaxHistory = 200
)

// Sentinel errors, returned wrapped.
var (
	// ErrInvalidNode reports a node ID that is not a markable attack-path
	// node: an entry, an unmanaged endpoint, a bad prefix or bad text.
	ErrInvalidNode = errors.New("invalid crown jewel node")
	// ErrInvalidRole reports an unknown role.
	ErrInvalidRole = errors.New("invalid crown jewel role")
	// ErrInvalidImpact reports a missing or out-of-range impact weight.
	ErrInvalidImpact = errors.New("invalid impact weight")
	// ErrInvalidText reports a bad admin name or reason.
	ErrInvalidText = errors.New("invalid text")
	// ErrLimit reports that MaxJewels crown jewels are already marked.
	ErrLimit = errors.New("crown jewel limit reached")
	// ErrNotFound reports an unmark of a node that is not a crown jewel.
	ErrNotFound = errors.New("crown jewel not found")
)

// Role says what a crown jewel is. Roles name kinds of subjects only, never
// addresses or host names.
type Role string

// Roles (ADR 0011 D10 table) plus RoleOther for anything else.
const (
	RoleExecutorHost  Role = "executor_host"
	RoleFirewall      Role = "firewall"
	RolePVENode       Role = "pve_node"
	RoleNAS           Role = "nas"
	RoleHomeAssistant Role = "home_assistant"
	RoleOther         Role = "other"
)

// roleInfo is the label and suggested default weight (0: none) of a role.
var roleInfo = map[Role]struct {
	label     string
	suggested int
}{
	RoleExecutorHost:  {"NOS executor host", 10},
	RoleFirewall:      {"Firewall", 10},
	RolePVENode:       {"Proxmox node", 8},
	RoleNAS:           {"NAS", 8},
	RoleHomeAssistant: {"Home Assistant host", 8},
	RoleOther:         {"Other", 0},
}

// Roles returns every role in display order.
func Roles() []Role {
	return []Role{RoleExecutorHost, RoleFirewall, RolePVENode, RoleNAS, RoleHomeAssistant, RoleOther}
}

// Valid reports whether r is a known role.
func (r Role) Valid() bool {
	_, ok := roleInfo[r]
	return ok
}

// Label returns the display label of r, or "" for an unknown role.
func (r Role) Label() string { return roleInfo[r].label }

// SuggestedImpact returns the default weight decided for r on 2026-11-09,
// and false when r has none. It is a suggestion for the admin to confirm
// or change; Mark never applies it.
func (r Role) SuggestedImpact() (int, bool) {
	s := roleInfo[r].suggested
	return s, s != 0
}

// markableKinds are the node kinds that can be crown jewels.
var markableKinds = []attackpath.NodeKind{
	attackpath.NodeHost, attackpath.NodePVENode, attackpath.NodeGuest,
	attackpath.NodeContainer, attackpath.NodeNetworkDevice,
}

// NodeKind returns the kind of a markable node ID, or ErrInvalidNode for an
// entry, an unmanaged endpoint or an ID that is not valid UTF-8, has
// control or space characters, is longer than attackpath.MaxIDBytes or has
// no markable prefix followed by at least one character.
func NodeKind(id string) (attackpath.NodeKind, error) {
	if id == "" || len(id) > attackpath.MaxIDBytes || !utf8.ValidString(id) {
		return 0, fmt.Errorf("node id: %w", ErrInvalidNode)
	}
	for _, r := range id {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return 0, fmt.Errorf("node id: %w", ErrInvalidNode)
		}
	}
	for _, k := range markableKinds {
		p := k.IDPrefix()
		if strings.HasPrefix(id, p) && len(id) > len(p) {
			return k, nil
		}
	}
	return 0, fmt.Errorf("node id kind: %w", ErrInvalidNode)
}

// checkText validates a bounded admin text; empty is allowed when optional.
func checkText(s string, maxBytes int, optional bool) error {
	if s == "" && optional {
		return nil
	}
	if s == "" || len(s) > maxBytes || !utf8.ValidString(s) {
		return ErrInvalidText
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return ErrInvalidText
		}
	}
	return nil
}

// Jewel is one marked crown jewel.
type Jewel struct {
	Node      string
	Role      Role
	Impact    int
	MarkedBy  string
	Reason    string
	MarkedAt  time.Time
	UpdatedAt time.Time
}

// Mark is an admin's request to mark a node or change its mark.
type Mark struct {
	// Node is the attack-path node ID.
	Node string
	// Role is the role the admin chose.
	Role Role
	// Impact is the weight the admin entered, 1–10. Zero is rejected: a
	// role's suggested weight is never filled in here.
	Impact int
	// Admin is the admin's user name.
	Admin string
	// Reason is optional free text.
	Reason string
}

// Action names a history entry.
type Action string

// Actions.
const (
	ActionMarked   Action = "marked"
	ActionChanged  Action = "changed"
	ActionUnmarked Action = "unmarked"
)

// Change is one admin action as recorded in history and the audit log.
type Change struct {
	ID        int64
	Node      string
	Action    Action
	OldRole   Role // "" for ActionMarked
	OldImpact int  // 0 for ActionMarked
	NewRole   Role // "" for ActionUnmarked
	NewImpact int  // 0 for ActionUnmarked
	// Suggested is the role's suggested weight shown to the admin, 0 when
	// the role has none or for ActionUnmarked.
	Suggested int
	Admin     string
	Reason    string
	At        time.Time
}

// Store reads and writes crown jewels in server.db (migration 0037).
type Store struct {
	db  *sql.DB
	log *slog.Logger
	now func() time.Time
}

// New returns a store on db. log receives the audit lines and must not be
// nil: every mark is audited. now may be nil (time.Now).
func New(db *sql.DB, log *slog.Logger, now func() time.Time) (*Store, error) {
	if db == nil || log == nil {
		return nil, errors.New("jewels: database and audit logger are required")
	}
	if now == nil {
		now = time.Now
	}
	return &Store{db: db, log: log, now: now}, nil
}

// List returns every crown jewel, highest impact first, then by node ID.
func (s *Store) List(ctx context.Context) ([]Jewel, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT node_id, role, impact, marked_by, reason, marked_at, updated_at
		FROM crown_jewels ORDER BY impact DESC, node_id LIMIT ?`, MaxJewels+1)
	if err != nil {
		return nil, fmt.Errorf("list crown jewels: %w", err)
	}
	defer rows.Close()
	var out []Jewel
	for rows.Next() {
		var j Jewel
		var role string
		var marked, updated int64
		if err := rows.Scan(&j.Node, &role, &j.Impact, &j.MarkedBy, &j.Reason, &marked, &updated); err != nil {
			return nil, fmt.Errorf("list crown jewels: %w", err)
		}
		j.Role = Role(role)
		j.MarkedAt, j.UpdatedAt = time.Unix(marked, 0).UTC(), time.Unix(updated, 0).UTC()
		out = append(out, j)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list crown jewels: %w", err)
	}
	if len(out) > MaxJewels {
		return nil, fmt.Errorf("list crown jewels: %d rows: %w", len(out), ErrLimit)
	}
	return out, nil
}

// Targets returns the crown jewels as attack-path targets.
func (s *Store) Targets(ctx context.Context) ([]attackpath.Target, error) {
	js, err := s.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]attackpath.Target, 0, len(js))
	for _, j := range js {
		out = append(out, attackpath.Target{Node: j.Node, Impact: j.Impact})
	}
	return out, nil
}

// Mark marks m.Node as a crown jewel or changes its role, weight or reason.
// It records the change in history and the audit log. Marking an existing
// jewel with the same role, weight and reason changes nothing and returns
// a zero Change with no error.
func (s *Store) Mark(ctx context.Context, m Mark) (Change, error) {
	if _, err := NodeKind(m.Node); err != nil {
		return Change{}, fmt.Errorf("mark crown jewel: %w", err)
	}
	if !m.Role.Valid() {
		return Change{}, fmt.Errorf("mark crown jewel %s: %w", m.Node, ErrInvalidRole)
	}
	if m.Impact < attackpath.MinImpact || m.Impact > attackpath.MaxImpact {
		return Change{}, fmt.Errorf("mark crown jewel %s: %w", m.Node, ErrInvalidImpact)
	}
	if err := checkText(m.Admin, MaxAdminBytes, false); err != nil {
		return Change{}, fmt.Errorf("mark crown jewel %s: admin: %w", m.Node, err)
	}
	if err := checkText(m.Reason, MaxReasonBytes, true); err != nil {
		return Change{}, fmt.Errorf("mark crown jewel %s: reason: %w", m.Node, err)
	}
	now := s.now().UTC().Truncate(time.Second)
	suggested, _ := m.Role.SuggestedImpact()
	c := Change{Node: m.Node, NewRole: m.Role, NewImpact: m.Impact, Suggested: suggested, Admin: m.Admin, Reason: m.Reason, At: now}

	err := s.tx(ctx, func(tx *sql.Tx) error {
		var oldRole, oldReason string
		var oldImpact int
		err := tx.QueryRowContext(ctx, `SELECT role, impact, reason FROM crown_jewels WHERE node_id = ?`, m.Node).
			Scan(&oldRole, &oldImpact, &oldReason)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			var n int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM crown_jewels`).Scan(&n); err != nil {
				return err
			}
			if n >= MaxJewels {
				return ErrLimit
			}
			c.Action = ActionMarked
			if _, err := tx.ExecContext(ctx, `INSERT INTO crown_jewels (node_id, role, impact, marked_by, reason, marked_at, updated_at)
				VALUES (?, ?, ?, ?, ?, ?, ?)`, m.Node, string(m.Role), m.Impact, m.Admin, m.Reason, now.Unix(), now.Unix()); err != nil {
				return err
			}
		case err != nil:
			return err
		default:
			if Role(oldRole) == m.Role && oldImpact == m.Impact && oldReason == m.Reason {
				c = Change{}
				return nil
			}
			c.Action, c.OldRole, c.OldImpact = ActionChanged, Role(oldRole), oldImpact
			if _, err := tx.ExecContext(ctx, `UPDATE crown_jewels SET role = ?, impact = ?, marked_by = ?, reason = ?, updated_at = ?
				WHERE node_id = ?`, string(m.Role), m.Impact, m.Admin, m.Reason, now.Unix(), m.Node); err != nil {
				return err
			}
		}
		return s.record(ctx, tx, &c)
	})
	if err != nil {
		return Change{}, fmt.Errorf("mark crown jewel %s: %w", m.Node, err)
	}
	if c.Action != "" {
		s.audit(ctx, c)
	}
	return c, nil
}

// Unmark removes node from the crown jewels and records it.
func (s *Store) Unmark(ctx context.Context, node, admin, reason string) (Change, error) {
	if _, err := NodeKind(node); err != nil {
		return Change{}, fmt.Errorf("unmark crown jewel: %w", err)
	}
	if err := checkText(admin, MaxAdminBytes, false); err != nil {
		return Change{}, fmt.Errorf("unmark crown jewel %s: admin: %w", node, err)
	}
	if err := checkText(reason, MaxReasonBytes, true); err != nil {
		return Change{}, fmt.Errorf("unmark crown jewel %s: reason: %w", node, err)
	}
	now := s.now().UTC().Truncate(time.Second)
	c := Change{Node: node, Action: ActionUnmarked, Admin: admin, Reason: reason, At: now}
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var oldRole string
		err := tx.QueryRowContext(ctx, `SELECT role, impact FROM crown_jewels WHERE node_id = ?`, node).Scan(&oldRole, &c.OldImpact)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		c.OldRole = Role(oldRole)
		if _, err := tx.ExecContext(ctx, `DELETE FROM crown_jewels WHERE node_id = ?`, node); err != nil {
			return err
		}
		return s.record(ctx, tx, &c)
	})
	if err != nil {
		return Change{}, fmt.Errorf("unmark crown jewel %s: %w", node, err)
	}
	s.audit(ctx, c)
	return c, nil
}

// History returns up to limit (at most MaxHistory) changes, newest first.
func (s *Store) History(ctx context.Context, limit int) ([]Change, error) {
	if limit <= 0 || limit > MaxHistory {
		limit = MaxHistory
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, node_id, action, COALESCE(old_role, ''), COALESCE(old_impact, 0),
		COALESCE(new_role, ''), COALESCE(new_impact, 0), COALESCE(suggested_impact, 0), admin, reason, at
		FROM crown_jewel_history ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("crown jewel history: %w", err)
	}
	defer rows.Close()
	var out []Change
	for rows.Next() {
		var c Change
		var action, oldRole, newRole string
		var at int64
		if err := rows.Scan(&c.ID, &c.Node, &action, &oldRole, &c.OldImpact, &newRole, &c.NewImpact, &c.Suggested, &c.Admin, &c.Reason, &at); err != nil {
			return nil, fmt.Errorf("crown jewel history: %w", err)
		}
		c.Action, c.OldRole, c.NewRole, c.At = Action(action), Role(oldRole), Role(newRole), time.Unix(at, 0).UTC()
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("crown jewel history: %w", err)
	}
	return out, nil
}

// tx runs f in a write transaction.
func (s *Store) tx(ctx context.Context, f func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := f(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// nullable maps a zero value to SQL NULL.
func nullable[T comparable](v T) any {
	var zero T
	if v == zero {
		return nil
	}
	return v
}

// record writes c to crown_jewel_history and sets c.ID.
func (s *Store) record(ctx context.Context, tx *sql.Tx, c *Change) error {
	res, err := tx.ExecContext(ctx, `INSERT INTO crown_jewel_history
		(node_id, action, old_role, old_impact, new_role, new_impact, suggested_impact, admin, reason, at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.Node, string(c.Action), nullable(string(c.OldRole)), nullable(c.OldImpact),
		nullable(string(c.NewRole)), nullable(c.NewImpact), nullable(c.Suggested), c.Admin, c.Reason, c.At.Unix())
	if err != nil {
		return err
	}
	c.ID, err = res.LastInsertId()
	return err
}

// audit writes the audit line of c. The reason is free admin text and is
// kept in history only, not in the log line.
func (s *Store) audit(ctx context.Context, c Change) {
	attrs := []any{"kind", "crown_jewel_" + string(c.Action), "node", c.Node, "user", c.Admin, "history_id", c.ID}
	if c.OldRole != "" {
		attrs = append(attrs, "old_role", string(c.OldRole), "old_impact", c.OldImpact)
	}
	if c.NewRole != "" {
		attrs = append(attrs, "role", string(c.NewRole), "impact", c.NewImpact)
		if c.Suggested != 0 {
			attrs = append(attrs, "suggested_impact", c.Suggested, "suggestion_confirmed", c.Suggested == c.NewImpact)
		}
	}
	s.log.InfoContext(ctx, "audit", attrs...)
}

// sortedUnique sorts ids and drops duplicates.
func sortedUnique(ids []string) []string {
	out := slices.Clone(ids)
	slices.Sort(out)
	return slices.Compact(out)
}
