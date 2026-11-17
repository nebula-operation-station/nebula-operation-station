// SPDX-License-Identifier: AGPL-3.0-or-later

// Single-endpoint edits (job ep01): the host page adds an alternate
// endpoint, changes the endpoint order or removes one endpoint. The
// endpoint at priority 0 is the primary; the others are alternates in
// priority order. Every edit runs in one transaction and rewrites the
// priorities of the host to 0..n-1, so the order is always explicit and
// unique.
//
// The host key pin is per host, not per endpoint (spec 08,
// internal/sshtransport): every endpoint of a host must present the same
// pinned key, and a different key on any endpoint is a hard stop, never
// a reason to fail over. Endpoint edits therefore never touch the pin.

package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// MaxEditableEndpoints is the most endpoints (primary plus alternates) a
// host may have when endpoints are edited in the web UI.
const MaxEditableEndpoints = 4

// maxHostnameLabel is the longest DNS label (RFC 1035).
const maxHostnameLabel = 63

// Sentinel errors of the endpoint edits.
var (
	// ErrInvalidEndpoint is returned for a malformed address, an
	// out-of-range port or an out-of-range position.
	ErrInvalidEndpoint = errors.New("inventory: invalid endpoint")
	// ErrEndpointExists is returned by AddEndpoint when the host
	// already has the endpoint.
	ErrEndpointExists = errors.New("inventory: endpoint already exists")
	// ErrEndpointNotFound is returned by MoveEndpoint and RemoveEndpoint
	// for an endpoint the host does not have.
	ErrEndpointNotFound = errors.New("inventory: endpoint not found")
	// ErrLastEndpoint is returned by RemoveEndpoint for the only
	// endpoint of a host.
	ErrLastEndpoint = errors.New("inventory: the last endpoint cannot be removed")
	// ErrTooManyEndpoints is returned by AddEndpoint when the host
	// already has MaxEditableEndpoints endpoints.
	ErrTooManyEndpoints = errors.New("inventory: too many endpoints")
)

// EndpointChange is the endpoint list of a host before and after an
// edit, in priority order, for the audit record.
type EndpointChange struct {
	Before []Endpoint
	After  []Endpoint
}

// NormalizeEndpoint checks one endpoint and returns its stored form: an
// IP address in canonical text form (IPv6 compressed, lower case), a
// hostname in lower case, and port 0 replaced by the default SSH port.
// Addresses with a port, brackets, an IPv6 zone or a numeric last label
// that is not an IP address are rejected with ErrInvalidEndpoint.
func NormalizeEndpoint(e Endpoint) (Endpoint, error) {
	if !utf8.ValidString(e.Address) {
		return Endpoint{}, fmt.Errorf("%w: address is not valid UTF-8", ErrInvalidEndpoint)
	}
	if e.Address == "" || strings.TrimSpace(e.Address) != e.Address {
		return Endpoint{}, fmt.Errorf("%w: address is empty or has surrounding spaces", ErrInvalidEndpoint)
	}
	if len(e.Address) > maxAddressLen {
		return Endpoint{}, fmt.Errorf("%w: address is longer than %d bytes", ErrInvalidEndpoint, maxAddressLen)
	}
	port := e.Port
	if port == 0 {
		port = defaultSSHPort
	}
	if port < 1 || port > 65535 {
		return Endpoint{}, fmt.Errorf("%w: port %d out of range 1..65535", ErrInvalidEndpoint, e.Port)
	}
	if ip, err := netip.ParseAddr(e.Address); err == nil {
		if ip.Zone() != "" {
			return Endpoint{}, fmt.Errorf("%w: IPv6 zones are not allowed", ErrInvalidEndpoint)
		}
		return Endpoint{Address: ip.String(), Port: port}, nil
	}
	a := strings.ToLower(e.Address)
	if !hostnameRe.MatchString(a) {
		return Endpoint{}, fmt.Errorf("%w: %q is neither an IP address nor a hostname", ErrInvalidEndpoint, e.Address)
	}
	labels := strings.Split(a, ".")
	for _, l := range labels {
		if len(l) > maxHostnameLabel {
			return Endpoint{}, fmt.Errorf("%w: hostname label longer than %d bytes", ErrInvalidEndpoint, maxHostnameLabel)
		}
	}
	if _, err := strconv.Atoi(labels[len(labels)-1]); err == nil {
		return Endpoint{}, fmt.Errorf("%w: %q is not a valid IP address", ErrInvalidEndpoint, e.Address)
	}
	return Endpoint{Address: a, Port: port}, nil
}

// EndpointKey is the comparison key of an endpoint: "address:port" with
// the address normalized like NormalizeEndpoint (IPv6 in brackets). A
// malformed endpoint is compared by its lower-case text.
func EndpointKey(e Endpoint) string {
	n, err := NormalizeEndpoint(e)
	if err != nil {
		n = Endpoint{Address: strings.ToLower(e.Address), Port: e.Port}
		if n.Port == 0 {
			n.Port = defaultSSHPort
		}
	}
	return net.JoinHostPort(n.Address, strconv.Itoa(n.Port))
}

// AddEndpoint appends e as the last alternate endpoint of the host. The
// endpoint is normalized first; a duplicate (compared by EndpointKey)
// returns ErrEndpointExists and a host that already has
// MaxEditableEndpoints endpoints returns ErrTooManyEndpoints.
func (s *Store) AddEndpoint(ctx context.Context, hostID string, e Endpoint) (EndpointChange, error) {
	n, err := NormalizeEndpoint(e)
	if err != nil {
		return EndpointChange{}, fmt.Errorf("inventory: add endpoint to %s: %w", hostID, err)
	}
	return s.editEndpoints(ctx, "add endpoint to", hostID, func(cur []Endpoint) ([]Endpoint, error) {
		if indexOf(cur, n) >= 0 {
			return nil, fmt.Errorf("%w: %s", ErrEndpointExists, EndpointKey(n))
		}
		if len(cur) >= MaxEditableEndpoints {
			return nil, fmt.Errorf("%w: at most %d endpoints per host", ErrTooManyEndpoints, MaxEditableEndpoints)
		}
		return append(append([]Endpoint(nil), cur...), n), nil
	})
}

// MoveEndpoint moves the endpoint e of the host to position to (0 is the
// primary); the others keep their relative order. An unknown endpoint
// returns ErrEndpointNotFound, a position outside 0..n-1
// ErrInvalidEndpoint.
func (s *Store) MoveEndpoint(ctx context.Context, hostID string, e Endpoint, to int) (EndpointChange, error) {
	return s.editEndpoints(ctx, "move endpoint of", hostID, func(cur []Endpoint) ([]Endpoint, error) {
		i := indexOf(cur, e)
		if i < 0 {
			return nil, fmt.Errorf("%w: %s", ErrEndpointNotFound, EndpointKey(e))
		}
		if to < 0 || to >= len(cur) {
			return nil, fmt.Errorf("%w: position %d outside 0..%d", ErrInvalidEndpoint, to, len(cur)-1)
		}
		rest := make([]Endpoint, 0, len(cur)-1)
		rest = append(rest, cur[:i]...)
		rest = append(rest, cur[i+1:]...)
		out := make([]Endpoint, 0, len(cur))
		out = append(out, rest[:to]...)
		out = append(out, cur[i])
		out = append(out, rest[to:]...)
		return out, nil
	})
}

// RemoveEndpoint removes the endpoint e of the host. The remaining
// endpoints keep their order (removing the primary makes the first
// alternate the primary). The only endpoint of a host cannot be removed
// (ErrLastEndpoint); an unknown endpoint returns ErrEndpointNotFound.
func (s *Store) RemoveEndpoint(ctx context.Context, hostID string, e Endpoint) (EndpointChange, error) {
	return s.editEndpoints(ctx, "remove endpoint of", hostID, func(cur []Endpoint) ([]Endpoint, error) {
		i := indexOf(cur, e)
		if i < 0 {
			return nil, fmt.Errorf("%w: %s", ErrEndpointNotFound, EndpointKey(e))
		}
		if len(cur) == 1 {
			return nil, ErrLastEndpoint
		}
		out := make([]Endpoint, 0, len(cur)-1)
		out = append(out, cur[:i]...)
		return append(out, cur[i+1:]...), nil
	})
}

// indexOf returns the position of e in eps by EndpointKey, or -1.
func indexOf(eps []Endpoint, e Endpoint) int {
	k := EndpointKey(e)
	for i, x := range eps {
		if EndpointKey(x) == k {
			return i
		}
	}
	return -1
}

// editEndpoints loads the endpoints of the host in priority order inside
// one transaction, applies edit and stores the result: removed rows are
// deleted, new rows inserted and every row gets priority = its position.
func (s *Store) editEndpoints(ctx context.Context, what, hostID string, edit func([]Endpoint) ([]Endpoint, error)) (EndpointChange, error) {
	fail := func(err error) (EndpointChange, error) {
		return EndpointChange{}, fmt.Errorf("inventory: %s %s: %w", what, hostID, err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fail(fmt.Errorf("begin: %w", err))
	}
	defer tx.Rollback()

	var hid int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM hosts WHERE name = ?`, hostID).Scan(&hid); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fail(ErrHostNotFound)
		}
		return fail(err)
	}
	type row struct {
		id int64
		e  Endpoint
	}
	rows, err := tx.QueryContext(ctx,
		`SELECT id, address, port FROM host_endpoints WHERE host_id = ? ORDER BY priority, id`, hid)
	if err != nil {
		return fail(err)
	}
	var stored []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.e.Address, &r.e.Port); err != nil {
			rows.Close()
			return fail(err)
		}
		stored = append(stored, r)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fail(err)
	}
	rows.Close()

	before := make([]Endpoint, len(stored))
	for i, r := range stored {
		before[i] = r.e
	}
	after, err := edit(before)
	if err != nil {
		return fail(err)
	}
	if p := endpointProblems(after); len(p) > 0 {
		return fail(&ValidationError{Problems: p})
	}

	keep := make(map[string]int64, len(stored))
	for _, r := range stored {
		keep[EndpointKey(r.e)] = r.id
	}
	ts := s.now().UTC().Format(time.RFC3339)
	wanted := make(map[string]bool, len(after))
	for _, e := range after {
		wanted[EndpointKey(e)] = true
	}
	for _, r := range stored {
		if !wanted[EndpointKey(r.e)] {
			if _, err := tx.ExecContext(ctx, `DELETE FROM host_endpoints WHERE id = ?`, r.id); err != nil {
				return fail(fmt.Errorf("delete endpoint: %w", err))
			}
		}
	}
	for i, e := range after {
		if id, ok := keep[EndpointKey(e)]; ok {
			if _, err := tx.ExecContext(ctx, `UPDATE host_endpoints SET priority = ? WHERE id = ?`, i, id); err != nil {
				return fail(fmt.Errorf("order endpoint: %w", err))
			}
			continue
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO host_endpoints (host_id, address, port, priority, created_at) VALUES (?, ?, ?, ?, ?)`,
			hid, e.Address, e.Port, i, ts); err != nil {
			if isUniqueViolation(err) {
				return fail(fmt.Errorf("%w: %s", ErrEndpointExists, EndpointKey(e)))
			}
			return fail(fmt.Errorf("insert endpoint: %w", err))
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE hosts SET updated_at = ? WHERE id = ?`, ts, hid); err != nil {
		return fail(err)
	}
	if err := tx.Commit(); err != nil {
		return fail(fmt.Errorf("commit: %w", err))
	}
	return EndpointChange{Before: before, After: after}, nil
}
