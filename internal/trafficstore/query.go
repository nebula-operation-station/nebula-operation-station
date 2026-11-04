// SPDX-License-Identifier: AGPL-3.0-or-later

package trafficstore

import (
	"cmp"
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/flowagg"
)

// Query bounds, next to the code that enforces them.
const (
	// MaxTopN is the largest per-node result size TopN and
	// OverviewUnion accept.
	MaxTopN = 20
	// MaxOverviewNodes is the largest node list OverviewUnion accepts; it
	// bounds the queries one call runs and its result to
	// MaxOverviewNodes*MaxTopN flows.
	MaxOverviewNodes = 4096
	// maxTopRows bounds the rows one per-node query returns to Go. The
	// SQL keeps the flows ranked within the top n by total bytes,
	// including ties at the boundary; when more than maxTopRows flows tie,
	// the extra ones are cut in flow key order (ab_key orders the
	// addresses as netip.Addr.Compare does), as flowagg breaks ties.
	maxTopRows = 256
)

// topFlowsSQL computes the top flows of one node in SQL, so no more than
// maxTopRows rows reach Go. Parameters: ?1 node address, ?2/?3 the
// inclusive hour range, ?4 n, ?5 the row cap.
//
// per_hour applies the flowagg merge per flow and hour: there is at most
// one row per side, and the server end's row is used when present,
// otherwise the client end's; an hour is confirmed when both sides
// reported. per_flow sums the hours (maxStoredCounter leaves headroom for
// these sums); a flow is confirmed when every counted hour is.
const topFlowsSQL = `
WITH node_rows AS (
	SELECT hour, a, b, ab_key, proto, server_port, server_side, tier, server_reported,
	       bytes_ab, bytes_ba, connections, lower_bound
	FROM flow_buckets WHERE a = ?1 AND hour BETWEEN ?2 AND ?3
	UNION ALL
	SELECT hour, a, b, ab_key, proto, server_port, server_side, tier, server_reported,
	       bytes_ab, bytes_ba, connections, lower_bound
	FROM flow_buckets WHERE b = ?1 AND hour BETWEEN ?2 AND ?3
), per_hour AS (
	SELECT a, b, MIN(ab_key) AS ab_key, proto, server_port, server_side, tier, hour,
	       MAX(server_reported) AS has_server,
	       COUNT(*) AS sides,
	       COALESCE(MAX(CASE WHEN server_reported = 1 THEN bytes_ab END), MAX(bytes_ab)) AS ab,
	       COALESCE(MAX(CASE WHEN server_reported = 1 THEN bytes_ba END), MAX(bytes_ba)) AS ba,
	       COALESCE(MAX(CASE WHEN server_reported = 1 THEN connections END), MAX(connections)) AS conns,
	       COALESCE(MAX(CASE WHEN server_reported = 1 THEN lower_bound END), MAX(lower_bound)) AS lb
	FROM node_rows
	GROUP BY a, b, proto, server_port, server_side, tier, hour
), per_flow AS (
	SELECT a, b, MIN(ab_key) AS ab_key, proto, server_port, server_side, tier,
	       SUM(ab) AS ab, SUM(ba) AS ba, SUM(conns) AS conns,
	       MAX(lb) AS lb, MAX(has_server) AS has_server, MIN(sides) AS min_sides,
	       MIN(hour) AS first_hour, MAX(hour) AS last_hour
	FROM per_hour
	GROUP BY a, b, proto, server_port, server_side, tier
), ranked AS (
	SELECT *, RANK() OVER (ORDER BY ab + ba DESC) AS rnk FROM per_flow
)
SELECT a, b, proto, server_port, server_side, tier, ab, ba, conns, lb, has_server, min_sides,
       first_hour, last_hour
FROM ranked WHERE rnk <= ?4
ORDER BY rnk, ab_key, proto, server_port, server_side, tier
LIMIT ?5`

// checkWindow validates a query window: non-empty and no wider than the
// retention.
func checkWindow(w flowagg.Window, retention time.Duration) error {
	if !w.From.Before(w.To) {
		return fmt.Errorf("%w: empty window", ErrInvalidWindow)
	}
	if w.To.Sub(w.From) > retention {
		return fmt.Errorf("%w: wider than the retention", ErrInvalidWindow)
	}
	return nil
}

// checkN applies the default to n and bounds it by MaxTopN.
func checkN(n int) (int, error) {
	if n <= 0 {
		return flowagg.DefaultOverviewN, nil
	}
	if n > MaxTopN {
		return 0, fmt.Errorf("%w: n %d exceeds %d", ErrInvalidQuery, n, MaxTopN)
	}
	return n, nil
}

// hourRange returns the inclusive range of hours that overlap w.
func hourRange(w flowagg.Window) (lo, hi int64) {
	return floorDiv(w.From.Unix(), secondsPerHour), floorDiv(w.To.Unix()-1, secondsPerHour)
}

func floorDiv(a, b int64) int64 {
	q := a / b
	if a%b != 0 && (a < 0) != (b < 0) {
		q--
	}
	return q
}

// normalizeNode returns the stored form of a query node.
func normalizeNode(a netip.Addr) (netip.Addr, error) {
	n, err := normalizeAddress(a)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%w: node %s: %v", ErrInvalidQuery, a, err)
	}
	return n, nil
}

// parseStoredAddr parses an address read from flow_buckets.
func parseStoredAddr(col, s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("trafficstore: stored flow end %s %q: %w", col, s, err)
	}
	return a, nil
}

// topFlows returns the top-n flows of node in hours [lo, hi], largest
// first with ties ordered by flow key, merged with flowagg semantics.
// stmt runs topFlowsSQL; OverviewUnion prepares it once for all nodes.
func topFlows(ctx context.Context, stmt *sql.Stmt, node netip.Addr, lo, hi int64, n int) ([]flowagg.FlowTotal, error) {
	rows, err := stmt.QueryContext(ctx, node.String(), lo, hi, n, maxTopRows)
	if err != nil {
		return nil, fmt.Errorf("trafficstore: query top flows of %s: %w", node, err)
	}
	defer rows.Close()
	out := make([]flowagg.FlowTotal, 0, n)
	for rows.Next() {
		var a, b, tier string
		var proto, port, side, ab, ba, conns, lb, server, minSides, first, last int64
		if err := rows.Scan(&a, &b, &proto, &port, &side, &tier, &ab, &ba, &conns, &lb, &server, &minSides, &first, &last); err != nil {
			return nil, fmt.Errorf("trafficstore: query top flows of %s: %w", node, err)
		}
		t, err := storedTotal(a, b, tier, proto, port, side)
		if err != nil {
			return nil, err
		}
		if ab < 0 || ba < 0 || conns < 0 {
			return nil, fmt.Errorf("trafficstore: stored flow %s-%s: negative counter", a, b)
		}
		t.BytesAB, t.BytesBA, t.Connections = uint64(ab), uint64(ba), uint64(conns)
		t.LowerBound = lb != 0
		t.ServerReported = server != 0
		t.Confirmed = minSides >= 2
		t.FirstSeen = time.Unix(first*secondsPerHour, 0).UTC()
		t.LastSeen = time.Unix((last+1)*secondsPerHour, 0).UTC()
		out = append(out, t)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("trafficstore: query top flows of %s: %w", node, err)
	}
	sortTotals(out)
	if len(out) > n {
		out = out[:n]
	}
	return out, nil
}

// storedTotal builds the key of a stored flow, checking the stored
// values instead of trusting them.
func storedTotal(a, b, tier string, proto, port, side int64) (flowagg.FlowTotal, error) {
	addrA, err := parseStoredAddr("a", a)
	if err != nil {
		return flowagg.FlowTotal{}, err
	}
	addrB, err := parseStoredAddr("b", b)
	if err != nil {
		return flowagg.FlowTotal{}, err
	}
	if port < 1 || port > 65535 || proto < 0 || proto > 255 || side < 0 || side > 255 {
		return flowagg.FlowTotal{}, fmt.Errorf("trafficstore: stored flow %s-%s: proto/port/side out of range", a, b)
	}
	k := flowagg.FlowKey{
		A:          addrA,
		B:          addrB,
		Proto:      flowagg.Proto(proto),
		ServerPort: uint16(port),
		Server:     flowagg.Side(side),
		Tier:       tier,
	}
	if err := validKey(k); err != nil {
		return flowagg.FlowTotal{}, fmt.Errorf("trafficstore: stored flow %s-%s: %v", a, b, err)
	}
	return flowagg.FlowTotal{Key: k}, nil
}

// compareKey orders flow keys deterministically, mirroring
// flowagg.compareKey.
func compareKey(a, b flowagg.FlowKey) int {
	if c := a.A.Compare(b.A); c != 0 {
		return c
	}
	if c := a.B.Compare(b.B); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Proto, b.Proto); c != 0 {
		return c
	}
	if c := cmp.Compare(a.ServerPort, b.ServerPort); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Server, b.Server); c != 0 {
		return c
	}
	return strings.Compare(a.Tier, b.Tier)
}

// sortTotals orders by total bytes (both directions) descending, ties by
// flow key.
func sortTotals(ts []flowagg.FlowTotal) {
	slices.SortFunc(ts, func(a, b flowagg.FlowTotal) int {
		if c := cmp.Compare(b.Total(), a.Total()); c != 0 {
			return c
		}
		return compareKey(a.Key, b.Key)
	})
}

// TopN returns the n flows of node with the most bytes (both directions)
// in w, largest first; ties are ordered by flow key. n <= 0 returns the
// top 5 (flowagg.DefaultOverviewN); n above MaxTopN is refused with
// ErrInvalidQuery. The stored rows are merged and ranked in SQL with
// flowagg semantics: per flow and hour the server end's report is used
// when present, otherwise the client end's.
func (s *Store) TopN(ctx context.Context, node netip.Addr, w flowagg.Window, n int) ([]flowagg.FlowTotal, error) {
	n, err := checkN(n)
	if err != nil {
		return nil, err
	}
	if err := checkWindow(w, s.retention); err != nil {
		return nil, err
	}
	node, err = normalizeNode(node)
	if err != nil {
		return nil, err
	}
	lo, hi := hourRange(w)
	stmt, err := s.db.PrepareContext(ctx, topFlowsSQL)
	if err != nil {
		return nil, fmt.Errorf("trafficstore: prepare top flows: %w", err)
	}
	defer stmt.Close()
	return topFlows(ctx, stmt, node, lo, hi, n)
}

// OverviewUnion returns the union of the top-n sets of every node in
// nodes over w, largest first with ties ordered by key. n <= 0 means
// flowagg.DefaultOverviewN; n above MaxTopN and more than
// MaxOverviewNodes nodes are refused with ErrInvalidQuery. Duplicate
// nodes are ignored. It runs one bounded query per node, so the result
// holds at most MaxOverviewNodes*MaxTopN flows.
func (s *Store) OverviewUnion(ctx context.Context, nodes []netip.Addr, w flowagg.Window, n int) ([]flowagg.FlowTotal, error) {
	n, err := checkN(n)
	if err != nil {
		return nil, err
	}
	if len(nodes) > MaxOverviewNodes {
		return nil, fmt.Errorf("%w: %d nodes exceed %d", ErrInvalidQuery, len(nodes), MaxOverviewNodes)
	}
	if err := checkWindow(w, s.retention); err != nil {
		return nil, err
	}
	set := make([]netip.Addr, 0, len(nodes))
	for _, nd := range nodes {
		a, err := normalizeNode(nd)
		if err != nil {
			return nil, err
		}
		set = append(set, a)
	}
	slices.SortFunc(set, netip.Addr.Compare)
	set = slices.Compact(set)
	lo, hi := hourRange(w)
	stmt, err := s.db.PrepareContext(ctx, topFlowsSQL)
	if err != nil {
		return nil, fmt.Errorf("trafficstore: prepare top flows: %w", err)
	}
	defer stmt.Close()
	union := make(map[flowagg.FlowKey]flowagg.FlowTotal)
	for _, nd := range set {
		ts, err := topFlows(ctx, stmt, nd, lo, hi, n)
		if err != nil {
			return nil, err
		}
		for _, t := range ts {
			union[t.Key] = t
		}
	}
	out := make([]flowagg.FlowTotal, 0, len(union))
	for _, t := range union {
		out = append(out, t)
	}
	sortTotals(out)
	return out, nil
}
