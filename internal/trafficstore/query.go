// SPDX-License-Identifier: AGPL-3.0-or-later

package trafficstore

import (
	"cmp"
	"context"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/flowagg"
)

// bucketRow is one stored flow_buckets row.
type bucketRow struct {
	hour           int64
	key            flowagg.FlowKey
	bytesAB        int64
	bytesBA        int64
	conns          int64
	lowerBound     bool
	serverReported bool
	reporter       string
}

const bucketSelect = `SELECT hour, a, b, proto, server_port, server_side, tier,
    bytes_ab, bytes_ba, connections, lower_bound, server_reported, reporter
    FROM flow_buckets`

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

// hourRange returns the inclusive range of hours that overlap w.
func hourRange(w flowagg.Window) (min, max int64) {
	from := w.From.Unix()
	to := w.To.Unix()
	min = floorDiv(from, secondsPerHour)
	if to%secondsPerHour == 0 {
		max = to/secondsPerHour - 1
	} else {
		max = to / secondsPerHour
	}
	return min, max
}

func floorDiv(a, b int64) int64 {
	q := a / b
	if a%b != 0 && (a < 0) != (b < 0) {
		q--
	}
	return q
}

func validNode(a netip.Addr) error {
	n := a.Unmap().WithZone("")
	switch {
	case !n.IsValid():
		return fmt.Errorf("%w: invalid node", ErrInvalidWindow)
	case n.IsUnspecified() || n.IsLoopback():
		return fmt.Errorf("%w: unspecified or loopback node", ErrInvalidWindow)
	}
	return nil
}

// queryRows returns the stored rows where a or b is endpoint and the
// hour lies in [hMin, hMax]. The indexes (a, hour) and (b, hour) back
// the two range scans.
func (s *Store) queryRows(ctx context.Context, endpoint string, hMin, hMax int64) ([]bucketRow, error) {
	rows, err := s.db.QueryContext(ctx,
		bucketSelect+` WHERE (a = ? OR b = ?) AND hour >= ? AND hour <= ?`,
		endpoint, endpoint, hMin, hMax)
	if err != nil {
		return nil, fmt.Errorf("trafficstore: query buckets: %w", err)
	}
	defer rows.Close()
	var out []bucketRow
	for rows.Next() {
		var r bucketRow
		var a, b, tier, reporter string
		var proto, port, side, lower, server int64
		if err := rows.Scan(&r.hour, &a, &b, &proto, &port, &side, &tier,
			&r.bytesAB, &r.bytesBA, &r.conns, &lower, &server, &reporter); err != nil {
			return nil, fmt.Errorf("trafficstore: query buckets: %w", err)
		}
		// The database is written only by this package's validated
		// writers; MustParse cannot fail on stored values.
		r.key = flowagg.FlowKey{
			A:          netip.MustParseAddr(a),
			B:          netip.MustParseAddr(b),
			Proto:      flowagg.Proto(proto),
			ServerPort: uint16(port),
			Server:     flowagg.Side(side),
			Tier:       tier,
		}
		r.lowerBound = lower != 0
		r.serverReported = server != 0
		r.reporter = reporter
		out = append(out, r)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("trafficstore: query buckets: %w", err)
	}
	return out, nil
}

// hourSides holds the chosen server and client row of one flow in one
// hour; when several reporters claim a side, the lexicographically
// smallest reporter wins (deterministic, fail-closed).
type hourSides struct {
	server, client *bucketRow
}

// mergeRows merges stored rows into per-flow totals with flowagg
// semantics: per flow and hour the server end's report is used when
// present, otherwise the client end's; Confirmed means both ends
// reported in every counted hour.
func mergeRows(rows []bucketRow) map[flowagg.FlowKey]*flowagg.FlowTotal {
	byHour := make(map[flowagg.FlowKey]map[int64]*hourSides)
	for i := range rows {
		r := &rows[i]
		hm := byHour[r.key]
		if hm == nil {
			hm = make(map[int64]*hourSides)
			byHour[r.key] = hm
		}
		hs := hm[r.hour]
		if hs == nil {
			hs = &hourSides{}
			hm[r.hour] = hs
		}
		slot := &hs.client
		if r.serverReported {
			slot = &hs.server
		}
		if *slot == nil || r.reporter < (*slot).reporter {
			*slot = r
		}
	}
	out := make(map[flowagg.FlowKey]*flowagg.FlowTotal, len(byHour))
	for k, hm := range byHour {
		t := &flowagg.FlowTotal{Key: k}
		counted, confirmed := 0, 0
		for _, hs := range hm {
			eff := hs.client
			if hs.server != nil {
				eff = hs.server
				t.ServerReported = true
			}
			if eff == nil {
				continue
			}
			start := time.Unix(eff.hour*secondsPerHour, 0).UTC()
			end := time.Unix((eff.hour+1)*secondsPerHour, 0).UTC()
			if counted == 0 || start.Before(t.FirstSeen) {
				t.FirstSeen = start
			}
			if counted == 0 || end.After(t.LastSeen) {
				t.LastSeen = end
			}
			counted++
			if hs.server != nil && hs.client != nil {
				confirmed++
			}
			t.BytesAB = satAdd(t.BytesAB, uint64(eff.bytesAB))
			t.BytesBA = satAdd(t.BytesBA, uint64(eff.bytesBA))
			t.Connections = satAdd(t.Connections, uint64(eff.conns))
			t.LowerBound = t.LowerBound || eff.lowerBound
		}
		t.Confirmed = counted > 0 && confirmed == counted
		out[k] = t
	}
	return out
}

func satAdd(a, b uint64) uint64 {
	if a > math.MaxUint64-b {
		return math.MaxUint64
	}
	return a + b
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

// topOf sorts the totals by total bytes (both directions) descending,
// ties by flow key, and returns the first n.
func topOf(ts []*flowagg.FlowTotal, n int) []*flowagg.FlowTotal {
	slices.SortFunc(ts, func(a, b *flowagg.FlowTotal) int {
		if c := cmp.Compare(b.Total(), a.Total()); c != 0 {
			return c
		}
		return compareKey(a.Key, b.Key)
	})
	if len(ts) > n {
		ts = ts[:n]
	}
	return ts
}

// TopN returns the n flows of node with the most bytes (both directions)
// in w, largest first; ties are ordered by flow key. n <= 0 returns the
// top 5 (flowagg.DefaultOverviewN). The stored rows are merged with
// flowagg semantics: per flow and hour the server end's report is used
// when present, otherwise the client end's.
func (s *Store) TopN(ctx context.Context, node netip.Addr, w flowagg.Window, n int) ([]flowagg.FlowTotal, error) {
	if n <= 0 {
		n = flowagg.DefaultOverviewN
	}
	if err := checkWindow(w, s.retention); err != nil {
		return nil, err
	}
	if err := validNode(node); err != nil {
		return nil, err
	}
	hMin, hMax := hourRange(w)
	node = node.Unmap().WithZone("")
	rows, err := s.queryRows(ctx, node.String(), hMin, hMax)
	if err != nil {
		return nil, err
	}
	merged := mergeRows(rows)
	totals := make([]*flowagg.FlowTotal, 0, len(merged))
	for _, t := range merged {
		totals = append(totals, t)
	}
	out := make([]flowagg.FlowTotal, 0, n)
	for _, t := range topOf(totals, n) {
		out = append(out, *t)
	}
	return out, nil
}

// OverviewUnion returns the union of the top-n sets of every node in
// nodes over w, largest first with ties ordered by key. n <= 0 means
// flowagg.DefaultOverviewN. Duplicate nodes are ignored.
func (s *Store) OverviewUnion(ctx context.Context, nodes []netip.Addr, w flowagg.Window, n int) ([]flowagg.FlowTotal, error) {
	if n <= 0 {
		n = flowagg.DefaultOverviewN
	}
	if err := checkWindow(w, s.retention); err != nil {
		return nil, err
	}
	set := make(map[string]struct{}, len(nodes))
	for _, nd := range nodes {
		if err := validNode(nd); err != nil {
			return nil, err
		}
		set[nd.Unmap().WithZone("").String()] = struct{}{}
	}
	hMin, hMax := hourRange(w)
	var rows []bucketRow
	for addr := range set {
		r, err := s.queryRows(ctx, addr, hMin, hMax)
		if err != nil {
			return nil, err
		}
		rows = append(rows, r...)
	}
	merged := mergeRows(rows)
	perNode := make(map[string][]*flowagg.FlowTotal, len(set))
	for _, t := range merged {
		if _, ok := set[t.Key.A.String()]; ok {
			perNode[t.Key.A.String()] = append(perNode[t.Key.A.String()], t)
		}
		if _, ok := set[t.Key.B.String()]; ok {
			perNode[t.Key.B.String()] = append(perNode[t.Key.B.String()], t)
		}
	}
	union := make(map[flowagg.FlowKey]*flowagg.FlowTotal, n*len(set))
	for _, ts := range perNode {
		for _, t := range topOf(ts, n) {
			union[t.Key] = t
		}
	}
	out := make([]flowagg.FlowTotal, 0, len(union))
	for _, t := range union {
		out = append(out, *t)
	}
	slices.SortFunc(out, func(a, b flowagg.FlowTotal) int {
		if c := cmp.Compare(b.Total(), a.Total()); c != 0 {
			return c
		}
		return compareKey(a.Key, b.Key)
	})
	return out, nil
}
