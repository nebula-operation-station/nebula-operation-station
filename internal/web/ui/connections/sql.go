// SPDX-License-Identifier: AGPL-3.0-or-later

package connections

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/flowagg"
)

// maxRecordReporters bounds the reporters kept per record read from the
// database; the page shows at most MaxReportersShown of them.
const maxRecordReporters = 16

// reporterSep separates reporter IDs in the aggregated column. Stored
// reporter IDs are validated host IDs without control characters.
const reporterSep = "\x1f"

const secondsPerHour = 3600

// flowsSQL lists every flow with one end in the node set ?1 (a JSON
// array of addresses in stored form) in the inclusive hour range
// ?2..?3, largest first, at most ?4 rows. Per flow and hour it applies
// the flowagg merge as internal/trafficstore's top-flow query does: the
// server end's row when present, otherwise the client end's; a flow is
// confirmed when both ends reported in every counted hour. reps lists
// every reporter of the flow's rows in the window.
const flowsSQL = `
WITH nodes AS (
	SELECT value AS addr FROM json_each(?1)
), node_rows AS (
	SELECT hour, a, b, ab_key, proto, server_port, server_side, tier, server_reported, reporter,
	       bytes_ab, bytes_ba, connections, lower_bound
	FROM flow_buckets WHERE a IN (SELECT addr FROM nodes) AND hour BETWEEN ?2 AND ?3
	UNION
	SELECT hour, a, b, ab_key, proto, server_port, server_side, tier, server_reported, reporter,
	       bytes_ab, bytes_ba, connections, lower_bound
	FROM flow_buckets WHERE b IN (SELECT addr FROM nodes) AND hour BETWEEN ?2 AND ?3
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
), reps AS (
	SELECT a, b, proto, server_port, server_side, tier, group_concat(reporter, char(31)) AS reporters
	FROM (SELECT DISTINCT a, b, proto, server_port, server_side, tier, reporter FROM node_rows ORDER BY reporter)
	GROUP BY a, b, proto, server_port, server_side, tier
)
SELECT f.a, f.b, f.proto, f.server_port, f.server_side, f.tier, f.ab, f.ba, f.conns, f.lb,
       f.has_server, f.min_sides, f.first_hour, f.last_hour, COALESCE(r.reporters, '')
FROM per_flow f LEFT JOIN reps r USING (a, b, proto, server_port, server_side, tier)
ORDER BY f.ab + f.ba DESC, f.ab_key, f.proto, f.server_port, f.server_side, f.tier
LIMIT ?4`

// SQLFlows returns a FlowSource that reads the server database's
// flow_buckets table (internal/trafficstore). Process names are not
// stored there, so Record.Process stays empty.
func SQLFlows(db *sql.DB) FlowSource { return sqlFlows{db: db} }

type sqlFlows struct{ db *sql.DB }

// Flows implements FlowSource. nodes must be at most MaxSubjectAddrs
// valid addresses, limit in 1..MaxRows+1, w non-empty and no wider than
// flowagg.Retention.
func (s sqlFlows) Flows(ctx context.Context, nodes []netip.Addr, w flowagg.Window, limit int) ([]Record, error) {
	if len(nodes) == 0 || len(nodes) > MaxSubjectAddrs {
		return nil, fmt.Errorf("connections: %d nodes, want 1..%d", len(nodes), MaxSubjectAddrs)
	}
	if limit < 1 || limit > MaxRows+1 {
		return nil, fmt.Errorf("connections: limit %d, want 1..%d", limit, MaxRows+1)
	}
	if !w.From.Before(w.To) || w.To.Sub(w.From) > flowagg.Retention {
		return nil, errors.New("connections: invalid window")
	}
	strs := make([]string, 0, len(nodes))
	for _, a := range nodes {
		a = a.Unmap().WithZone("")
		if !a.IsValid() {
			return nil, errors.New("connections: invalid node address")
		}
		strs = append(strs, a.String())
	}
	js, err := json.Marshal(strs)
	if err != nil {
		return nil, fmt.Errorf("connections: encode nodes: %w", err)
	}
	lo := floorDiv(w.From.Unix(), secondsPerHour)
	hi := floorDiv(w.To.Unix()-1, secondsPerHour)
	rows, err := s.db.QueryContext(ctx, flowsSQL, string(js), lo, hi, limit)
	if err != nil {
		return nil, fmt.Errorf("connections: query flows: %w", err)
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		var a, b, tier, reps string
		var proto, port, side, ab, ba, conns, lb, server, minSides, first, last int64
		if err := rows.Scan(&a, &b, &proto, &port, &side, &tier, &ab, &ba, &conns, &lb, &server, &minSides, &first, &last, &reps); err != nil {
			return nil, fmt.Errorf("connections: scan flow: %w", err)
		}
		r, err := storedRecord(a, b, tier, proto, port, side)
		if err != nil {
			return nil, err
		}
		if ab < 0 || ba < 0 || conns < 0 {
			return nil, fmt.Errorf("connections: stored flow %s-%s: negative counter", r.Key.A, r.Key.B)
		}
		r.BytesAB, r.BytesBA, r.Connections = uint64(ab), uint64(ba), uint64(conns)
		r.LowerBound = lb != 0
		r.ServerReported = server != 0
		r.Confirmed = minSides >= 2
		r.FirstSeen = time.Unix(first*secondsPerHour, 0).UTC()
		r.LastSeen = time.Unix((last+1)*secondsPerHour, 0).UTC()
		r.Reporters = splitReporters(reps)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("connections: read flows: %w", err)
	}
	return out, nil
}

// storedRecord builds the key of a stored flow, checking the stored
// values instead of trusting them.
func storedRecord(a, b, tier string, proto, port, side int64) (Record, error) {
	addrA, errA := netip.ParseAddr(a)
	addrB, errB := netip.ParseAddr(b)
	if errA != nil || errB != nil {
		return Record{}, errors.New("connections: stored flow with invalid address")
	}
	if port < 1 || port > 65535 || proto < 0 || proto > 255 || (side != int64(flowagg.SideA) && side != int64(flowagg.SideB)) {
		return Record{}, fmt.Errorf("connections: stored flow %s-%s: proto/port/side out of range", addrA, addrB)
	}
	if tier == "" || len(tier) > flowagg.MaxTierLen || !utf8.ValidString(tier) {
		return Record{}, fmt.Errorf("connections: stored flow %s-%s: invalid tier", addrA, addrB)
	}
	return Record{FlowTotal: flowagg.FlowTotal{Key: flowagg.FlowKey{
		A: addrA, B: addrB, Proto: flowagg.Proto(proto), ServerPort: uint16(port), Server: flowagg.Side(side), Tier: tier,
	}}}, nil
}

// splitReporters splits the aggregated reporter column, keeping at most
// maxRecordReporters non-empty IDs.
func splitReporters(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for rep := range strings.SplitSeq(s, reporterSep) {
		if rep == "" {
			continue
		}
		if len(out) == maxRecordReporters {
			break
		}
		out = append(out, rep)
	}
	return out
}

func floorDiv(a, b int64) int64 {
	q := a / b
	if a%b != 0 && (a < 0) != (b < 0) {
		q--
	}
	return q
}
