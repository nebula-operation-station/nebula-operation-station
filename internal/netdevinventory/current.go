// SPDX-License-Identifier: AGPL-3.0-or-later

package netdevinventory

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

// CurrentTable is the current dataset of one device for one switch read:
// its state, its observation time and the rows present in it. A device
// without a current dataset is not listed at all, so a caller cannot take
// "unavailable" for "empty" (ADR 0010 D3).
type CurrentTable[T any] struct {
	DeviceID   string
	State      DatasetState
	ObservedAt time.Time
	// Rows are the rows present in the current dataset: those of the
	// latest read and the ones an incomplete read carried over. Rows a
	// complete read did not contain are left out.
	Rows []T
}

// CurrentMACTables lists the current MAC table of every device that has
// one, ordered by device ID and then by row key. A table over
// netdevcontract.MaxMACEntriesPerDevice is cut at that limit and marked
// partial.
func (s *Store) CurrentMACTables(ctx context.Context) ([]CurrentTable[netdevcontract.MACEntry], error) {
	return currentTables(ctx, s, ReadMACTable, tblMAC, netdevcontract.MaxMACEntriesPerDevice,
		func(sc rowScanner) (int64, netdevcontract.MACEntry, error) {
			var id, vlan int64
			var e netdevcontract.MACEntry
			var typ string
			if err := sc.Scan(&id, &vlan, &e.MAC, &e.Port, &typ); err != nil {
				return 0, netdevcontract.MACEntry{}, err
			}
			if vlan < 0 || vlan > math.MaxUint16 {
				return 0, netdevcontract.MACEntry{}, fmt.Errorf("netdevinventory: stored mac vlan %d out of range", vlan)
			}
			e.VLAN = uint16(vlan)
			e.Type = netdevcontract.MACType(typ)
			return id, e, nil
		})
}

// CurrentVLANTables lists the current VLAN table of every device that has
// one, ordered by device ID and then by row key. A table over
// netdevcontract.MaxVLANsPerDevice is cut at that limit and marked partial.
func (s *Store) CurrentVLANTables(ctx context.Context) ([]CurrentTable[netdevcontract.VLAN], error) {
	return currentTables(ctx, s, ReadVLANs, tblVLANs, netdevcontract.MaxVLANsPerDevice,
		func(sc rowScanner) (int64, netdevcontract.VLAN, error) {
			var id, vlan int64
			var v netdevcontract.VLAN
			if err := sc.Scan(&id, &vlan, &v.Name); err != nil {
				return 0, netdevcontract.VLAN{}, err
			}
			if vlan < 0 || vlan > math.MaxUint16 {
				return 0, netdevcontract.VLAN{}, fmt.Errorf("netdevinventory: stored vlan id %d out of range", vlan)
			}
			v.ID = uint16(vlan)
			return id, v, nil
		})
}

// CurrentLLDPTables lists the current LLDP neighbor table of every device
// that has one, ordered by device ID and then by row key. Neighbors with
// the same local port, chassis and port ID are all kept. A table over
// netdevcontract.MaxLLDPNeighborsPerDevice is cut at that limit and marked
// partial.
func (s *Store) CurrentLLDPTables(ctx context.Context) ([]CurrentTable[netdevcontract.LLDPNeighbor], error) {
	return currentTables(ctx, s, ReadLLDPNeighbors, tblLLDP, netdevcontract.MaxLLDPNeighborsPerDevice,
		func(sc rowScanner) (int64, netdevcontract.LLDPNeighbor, error) {
			var id int64
			var n netdevcontract.LLDPNeighbor
			var caps string
			if err := sc.Scan(&id, &n.LocalPort, &n.ChassisID, &n.PortID, &n.SystemName,
				&n.ManagementAddress, &caps); err != nil {
				return 0, netdevcontract.LLDPNeighbor{}, err
			}
			var names []string
			if err := json.Unmarshal([]byte(caps), &names); err != nil {
				return 0, netdevcontract.LLDPNeighbor{}, fmt.Errorf("netdevinventory: stored lldp capabilities: %w", err)
			}
			for _, c := range names {
				n.Capabilities = append(n.Capabilities, netdevcontract.LLDPCapability(c))
			}
			return id, n, nil
		})
}

// hookCurrentBetween names the test hook stage between the dataset query
// and the row query of currentTables.
const hookCurrentBetween = "current:between"

// currentTables reads the current dataset of every device for one read and
// the rows present in them. scan reads one row of t: its dataset ID first,
// then the columns of t in order.
func currentTables[T any](ctx context.Context, s *Store, read Read, t *table, limit int,
	scan func(rowScanner) (int64, T, error)) ([]CurrentTable[T], error) {
	// Both queries run in one read transaction: on a WAL database each
	// statement otherwise sees its own snapshot, and a replacement between
	// them would either fail the list ("row of unknown dataset") or show a
	// table under its superseded state with no rows.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("netdevinventory: begin current %s read: %w", read, err)
	}
	defer func() { _ = tx.Rollback() }()

	dsRows, err := tx.QueryContext(ctx, `SELECT id, device_id, observed_at, state FROM netdev_datasets
		WHERE read = ? AND current = 1 ORDER BY device_id`, string(read))
	if err != nil {
		return nil, fmt.Errorf("netdevinventory: list current %s datasets: %w", read, err)
	}
	var out []CurrentTable[T]
	index := map[int64]int{}
	for dsRows.Next() {
		var id, observed int64
		var deviceID, state string
		if err := dsRows.Scan(&id, &deviceID, &observed, &state); err != nil {
			dsRows.Close()
			return nil, fmt.Errorf("netdevinventory: scan current %s dataset: %w", read, err)
		}
		index[id] = len(out)
		out = append(out, CurrentTable[T]{DeviceID: deviceID, State: DatasetState(state), ObservedAt: fromMicros(observed)})
	}
	if err := dsRows.Close(); err != nil {
		return nil, fmt.Errorf("netdevinventory: close current %s datasets: %w", read, err)
	}
	if err := dsRows.Err(); err != nil {
		return nil, fmt.Errorf("netdevinventory: list current %s datasets: %w", read, err)
	}
	if len(out) == 0 {
		return nil, nil
	}
	if err := s.runHook(hookCurrentBetween); err != nil {
		return nil, err
	}
	now := s.now()
	for i := range out {
		// The same staleness rule as GetDataset.
		if now.Sub(out[i].ObservedAt) > StaleAfterIntervals*PollInterval(read) {
			out[i].State = StateStale
		}
	}

	cols := strings.Join(t.cols, ", ")
	rows, err := tx.QueryContext(ctx, `SELECT dataset_id, `+cols+` FROM `+t.name+`
		WHERE absent = 0 AND dataset_id IN (SELECT id FROM netdev_datasets WHERE read = ? AND current = 1)
		ORDER BY dataset_id, row_key`, string(read))
	if err != nil {
		return nil, fmt.Errorf("netdevinventory: read current %s rows: %w", read, err)
	}
	defer rows.Close()
	// overflow marks the tables with more rows than limit. Rows beyond the
	// limit are not appended, so a table never holds more than limit rows.
	overflow := make([]bool, len(out))
	for rows.Next() {
		id, v, err := scan(rows)
		if err != nil {
			return nil, fmt.Errorf("netdevinventory: scan current %s row: %w", read, err)
		}
		i, ok := index[id]
		if !ok {
			return nil, fmt.Errorf("netdevinventory: %s row of unknown dataset %d", read, id)
		}
		if len(out[i].Rows) >= limit {
			overflow[i] = true
			continue
		}
		out[i].Rows = append(out[i].Rows, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("netdevinventory: read current %s rows: %w", read, err)
	}
	for i := range out {
		if overflow[i] && out[i].State == StateFresh {
			// More rows than the contract allows (carried rows of an
			// incomplete read add to the rows of the latest one): cut and
			// say so. A stale table keeps its state, which is the worse one.
			out[i].State = StatePartial
		}
	}
	return out, nil
}
