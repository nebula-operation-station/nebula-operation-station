// SPDX-License-Identifier: AGPL-3.0-or-later

package netdevinventory

// Per-part state of the PAN-OS firewall policy (ADR 0010 D4, plan ND-16
// part 2). The zones, objects, security rule and NAT rule reads are polled
// separately and each is stored as its own firewall_policy dataset (a
// PolicyPartRows) that carries the other parts' rows. Ordering and
// completeness belong to the part, not to the shared dataset:
//
//   - a part is refused as out of order only when a dataset of the same
//     part is at least as new; an older part record whose part has no newer
//     read is stored, even if another part was stored after it;
//   - the dataset reports state partial while the newest read of any part
//     was incomplete, whichever part was stored last.
//
// The schema has no part column. The part of a stored dataset follows from
// its present rows (seq NOT NULL): a part dataset holds present rows only in
// its own part's scope. A part read without rows stores row_count 0 and the
// payload hash of the empty part, which names the part as well. A full
// PolicyRows dataset counts as a read of every part it has present rows
// for.

import (
	"context"
	"database/sql"
	"fmt"
)

// maxPolicyPartScan bounds the firewall_policy datasets one lookup of the
// newest dataset per part visits, newest observed_at first. Normal polling
// stores the four parts within four datasets, so a part missing from that
// many has not been read for many poll intervals. A lookup that reaches the
// bound without finding a part treats it conservatively: a write of that
// part older than the visited datasets is refused as out of order, and
// the dataset is reported partial.
const maxPolicyPartScan = 64

// policyParts lists the parts in a fixed order.
var policyParts = []PolicyPart{PolicyZones, PolicyObjects, PolicySecurityRules, PolicyNATRules}

// emptyPartSums maps the payload hash of each part read without rows to
// its part.
var emptyPartSums = func() map[string]PolicyPart {
	m := make(map[string]PolicyPart, len(policyParts))
	for _, p := range policyParts {
		if sum, err := payloadSHA256(PolicyPartRows{Part: p}); err == nil {
			m[sum] = p
		}
	}
	return m
}()

// partPresentSQL reports, for one dataset, whether it holds present rows of
// the zones, objects, security rule and NAT rule parts. Its four
// parameters are the dataset ID.
const partPresentSQL = `SELECT
	EXISTS(SELECT 1 FROM netdev_objects WHERE dataset_id = ? AND seq IS NOT NULL AND kind = 'zone'),
	EXISTS(SELECT 1 FROM netdev_objects WHERE dataset_id = ? AND seq IS NOT NULL AND kind <> 'zone'),
	EXISTS(SELECT 1 FROM netdev_fw_rules WHERE dataset_id = ? AND seq IS NOT NULL),
	EXISTS(SELECT 1 FROM netdev_nat_rules WHERE dataset_id = ? AND seq IS NOT NULL)`

// partDataset is the newest stored dataset of one policy part.
type partDataset struct {
	id         int64
	obs        int64
	sum        string
	incomplete bool
}

// querier is the read side shared by *sql.DB and *sql.Tx.
type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type policyDatasetRow struct {
	partDataset
	rowCount int64
}

// latestPolicyParts returns the newest firewall_policy dataset of each
// wanted part (every part when want is empty) among the datasets of
// deviceID observed at or after since, visiting at most maxPolicyPartScan
// of them newest first. cut reports that the bound stopped the lookup
// before every wanted part was found.
func latestPolicyParts(ctx context.Context, q querier, deviceID string, since int64, want PolicyPart) (map[PolicyPart]partDataset, bool, error) {
	rs, err := q.QueryContext(ctx, `SELECT id, observed_at, payload_sha256, incomplete, row_count FROM netdev_datasets
		WHERE device_id = ? AND read = ? AND observed_at >= ? ORDER BY observed_at DESC, id DESC LIMIT ?`,
		deviceID, string(ReadFirewallPolicy), since, maxPolicyPartScan+1)
	if err != nil {
		return nil, false, fmt.Errorf("netdevinventory: list policy datasets: %w", err)
	}
	var list []policyDatasetRow
	for rs.Next() {
		var d policyDatasetRow
		var inc int
		if err := rs.Scan(&d.id, &d.obs, &d.sum, &inc, &d.rowCount); err != nil {
			rs.Close()
			return nil, false, fmt.Errorf("netdevinventory: scan policy dataset: %w", err)
		}
		d.incomplete = inc == 1
		list = append(list, d)
	}
	if err := rs.Err(); err != nil {
		rs.Close()
		return nil, false, fmt.Errorf("netdevinventory: list policy datasets: %w", err)
	}
	rs.Close()
	cut := len(list) > maxPolicyPartScan
	list = list[:min(len(list), maxPolicyPartScan)]

	wanted := 1
	if want == "" {
		wanted = len(policyParts)
	}
	found := make(map[PolicyPart]partDataset, wanted)
	for _, d := range list {
		parts, err := datasetParts(ctx, q, d.id, d.sum, d.rowCount)
		if err != nil {
			return nil, false, err
		}
		for _, p := range parts {
			if _, seen := found[p]; seen || (want != "" && p != want) {
				continue
			}
			found[p] = d.partDataset
		}
		if len(found) == wanted {
			return found, false, nil
		}
	}
	return found, cut, nil
}

// datasetParts returns the parts one firewall_policy dataset read.
func datasetParts(ctx context.Context, q querier, id int64, sum string, rowCount int64) ([]PolicyPart, error) {
	if rowCount == 0 {
		if p, ok := emptyPartSums[sum]; ok {
			return []PolicyPart{p}, nil
		}
		return nil, nil
	}
	var has [4]bool
	if err := q.QueryRowContext(ctx, partPresentSQL, id, id, id, id).Scan(&has[0], &has[1], &has[2], &has[3]); err != nil {
		return nil, fmt.Errorf("netdevinventory: classify policy dataset: %w", err)
	}
	var parts []PolicyPart
	for i, p := range policyParts {
		if has[i] {
			parts = append(parts, p)
		}
	}
	return parts, nil
}

// policyIncomplete reports whether the newest read of any policy part of
// deviceID was incomplete, or a part could not be found within
// maxPolicyPartScan datasets although older datasets exist.
func policyIncomplete(ctx context.Context, q querier, deviceID string) (bool, error) {
	found, cut, err := latestPolicyParts(ctx, q, deviceID, minMicros, "")
	if err != nil {
		return false, err
	}
	for _, p := range policyParts {
		d, ok := found[p]
		if (ok && d.incomplete) || (!ok && cut) {
			return true, nil
		}
	}
	return false, nil
}

// minMicros is a lower bound below every stored observed_at.
const minMicros = -1 << 63
