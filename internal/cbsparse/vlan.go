// SPDX-License-Identifier: AGPL-3.0-or-later

package cbsparse

import (
	"fmt"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

// Limits of the "show vlan" parser.
const (
	// vlanMaxContinuationLines bounds the wrapped port-list lines of one
	// VLAN row; a longer row is malformed.
	vlanMaxContinuationLines = 64
	// vlanTypeMaxBytes bounds the "Created by" (type) cell, a few legend
	// letters such as "DV" on real output.
	vlanTypeMaxBytes = 16
)

// VLAN is one row of "show vlan" on a CBS switch.
type VLAN struct {
	// ID is the 802.1Q VLAN ID, 1 to netdevcontract.MaxVLANID.
	ID uint16
	// Name is the VLAN name as printed (may be empty).
	Name string
	// Tagged and Untagged list the member ports in output order, with
	// ranges expanded.
	Tagged   []string
	Untagged []string
	// Type is the "Created by" cell, legend letters such as "DV" (Default,
	// Voice) or "S" (Static); empty when the table has no such column.
	Type string
}

// VLAN table fields.
const (
	vlanFieldID = iota
	vlanFieldName
	vlanFieldTagged
	vlanFieldUntagged
	vlanFieldType
	numVLANFields
)

var vlanTitles = map[string]int{
	"vlan":           vlanFieldID,
	"name":           vlanFieldName,
	"tagged ports":   vlanFieldTagged,
	"untagged ports": vlanFieldUntagged,
	"created by":     vlanFieldType,
	"type":           vlanFieldType,
}

// vlanGroup is one VLAN row with its continuation lines.
type vlanGroup struct {
	line             int
	id, name, typ    string
	tagged, untagged string
	continuations    int
	bad              bool
}

// ParseVLANs parses the output of "show vlan" on a CBS switch.
//
// The input is untrusted device text (spec 09). Output limits, invalid
// UTF-8 and control characters refuse the whole output (see splitTables);
// output without a table is ErrNoTable, a table without the Vlan, Name,
// Tagged Ports and UnTagged Ports columns is ErrUnrecognizedTable.
//
// A row starts with a VLAN ID; following lines with an empty ID column
// continue its port lists (a wrapped cell must end with a comma before it
// continues). A row that cannot be read exactly is dropped and incomplete
// is true: text crossing a column gap, a tab, an ID outside 1 to
// MaxVLANID or not in canonical decimal, a name that violates the text
// rule or MaxLabelBytes, an unknown port name or malformed port list, a
// port both tagged and untagged, a continuation line that fills the name
// or type column, or more than vlanMaxContinuationLines continuation
// lines. A continuation line without a row before it is dropped the same
// way. Two valid rows with the same ID are ErrDuplicate.
//
// At most netdevcontract.MaxVLANsPerDevice VLANs are returned; further
// rows are not read and incomplete is true. On error the result is nil
// and incomplete is false.
func ParseVLANs(out []byte) (vlans []VLAN, incomplete bool, err error) {
	const what = "show vlan"
	blocks, err := splitTables(out, what)
	if err != nil {
		return nil, false, err
	}
	seen := map[uint16]int{}
	for _, b := range blocks {
		idx, err := columnIndex(b.titles, vlanTitles, numVLANFields,
			vlanFieldID, vlanFieldName, vlanFieldTagged, vlanFieldUntagged)
		if err != nil {
			return nil, false, fmt.Errorf("cbsparse: %s: %w", what, err)
		}
		groups, orphans := groupVLANRows(b.rows, idx)
		if orphans {
			incomplete = true
		}
		for _, g := range groups {
			if netdevcontract.CheckCount("vlans", len(vlans)+1, netdevcontract.MaxVLANsPerDevice) != nil {
				return vlans, true, nil
			}
			v, ok := buildVLAN(g)
			if !ok {
				incomplete = true
				continue
			}
			if first, dup := seen[v.ID]; dup {
				return nil, false, fmt.Errorf("cbsparse: %s line %d: VLAN of line %d repeated: %w", what, g.line, first, ErrDuplicate)
			}
			seen[v.ID] = g.line
			vlans = append(vlans, v)
		}
	}
	return vlans, incomplete, nil
}

// groupVLANRows joins every VLAN row with its continuation lines. orphans
// reports continuation or malformed lines without a row before them.
func groupVLANRows(rows []tableRow, idx []int) (groups []*vlanGroup, orphans bool) {
	var cur *vlanGroup
	for _, r := range rows {
		if !r.ok {
			if r.lead != "" {
				// A malformed new row: dropped together with any
				// continuation lines that follow it.
				cur = &vlanGroup{line: r.line, bad: true}
				groups = append(groups, cur)
				continue
			}
			// A malformed continuation line: the current row cannot be
			// trusted.
			if cur != nil {
				cur.bad = true
			} else {
				orphans = true
			}
			continue
		}
		if id := r.cells[idx[vlanFieldID]]; id != "" {
			cur = &vlanGroup{
				line:     r.line,
				id:       id,
				name:     r.cells[idx[vlanFieldName]],
				typ:      cell(r.cells, idx[vlanFieldType]),
				tagged:   r.cells[idx[vlanFieldTagged]],
				untagged: r.cells[idx[vlanFieldUntagged]],
			}
			groups = append(groups, cur)
			continue
		}
		if cur == nil {
			orphans = true
			continue
		}
		cur.continuations++
		if cur.continuations > vlanMaxContinuationLines ||
			r.cells[idx[vlanFieldName]] != "" || cell(r.cells, idx[vlanFieldType]) != "" {
			cur.bad = true
			continue
		}
		var ok1, ok2 bool
		cur.tagged, ok1 = joinWrapped(cur.tagged, r.cells[idx[vlanFieldTagged]])
		cur.untagged, ok2 = joinWrapped(cur.untagged, r.cells[idx[vlanFieldUntagged]])
		if !ok1 || !ok2 {
			cur.bad = true
		}
	}
	return groups, orphans
}

// joinWrapped appends the continuation of a wrapped port-list cell. A
// non-empty cell may only continue after a trailing comma, so that a port
// name or range is never glued together from two lines.
func joinWrapped(prev, next string) (string, bool) {
	if next == "" {
		return prev, true
	}
	if prev != "" && !strings.HasSuffix(prev, ",") {
		return prev, false
	}
	return prev + next, true
}

// buildVLAN validates one grouped row.
func buildVLAN(g *vlanGroup) (VLAN, bool) {
	if g.bad {
		return VLAN{}, false
	}
	id, ok := parseDecimal(g.id, 4)
	if !ok || id < 1 || id > netdevcontract.MaxVLANID {
		return VLAN{}, false
	}
	if !validLabel(g.name) {
		return VLAN{}, false
	}
	if netdevcontract.CheckCount("vlan type bytes", len(g.typ), vlanTypeMaxBytes) != nil || !validValueText(g.typ) {
		return VLAN{}, false
	}
	tagged, ok := parsePortList(g.tagged)
	if !ok {
		return VLAN{}, false
	}
	untagged, ok := parsePortList(g.untagged)
	if !ok {
		return VLAN{}, false
	}
	inTagged := make(map[string]struct{}, len(tagged))
	for _, p := range tagged {
		inTagged[p] = struct{}{}
	}
	for _, p := range untagged {
		if _, both := inTagged[p]; both {
			return VLAN{}, false
		}
	}
	return VLAN{ID: uint16(id), Name: g.name, Tagged: tagged, Untagged: untagged, Type: g.typ}, true
}
