// SPDX-License-Identifier: AGPL-3.0-or-later

package cbsparse

import (
	"fmt"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

// speedMaxDigits bounds the digits of a speed cell before it is
// converted; netdevcontract.MaxSpeedMbps has seven.
const speedMaxDigits = 7

// Duplex is the duplex mode of a port.
type Duplex string

// Duplex modes. DuplexUnknown covers "--" and an absent column.
const (
	DuplexFull    Duplex = "full"
	DuplexHalf    Duplex = "half"
	DuplexUnknown Duplex = ""
)

// Interface is one row of "show interfaces status" on a CBS switch,
// optionally merged with "show interfaces description".
type Interface struct {
	// Name is a validated CBS port name (gi, te or Po form).
	Name string
	// Type is the media type as printed, e.g. "1G-Copper"; empty when
	// unknown.
	Type string
	// Status is the link state.
	Status netdevcontract.LinkState
	// VLAN is the access VLAN when the table has a Vlan column that shows
	// one; 0 otherwise (no such column, trunk, routed or "--").
	VLAN uint16
	// Duplex is the negotiated duplex.
	Duplex Duplex
	// SpeedMbps is the speed in Mbit/s; 0 when unknown ("--").
	SpeedMbps uint64
	// Description is set by MergeDescriptions.
	Description string
}

// Interface table fields.
const (
	ifFieldName = iota
	ifFieldStatus
	ifFieldType
	ifFieldDuplex
	ifFieldSpeed
	ifFieldVLAN
	ifFieldDescription
	numIfFields
)

var interfaceTitles = map[string]int{
	"port":       ifFieldName,
	"ch":         ifFieldName,
	"link state": ifFieldStatus,
	"status":     ifFieldStatus,
	"type":       ifFieldType,
	"duplex":     ifFieldDuplex,
	"speed":      ifFieldSpeed,
	"vlan":       ifFieldVLAN,
}

var descriptionTitles = map[string]int{
	"port":        ifFieldName,
	"ch":          ifFieldName,
	"description": ifFieldDescription,
}

// ParseInterfaces parses the output of "show interfaces status" on a CBS
// switch: the port table and the port-channel table that follows it.
//
// The input is untrusted device text (spec 09). Output limits, invalid
// UTF-8 and control characters refuse the whole output (see splitTables);
// output without a table is ErrNoTable, a table without a Port (or Ch)
// and a Link State (or Status) column is ErrUnrecognizedTable. Type,
// Duplex, Speed and Vlan columns are optional.
//
// A row whose port name is not an accepted CBS port name (see
// parsePortName), that has text crossing a column gap or a tab, is
// dropped and incomplete is true. A cell value that is not recognised is
// stored as unknown (empty type, LinkUnknown, DuplexUnknown, speed 0,
// VLAN 0) and incomplete is true; "--", an empty cell and the status "Not
// Present" are recognised unknowns and do not set incomplete. Two valid
// rows for the same port are ErrDuplicate. A title line of the second
// table that may be a row of the first one (see splitTables) sets
// incomplete.
//
// At most netdevcontract.MaxInterfacesPerDevice interfaces are returned;
// further rows are not read and incomplete is true. On error the result
// is nil and incomplete is false.
func ParseInterfaces(out []byte) (ifaces []Interface, incomplete bool, err error) {
	const what = "show interfaces status"
	blocks, err := splitTables(out, what, tableMaxLines, func(titles []string) ([]int, error) {
		return columnIndex(titles, interfaceTitles, numIfFields, ifFieldName, ifFieldStatus)
	})
	if err != nil {
		return nil, false, err
	}
	seen := map[string]int{}
	for _, b := range blocks {
		idx := b.idx
		if b.lostRows {
			incomplete = true
		}
		for _, r := range b.rows {
			if netdevcontract.CheckCount("interfaces", len(ifaces)+1, netdevcontract.MaxInterfacesPerDevice) != nil {
				return ifaces, true, nil
			}
			if !r.ok || !validPortName(r.cells[idx[ifFieldName]]) {
				incomplete = true
				continue
			}
			itf, complete := buildInterface(r.cells, idx)
			if !complete {
				incomplete = true
			}
			if first, dup := seen[itf.Name]; dup {
				return nil, false, fmt.Errorf("cbsparse: %s line %d: port of line %d repeated: %w", what, r.line, first, ErrDuplicate)
			}
			seen[itf.Name] = r.line
			ifaces = append(ifaces, itf)
		}
	}
	return ifaces, incomplete, nil
}

// buildInterface converts the cells of one row with a valid port name.
// complete is false when a cell value was not recognised.
func buildInterface(cells []string, idx []int) (itf Interface, complete bool) {
	complete = true
	itf.Name = cells[idx[ifFieldName]]

	switch s := strings.ToLower(cells[idx[ifFieldStatus]]); s {
	case "up":
		itf.Status = netdevcontract.LinkUp
	case "down":
		itf.Status = netdevcontract.LinkDown
	case "--", "", "not present":
		itf.Status = netdevcontract.LinkUnknown
	default:
		itf.Status = netdevcontract.LinkUnknown
		complete = false
	}

	switch t := cell(cells, idx[ifFieldType]); {
	case t == "--":
	case validLabel(t):
		itf.Type = t
	default:
		complete = false
	}

	switch d := strings.ToLower(cell(cells, idx[ifFieldDuplex])); d {
	case "full":
		itf.Duplex = DuplexFull
	case "half":
		itf.Duplex = DuplexHalf
	case "--", "":
	default:
		complete = false
	}

	if s := cell(cells, idx[ifFieldSpeed]); s != "--" && s != "" {
		mbps, ok := parseSpeed(s)
		if !ok {
			complete = false
		}
		itf.SpeedMbps = mbps
	}

	switch v := strings.ToLower(cell(cells, idx[ifFieldVLAN])); v {
	case "--", "", "trunk", "routed":
	default:
		id, ok := parseDecimal(v, 4)
		if !ok || id < 1 || id > netdevcontract.MaxVLANID {
			complete = false
			break
		}
		itf.VLAN = uint16(id)
	}
	return itf, complete
}

// parseSpeed parses a speed cell: decimal Mbit/s ("1000"), or a decimal
// with an "M" or "G" unit ("100M", "10G"). The result is at most
// netdevcontract.MaxSpeedMbps; any other text is not recognised.
func parseSpeed(s string) (uint64, bool) {
	mult := uint64(1)
	switch {
	case strings.HasSuffix(s, "G"):
		s, mult = s[:len(s)-1], 1000
	case strings.HasSuffix(s, "M"):
		s = s[:len(s)-1]
	}
	n, ok := parseDecimal(s, speedMaxDigits)
	if !ok || n == 0 {
		return 0, false
	}
	mbps := uint64(n) * mult
	if mbps > netdevcontract.MaxSpeedMbps {
		return 0, false
	}
	return mbps, true
}

// ParseInterfaceDescriptions parses the output of "show interfaces
// description" on a CBS switch into a map from port name to description
// (empty for a port without one). The Description column is the last
// column and extends to the end of the line.
//
// The output rules are those of ParseInterfaces: limits, invalid UTF-8
// and control characters refuse the whole output; ErrNoTable,
// ErrUnrecognizedTable (no Port/Ch or no Description column) and
// ErrDuplicate are errors. A row with an unknown port name, a tab or text
// crossing a column gap is dropped and incomplete is true. A description
// that violates the text rule (e.g. U+FFFD) or is longer than
// netdevcontract.MaxLabelBytes is dropped: the port is kept with an
// empty description and incomplete is true; it is never truncated.
//
// At most netdevcontract.MaxInterfacesPerDevice ports are returned;
// further rows are not read and incomplete is true. On error the result
// is nil and incomplete is false.
func ParseInterfaceDescriptions(out []byte) (descs map[string]string, incomplete bool, err error) {
	const what = "show interfaces description"
	blocks, err := splitTables(out, what, tableMaxLines, func(titles []string) ([]int, error) {
		return columnIndex(titles, descriptionTitles, numIfFields, ifFieldName, ifFieldDescription)
	})
	if err != nil {
		return nil, false, err
	}
	descs = map[string]string{}
	lines := map[string]int{}
	for _, b := range blocks {
		idx := b.idx
		if b.lostRows {
			incomplete = true
		}
		for _, r := range b.rows {
			if netdevcontract.CheckCount("interfaces", len(descs)+1, netdevcontract.MaxInterfacesPerDevice) != nil {
				return descs, true, nil
			}
			if !r.ok || !validPortName(r.cells[idx[ifFieldName]]) {
				incomplete = true
				continue
			}
			name := r.cells[idx[ifFieldName]]
			if first, dup := lines[name]; dup {
				return nil, false, fmt.Errorf("cbsparse: %s line %d: port of line %d repeated: %w", what, r.line, first, ErrDuplicate)
			}
			lines[name] = r.line
			d := r.cells[idx[ifFieldDescription]]
			if !validLabel(d) {
				incomplete = true
				d = ""
			}
			descs[name] = d
		}
	}
	return descs, incomplete, nil
}

// MergeDescriptions returns a copy of ifaces with the descriptions from
// descs (the result of ParseInterfaceDescriptions) filled in. The input
// slice is not modified. incomplete is true when the two outputs do not
// cover the same ports: a port without a description entry, or a
// description for a port that is not in ifaces (such a description is
// not used).
func MergeDescriptions(ifaces []Interface, descs map[string]string) (merged []Interface, incomplete bool) {
	merged = make([]Interface, len(ifaces))
	copy(merged, ifaces)
	used := 0
	for i := range merged {
		d, ok := descs[merged[i].Name]
		if !ok {
			incomplete = true
			continue
		}
		merged[i].Description = d
		used++
	}
	if used != len(descs) {
		incomplete = true
	}
	return merged, incomplete
}
