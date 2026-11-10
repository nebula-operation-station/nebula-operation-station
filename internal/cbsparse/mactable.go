// SPDX-License-Identifier: AGPL-3.0-or-later

package cbsparse

import (
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

// Limits of the "show mac address-table" parser.
const (
	// macMaxLines bounds the lines of one "show mac address-table" output.
	// It is four times MaxMACEntriesPerDevice, so that a table somewhat
	// over the entry limit is still read up to the limit and marked
	// incomplete, while a line flood is refused by a named limit before
	// any row is split into cells. The MaxCBSCommandOutputBytes transport
	// cap applies as well and is reached first by tables of long lines.
	macMaxLines = 4 * netdevcontract.MaxMACEntriesPerDevice
	// macTextLen is the length of a MAC address in colon form.
	macTextLen = len("00:00:5e:00:53:00")
)

// MAC table fields.
const (
	macFieldVLAN = iota
	macFieldMAC
	macFieldPort
	macFieldType
	numMACFields
)

var macTitles = map[string]int{
	"vlan":        macFieldVLAN,
	"mac address": macFieldMAC,
	"mac":         macFieldMAC,
	"port":        macFieldPort,
	"type":        macFieldType,
}

// macNoPort lists the Port cells that name no front port: the switch's own
// address (*verify* in ND-03 against lab output). Such entries get an
// empty Port, as netdevcontract.MACEntry documents.
var macNoPort = map[string]struct{}{
	"0":   {},
	"CPU": {},
}

// macTypes maps the Type cell (compared case-insensitively) to an entry
// type. "self" and "management" (the switch's own address, *verify* in
// ND-03) are kept as MACOther; any other type drops the row.
var macTypes = map[string]netdevcontract.MACType{
	"dynamic":    netdevcontract.MACDynamic,
	"static":     netdevcontract.MACStatic,
	"self":       netdevcontract.MACOther,
	"management": netdevcontract.MACOther,
}

// macKey identifies one MAC table entry.
type macKey struct {
	vlan uint16
	mac  string
}

// ParseMACTable parses the output of "show mac address-table" on a CBS
// switch into netdevcontract.MACEntry values in output order.
//
// The input is untrusted device text (spec 09). Output limits (including
// macMaxLines), invalid UTF-8 and control characters refuse the whole
// output (see splitTables); output without a table is ErrNoTable, a table
// without the Vlan, Mac Address, Port and Type columns is
// ErrUnrecognizedTable.
//
// A row that cannot be read exactly is dropped and incomplete is true:
// text crossing a column gap, a tab, an empty VLAN cell (a wrapped or
// continuation line), a VLAN outside 1 to MaxVLANID or not in canonical
// decimal, a MAC that is not six colon-separated pairs of hex digits, an
// unknown port name or an unknown type. The MAC is returned in lower-case
// colon form. A title line of a later table that may be a row is dropped
// the same way (see splitTables).
//
// A (VLAN, MAC) pair that occurs in more than one readable row cannot be
// placed on one port with certainty: every row with that pair is dropped
// and incomplete is true, also when the rows are identical.
//
// At most netdevcontract.MaxMACEntriesPerDevice entries are returned; at
// the limit further rows are not returned and incomplete is true. ADR 0010
// D3 names no per-port MAC limit (an uplink can carry every address of the
// device), so the per-device limit is the only count limit. On error the
// result is nil and incomplete is false.
func ParseMACTable(out []byte) (entries []netdevcontract.MACEntry, incomplete bool, err error) {
	const what = "show mac address-table"
	blocks, err := splitTables(out, what, macMaxLines, func(titles []string) ([]int, error) {
		return columnIndex(titles, macTitles, numMACFields,
			macFieldVLAN, macFieldMAC, macFieldPort, macFieldType)
	})
	if err != nil {
		return nil, false, err
	}
	var rows []netdevcontract.MACEntry
	count := map[macKey]int{}
	for _, b := range blocks {
		if b.lostRows {
			incomplete = true
		}
		for _, r := range b.rows {
			e, ok := buildMACEntry(r, b.idx)
			if !ok {
				incomplete = true
				continue
			}
			rows = append(rows, e)
			count[macKey{e.VLAN, e.MAC}]++
		}
	}
	entries = make([]netdevcontract.MACEntry, 0, min(len(rows), netdevcontract.MaxMACEntriesPerDevice))
	for _, e := range rows {
		if count[macKey{e.VLAN, e.MAC}] > 1 {
			incomplete = true
			continue
		}
		if netdevcontract.CheckCount("mac entries", len(entries)+1, netdevcontract.MaxMACEntriesPerDevice) != nil {
			return entries, true, nil
		}
		entries = append(entries, e)
	}
	return entries, incomplete, nil
}

// buildMACEntry validates one table row.
func buildMACEntry(r tableRow, idx []int) (netdevcontract.MACEntry, bool) {
	if !r.ok {
		return netdevcontract.MACEntry{}, false
	}
	vlan, ok := parseDecimal(r.cells[idx[macFieldVLAN]], 4)
	if !ok || vlan < 1 || vlan > netdevcontract.MaxVLANID {
		return netdevcontract.MACEntry{}, false
	}
	mac, ok := normalizeMAC(r.cells[idx[macFieldMAC]])
	if !ok {
		return netdevcontract.MACEntry{}, false
	}
	port := r.cells[idx[macFieldPort]]
	if _, none := macNoPort[port]; none {
		port = ""
	} else if !validPortName(port) {
		return netdevcontract.MACEntry{}, false
	}
	typ, ok := macTypes[strings.ToLower(r.cells[idx[macFieldType]])]
	if !ok {
		return netdevcontract.MACEntry{}, false
	}
	return netdevcontract.MACEntry{VLAN: uint16(vlan), MAC: mac, Port: port, Type: typ}, true
}

// normalizeMAC accepts exactly six colon-separated pairs of hex digits in
// either case and returns them in lower case. Every other form (dashes,
// dots, single digits, missing or extra pairs, surrounding text) is
// refused.
func normalizeMAC(s string) (string, bool) {
	if len(s) != macTextLen {
		return "", false
	}
	b := []byte(s)
	for i, c := range b {
		if i%3 == 2 {
			if c != ':' {
				return "", false
			}
			continue
		}
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
			b[i] = c + ('a' - 'A')
		default:
			return "", false
		}
	}
	mac := string(b)
	if !netdevcontract.ValidMAC(mac) {
		return "", false
	}
	return mac, true
}
