// SPDX-License-Identifier: AGPL-3.0-or-later

package cbsparse

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

// Limits of the LLDP parsers.
const (
	// lldpMaxLines bounds the lines of one "show lldp neighbors" summary.
	// It is four times MaxLLDPNeighborsPerDevice, so that a summary over
	// the neighbor limit is still read up to the limit and marked
	// incomplete, while a line flood is refused before any row is split.
	lldpMaxLines = 4 * netdevcontract.MaxLLDPNeighborsPerDevice
	// lldpDetailMaxLines bounds the lines of one "show lldp neighbors
	// <if>" output. The detail parser does constant work per line and
	// keeps at most one neighbor per two lines, so the bound is the
	// transport cap itself: any neighbor can send frames, and a port
	// flooded with neighbors must end as incomplete at the per-port limit,
	// not as a refused output.
	lldpDetailMaxLines = netdevcontract.MaxCBSCommandOutputBytes
	// lldpMaxKeyBytes bounds the key of one "Key: value" detail line; the
	// longest CBS key is about 30 bytes.
	lldpMaxKeyBytes = 48
)

// ErrNoLLDPDetail reports "show lldp neighbors <if>" output without any
// neighbor block. The text CBS prints for a port without neighbors is
// not known (*verify* in ND-03), so such output is not read as "no
// neighbors": the summary table is the enumeration, the detail form only
// adds the management address and the full strings.
var ErrNoLLDPDetail = errors.New("cbsparse: no LLDP neighbor in detail output")

// LLDP summary table fields.
const (
	lldpFieldLocalPort = iota
	lldpFieldChassisID
	lldpFieldPortID
	lldpFieldSystemName
	lldpFieldCapabilities
	numLLDPFields
)

var lldpTitles = map[string]int{
	"port":                lldpFieldLocalPort,
	"local port":          lldpFieldLocalPort,
	"device id":           lldpFieldChassisID,
	"chassis id":          lldpFieldChassisID,
	"port id":             lldpFieldPortID,
	"system name":         lldpFieldSystemName,
	"capabilities":        lldpFieldCapabilities,
	"system capabilities": lldpFieldCapabilities,
}

// lldpCapLetters maps the legend letters of the summary table
// (case-sensitive: "r" is repeater, "R" router).
var lldpCapLetters = map[string]netdevcontract.LLDPCapability{
	"O": netdevcontract.CapOther,
	"r": netdevcontract.CapRepeater,
	"B": netdevcontract.CapBridge,
	"W": netdevcontract.CapWLANAP,
	"R": netdevcontract.CapRouter,
	"T": netdevcontract.CapTelephone,
	"C": netdevcontract.CapDOCSIS,
	"S": netdevcontract.CapStationOnly,
}

// lldpCapWords maps the lower-case capability names of the detail form.
var lldpCapWords = map[string]netdevcontract.LLDPCapability{
	"other":               netdevcontract.CapOther,
	"repeater":            netdevcontract.CapRepeater,
	"bridge":              netdevcontract.CapBridge,
	"wlan access point":   netdevcontract.CapWLANAP,
	"wlan-access-point":   netdevcontract.CapWLANAP,
	"router":              netdevcontract.CapRouter,
	"telephone":           netdevcontract.CapTelephone,
	"docsis cable device": netdevcontract.CapDOCSIS,
	"docsis-cable-device": netdevcontract.CapDOCSIS,
	"station":             netdevcontract.CapStationOnly,
	"station only":        netdevcontract.CapStationOnly,
	"station-only":        netdevcontract.CapStationOnly,
}

// ParseLLDPNeighbors parses the summary output of "show lldp neighbors"
// on a CBS switch: local port, chassis ID ("Device ID"), port ID, system
// name and capabilities. The summary has no management address; see
// ParseLLDPNeighborDetail.
//
// Everything but the local port was sent by an arbitrary device on the
// wire and is hostile text. Output limits (including lldpMaxLines),
// invalid UTF-8 and control or format characters (escape sequences, bidi
// overrides, zero-width runes) refuse the whole output (see
// splitTables); output without a table is ErrNoTable, a table without the
// Port, Device ID and Port ID columns is ErrUnrecognizedTable.
//
// A row that cannot be read exactly is dropped and incomplete is true:
// text crossing a column gap, a tab, an unknown local port name, a
// missing chassis or port ID, a chassis ID, port ID or system name that
// violates the text rule or MaxLabelBytes, or an unknown or repeated
// capability letter. A line with an empty Port cell may be the wrapped
// rest of a value of the row above it, so it drops that row as well.
//
// Duplicates and the per-port and per-device limits are applied as in
// CapLLDPNeighbors. On error the result is nil and incomplete is false.
//
// A hostile value with an inner space run can spill into the following
// cells of its own row; those cells (capabilities) are sent by the same
// neighbor, so this cannot attribute data to another port or neighbor.
func ParseLLDPNeighbors(out []byte) (neighbors []netdevcontract.LLDPNeighbor, incomplete bool, err error) {
	const what = "show lldp neighbors"
	blocks, err := splitTables(out, what, lldpMaxLines, func(titles []string) ([]int, error) {
		return columnIndex(titles, lldpTitles, numLLDPFields,
			lldpFieldLocalPort, lldpFieldChassisID, lldpFieldPortID)
	})
	if err != nil {
		return nil, false, err
	}
	var all []netdevcontract.LLDPNeighbor
	for _, b := range blocks {
		if b.lostRows {
			incomplete = true
		}
		// last is the index in all of the row the next line may continue,
		// or -1.
		last := -1
		for _, r := range b.rows {
			if r.lead == "" {
				// A continuation (wrapped value) or a malformed line
				// without a port: the row above it is not exact.
				incomplete = true
				if last >= 0 {
					all = append(all[:last], all[last+1:]...)
					last = -1
				}
				continue
			}
			last = -1
			n, ok := buildLLDPRow(r, b.idx)
			if !ok {
				incomplete = true
				continue
			}
			all = append(all, n)
			last = len(all) - 1
		}
	}
	neighbors, capped := CapLLDPNeighbors(all)
	return neighbors, incomplete || capped, nil
}

// buildLLDPRow validates one summary row.
func buildLLDPRow(r tableRow, idx []int) (netdevcontract.LLDPNeighbor, bool) {
	if !r.ok {
		return netdevcontract.LLDPNeighbor{}, false
	}
	n := netdevcontract.LLDPNeighbor{
		LocalPort:  r.cells[idx[lldpFieldLocalPort]],
		ChassisID:  r.cells[idx[lldpFieldChassisID]],
		PortID:     r.cells[idx[lldpFieldPortID]],
		SystemName: cell(r.cells, idx[lldpFieldSystemName]),
	}
	caps, ok := parseCapabilities(cell(r.cells, idx[lldpFieldCapabilities]), lldpCapLetters, false)
	if !ok || !validLLDPStrings(n) {
		return netdevcontract.LLDPNeighbor{}, false
	}
	n.Capabilities = caps
	return n, true
}

// validLLDPStrings checks the local port name and the remote strings of
// n: chassis and port ID are required, every remote string satisfies the
// netdevcontract text rule and MaxLabelBytes.
func validLLDPStrings(n netdevcontract.LLDPNeighbor) bool {
	return validPortName(n.LocalPort) &&
		n.ChassisID != "" && validLabel(n.ChassisID) &&
		n.PortID != "" && validLabel(n.PortID) &&
		validLabel(n.SystemName)
}

// parseCapabilities parses a comma-separated capability list. An empty
// list is valid and has no capabilities. With fold the names are
// compared in lower case with spaces collapsed (detail form); without it
// they are compared exactly (legend letters). Any unknown or repeated
// capability, or more than MaxLLDPCapabilities, refuses the list.
func parseCapabilities(s string, names map[string]netdevcontract.LLDPCapability, fold bool) ([]netdevcontract.LLDPCapability, bool) {
	if strings.TrimSpace(s) == "" {
		return nil, true
	}
	if netdevcontract.CheckCount("lldp capabilities", strings.Count(s, ",")+1, netdevcontract.MaxLLDPCapabilities) != nil {
		return nil, false
	}
	var caps []netdevcontract.LLDPCapability
	seen := map[netdevcontract.LLDPCapability]struct{}{}
	for tok := range strings.SplitSeq(s, ",") {
		tok = strings.Trim(tok, " ")
		if fold {
			tok = strings.ToLower(strings.Join(strings.Fields(tok), " "))
		}
		c, ok := names[tok]
		if !ok {
			return nil, false
		}
		if _, dup := seen[c]; dup {
			return nil, false
		}
		seen[c] = struct{}{}
		caps = append(caps, c)
	}
	return caps, true
}

// lldpKey identifies one neighbor on one local port.
type lldpKey struct{ local, chassis, port string }

// CapLLDPNeighbors applies the duplicate rule and the ADR 0010 D3 limits
// to parsed neighbors and reports whether anything was dropped. A
// (local port, chassis ID, port ID) triple that occurs more than once is
// not one exact neighbor: every copy is dropped. Of the rest, neighbors
// beyond netdevcontract.MaxLLDPNeighborsPerPort on one local port are
// dropped, and the result ends at netdevcontract.MaxLLDPNeighborsPerDevice
// neighbors. Order is kept.
//
// The parsers apply it to their own result; a caller that merges the
// detail outputs of several ports applies it again to the merged list.
// The result is never nil.
func CapLLDPNeighbors(ns []netdevcontract.LLDPNeighbor) (capped []netdevcontract.LLDPNeighbor, dropped bool) {
	count := make(map[lldpKey]int, len(ns))
	for _, n := range ns {
		count[lldpKey{n.LocalPort, n.ChassisID, n.PortID}]++
	}
	perPort := map[string]int{}
	capped = make([]netdevcontract.LLDPNeighbor, 0, min(len(ns), netdevcontract.MaxLLDPNeighborsPerDevice))
	for _, n := range ns {
		if count[lldpKey{n.LocalPort, n.ChassisID, n.PortID}] > 1 {
			dropped = true
			continue
		}
		if netdevcontract.CheckCount("lldp neighbors per port", perPort[n.LocalPort]+1, netdevcontract.MaxLLDPNeighborsPerPort) != nil {
			dropped = true
			continue
		}
		if netdevcontract.CheckCount("lldp neighbors", len(capped)+1, netdevcontract.MaxLLDPNeighborsPerDevice) != nil {
			return capped, true
		}
		perPort[n.LocalPort]++
		capped = append(capped, n)
	}
	return capped, dropped
}

// LLDP detail keys, normalised to lower case with single spaces.
const (
	lldpKeyChassisID  = "device id"
	lldpKeyChassisAlt = "chassis id"
	lldpKeyPortID     = "port id"
	lldpKeySystemName = "system name"
	lldpKeyCaps       = "capabilities"
	lldpKeyMgmtAddr   = "management address"
	lldpKeyLocalPort  = "local port"
)

// lldpBlock is one neighbor of the detail form while it is read.
type lldpBlock struct {
	n        netdevcontract.LLDPNeighbor
	seen     map[string]bool // kept keys already set
	bad      bool            // the neighbor is dropped
	lostAddr bool            // a management address was dropped
}

// ParseLLDPNeighborDetail parses the output of "show lldp neighbors
// <localPort>" on a CBS switch. localPort is the port the command was
// issued for (caller input, not device text); an unknown port name is an
// error. The detail form is a sequence of "Key: value" lines; every
// neighbor starts at a "Device ID" (or "Chassis ID") line. Port ID,
// System Name, Capabilities (names such as "Bridge, Router") and
// Management address are kept; other keys (descriptions, TTL, subtypes)
// are ignored, and so are lines before the first neighbor that carry no
// kept key. An optional "Local port" line must name localPort.
//
// Everything but the local port is hostile text sent by any device on
// the wire. Output limits, invalid UTF-8 and control or format characters
// refuse the whole output, as in ParseLLDPNeighbors. Output without a
// neighbor is ErrNoLLDPDetail.
//
// A neighbor that cannot be read exactly is dropped and incomplete is
// true: a missing chassis or port ID, a kept key given twice, a remote
// string that violates the text rule or MaxLabelBytes, an unknown or
// repeated capability, a "Local port" other than localPort, a kept key
// before the first neighbor, or a line without a key directly after a
// kept key (a wrapped value that would otherwise be cut silently). A
// management address that does not parse as an IP address without a zone
// (net/netip) is dropped, the neighbor is kept without it and incomplete
// is true; the first valid address is kept in canonical form and further
// valid ones are ignored (the contract carries one).
//
// A hostile description wrapped by the CLI can start a line with a kept
// key and so fake a value or a neighbor; any such line still belongs to
// the same local port, and a neighbor can claim that much by sending
// frames anyway. A faked repeat of a kept key drops the neighbor.
//
// Duplicates and the per-port limit are applied as in CapLLDPNeighbors.
// On error the result is nil and incomplete is false.
func ParseLLDPNeighborDetail(localPort string, out []byte) (neighbors []netdevcontract.LLDPNeighbor, incomplete bool, err error) {
	const what = "show lldp neighbors <if>"
	if !validPortName(localPort) {
		return nil, false, fmt.Errorf("cbsparse: %s: local port name is not a CBS port", what)
	}
	if err := netdevcontract.CheckLines(out, netdevcontract.MaxCBSCommandOutputBytes, lldpDetailMaxLines); err != nil {
		return nil, false, fmt.Errorf("cbsparse: %s: %w", what, err)
	}
	var blocks []*lldpBlock
	var cur *lldpBlock
	afterKept := false // the previous line set a kept key
	for i, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if err := checkLineText(line); err != nil {
			return nil, false, fmt.Errorf("cbsparse: %s line %d: %w", what, i+1, err)
		}
		if strings.TrimSpace(line) == "" {
			afterKept = false
			continue
		}
		key, value, isKey := detailKeyValue(line)
		if !isKey {
			if afterKept && cur != nil {
				cur.bad = true
			}
			continue
		}
		afterKept = false
		switch key {
		case lldpKeyChassisID, lldpKeyChassisAlt:
			cur = &lldpBlock{n: netdevcontract.LLDPNeighbor{LocalPort: localPort, ChassisID: value}, seen: map[string]bool{lldpKeyChassisID: true}}
			blocks = append(blocks, cur)
			afterKept = true
		case lldpKeyPortID, lldpKeySystemName, lldpKeyCaps, lldpKeyMgmtAddr, lldpKeyLocalPort:
			if cur == nil {
				incomplete = true
				continue
			}
			cur.set(key, value, localPort)
			afterKept = true
		}
	}
	if len(blocks) == 0 {
		return nil, false, fmt.Errorf("cbsparse: %s: %w", what, ErrNoLLDPDetail)
	}
	var all []netdevcontract.LLDPNeighbor
	for _, b := range blocks {
		if b.lostAddr {
			incomplete = true
		}
		if b.bad || !validLLDPStrings(b.n) {
			incomplete = true
			continue
		}
		all = append(all, b.n)
	}
	neighbors, capped := CapLLDPNeighbors(all)
	return neighbors, incomplete || capped, nil
}

// set stores one kept key of the block.
func (b *lldpBlock) set(key, value, localPort string) {
	if key == lldpKeyMgmtAddr {
		a, err := netip.ParseAddr(value)
		switch {
		case err != nil || a.Zone() != "":
			b.lostAddr = true
		case b.n.ManagementAddress == "":
			b.n.ManagementAddress = a.String()
		}
		return
	}
	if b.seen[key] {
		b.bad = true
		return
	}
	b.seen[key] = true
	switch key {
	case lldpKeyPortID:
		b.n.PortID = value
	case lldpKeySystemName:
		b.n.SystemName = value
	case lldpKeyCaps:
		caps, ok := parseCapabilities(value, lldpCapWords, true)
		if !ok {
			b.bad = true
		}
		b.n.Capabilities = caps
	case lldpKeyLocalPort:
		if value != localPort {
			b.bad = true
		}
	}
}

// detailKeyValue splits a "Key: value" line. The key is the text before
// the first colon: 1 to lldpMaxKeyBytes bytes that start with an ASCII
// letter and continue with ASCII letters, digits, spaces and "-./()" (as
// in "Auto-negotiation support" or "802.3 ..." lines of the detail form),
// returned in lower case with single spaces; the value is the rest with
// surrounding spaces removed (tabs are kept and fail the text rule).
// isKey is false for any other line.
func detailKeyValue(line string) (key, value string, isKey bool) {
	k, v, found := strings.Cut(line, ":")
	k = strings.Trim(k, " ")
	if !found || k == "" || len(k) > lldpMaxKeyBytes || !isASCIILetter(k[0]) {
		return "", "", false
	}
	for i := 1; i < len(k); i++ {
		c := k[i]
		if !isASCIILetter(c) && (c < '0' || c > '9') && !strings.ContainsRune(" -./()", rune(c)) {
			return "", "", false
		}
	}
	return strings.ToLower(strings.Join(strings.Fields(k), " ")), strings.Trim(v, " "), true
}

func isASCIILetter(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
