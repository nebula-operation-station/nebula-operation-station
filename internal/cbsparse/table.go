// SPDX-License-Identifier: AGPL-3.0-or-later

package cbsparse

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

// Limits of the fixed-width table lexer shared by the table parsers.
const (
	// tableMaxLines bounds the lines of one table output ("show vlan",
	// "show interfaces status", "show interfaces description"). The ADR
	// 0010 D3 table names a line limit only for configurations; this bound
	// leaves room for MaxVLANsPerDevice rows with several continuation
	// lines each and keeps line floods refused by a named limit. The
	// MaxCBSCommandOutputBytes transport cap applies as well.
	tableMaxLines = 5 * netdevcontract.MaxVLANsPerDevice
	// tableMaxHeaderLines bounds the title lines above one dash line.
	tableMaxHeaderLines = 3
	// tableMinFirstDashes is the minimum length of the first dash run of a
	// dash line, so that a short "--" is never taken for a table rule.
	tableMinFirstDashes = 3
)

var (
	// ErrNoTable reports output without any table (no dash line). Empty
	// output is this error: a table command that returned nothing did
	// not produce a dataset, which is distinct from an empty one.
	ErrNoTable = errors.New("cbsparse: no table in output")
	// ErrUnrecognizedTable reports a table whose header is missing,
	// misaligned or lacks a required column.
	ErrUnrecognizedTable = errors.New("cbsparse: unrecognized table header")
	// ErrDuplicate reports a key (VLAN ID, port name) that occurs in more
	// than one valid row of a table.
	ErrDuplicate = errors.New("cbsparse: duplicate table key")
)

// span is one column of a table: rune offsets, end exclusive. The last
// column of a table extends to the end of the line.
type span struct{ start, end int }

// tableRow is one non-blank line below a dash line.
type tableRow struct {
	line  int      // 1-based line number in the output
	cells []string // one trimmed cell per column
	// filled[i] is true when column i is not the last column and its text
	// reaches the last rune before the gap. Such a cell may be the start
	// of a value with an inner space that overflows into the next column
	// (the gap check cannot see a space), so a free-text cell that is
	// filled is ambiguous.
	filled []bool
	// ok is false when the line contains a tab or has text in a gap
	// between two columns; its cells are then not trustworthy and the
	// parsers drop it and mark the result incomplete.
	ok bool
	// lead is the trimmed text of the first column up to the first tab.
	// It is set for every row, also when ok is false, so that a parser
	// can tell whether a malformed line starts a new row (lead not empty)
	// or may continue the previous one.
	lead string
}

// tableBlock is one table: the normalised column titles and the rows up
// to the header of the next table (or the end of the output).
type tableBlock struct {
	titles []string
	rows   []tableRow
	// lostRows is true when a title line of this table does not look like
	// a title (see titleLike) and directly follows the rows of the
	// previous table: it may be a row of that table that was taken for a
	// title. The parsers mark the result incomplete.
	lostRows bool
}

// splitTables checks out against the CBS output limits and the text rule
// and splits it into fixed-width tables. A table starts at a dash line (a
// line that begins with at least tableMinFirstDashes dashes and contains
// only dash runs separated by spaces); the dash runs define the columns.
// Its titles are the up to tableMaxHeaderLines non-blank lines directly
// above the dash line, read column by column and joined top to bottom.
// Lines before the first table are ignored. Every non-blank line after a
// dash line up to the title lines of the next table is a row of that
// table. A title line of a later table that is not titleLike may be a row
// of the table before it; the table is then marked lostRows.
//
// Invalid UTF-8 or a control character anywhere refuses the whole output,
// as in ParseVersion. A missing table is ErrNoTable; a table without
// titles or with a title crossing a column gap is ErrUnrecognizedTable.
func splitTables(out []byte, what string) ([]tableBlock, error) {
	if err := netdevcontract.CheckLines(out, netdevcontract.MaxCBSCommandOutputBytes, tableMaxLines); err != nil {
		return nil, fmt.Errorf("cbsparse: %s: %w", what, err)
	}
	lines := strings.Split(string(out), "\n")
	var dashLines []int
	var cols [][]span
	for i := range lines {
		lines[i] = strings.TrimSuffix(lines[i], "\r")
		if err := checkLineText(lines[i]); err != nil {
			return nil, fmt.Errorf("cbsparse: %s line %d: %w", what, i+1, err)
		}
		if c, ok := dashColumns(lines[i]); ok {
			dashLines = append(dashLines, i)
			cols = append(cols, c)
		}
	}
	if len(dashLines) == 0 {
		return nil, fmt.Errorf("cbsparse: %s: %w", what, ErrNoTable)
	}

	// headerStart[k] is the first title line of table k.
	headerStart := make([]int, len(dashLines))
	for k, d := range dashLines {
		floor := 0
		if k > 0 {
			floor = dashLines[k-1] + 1
		}
		h := d
		for h > floor && d-h < tableMaxHeaderLines && strings.TrimSpace(lines[h-1]) != "" {
			h--
		}
		if h == d {
			return nil, fmt.Errorf("cbsparse: %s line %d: table without titles: %w", what, d+1, ErrUnrecognizedTable)
		}
		headerStart[k] = h
	}

	blocks := make([]tableBlock, len(dashLines))
	for k, d := range dashLines {
		titles := make([]string, len(cols[k]))
		lostRows := false
		for h := headerStart[k]; h < d; h++ {
			cells, _, ok := splitCells(lines[h], cols[k])
			if !ok {
				return nil, fmt.Errorf("cbsparse: %s line %d: misaligned title: %w", what, h+1, ErrUnrecognizedTable)
			}
			if k > 0 && !titleLike(lines[h]) {
				lostRows = true
			}
			for i, c := range cells {
				if c == "" {
					continue
				}
				if titles[i] != "" {
					titles[i] += " "
				}
				titles[i] += c
			}
		}
		for i := range titles {
			titles[i] = strings.ToLower(strings.Join(strings.Fields(titles[i]), " "))
		}
		end := len(lines)
		if k+1 < len(dashLines) {
			end = headerStart[k+1]
		}
		var rows []tableRow
		for i := d + 1; i < end; i++ {
			if strings.TrimSpace(lines[i]) == "" {
				continue
			}
			cells, filled, ok := splitCells(lines[i], cols[k])
			rows = append(rows, tableRow{line: i + 1, cells: cells, filled: filled, ok: ok, lead: leadText(lines[i], cols[k][0])})
		}
		blocks[k] = tableBlock{titles: titles, rows: rows, lostRows: lostRows}
	}
	return blocks, nil
}

// titleLike reports whether line looks like a column title line: letters
// and spaces only. Rows of the CBS tables carry port names, VLAN IDs,
// numbers or "--" markers, so a title line with any other rune may be a
// row of the table above it.
func titleLike(line string) bool {
	for _, r := range line {
		if r != ' ' && !unicode.IsLetter(r) {
			return false
		}
	}
	return true
}

// dashColumns reports whether line is a table rule and returns its
// columns.
func dashColumns(line string) ([]span, bool) {
	line = strings.TrimRight(line, " ")
	if !strings.HasPrefix(line, strings.Repeat("-", tableMinFirstDashes)) {
		return nil, false
	}
	var cols []span
	start := -1
	for i, r := range []rune(line) {
		switch {
		case r == '-' && start < 0:
			start = i
		case r == '-':
		case r == ' ' && start >= 0:
			cols = append(cols, span{start, i})
			start = -1
		case r == ' ':
		default:
			return nil, false
		}
	}
	cols = append(cols, span{start, len([]rune(line))})
	return cols, true
}

// splitCells cuts line into one trimmed cell per column. ok is false when
// the line contains a tab (which breaks column alignment) or any
// non-space rune in a gap between columns (text that crosses a column
// boundary, which would otherwise be silently split between two fields).
// Text left of the first column cannot occur: dash lines start at offset
// zero. The last column extends to the end of the line. filled reports
// for every column but the last whether its last rune is not a space (see
// tableRow.filled).
func splitCells(line string, cols []span) (cells []string, filled []bool, ok bool) {
	if strings.ContainsRune(line, '\t') {
		return nil, nil, false
	}
	r := []rune(line)
	cells = make([]string, len(cols))
	filled = make([]bool, len(cols))
	for i, c := range cols {
		if i > 0 {
			for p := cols[i-1].end; p < c.start && p < len(r); p++ {
				if r[p] != ' ' {
					return nil, nil, false
				}
			}
		}
		end := c.end
		if i == len(cols)-1 {
			end = len(r)
		} else {
			filled[i] = c.end <= len(r) && r[c.end-1] != ' '
		}
		lo, hi := min(c.start, len(r)), min(end, len(r))
		cells[i] = strings.TrimSpace(string(r[lo:hi]))
	}
	return cells, filled, true
}

// leadText returns the trimmed text of the first column of line, cut at
// the first tab.
func leadText(line string, first span) string {
	line, _, _ = strings.Cut(line, "\t")
	r := []rune(line)
	return strings.TrimSpace(string(r[:min(first.end, len(r))]))
}

// columnIndex maps the normalised titles of one table to field indexes.
// aliases maps every accepted title to a field; a field without a title
// gets -1. Two titles for one field are ErrUnrecognizedTable, and so is a
// missing field listed in required. Titles not in aliases are ignored.
func columnIndex(titles []string, aliases map[string]int, numFields int, required ...int) ([]int, error) {
	idx := make([]int, numFields)
	for i := range idx {
		idx[i] = -1
	}
	for col, t := range titles {
		f, known := aliases[t]
		if !known {
			continue
		}
		if idx[f] >= 0 {
			return nil, fmt.Errorf("column %d: field named twice: %w", col+1, ErrUnrecognizedTable)
		}
		idx[f] = col
	}
	for _, f := range required {
		if idx[f] < 0 {
			return nil, fmt.Errorf("required column missing: %w", ErrUnrecognizedTable)
		}
	}
	return idx, nil
}

// cell returns the cell of field index i, or "" when the table has no
// such column.
func cell(cells []string, i int) string {
	if i < 0 {
		return ""
	}
	return cells[i]
}

// parseDecimal parses 1 to maxDigits ASCII digits without a sign or a
// leading zero (a lone "0" is allowed).
func parseDecimal(s string, maxDigits int) (int, bool) {
	if s == "" || len(s) > maxDigits || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		n = n*10 + int(s[i]-'0')
	}
	return n, true
}

// validLabel reports whether s is a field value that satisfies the
// netdevcontract text rule and MaxLabelBytes.
func validLabel(s string) bool {
	return netdevcontract.CheckCount("label bytes", len(s), netdevcontract.MaxLabelBytes) == nil && validValueText(s)
}
