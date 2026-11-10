// SPDX-License-Identifier: AGPL-3.0-or-later

package cbsparse

import (
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

// tableParsers runs every table parser and returns only its error.
var tableParsers = []struct {
	name   string
	titles []string // titles of the required columns, in order
	parse  func([]byte) error
}{
	{"show vlan", []string{"Vlan", "Name", "Tagged Ports", "UnTagged Ports"}, func(b []byte) error {
		_, _, err := ParseVLANs(b)
		return err
	}},
	{"show interfaces status", []string{"Port", "Link State"}, func(b []byte) error {
		_, _, err := ParseInterfaces(b)
		return err
	}},
	{"show interfaces description", []string{"Port", "Description"}, func(b []byte) error {
		_, _, err := ParseInterfaceDescriptions(b)
		return err
	}},
}

// wideHeader returns a title line and a dash line with n columns of width
// w; the first columns carry titles, the others have no title.
func wideHeader(titles []string, n, w int) string {
	widths := make([]int, n)
	cells := make([]string, n)
	for i := range widths {
		widths[i] = w
	}
	copy(cells, titles)
	return fixedRow(widths, cells...) + dashRule(widths)
}

func TestSplitTablesColumnLimit(t *testing.T) {
	for _, p := range tableParsers {
		t.Run(p.name+" at the limit", func(t *testing.T) {
			in := wideHeader(p.titles, tableMaxColumns, 14)
			if err := p.parse([]byte(in)); err != nil {
				t.Fatalf("%d columns: %v", tableMaxColumns, err)
			}
		})
		t.Run(p.name+" over the limit", func(t *testing.T) {
			in := wideHeader(p.titles, tableMaxColumns+1, 14)
			err := p.parse([]byte(in))
			if !errors.Is(err, ErrUnrecognizedTable) || !errors.Is(err, netdevcontract.ErrOverLimit) {
				t.Fatalf("%d columns: err %v", tableMaxColumns+1, err)
			}
		})
	}
	t.Run("lexer", func(t *testing.T) {
		at := "x\n---" + strings.Repeat(" -", tableMaxColumns-1) + "\n"
		blocks, err := splitTables([]byte(at), "test", tableMaxLines, nil)
		if err != nil || len(blocks) != 1 || len(blocks[0].titles) != tableMaxColumns {
			t.Fatalf("at the limit: %+v, err %v", blocks, err)
		}
		over := "x\n---" + strings.Repeat(" -", tableMaxColumns) + "\n"
		if _, err := splitTables([]byte(over), "test", tableMaxLines, nil); !errors.Is(err, ErrUnrecognizedTable) {
			t.Fatalf("over the limit: err %v", err)
		}
	})
}

// fillRows appends row until out is close to MaxCBSCommandOutputBytes or
// the table line limit.
func fillRows(out, row string) []byte {
	var b strings.Builder
	b.WriteString(out)
	for n := strings.Count(out, "\n"); n < tableMaxLines-1 && b.Len()+len(row) <= netdevcontract.MaxCBSCommandOutputBytes; n++ {
		b.WriteString(row)
	}
	return []byte(b.String())
}

// allocDuring returns the bytes allocated by f and its wall time.
func allocDuring(f func()) (uint64, time.Duration) {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	start := time.Now()
	f()
	d := time.Since(start)
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc, d
}

func TestHostileWideTableHasBoundedCost(t *testing.T) {
	// Before tableMaxColumns a dash line of about 2000 one-rune columns
	// (the most MaxLineBytes allows) below a short title and 20000 short
	// rows cost rows x columns cell allocations: about 1 GiB and 4*10^7
	// iterations per parser. The limits allocate a small multiple of the
	// input size.
	const maxAlloc = 64 << 20
	const maxTime = 10 * time.Second // generous for -race on a slow runner
	row := strings.Repeat("1 ", 24) + "1\n"
	wide := "x\n---" + strings.Repeat(" -", (netdevcontract.MaxLineBytes-4)/2) + "\n"
	if len(wide) > netdevcontract.MaxLineBytes+2 {
		t.Fatalf("test dash line too long: %d", len(wide))
	}
	hostile := fillRows(wide, row)
	if len(hostile) < netdevcontract.MaxCBSCommandOutputBytes*9/10 {
		t.Fatalf("hostile input only %d bytes", len(hostile))
	}
	for _, p := range tableParsers {
		// The same with the required titles over 16-rune columns, then
		// one-rune columns up to MaxLineBytes: the titles are valid, so
		// only the column limit stops the rows from being split.
		widths := make([]int, len(p.titles))
		for i := range widths {
			widths[i] = 16
		}
		head := fixedRow(widths, p.titles...)
		rule := strings.TrimSuffix(dashRule(widths), "\n")
		rule += strings.Repeat(" -", (netdevcontract.MaxLineBytes-len(rule))/2) + "\n"
		titled := fillRows(head+rule, row)
		for _, h := range []struct {
			name string
			in   []byte
		}{{"wide dash line", hostile}, {"wide dash line with valid titles", titled}} {
			t.Run(p.name+" "+h.name, func(t *testing.T) {
				var err error
				alloc, d := allocDuring(func() { err = p.parse(h.in) })
				if alloc > maxAlloc || d > maxTime {
					t.Fatalf("allocated %d bytes in %v", alloc, d)
				}
				if !errors.Is(err, ErrUnrecognizedTable) || !errors.Is(err, netdevcontract.ErrOverLimit) {
					t.Fatalf("err %v", err)
				}
			})
		}
		t.Run(p.name+" valid titles at the column limit", func(t *testing.T) {
			// The worst case the limit admits: every row is split into
			// tableMaxColumns cells.
			in := fillRows(wideHeader(p.titles, tableMaxColumns, 14), "xxxx           yyyy            zzzz\n")
			var err error
			alloc, d := allocDuring(func() { err = p.parse(in) })
			if alloc > maxAlloc || d > maxTime {
				t.Fatalf("allocated %d bytes in %v", alloc, d)
			}
			if err != nil && !errors.Is(err, ErrDuplicate) {
				t.Fatalf("err %v", err)
			}
		})
		t.Run(p.name+" unknown titles", func(t *testing.T) {
			// A table that lacks the required columns is refused before
			// any of its rows is split into cells.
			in := fillRows(wideHeader([]string{"Foo"}, tableMaxColumns, 14), "xxxx           yyyy            zzzz\n")
			var err error
			alloc, d := allocDuring(func() { err = p.parse(in) })
			if alloc > 8<<20 || d > maxTime {
				t.Fatalf("allocated %d bytes in %v", alloc, d)
			}
			if !errors.Is(err, ErrUnrecognizedTable) {
				t.Fatalf("err %v", err)
			}
		})
	}
}
