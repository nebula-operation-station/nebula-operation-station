// SPDX-License-Identifier: AGPL-3.0-or-later

package csvimport

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// fixedMapping is the mapping used by most tests: id, display name, two
// endpoints, environment, criticality and tags.
var fixedMapping = Mapping{
	FieldID:          "id",
	FieldDisplayName: "server_name",
	EndpointField(1): "ip",
	EndpointField(2): "vpn_ip",
	FieldEnvironment: "env",
	FieldCriticality: "crit",
	FieldTags:        "tags",
}

const fixedHeader = "id,server_name,ip,vpn_ip,env,crit,tags"

func parseOK(t *testing.T, data string, m Mapping) *Result {
	t.Helper()
	res, err := Parse([]byte(data), m)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return res
}

func TestParseMapsColumns(t *testing.T) {
	res := parseOK(t, fixedHeader+"\nweb-1,Web one,10.0.0.11,10.9.0.11,PROD,HIGH,\"role=web,gpu=a2000\"\n", fixedMapping)
	if len(res.Rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(res.Rows))
	}
	row := res.Rows[0]
	if row.Number != 1 {
		t.Errorf("row number = %d, want 1", row.Number)
	}
	if len(row.Errors) != 0 {
		t.Fatalf("row errors = %v, want none", row.Errors)
	}
	h := row.Host
	if h.ID != "web-1" {
		t.Errorf("id = %q", h.ID)
	}
	if h.DisplayName != "Web one" {
		t.Errorf("display name = %q", h.DisplayName)
	}
	if h.Environment != "PROD" {
		t.Errorf("environment = %q", h.Environment)
	}
	if h.Criticality != "HIGH" {
		t.Errorf("criticality = %q", h.Criticality)
	}
	if len(h.Endpoints) != 2 || h.Endpoints[0].Address != "10.0.0.11" || h.Endpoints[1].Address != "10.9.0.11" {
		t.Errorf("endpoints = %+v", h.Endpoints)
	}
	if h.Tags["role"] != "web" || h.Tags["gpu"] != "a2000" || len(h.Tags) != 2 {
		t.Errorf("tags = %v", h.Tags)
	}
	if len(res.Columns) != 7 {
		t.Errorf("columns = %v", res.Columns)
	}
}

// The spec example: arbitrary column names, server_name -> display name,
// ip -> endpoint 1, vpn_ip -> endpoint 2.
func TestParseSpecExampleMapping(t *testing.T) {
	m := Mapping{
		FieldDisplayName: "server_name",
		EndpointField(1): "ip",
		EndpointField(2): "vpn_ip",
	}
	res := parseOK(t, "server_name,ip,vpn_ip\nweb1,10.0.0.5,10.9.0.5\n", m)
	if len(res.Rows) != 1 {
		t.Fatalf("rows = %d", len(res.Rows))
	}
	h := res.Rows[0].Host
	if h.DisplayName != "web1" || len(h.Endpoints) != 2 {
		t.Errorf("host = %+v", h)
	}
	// No id column mapped: the row must carry the validation error, not
	// silently stage an unusable host.
	if len(res.Rows[0].Errors) == 0 {
		t.Error("row without id mapping should have validation errors")
	}
}

func TestParseBOMStripped(t *testing.T) {
	res := parseOK(t, "\xef\xbb\xbf"+fixedHeader+"\nweb-1,Web one,10.0.0.11,,,,\n", fixedMapping)
	if len(res.Rows) != 1 || res.Rows[0].Host.ID != "web-1" {
		t.Fatalf("BOM not handled: %+v", res.Rows)
	}
}

func TestParseInvalidUTF8(t *testing.T) {
	_, err := Parse([]byte("id\nweb-1\xff\xfe\n"), Mapping{FieldID: "id"})
	if !errors.Is(err, ErrInvalidUTF8) {
		t.Fatalf("err = %v, want ErrInvalidUTF8", err)
	}
}

func TestParseFileTooLarge(t *testing.T) {
	data := make([]byte, MaxFileSize+1)
	for i := range data {
		data[i] = 'a'
	}
	_, err := Parse(data, Mapping{FieldID: "id"})
	if !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("err = %v, want ErrFileTooLarge", err)
	}
	// Exactly at the limit is not a size error (the one giant cell fails
	// per-row instead, which is the correct non-truncating behaviour).
	data = make([]byte, MaxFileSize)
	for i := range data {
		data[i] = 'a'
	}
	_, err = Parse(data, Mapping{FieldID: "id"})
	if errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("at-limit file: err = %v, want not ErrFileTooLarge", err)
	}
}

func TestParseTooManyRows(t *testing.T) {
	var b strings.Builder
	b.WriteString("id\n")
	for i := 0; i < MaxRows+1; i++ {
		fmt.Fprintf(&b, "h-%d\n", i)
	}
	_, err := Parse([]byte(b.String()), Mapping{FieldID: "id"})
	if !errors.Is(err, ErrTooManyRows) {
		t.Fatalf("err = %v, want ErrTooManyRows", err)
	}
	// Exactly at the limit is fine.
	b.Reset()
	b.WriteString("id\n")
	for i := 0; i < MaxRows; i++ {
		fmt.Fprintf(&b, "h-%d\n", i)
	}
	res, err := Parse([]byte(b.String()), Mapping{FieldID: "id"})
	if err != nil {
		t.Fatalf("at-limit: %v", err)
	}
	if len(res.Rows) != MaxRows {
		t.Fatalf("rows = %d, want %d", len(res.Rows), MaxRows)
	}
}

func TestParseTooManyColumns(t *testing.T) {
	header := make([]string, MaxColumns+1)
	for i := range header {
		header[i] = fmt.Sprintf("c%d", i)
	}
	_, err := Parse([]byte(strings.Join(header, ",")+"\n"), Mapping{FieldID: "c0"})
	if !errors.Is(err, ErrTooManyColumns) {
		t.Fatalf("err = %v, want ErrTooManyColumns", err)
	}
	header = header[:MaxColumns]
	if _, err := Parse([]byte(strings.Join(header, ",")+"\n"), Mapping{FieldID: "c0"}); err != nil {
		t.Fatalf("64 columns: %v", err)
	}
}

func TestParseCellTooLarge(t *testing.T) {
	// The pad column is not mapped, so an at-limit cell there produces no
	// errors at all; the oversized id cell produces a per-row error.
	header := "id,name,ip,env,crit,pad"
	m := Mapping{
		FieldID:          "id",
		FieldDisplayName: "name",
		EndpointField(1): "ip",
		FieldEnvironment: "env",
		FieldCriticality: "crit",
	}
	big := strings.Repeat("x", MaxCellSize+1)
	data := header + "\nok-1,small,10.0.0.1,DEV,LOW,\n" + big + ",big,10.0.0.2,DEV,LOW,\n"
	res := parseOK(t, data, m)
	if len(res.Rows) != 2 {
		t.Fatalf("rows = %d, want 2 (error, not truncation)", len(res.Rows))
	}
	if len(res.Rows[0].Errors) != 0 {
		t.Errorf("row 1 errors = %v", res.Rows[0].Errors)
	}
	if len(res.Rows[1].Errors) == 0 || !strings.Contains(res.Rows[1].Errors[0], "1 KiB") {
		t.Errorf("row 2 errors = %v, want a 1 KiB cell error", res.Rows[1].Errors)
	}
	// Exactly at the limit is fine.
	exact := strings.Repeat("x", MaxCellSize)
	res = parseOK(t, header+"\nok-1,small,10.0.0.1,DEV,LOW,"+exact+"\n", m)
	if len(res.Rows[0].Errors) != 0 {
		t.Errorf("at-limit cell errors = %v", res.Rows[0].Errors)
	}
}

func TestParseUnknownMappedColumn(t *testing.T) {
	_, err := Parse([]byte("id\nweb-1\n"), Mapping{FieldID: "missing"})
	if !errors.Is(err, ErrUnknownColumn) {
		t.Fatalf("err = %v, want ErrUnknownColumn", err)
	}
}

func TestParseUnknownField(t *testing.T) {
	_, err := Parse([]byte("id\nweb-1\n"), Mapping{Field("bogus"): "id"})
	if !errors.Is(err, ErrUnknownField) {
		t.Fatalf("err = %v, want ErrUnknownField", err)
	}
	// Endpoint fields above the inventory limit are unknown fields.
	_, err = Parse([]byte("id\nweb-1\n"), Mapping{EndpointField(MaxEndpoints + 1): "id"})
	if !errors.Is(err, ErrUnknownField) {
		t.Fatalf("err = %v, want ErrUnknownField for endpoint 17", err)
	}
}

func TestParseNoHeader(t *testing.T) {
	for _, data := range []string{"", "\n", "\xef\xbb\xbf"} {
		if _, err := Parse([]byte(data), Mapping{FieldID: "id"}); !errors.Is(err, ErrNoHeader) {
			t.Fatalf("data %q: err = %v, want ErrNoHeader", data, err)
		}
	}
}

func TestParseRowValidationErrors(t *testing.T) {
	cases := []struct {
		name    string
		row     string
		wantSub string
	}{
		{"bad id", "web 1,Name,10.0.0.11,,,,", "id"},
		{"bad environment", "web-1,Name,10.0.0.11,,,STAGE,", "environment"},
		{"bad criticality", "web-1,Name,10.0.0.11,,,HUGE,", "criticality"},
		{"bad endpoint", "web-1,Name,not an ip,,,,", "endpoint"},
		{"duplicate endpoints", "web-1,Name,10.0.0.11,10.0.0.11,,,", "duplicate"},
		{"display name too long", "web-1," + strings.Repeat("n", 129) + ",10.0.0.11,,,,", "display_name"},
		{"all empty row", ",,,,,,", "id"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := parseOK(t, fixedHeader+"\n"+tc.row+"\n", fixedMapping)
			if len(res.Rows) != 1 {
				t.Fatalf("rows = %d", len(res.Rows))
			}
			joined := strings.Join(res.Rows[0].Errors, "; ")
			if !strings.Contains(joined, tc.wantSub) {
				t.Fatalf("errors = %q, want substring %q", joined, tc.wantSub)
			}
		})
	}
}

func TestParseEndpointOrderAndGaps(t *testing.T) {
	// Endpoint 2 empty, endpoint 3 filled: order is preserved, the gap is
	// skipped.
	res := parseOK(t,
		"id,a,b,c\nweb-1,10.0.0.1,,10.0.0.3\n",
		Mapping{FieldID: "id", EndpointField(1): "a", EndpointField(2): "b", EndpointField(3): "c"})
	h := res.Rows[0].Host
	if len(h.Endpoints) != 2 || h.Endpoints[0].Address != "10.0.0.1" || h.Endpoints[1].Address != "10.0.0.3" {
		t.Fatalf("endpoints = %+v", h.Endpoints)
	}
}

func TestParseTags(t *testing.T) {
	cases := []struct {
		name    string
		cell    string
		want    map[string]string
		wantSub string
	}{
		{"two tags", "\"role=web,gpu=a2000\"", map[string]string{"role": "web", "gpu": "a2000"}, ""},
		{"missing equals", "novalue", nil, "missing '='"},
		{"empty key", "=web", nil, "empty key"},
		{"empty value", "role=", nil, "empty value"},
		{"duplicate key", "\"role=web,role=db\"", map[string]string{"role": "web"}, "duplicate"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := parseOK(t, "id,ip,env,crit,tags\nweb-1,10.0.0.1,DEV,LOW,"+tc.cell+"\n",
				Mapping{FieldID: "id", EndpointField(1): "ip", FieldEnvironment: "env", FieldCriticality: "crit", FieldTags: "tags"})
			row := res.Rows[0]
			if tc.wantSub == "" {
				if len(row.Errors) != 0 {
					t.Fatalf("errors = %v", row.Errors)
				}
				for k, v := range tc.want {
					if row.Host.Tags[k] != v {
						t.Fatalf("tags = %v, want %v", row.Host.Tags, tc.want)
					}
				}
				return
			}
			joined := strings.Join(row.Errors, "; ")
			if !strings.Contains(joined, tc.wantSub) {
				t.Fatalf("errors = %q, want substring %q", joined, tc.wantSub)
			}
		})
	}
}

func TestParseBlankLinesSkipped(t *testing.T) {
	res := parseOK(t, "id\nweb-1\n\nweb-2\n\n", Mapping{FieldID: "id"})
	if len(res.Rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(res.Rows))
	}
	if res.Rows[1].Number != 2 || res.Rows[1].Host.ID != "web-2" {
		t.Fatalf("rows = %+v", res.Rows)
	}
}

func TestParseQuotedCells(t *testing.T) {
	res := parseOK(t, "id,name\nweb-1,\"a,b \"\"c\"\"\"\n",
		Mapping{FieldID: "id", FieldDisplayName: "name"})
	if res.Rows[0].Host.DisplayName != `a,b "c"` {
		t.Fatalf("display name = %q", res.Rows[0].Host.DisplayName)
	}
}

func TestParseRowColumnMismatch(t *testing.T) {
	// Row 1 has one column (want seven), row 2 is complete and valid,
	// row 3 has one column.
	res := parseOK(t,
		fixedHeader+"\nweb-1\nweb-2,Two,10.0.0.22,,DEV,LOW,\nshort\n",
		fixedMapping)
	if len(res.Rows) != 3 {
		t.Fatalf("rows = %d, want 3", len(res.Rows))
	}
	joined := strings.Join(res.Rows[0].Errors, "; ")
	if !strings.Contains(joined, "column count") {
		t.Errorf("row 1 errors = %v, want a column count error", res.Rows[0].Errors)
	}
	if len(res.Rows[1].Errors) != 0 {
		t.Errorf("row 2 errors = %v, want none", res.Rows[1].Errors)
	}
	joined = strings.Join(res.Rows[2].Errors, "; ")
	if !strings.Contains(joined, "column count") {
		t.Errorf("row 3 errors = %v, want a column count error", res.Rows[2].Errors)
	}
}

func TestParseMalformedCSV(t *testing.T) {
	// A bare quote is a structural error: the file cannot be trusted.
	_, err := Parse([]byte("id,name\nweb-1,\"broken\n"), Mapping{FieldID: "id", FieldDisplayName: "name"})
	if err == nil {
		t.Fatal("bare quote: want error")
	}
	if errors.Is(err, ErrNoHeader) || errors.Is(err, ErrInvalidUTF8) {
		t.Fatalf("unexpected sentinel: %v", err)
	}
}

func TestParseNothingWritten(t *testing.T) {
	// Parse takes no store and no database handle: structurally nothing
	// can be written to the inventory. The staging list is the whole
	// result.
	res := parseOK(t, fixedHeader+"\nweb-1,Web one,10.0.0.11,,,,\n", fixedMapping)
	if res == nil || len(res.Rows) != 1 {
		t.Fatalf("staging list = %+v", res)
	}
}

func TestParseMultipleRowsMixed(t *testing.T) {
	res := parseOK(t,
		fixedHeader+"\n"+
			"web-1,One,10.0.0.11,,DEV,LOW,\n"+
			"bad id,Two,10.0.0.12,,DEV,LOW,\n"+
			"web-3,Three,10.0.0.13,,QA,MEDIUM,role=db\n",
		fixedMapping)
	if len(res.Rows) != 3 {
		t.Fatalf("rows = %d", len(res.Rows))
	}
	if len(res.Rows[0].Errors) != 0 || len(res.Rows[2].Errors) != 0 {
		t.Errorf("valid rows have errors: %v / %v", res.Rows[0].Errors, res.Rows[2].Errors)
	}
	if len(res.Rows[1].Errors) == 0 {
		t.Error("invalid row has no errors")
	}
}

func TestParseHeaderOnly(t *testing.T) {
	res := parseOK(t, fixedHeader+"\n", fixedMapping)
	if len(res.Rows) != 0 {
		t.Fatalf("rows = %d, want 0", len(res.Rows))
	}
}

// FuzzParse must never panic on arbitrary bytes (spec 09: parsers for
// untrusted data get fuzz tests).
func FuzzParse(f *testing.F) {
	seeds := [][]byte{
		[]byte(fixedHeader + "\nweb-1,Web one,10.0.0.11,10.9.0.11,PROD,HIGH,role=web\n"),
		[]byte("\xef\xbb\xbf" + fixedHeader + "\nweb-1,Web one,10.0.0.11,,,,\n"),
		[]byte("id\n"),
		[]byte("id,name\n\"unterminated,10.0.0.1\n"),
		[]byte{0xff, 0xfe, 0x00, 'a'},
		[]byte(""),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Parse(data, fixedMapping)
	})
}

// Sanity check that the fuzz target's fixed mapping is itself valid, so a
// regression in mapping validation is not masked by the fuzz harness.
func TestFuzzMappingIsValid(t *testing.T) {
	if _, err := Parse([]byte(fixedHeader+"\n"), fixedMapping); err != nil {
		t.Fatalf("fixed mapping invalid: %v", err)
	}
}
