// SPDX-License-Identifier: AGPL-3.0-or-later

// Package csvimport parses untrusted CSV files into a staging list of
// inventory hosts (spec 12, CSV import).
//
// The mapping assigns arbitrary CSV columns to inventory fields: display
// name, endpoint 1..n, environment, criticality, tags (and the host id,
// which a staged host needs to be importable). Nothing is written to the
// inventory: Parse returns a staging list with per-row errors and the
// caller decides what to import.
//
// Every value is untrusted input (spec 09): the file has hard limits that
// are errors, never truncation, and each staged row is validated with the
// inventory's own validation.
package csvimport

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/sshtransport"
)

// Limits (spec 09: maximum payload size, maximum object count, maximum
// field length). Exceeding any limit is an error, never truncation.
const (
	// MaxFileSize is the maximum size of the whole CSV file.
	MaxFileSize = 5 << 20 // 5 MiB
	// MaxRows is the maximum number of data rows (the header is not
	// counted).
	MaxRows = 10000
	// MaxColumns is the maximum number of columns in the header.
	MaxColumns = 64
	// MaxCellSize is the maximum size of a single cell in bytes.
	MaxCellSize = 1 << 10 // 1 KiB

	// MaxEndpoints is the maximum number of endpoint fields a mapping may
	// use. It matches the per-host endpoint limit of the inventory.
	MaxEndpoints = 16
)

// Sentinel errors for file-level problems. Row-level problems are reported
// per row in Result.Rows, not as errors.
var (
	// ErrFileTooLarge: the file exceeds MaxFileSize.
	ErrFileTooLarge = errors.New("csvimport: file exceeds 5 MiB")
	// ErrInvalidUTF8: the file is not valid UTF-8.
	ErrInvalidUTF8 = errors.New("csvimport: data is not valid UTF-8")
	// ErrTooManyRows: the file has more than MaxRows data rows.
	ErrTooManyRows = errors.New("csvimport: more than 10000 data rows")
	// ErrTooManyColumns: the header has more than MaxColumns columns.
	ErrTooManyColumns = errors.New("csvimport: more than 64 columns")
	// ErrUnknownColumn: a mapped column is not present in the header.
	ErrUnknownColumn = errors.New("csvimport: mapped column not found in header")
	// ErrUnknownField: the mapping uses a field that is not supported.
	ErrUnknownField = errors.New("csvimport: unknown mapping field")
	// ErrNoHeader: the file has no header row.
	ErrNoHeader = errors.New("csvimport: missing header row")
)

// Field is an inventory field that a CSV column can be mapped to.
type Field string

// Mappable fields. Endpoint fields are produced by EndpointField.
const (
	FieldID          Field = "id"
	FieldDisplayName Field = "display_name"
	FieldEnvironment Field = "environment"
	FieldCriticality Field = "criticality"
	FieldTags        Field = "tags"
)

// endpointPrefix is the prefix of the endpoint field names.
const endpointPrefix = "endpoint"

// EndpointField returns the field for the nth endpoint (1-based, up to
// MaxEndpoints).
func EndpointField(n int) Field {
	return Field(endpointPrefix + strconv.Itoa(n))
}

// Mapping assigns inventory fields to CSV columns by header name.
type Mapping map[Field]string

// Row is one staged host: the host built from the row's cells plus the
// per-row problems found while mapping and validating it. A row with a
// non-empty Errors list must not be imported.
type Row struct {
	// Number is the 1-based data row number (the header is not counted).
	Number int
	// Host is the host built from the row's cells.
	Host inventory.Host
	// Errors lists the problems found in this row.
	Errors []string
}

// Result is the staging list produced by Parse. Nothing here is written to
// the inventory; the caller decides what to import.
type Result struct {
	// Columns is the file's header row, for the mapping UI.
	Columns []string
	// Rows are the staged hosts in file order.
	Rows []Row
}

// bom is the UTF-8 byte order mark, stripped from the start of the file.
var bom = []byte{0xEF, 0xBB, 0xBF}

// validField reports whether f is a supported mapping field.
func validField(f Field) bool {
	switch f {
	case FieldID, FieldDisplayName, FieldEnvironment, FieldCriticality, FieldTags:
		return true
	}
	if strings.HasPrefix(string(f), endpointPrefix) {
		n, err := strconv.Atoi(string(f)[len(endpointPrefix):])
		return err == nil && n >= 1 && n <= MaxEndpoints
	}
	return false
}

// Parse parses data as a CSV file with the given mapping and returns the
// staging list. It never writes to the inventory.
//
// File-level problems (size, UTF-8, header, column count, row count,
// mapping, malformed CSV structure) are returned as errors. Row-level
// problems (cell size, column count of the row, and everything the
// inventory validation rejects) are reported per row.
func Parse(data []byte, mapping Mapping) (*Result, error) {
	return ParseWithDefaults(data, mapping, Defaults{})
}

// Defaults fill fields a row leaves empty (an unmapped column or an empty
// cell) before validation.
type Defaults struct {
	Environment inventory.Environment
	Criticality inventory.Criticality
}

// ParseWithDefaults is Parse with defaults for empty fields.
func ParseWithDefaults(data []byte, mapping Mapping, def Defaults) (*Result, error) {
	if len(data) > MaxFileSize {
		return nil, fmt.Errorf("%w: %d bytes", ErrFileTooLarge, len(data))
	}
	if !utf8.Valid(data) {
		return nil, ErrInvalidUTF8
	}
	data = bytes.TrimPrefix(data, bom)
	for f := range mapping {
		if !validField(f) {
			return nil, fmt.Errorf("%w: %q", ErrUnknownField, f)
		}
	}

	r := csv.NewReader(bytes.NewReader(data))
	r.FieldsPerRecord = -1 // column counts are checked explicitly below
	header, err := r.Read()
	if errors.Is(err, io.EOF) {
		return nil, ErrNoHeader
	}
	if err != nil {
		return nil, fmt.Errorf("csvimport: header: %w", err)
	}
	if len(header) == 0 {
		return nil, ErrNoHeader
	}
	if len(header) > MaxColumns {
		return nil, fmt.Errorf("%w: %d", ErrTooManyColumns, len(header))
	}

	colIndex := make(map[string]int, len(header))
	for i, c := range header {
		if _, ok := colIndex[c]; !ok {
			colIndex[c] = i
		}
	}
	fieldCol := make(map[Field]int, len(mapping))
	for f, col := range mapping {
		i, ok := colIndex[col]
		if !ok {
			return nil, fmt.Errorf("%w: %q (for field %q)", ErrUnknownColumn, col, f)
		}
		fieldCol[f] = i
	}

	res := &Result{Columns: header, Rows: []Row{}}
	seenID := map[string]int{} // host ID -> 1-based row number of first occurrence
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("csvimport: %w", err)
		}
		if len(rec) == 0 {
			continue // blank line
		}
		if len(res.Rows) >= MaxRows {
			return nil, fmt.Errorf("%w: at least %d", ErrTooManyRows, len(res.Rows)+1)
		}

		row := Row{Number: len(res.Rows) + 1, Host: inventory.Host{Tags: map[string]string{}}}
		if len(rec) != len(header) {
			row.Errors = append(row.Errors, fmt.Sprintf("column count %d, want %d", len(rec), len(header)))
			res.Rows = append(res.Rows, row)
			continue
		}
		for i, cell := range rec {
			if len(cell) > MaxCellSize {
				row.Errors = append(row.Errors, fmt.Sprintf("column %d (%s): cell exceeds 1 KiB", i+1, header[i]))
			}
		}

		h := &row.Host
		if i, ok := fieldCol[FieldID]; ok {
			h.ID = rec[i]
		}
		if h.ID != "" {
			// IDs are compared case-sensitively (they are lowercase by
			// validation anyway); empty IDs are not compared.
			if first, dup := seenID[h.ID]; dup {
				row.Errors = append(row.Errors, fmt.Sprintf("id %q is duplicated (first at row %d)", h.ID, first))
			} else {
				seenID[h.ID] = row.Number
			}
		}
		if i, ok := fieldCol[FieldDisplayName]; ok {
			h.DisplayName = rec[i]
		}
		if i, ok := fieldCol[FieldEnvironment]; ok {
			h.Environment = inventory.Environment(rec[i])
		}
		if i, ok := fieldCol[FieldCriticality]; ok {
			h.Criticality = inventory.Criticality(rec[i])
		}
		if h.Environment == "" {
			h.Environment = def.Environment
		}
		if h.Criticality == "" {
			h.Criticality = def.Criticality
		}
		h.Endpoints = []inventory.Endpoint{}
		for n := 1; n <= MaxEndpoints; n++ {
			if i, ok := fieldCol[EndpointField(n)]; ok && rec[i] != "" {
				ep, err := sshtransport.ParseEndpoint(rec[i])
				if err != nil {
					row.Errors = append(row.Errors, fmt.Sprintf("endpoint %d: %v", n, err))
					continue
				}
				h.Endpoints = append(h.Endpoints, inventory.Endpoint{Address: ep.Host, Port: int(ep.Port)})
			}
		}
		if i, ok := fieldCol[FieldTags]; ok && rec[i] != "" {
			h.Tags, row.Errors = mergeTags(h.Tags, row.Errors, rec[i])
		}

		var verr *inventory.ValidationError
		if errors.As(inventory.Validate(*h), &verr) {
			row.Errors = append(row.Errors, verr.Problems...)
		}
		res.Rows = append(res.Rows, row)
	}
	return res, nil
}

// mergeTags parses a tags cell (comma-separated key=value pairs) into the
// row's tag map, appending problems to errs.
func mergeTags(tags map[string]string, errs []string, cell string) (map[string]string, []string) {
	for _, part := range strings.Split(cell, ",") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			errs = append(errs, fmt.Sprintf("tag %q: missing '='", part))
			continue
		}
		if k == "" {
			errs = append(errs, fmt.Sprintf("tag %q: empty key", part))
			continue
		}
		if v == "" {
			errs = append(errs, fmt.Sprintf("tag %q: empty value", part))
			continue
		}
		if _, dup := tags[k]; dup {
			errs = append(errs, fmt.Sprintf("tag %q: duplicate key", k))
			continue
		}
		tags[k] = v
	}
	return tags, errs
}
