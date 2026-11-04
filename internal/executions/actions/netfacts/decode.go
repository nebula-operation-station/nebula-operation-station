// SPDX-License-Identifier: AGPL-3.0-or-later

// Package netfacts decodes the result of the built-in net.facts read action
// (ADR 0009 D1, scripts/net_facts.sh). The result is a JSON document with
// one base64 section per fixed read-only command, like core.facts. Every
// byte is untrusted host data (spec 09): the document, every section and
// all sections together are bounded, the schema is strict, and each
// section is parsed by the bounded parsers of internal/netfacts.
//
// A section that was cut, skipped, not parseable or (for a required
// command) did not run makes the result Incomplete; it is never presented
// as an empty table. lldpcli and conntrack output has no parser yet and is
// kept as raw, bounded, untrusted bytes.
package netfacts

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	hostnet "github.com/nebula-operation-station/nebula-operation-station/internal/netfacts"
)

// Limits shared with scripts/net_facts.sh (section_max, total_max); a test
// in package actions keeps them equal.
const (
	// MaxSection bounds the decoded bytes of one section (256 KiB).
	MaxSection = 256 << 10
	// MaxTotal bounds the decoded bytes of all sections together, so the
	// base64 document stays below the executor's 1 MiB result limit.
	MaxTotal = 720 << 10
	// MaxDocument bounds the raw result document (hostrun.MaxResult).
	MaxDocument = 1 << 20
	// maxSectionB64 bounds the base64 text of one section.
	maxSectionB64 = (MaxSection + 2) / 3 * 4
)

// Format is the result format the script prints.
const Format = "net-facts-v1"

// ErrInvalidResult marks a result that does not follow the net.facts
// contract; nothing of it may be used.
var ErrInvalidResult = errors.New("invalid net.facts result")

// Status is how one section's command ended.
type Status string

// Section statuses.
const (
	// StatusOK: the command ran and exited 0; its stdout is the data.
	StatusOK Status = "ok"
	// StatusAbsent: the command is not installed on the host.
	StatusAbsent Status = "absent"
	// StatusFailed: the command exited non-zero (e.g. conntrack without
	// CAP_NET_ADMIN); there is no data.
	StatusFailed Status = "failed"
	// StatusSkipped: the total budget was spent; the command did not run.
	StatusSkipped Status = "skipped"
)

// Section names in script order.
const (
	SectionAddr       = "addr"
	SectionLink       = "link"
	SectionRoute      = "route"
	SectionRoute6     = "route6"
	SectionNeigh      = "neigh"
	SectionNeigh6     = "neigh6"
	SectionBridgeVLAN = "bridge_vlan"
	SectionLLDP       = "lldp"
	SectionSockets    = "sockets"
	SectionConntrack  = "conntrack"
)

// SectionNames lists every section in script order.
var SectionNames = []string{
	SectionAddr, SectionLink, SectionRoute, SectionRoute6, SectionNeigh, SectionNeigh6,
	SectionBridgeVLAN, SectionLLDP, SectionSockets, SectionConntrack,
}

// optional reports whether a section's tool is optional on a host: its
// absence or failure is not a loss of data.
func optional(name string) bool {
	return name == SectionBridgeVLAN || name == SectionLLDP || name == SectionConntrack
}

// Section is the state of one section.
type Section struct {
	Status Status
	// Truncated is true when the data was cut at its cap or the section
	// was skipped.
	Truncated bool
	// Invalid is true when an ok section's data was rejected by its
	// parser (for example JSON cut by truncation).
	Invalid bool
}

// Facts is a decoded net.facts result.
type Facts struct {
	// Sections holds the state of every section, keyed by SectionNames.
	Sections   map[string]Section
	Addrs      hostnet.AddrTable
	Links      hostnet.LinkTable
	Routes     hostnet.RouteTable
	Routes6    hostnet.RouteTable
	Neigh      hostnet.NeighborTable
	Neigh6     hostnet.NeighborTable
	BridgeVLAN hostnet.BridgeVLANTable
	// Sockets is the `ss -tinuaH` table; Process is always empty because
	// net.facts runs ss without -p (ADR 0009 Q3).
	Sockets hostnet.SocketTable
	// LLDP and Conntrack are the raw, unparsed and untrusted outputs of
	// `lldpcli -f json show neighbors` and `conntrack -L` (at most
	// MaxSection bytes each); nil unless their section is ok.
	LLDP      []byte
	Conntrack []byte

	tablesIncomplete bool
}

// Incomplete reports whether the result lost data: a section cut,
// skipped, unparseable, a required command absent or failed, or a parsed
// table that dropped entries. An incomplete result must be presented as
// such (spec 09).
func (f Facts) Incomplete() bool {
	if f.tablesIncomplete {
		return true
	}
	for name, s := range f.Sections {
		if s.Truncated || s.Invalid || s.Status == StatusSkipped {
			return true
		}
		if (s.Status == StatusAbsent || s.Status == StatusFailed) && !optional(name) {
			return true
		}
	}
	return false
}

type sectionDoc struct {
	Status    *string `json:"status"`
	Truncated *bool   `json:"truncated"`
	Data      *string `json:"data"`
}

type resultDoc struct {
	Format     string      `json:"format"`
	Phase      string      `json:"phase"`
	Addr       *sectionDoc `json:"addr"`
	Link       *sectionDoc `json:"link"`
	Route      *sectionDoc `json:"route"`
	Route6     *sectionDoc `json:"route6"`
	Neigh      *sectionDoc `json:"neigh"`
	Neigh6     *sectionDoc `json:"neigh6"`
	BridgeVLAN *sectionDoc `json:"bridge_vlan"`
	LLDP       *sectionDoc `json:"lldp"`
	Sockets    *sectionDoc `json:"sockets"`
	Conntrack  *sectionDoc `json:"conntrack"`
}

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidResult, fmt.Sprintf(format, a...))
}

// Decode decodes and parses a net.facts result. Every contract violation
// is an error wrapping ErrInvalidResult; a section the parsers reject is
// not an error but marks the result incomplete.
func Decode(raw []byte) (Facts, error) {
	if len(raw) > MaxDocument {
		return Facts{}, invalid("document exceeds %d bytes", MaxDocument)
	}
	var d resultDoc
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return Facts{}, invalid("document: %v", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return Facts{}, invalid("data after the document")
	}
	if d.Format != Format || d.Phase != "done" {
		return Facts{}, invalid("format %q phase %q", d.Format, d.Phase)
	}
	docs := map[string]*sectionDoc{
		SectionAddr: d.Addr, SectionLink: d.Link, SectionRoute: d.Route, SectionRoute6: d.Route6,
		SectionNeigh: d.Neigh, SectionNeigh6: d.Neigh6, SectionBridgeVLAN: d.BridgeVLAN,
		SectionLLDP: d.LLDP, SectionSockets: d.Sockets, SectionConntrack: d.Conntrack,
	}
	f := Facts{Sections: make(map[string]Section, len(SectionNames))}
	data := make(map[string][]byte, len(SectionNames))
	total := 0
	for _, name := range SectionNames {
		s, b, err := decodeSection(docs[name])
		if err != nil {
			return Facts{}, invalid("section %s: %v", name, err)
		}
		total += len(b)
		if total > MaxTotal {
			return Facts{}, invalid("sections exceed %d bytes", MaxTotal)
		}
		f.Sections[name] = s
		data[name] = b
	}
	f.parse(data)
	return f, nil
}

// decodeSection checks one section's schema and returns its data.
func decodeSection(d *sectionDoc) (Section, []byte, error) {
	if d == nil {
		return Section{}, nil, errors.New("missing")
	}
	if d.Status == nil || d.Truncated == nil || d.Data == nil {
		return Section{}, nil, errors.New("missing member")
	}
	s := Section{Status: Status(*d.Status), Truncated: *d.Truncated}
	switch s.Status {
	case StatusOK:
	case StatusAbsent, StatusFailed:
		if s.Truncated || *d.Data != "" {
			return Section{}, nil, fmt.Errorf("%s section with data or truncation", s.Status)
		}
		return s, nil, nil
	case StatusSkipped:
		if !s.Truncated || *d.Data != "" {
			return Section{}, nil, errors.New("skipped section with data or without truncation")
		}
		return s, nil, nil
	default:
		return Section{}, nil, errors.New("unknown status")
	}
	if len(*d.Data) > maxSectionB64 {
		return Section{}, nil, fmt.Errorf("data exceeds %d bytes", MaxSection)
	}
	b, err := strictBase64(*d.Data)
	if err != nil {
		return Section{}, nil, err
	}
	if len(b) > MaxSection {
		return Section{}, nil, fmt.Errorf("data exceeds %d bytes", MaxSection)
	}
	return s, b, nil
}

// strictBase64 decodes standard padded base64 with no other bytes: the
// standard decoder silently skips CR and LF.
func strictBase64(s string) ([]byte, error) {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '+', c == '/', c == '=':
		default:
			return nil, errors.New("data is not base64")
		}
	}
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, errors.New("data is not base64")
	}
	return b, nil
}

// parse fills the tables from the ok sections. A parser error marks the
// section invalid; its table stays empty and the result incomplete.
func (f *Facts) parse(data map[string][]byte) {
	usable := func(name string) bool { return f.Sections[name].Status == StatusOK }
	mark := func(name string, err error, tableIncomplete bool) {
		if err != nil {
			s := f.Sections[name]
			s.Invalid = true
			f.Sections[name] = s
			return
		}
		if tableIncomplete {
			f.tablesIncomplete = true
		}
	}
	if usable(SectionAddr) {
		t, err := hostnet.ParseAddrs(data[SectionAddr])
		f.Addrs = t
		mark(SectionAddr, err, t.Incomplete)
	}
	if usable(SectionLink) {
		t, err := hostnet.ParseLinks(data[SectionLink])
		f.Links = t
		mark(SectionLink, err, t.Incomplete)
	}
	if usable(SectionRoute) {
		t, err := hostnet.ParseRoutes(data[SectionRoute])
		f.Routes = t
		mark(SectionRoute, err, t.Incomplete)
	}
	if usable(SectionRoute6) {
		t, err := hostnet.ParseRoutes(data[SectionRoute6])
		f.Routes6 = t
		mark(SectionRoute6, err, t.Incomplete)
	}
	if usable(SectionNeigh) {
		t, err := hostnet.ParseNeigh(data[SectionNeigh])
		f.Neigh = t
		mark(SectionNeigh, err, t.Incomplete)
	}
	if usable(SectionNeigh6) {
		t, err := hostnet.ParseNeigh(data[SectionNeigh6])
		f.Neigh6 = t
		mark(SectionNeigh6, err, t.Incomplete)
	}
	if usable(SectionBridgeVLAN) {
		t, err := hostnet.ParseBridgeVLAN(data[SectionBridgeVLAN])
		f.BridgeVLAN = t
		mark(SectionBridgeVLAN, err, t.Incomplete)
	}
	if usable(SectionSockets) {
		t, err := hostnet.ParseSocketTable(data[SectionSockets])
		f.Sockets = t
		mark(SectionSockets, err, t.Incomplete)
	}
	if usable(SectionLLDP) {
		f.LLDP = data[SectionLLDP]
	}
	if usable(SectionConntrack) {
		f.Conntrack = data[SectionConntrack]
	}
}
