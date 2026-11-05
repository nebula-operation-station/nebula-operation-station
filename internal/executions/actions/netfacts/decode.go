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
// kept as raw, bounded, untrusted bytes that are valid UTF-8 text without
// control characters other than newline and tab.
//
// net.facts runs ss without -p (ADR 0009 Q3), so a sockets section that
// carries a users:((...)) column did not come from that command (a wrapped
// or replaced ss) and is refused: Sockets.Process is always empty.
package netfacts

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

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
	// StatusUnavailable: an IPv6 section whose command failed because the
	// host has IPv6 disabled (ipv6.disable=1, EAFNOSUPPORT); there is no
	// data and nothing is lost. Only route6 and neigh6 may carry it.
	StatusUnavailable Status = "unavailable"
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

// ipv6Section reports whether a section is an IPv6 table, which may be
// unavailable on a host with IPv6 disabled.
func ipv6Section(name string) bool {
	return name == SectionRoute6 || name == SectionNeigh6
}

// Section is the state of one section.
type Section struct {
	Status Status
	// Truncated is true when the data was cut at its cap or the section
	// was skipped.
	Truncated bool
	// Invalid is true when an ok section's data was rejected by its
	// parser (for example JSON cut by truncation), when raw LLDP or
	// conntrack text is not valid UTF-8 or carries control characters, or
	// when the sockets section carries a users:((...)) column.
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
	// net.facts runs ss without -p (ADR 0009 Q3): a section with a
	// users:((...)) column is refused (Invalid, empty table).
	Sockets hostnet.SocketTable
	// LLDP and Conntrack are the raw, unparsed and untrusted outputs of
	// `lldpcli -f json show neighbors` and `conntrack -L` (at most
	// MaxSection bytes each); nil unless their section is ok and valid
	// UTF-8 text with no control characters but newline and tab. A cut
	// section loses a trailing incomplete UTF-8 sequence.
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

// IPv6Unavailable reports whether the host has IPv6 disabled: both IPv6
// sections are unavailable.
func (f Facts) IPv6Unavailable() bool {
	return f.Sections[SectionRoute6].Status == StatusUnavailable &&
		f.Sections[SectionNeigh6].Status == StatusUnavailable
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

// maxInvalidDetail bounds the detail of an ErrInvalidResult message, so
// no error path (including encoding/json's own messages, which quote
// unknown field names and number literals) carries an unbounded amount of
// host-supplied text.
const maxInvalidDetail = 256

func invalid(format string, a ...any) error {
	detail := fmt.Sprintf(format, a...)
	if len(detail) > maxInvalidDetail {
		detail = strings.ToValidUTF8(detail[:maxInvalidDetail], "") + "..."
	}
	return fmt.Errorf("%w: %s", ErrInvalidResult, detail)
}

// Decode decodes and parses a net.facts result. Every contract violation
// is an error wrapping ErrInvalidResult; a section the parsers reject is
// not an error but marks the result incomplete.
func Decode(raw []byte) (Facts, error) {
	if len(raw) > MaxDocument {
		return Facts{}, invalid("document exceeds %d bytes", MaxDocument)
	}
	// encoding/json matches member names case-insensitively and lets the
	// last of two equal members win; the schema is exact. The key check
	// runs first, so the decoder never reports a host-supplied unknown
	// member name.
	if err := checkDocumentKeys(raw); err != nil {
		return Facts{}, invalid("document: %v", err)
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
		return Facts{}, invalid("format %s phase %s", quoteKey(d.Format), quoteKey(d.Phase))
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
		s, b, err := decodeSection(name, docs[name])
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
func decodeSection(name string, d *sectionDoc) (Section, []byte, error) {
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
	case StatusUnavailable:
		if !ipv6Section(name) {
			return Section{}, nil, errors.New("unavailable status on a section that is not IPv6")
		}
		if s.Truncated || *d.Data != "" {
			return Section{}, nil, errors.New("unavailable section with data or truncation")
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
	// jsonSection runs parse on an ok JSON section whose member names pass
	// the strict key check; a failing check marks the section invalid and
	// leaves its table empty.
	jsonSection := func(name string, parse func([]byte) (incomplete bool, err error)) {
		if !usable(name) {
			return
		}
		if err := checkSectionKeys(data[name]); err != nil {
			mark(name, err, false)
			return
		}
		incomplete, err := parse(data[name])
		mark(name, err, incomplete)
	}
	jsonSection(SectionAddr, func(b []byte) (bool, error) {
		t, err := hostnet.ParseAddrs(b)
		f.Addrs = t
		return t.Incomplete, err
	})
	jsonSection(SectionLink, func(b []byte) (bool, error) {
		t, err := hostnet.ParseLinks(b)
		f.Links = t
		return t.Incomplete, err
	})
	jsonSection(SectionRoute, func(b []byte) (bool, error) {
		t, err := hostnet.ParseRoutes(b)
		f.Routes = t
		return t.Incomplete, err
	})
	jsonSection(SectionRoute6, func(b []byte) (bool, error) {
		t, err := hostnet.ParseRoutes(b)
		f.Routes6 = t
		return t.Incomplete, err
	})
	jsonSection(SectionNeigh, func(b []byte) (bool, error) {
		t, err := hostnet.ParseNeigh(b)
		f.Neigh = t
		return t.Incomplete, err
	})
	jsonSection(SectionNeigh6, func(b []byte) (bool, error) {
		t, err := hostnet.ParseNeigh(b)
		f.Neigh6 = t
		return t.Incomplete, err
	})
	jsonSection(SectionBridgeVLAN, func(b []byte) (bool, error) {
		t, err := hostnet.ParseBridgeVLAN(b)
		f.BridgeVLAN = t
		return t.Incomplete, err
	})
	if usable(SectionSockets) {
		raw := data[SectionSockets]
		if bytes.Contains(raw, []byte("users:(")) {
			// ss ran without -p: process names here are not ss output.
			mark(SectionSockets, errors.New("users column without ss -p"), false)
		} else {
			t, err := hostnet.ParseSocketTable(raw)
			f.Sockets = t
			mark(SectionSockets, err, t.Incomplete)
			for _, e := range t.Entries {
				if e.Process != "" {
					f.Sockets = hostnet.SocketTable{}
					mark(SectionSockets, errors.New("process name without ss -p"), false)
					break
				}
			}
		}
	}
	if usable(SectionLLDP) {
		b, err := rawText(data[SectionLLDP], f.Sections[SectionLLDP].Truncated)
		f.LLDP = b
		mark(SectionLLDP, err, false)
	}
	if usable(SectionConntrack) {
		b, err := rawText(data[SectionConntrack], f.Sections[SectionConntrack].Truncated)
		f.Conntrack = b
		mark(SectionConntrack, err, false)
	}
}

// rawText checks an unparsed section: valid UTF-8 with no control or
// other non-printable characters except newline and tab. A cut section
// may end inside a multi-byte sequence; that incomplete tail is dropped.
// It returns nil and an error for anything else.
func rawText(b []byte, truncated bool) ([]byte, error) {
	if truncated {
		b = trimIncompleteRune(b)
	}
	if !utf8.Valid(b) {
		return nil, errors.New("not valid UTF-8")
	}
	for _, r := range string(b) {
		if r != '\n' && r != '\t' && !unicode.IsPrint(r) {
			return nil, fmt.Errorf("character %U", r)
		}
	}
	if b == nil {
		b = []byte{}
	}
	return b, nil
}

// trimIncompleteRune drops an incomplete UTF-8 sequence at the end of b.
func trimIncompleteRune(b []byte) []byte {
	for i := len(b) - 1; i >= 0 && i >= len(b)-utf8.UTFMax; i-- {
		if utf8.RuneStart(b[i]) {
			if !utf8.FullRune(b[i:]) {
				return b[:i]
			}
			break
		}
	}
	return b
}
