// SPDX-License-Identifier: AGPL-3.0-or-later

package panapi

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"unicode"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

// ErrInvalidConfig is returned when a well-formed configuration response
// carries content that violates the PAN-OS rules NOS relies on: a malformed
// or duplicated name, an address value that does not match its type, more
// than one vsys, and similar. The error never repeats device text.
var ErrInvalidConfig = errors.New("panapi: invalid configuration content")

// MaxParseResponseBytes is the byte cap the parsers apply before decoding:
// configuration responses are the largest PAN-OS responses (ADR 0010 D3).
const MaxParseResponseBytes = netdevcontract.MaxPANOSConfigResponseBytes

// supportedVsys is the only vsys NOS reads (ADR 0010 D3, Q2); it matches
// the fixed xpath anchor of request.go.
const supportedVsys = "vsys1"

// The types below are the element allowlist of ADR 0010 D4 (N7) for the
// object and zone subtrees. encoding/xml fills only the fields declared
// here: every other element is dropped together with its subtree and every
// attribute other than name and uuid is ignored. No field uses ",any",
// ",innerxml" or a catch-all, so unknown content cannot reach a caller.
// Single-valued elements are slices, or are decoded by UnmarshalXML with a
// duplicate check, so that a repeated element is refused instead of being
// merged into the first one.

// xmlResponse is the <response> root.
type xmlResponse struct {
	XMLName xml.Name    `xml:"response"`
	Status  string      `xml:"status,attr"`
	Result  []xmlResult `xml:"result"`
}

// xmlResult is <result>: either one <vsys> holding <entry name="vsys1">
// (a read of the whole vsys subtree) or the requested subtree containers
// directly (a read of one subtree). foreign counts child elements outside
// the allowlist, which are skipped.
type xmlResult struct {
	Vsys *xmlList[xmlVsysEntry]
	xmlSection
	foreign int
}

// UnmarshalXML decodes <result>, refusing a repeated <vsys> or subtree
// container.
func (r *xmlResult) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	return decodeChildren(d, func(se xml.StartElement) error {
		if se.Name.Local == "vsys" {
			if r.Vsys != nil {
				return errRepeated("vsys")
			}
			r.Vsys = new(xmlList[xmlVsysEntry])
			return d.DecodeElement(r.Vsys, &se)
		}
		known, err := r.decodeChild(d, se)
		if err == nil && !known {
			r.foreign++
		}
		return err
	})
}

// xmlVsysEntry is one <vsys><entry>.
type xmlVsysEntry struct {
	Name string
	xmlSection
}

// UnmarshalXML decodes one vsys entry, refusing a repeated subtree
// container.
func (e *xmlVsysEntry) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	for _, a := range start.Attr {
		if a.Name.Space == "" && a.Name.Local == "name" {
			e.Name = a.Value
		}
	}
	return decodeChildren(d, func(se xml.StartElement) error {
		_, err := e.decodeChild(d, se)
		return err
	})
}

// decodeChildren calls child for every direct child element of the element
// being decoded until its end element. child must consume the whole child
// element (DecodeElement or Skip).
func decodeChildren(d *xml.Decoder, child func(xml.StartElement) error) error {
	for {
		tok, err := d.Token()
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if err := child(t); err != nil {
				return err
			}
		case xml.EndElement:
			return nil
		}
	}
}

// errRepeated is the error for a repeated single-valued container; what is
// a fixed element name of the allowlist, never device text.
func errRepeated(what string) error {
	return fmt.Errorf("%w: %s repeated", ErrInvalidConfig, what)
}

// decodeChild decodes se into the matching subtree container of s. It
// returns false (after skipping se) for an element outside the allowlist
// and an error for a container that is already set.
func (s *xmlSection) decodeChild(d *xml.Decoder, se xml.StartElement) (bool, error) {
	switch se.Name.Local {
	case "zone":
		return true, decodeOnce(d, se, &s.Zone)
	case "address":
		return true, decodeOnce(d, se, &s.Address)
	case "address-group":
		return true, decodeOnce(d, se, &s.AddressGroup)
	case "service":
		return true, decodeOnce(d, se, &s.Service)
	case "service-group":
		return true, decodeOnce(d, se, &s.ServiceGroup)
	case "tag":
		return true, decodeOnce(d, se, &s.Tag)
	}
	return false, d.Skip()
}

// decodeOnce decodes se into a new *dst, or fails if *dst is already set.
func decodeOnce[T any](d *xml.Decoder, se xml.StartElement, dst **T) error {
	if *dst != nil {
		return errRepeated(se.Name.Local)
	}
	*dst = new(T)
	return d.DecodeElement(*dst, &se)
}

// xmlSection holds the allowlisted subtrees of one vsys; it is filled by
// decodeChild.
type xmlSection struct {
	Zone         *xmlList[xmlZone]
	Address      *xmlList[xmlAddress]
	AddressGroup *xmlList[xmlAddressGroup]
	Service      *xmlList[xmlService]
	ServiceGroup *xmlList[xmlServiceGroup]
	Tag          *xmlList[xmlTag]
}

// empty reports whether no allowlisted subtree is present.
func (s xmlSection) empty() bool {
	return s.Zone == nil && s.Address == nil && s.AddressGroup == nil &&
		s.Service == nil && s.ServiceGroup == nil && s.Tag == nil
}

// xmlList is a container of named <entry> elements.
type xmlList[T any] struct {
	Entries []T `xml:"entry"`
}

// xmlMembers is a list of <member> elements.
type xmlMembers struct {
	Members []string `xml:"member"`
}

// xmlZone is one zone entry: name and member interfaces only.
type xmlZone struct {
	Name    string `xml:"name,attr"`
	Network []struct {
		Layer3      []xmlMembers `xml:"layer3"`
		Layer2      []xmlMembers `xml:"layer2"`
		VirtualWire []xmlMembers `xml:"virtual-wire"`
		Tap         []xmlMembers `xml:"tap"`
	} `xml:"network"`
}

// xmlAddress is one address object. The value elements are slices so that
// a repeated or second value element is detected instead of overwritten.
type xmlAddress struct {
	Name        string       `xml:"name,attr"`
	IPNetmask   []string     `xml:"ip-netmask"`
	IPRange     []string     `xml:"ip-range"`
	IPWildcard  []string     `xml:"ip-wildcard"`
	FQDN        []string     `xml:"fqdn"`
	Description []string     `xml:"description"`
	Tag         []xmlMembers `xml:"tag"`
}

// xmlAddressGroup is one address group: static members or a dynamic filter.
type xmlAddressGroup struct {
	Name    string       `xml:"name,attr"`
	Static  []xmlMembers `xml:"static"`
	Dynamic []struct {
		Filter []string `xml:"filter"`
	} `xml:"dynamic"`
	Description []string     `xml:"description"`
	Tag         []xmlMembers `xml:"tag"`
}

// xmlPorts is the port specification of one service protocol.
type xmlPorts struct {
	Port       []string `xml:"port"`
	SourcePort []string `xml:"source-port"`
}

// xmlService is one service object.
type xmlService struct {
	Name     string `xml:"name,attr"`
	Protocol []struct {
		TCP  []xmlPorts `xml:"tcp"`
		UDP  []xmlPorts `xml:"udp"`
		SCTP []xmlPorts `xml:"sctp"`
	} `xml:"protocol"`
	Description []string     `xml:"description"`
	Tag         []xmlMembers `xml:"tag"`
}

// xmlServiceGroup is one service group.
type xmlServiceGroup struct {
	Name    string       `xml:"name,attr"`
	Members []xmlMembers `xml:"members"`
	Tag     []xmlMembers `xml:"tag"`
}

// xmlTag is one tag object; only its name is kept.
type xmlTag struct {
	Name string `xml:"name,attr"`
}

// decodeConfig is the shared decode step of every ND-09 parser. It
//
//  1. enforces the byte, UTF-8, depth, element and text limits with
//     netdevcontract.CheckXML before any decoding, which also refuses a
//     DTD and therefore every entity definition;
//  2. requires a <response status="success"> root (status="error" yields
//     an *APIError with the numeric code only);
//  3. decodes the allowlisted elements with a strict encoding/xml decoder
//     that knows no entities beyond the five XML ones and no charset other
//     than UTF-8;
//  4. refuses a repeated <result>, <vsys> or subtree container;
//  5. selects the content of the single supported vsys.
//
// incomplete is true when the response cannot be told apart from a
// configuration with missing data: a <vsys> without any entry, or a
// <result> whose child elements are all outside the allowlist. The section
// is then empty and must not be read as "no objects configured". An empty
// <result/> is a complete, empty configuration.
//
// Errors never contain response text.
func decodeConfig(data []byte) (sec xmlSection, incomplete bool, err error) {
	if err := netdevcontract.CheckXML(data, MaxParseResponseBytes); err != nil {
		if errors.Is(err, netdevcontract.ErrOverLimit) {
			// the limit error carries numbers only
			return xmlSection{}, false, fmt.Errorf("%w: %w", ErrXMLLimit, err)
		}
		return xmlSection{}, false, fmt.Errorf("%w: XML check failed", ErrMalformedResponse)
	}
	if err := checkResponse(data); err != nil {
		return xmlSection{}, false, err
	}
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = true
	// Entity stays nil and CharsetReader stays nil: only the predefined
	// entities and UTF-8 are accepted.
	var resp xmlResponse
	if err := dec.Decode(&resp); err != nil {
		if errors.Is(err, ErrInvalidConfig) {
			// a repeated container; the message holds fixed names only
			return xmlSection{}, false, err
		}
		return xmlSection{}, false, fmt.Errorf("%w: decode failed", ErrMalformedResponse)
	}
	if resp.Status != "success" {
		// checkResponse already enforced this; kept as defence in depth
		return xmlSection{}, false, fmt.Errorf("%w: status is not success", ErrMalformedResponse)
	}
	switch len(resp.Result) {
	case 0:
		return xmlSection{}, false, fmt.Errorf("%w: no result element", ErrMalformedResponse)
	case 1:
	default:
		return xmlSection{}, false, errRepeated("result")
	}
	r := resp.Result[0]
	if r.Vsys == nil {
		return r.xmlSection, r.xmlSection.empty() && r.foreign > 0, nil
	}
	if !r.xmlSection.empty() {
		return xmlSection{}, false, fmt.Errorf("%w: result mixes a vsys and subtree content", ErrInvalidConfig)
	}
	switch len(r.Vsys.Entries) {
	case 0:
		return xmlSection{}, true, nil
	case 1:
	default:
		return xmlSection{}, false, fmt.Errorf("%w: more than one vsys", ErrInvalidConfig)
	}
	if r.Vsys.Entries[0].Name != supportedVsys {
		return xmlSection{}, false, fmt.Errorf("%w: unsupported vsys", ErrInvalidConfig)
	}
	return r.Vsys.Entries[0].xmlSection, false, nil
}

// atMostOne returns the single value of an optional element. More than
// one occurrence is an error; none returns "".
func atMostOne(vs []string, what string) (string, error) {
	switch len(vs) {
	case 0:
		return "", nil
	case 1:
		return vs[0], nil
	}
	return "", fmt.Errorf("%w: %s repeated", ErrInvalidConfig, what)
}

// validText reports whether s is valid UTF-8 of at most limit bytes in
// which every rune is printable (the netdevcontract rule for untrusted
// text: no controls, format characters, line separators or U+FFFD).
func validText(s string, limit int) bool {
	if len(s) > limit || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r == utf8.RuneError || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// nameList validates a list of PAN-OS names (members, tags). Lists longer
// than limit are cut to limit and reported as truncated. Duplicates are
// refused.
func nameList(ms []xmlMembers, limit int, what string) (names []string, truncated bool, err error) {
	if len(ms) > 1 {
		return nil, false, fmt.Errorf("%w: %s repeated", ErrInvalidConfig, what)
	}
	if len(ms) == 0 || len(ms[0].Members) == 0 {
		return nil, false, nil
	}
	in := ms[0].Members
	if err := netdevcontract.CheckCount(what, len(in), limit); err != nil {
		in, truncated = in[:limit], true
	}
	seen := make(map[string]struct{}, len(in))
	names = make([]string, 0, len(in))
	for i, m := range in {
		if ValidateName(m) != nil {
			return nil, false, fmt.Errorf("%w: %s %d: invalid name", ErrInvalidConfig, what, i)
		}
		if _, dup := seen[m]; dup {
			return nil, false, fmt.Errorf("%w: %s %d: duplicated", ErrInvalidConfig, what, i)
		}
		seen[m] = struct{}{}
		names = append(names, m)
	}
	return names, truncated, nil
}
