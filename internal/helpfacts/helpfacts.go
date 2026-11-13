// SPDX-License-Identifier: AGPL-3.0-or-later

// Package helpfacts projects the minimised, fixed set of inventory facts
// the help assistant may put into a prompt (ADR 0014 D3, AS-06).
//
// Only hosts that the question names (an address or CIDR literal of an
// endpoint, or a name or ID literal) and that the caller's Visibility
// check admits are projected. The output is the fixed struct Fact and
// nothing else; no other store is reachable from this package. Every
// host value is untrusted: text is cleaned and marked, enums are
// validated, and the total size is bounded by MaxFactBytes.
package helpfacts

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"time"
)

// Limits enforced by Project. They are the AS-06 bounds of ADR 0014 D3.
const (
	// MaxFactHosts is the maximum number of hosts in one projection.
	MaxFactHosts = 10
	// MaxFactBytes is the maximum payload of one projection. It counts the
	// text of every field, the port digits and the enrollment date as
	// RFC 3339 (the default JSON encoding of the date), but not JSON keys
	// or punctuation.
	MaxFactBytes = 4 << 10
	// MaxNamedCandidates bounds the hosts one question may select before the
	// Visibility check runs: MaxFactHosts plus a small slack. Each candidate
	// costs one authorisation lookup, so a /16 or a common word cannot cause
	// unbounded lookups. Candidates beyond the bound are not checked and set
	// Truncated.
	MaxNamedCandidates = MaxFactHosts + 10
	// MaxQuestionBytes is the largest question Project scans.
	MaxQuestionBytes = 2 << 10
	// MaxEndpoints is the maximum number of endpoints shown per host.
	MaxEndpoints = 4
	// MaxSourceAddresses is the maximum number of NOS source addresses.
	MaxSourceAddresses = 4
	// MaxIDBytes bounds the host ID text.
	MaxIDBytes = 64
	// MaxNameBytes bounds the display name (ADR 0014 D3: name ≤ 64 bytes).
	MaxNameBytes = 64
	// MaxLabelBytes bounds an endpoint label such as "lan" or "vpn".
	MaxLabelBytes = 16
	// MaxOSBytes bounds the OS family and release (ADR 0014 D3: ≤ 32 bytes).
	MaxOSBytes = 32
	// MaxAddressBytes bounds an endpoint address: a canonical IP or a DNS
	// name (DNS limit).
	MaxAddressBytes = 253
)

// minEnrollmentYear is the earliest enrollment year Project accepts.
const minEnrollmentYear = 2000

// Sentinel errors callers branch on.
var (
	// ErrNoVisibility is returned when Request.Visible is nil. Projection
	// fails closed rather than showing every host.
	ErrNoVisibility = errors.New("helpfacts: no visibility check")
	// ErrNoSource is returned when Request.Source is nil.
	ErrNoSource = errors.New("helpfacts: no inventory source")
	// ErrQuestionTooLong is returned for a question above MaxQuestionBytes.
	ErrQuestionTooLong = errors.New("helpfacts: question too long")
	// ErrInvalidSourceAddress is returned for a NOS source address that is
	// not an IP address. It is an admin setting, so it is a hard error.
	ErrInvalidSourceAddress = errors.New("helpfacts: invalid NOS source address")
	// ErrTooManySourceAddresses is returned for more than
	// MaxSourceAddresses NOS source addresses.
	ErrTooManySourceAddresses = errors.New("helpfacts: too many NOS source addresses")
)

// EnrollmentState is the enrollment state of a host (ADR 0014 D3).
type EnrollmentState string

// The enrollment states of ADR 0014 D3. Any other input becomes
// EnrollmentUnknown.
const (
	EnrollmentUnknown          EnrollmentState = "unknown"
	EnrollmentNotEnrolled      EnrollmentState = "not_enrolled"
	EnrollmentScriptRunUnknown EnrollmentState = "script_run_unknown"
	EnrollmentHostKeyPinned    EnrollmentState = "host_key_pinned"
	EnrollmentLoginTestOK      EnrollmentState = "login_test_ok"
	EnrollmentBlocked          EnrollmentState = "blocked_key_changed"
)

// Text is a value taken from inventory or host data. Altered reports
// that the value was cleaned (non-printable characters replaced, whitespace
// collapsed, bytes dropped, cut to length, or the input was too long to
// scan). Text is data: it is never an instruction and is rendered as plain
// text only.
type Text struct {
	Value   string
	Altered bool
}

// Endpoint is one validated address of a host. Port 0 means the stored
// port was not a valid port number; the address itself is still in the
// inventory.
type Endpoint struct {
	Address string
	Port    int
	Label   Text
}

// Fact is the fixed projection of one host. It has no other fields.
// InventoryCriticality and ExecutorCriticality are the two values of
// ADR 0014 D3, each labelled by its field: they may differ. An empty value
// means not set or not a known class.
type Fact struct {
	ID                   Text
	Name                 Text
	Endpoints            []Endpoint
	EndpointsDropped     int
	InventoryCriticality string
	ExecutorCriticality  string
	Enrollment           EnrollmentState
	EnrollmentSince      time.Time
	OSFamily             Text
	OSRelease            Text
}

// RawEndpoint is an endpoint as stored, before validation.
type RawEndpoint struct {
	Address string
	Port    int
	Label   string
}

// Record is a host as the caller supplies it. All fields are untrusted
// input and are validated by Project before use.
type Record struct {
	ID                   string
	DisplayName          string
	Endpoints            []RawEndpoint
	InventoryCriticality string
	ExecutorCriticality  string
	Enrollment           EnrollmentState
	EnrollmentSince      time.Time
	OSFamily             string
	OSRelease            string
}

// Source lists the hosts of the inventory. It is the only I/O of this
// package and the only route to host data.
type Source interface {
	// Hosts returns every host of the inventory.
	Hosts(ctx context.Context) ([]Record, error)
}

// Visibility reports whether the current user may see the host with
// the given ID. Callers pass the check the inventory page uses; this
// package does not implement its own. An error means the check failed
// and nothing is projected.
type Visibility func(ctx context.Context, hostID string) (bool, error)

// Request is one projection request.
type Request struct {
	// Question is the user's question, scanned for literals only.
	Question string
	// Source lists the inventory.
	Source Source
	// Visible is the inventory page's authorisation check.
	Visible Visibility
	// SourceAddresses are the admin-set NOS source addresses (ADR 0014
	// Q6). They are included only when the question names a host.
	SourceAddresses []string
	// Now is the clock used to reject future enrollment dates. Nil means
	// time.Now.
	Now func() time.Time
}

// Result is the projection. Hosts are sorted by ID.
type Result struct {
	Hosts []Fact
	// NotInInventory lists canonical addresses from the question that
	// no visible host has as an endpoint.
	NotInInventory []string
	// SourceAddresses are the validated NOS source addresses.
	SourceAddresses []string
	// Truncated reports that hosts, literals or bytes were left out.
	Truncated bool
}

// Project selects the hosts the question names and returns their fixed
// facts. Visible is called only for hosts the question names. A host the
// Visibility check rejects contributes nothing to the result: for a
// question that names only hidden hosts the result is the same as for a
// question naming hosts that do not exist.
func Project(ctx context.Context, req Request) (Result, error) {
	if req.Visible == nil {
		return Result{}, ErrNoVisibility
	}
	if req.Source == nil {
		return Result{}, ErrNoSource
	}
	if len(req.Question) > MaxQuestionBytes {
		return Result{}, ErrQuestionTooLong
	}
	sources, err := normaliseSourceAddresses(req.SourceAddresses)
	if err != nil {
		return Result{}, err
	}
	lits, litTruncated := parseLiterals(req.Question)
	if len(lits) == 0 {
		return Result{Truncated: litTruncated}, nil
	}
	now := time.Now
	if req.Now != nil {
		now = req.Now
	}
	ms := newMatchSet(lits)
	records, err := req.Source.Hosts(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("helpfacts: list hosts: %w", err)
	}

	// Only hosts the question names are checked: a host that no literal
	// selects is never visible to Visible and never projected. Candidates
	// are taken in ID order, so the bound does not depend on inventory order.
	var candidates []Record
	for _, r := range records {
		if ms.selectsHost(r) {
			candidates = append(candidates, r)
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].ID < candidates[j].ID })
	var res Result
	res.Truncated = litTruncated
	capped := len(candidates) > MaxNamedCandidates
	if capped {
		candidates = candidates[:MaxNamedCandidates]
		res.Truncated = true
	}
	var matched []Record
	for i, r := range candidates {
		ok, err := req.Visible(ctx, r.ID)
		if err != nil {
			return Result{}, fmt.Errorf("helpfacts: check visibility of named host %d: %w", i, err)
		}
		if ok {
			matched = append(matched, r)
		}
	}

	used := 0
	for _, r := range matched {
		if len(res.Hosts) == MaxFactHosts {
			res.Truncated = true
			break
		}
		f := buildFact(r, ms, now().UTC())
		n := factBytes(f)
		if used+n > MaxFactBytes {
			res.Truncated = true
			continue
		}
		used += n
		res.Hosts = append(res.Hosts, f)
	}
	// NotInInventory needs every candidate checked: when the bound cut the
	// list, an address may be held by an unchecked host, so nothing is said.
	if !capped {
		for _, s := range ms.addressesNotIn(matched) {
			if len(res.NotInInventory) == MaxFactHosts || used+len(s) > MaxFactBytes {
				res.Truncated = true
				break
			}
			used += len(s)
			res.NotInInventory = append(res.NotInInventory, s)
		}
	}
	if len(res.Hosts) == 0 && len(res.NotInInventory) == 0 {
		// Nothing the user may see or that the question names as absent:
		// no facts at all, not even the NOS source addresses.
		return Result{Truncated: res.Truncated}, nil
	}
	for _, s := range sources {
		if used+len(s) > MaxFactBytes {
			res.Truncated = true
			break
		}
		used += len(s)
		res.SourceAddresses = append(res.SourceAddresses, s)
	}
	return res, nil
}

// matchSet is the question's literals indexed for matching.
type matchSet struct {
	addrs map[string]bool // canonical IP strings
	order []string        // canonical IP strings in order of appearance
	cidrs []*net.IPNet
	names map[string]bool // ASCII-lowercased names and IDs
	// identNames are the name literals specific enough to match a display
	// name: they contain a digit, hyphen, dot or underscore.
	identNames map[string]bool
}

// identifierLike reports whether a name literal is at least as specific as
// a host ID: it contains a digit, hyphen, dot or underscore. Ordinary words
// such as "is", "up" or "database" are not identifier-like.
func identifierLike(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' {
			return true
		}
	}
	return false
}

// newMatchSet indexes the literals of a question.
func newMatchSet(lits []literal) *matchSet {
	ms := &matchSet{addrs: map[string]bool{}, names: map[string]bool{}, identNames: map[string]bool{}}
	for _, l := range lits {
		switch l.kind {
		case litAddress:
			s := l.ip.String()
			if !ms.addrs[s] {
				ms.addrs[s] = true
				ms.order = append(ms.order, s)
			}
		case litCIDR:
			ms.cidrs = append(ms.cidrs, l.network)
		default:
			folded := asciiLower(l.name)
			ms.names[folded] = true
			if identifierLike(folded) {
				ms.identNames[folded] = true
			}
		}
	}
	return ms
}

// addressSelected reports whether a literal selects the IP address ip.
func (ms *matchSet) addressSelected(ip net.IP) bool {
	if ms.addrs[ip.String()] {
		return true
	}
	for _, n := range ms.cidrs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// nameSelected reports whether a name literal equals s. Only ASCII
// letters are folded, and s must be ASCII.
func (ms *matchSet) nameSelected(s string) bool {
	folded, ok := asciiName(s)
	return ok && ms.names[folded]
}

// selectsHost reports whether a literal selects the host. It reads only
// the endpoint addresses and the ID and display name needed for matching;
// the result is a boolean and no other host field leaves this function.
func (ms *matchSet) selectsHost(r Record) bool {
	for _, ep := range r.Endpoints {
		if ip := net.ParseIP(ep.Address); ip != nil && ms.addressSelected(ip) {
			return true
		}
	}
	// A display name selects only through an identifier-like literal, so a
	// host whose display name is a common word is not selected by it.
	if ms.nameSelected(r.ID) {
		return true
	}
	folded, ok := asciiName(r.DisplayName)
	return ok && ms.identNames[folded]
}

// addressesNotIn returns the question's address literals that no host in
// visible has as an endpoint, in order of appearance. CIDR literals never
// appear here.
func (ms *matchSet) addressesNotIn(visible []Record) []string {
	have := make(map[string]bool)
	for _, r := range visible {
		for _, ep := range r.Endpoints {
			if ip := net.ParseIP(ep.Address); ip != nil {
				have[ip.String()] = true
			}
		}
	}
	var out []string
	for _, s := range ms.order {
		if !have[s] {
			out = append(out, s)
		}
	}
	return out
}

// buildFact turns a visible record into the fixed struct, validating
// every field. Endpoints that the question names come first, so the
// address the user asked about is shown; the rest follow in stored order.
func buildFact(r Record, ms *matchSet, now time.Time) Fact {
	f := Fact{
		ID:                   cleanText(r.ID, MaxIDBytes),
		Name:                 cleanText(r.DisplayName, MaxNameBytes),
		InventoryCriticality: validCriticality(r.InventoryCriticality),
		ExecutorCriticality:  validCriticality(r.ExecutorCriticality),
		Enrollment:           validEnrollment(r.Enrollment),
		EnrollmentSince:      validDate(r.EnrollmentSince, now),
		OSFamily:             cleanOS(r.OSFamily),
		OSRelease:            cleanOS(r.OSRelease),
	}
	var selected, rest []Endpoint
	for _, ep := range r.Endpoints {
		addr, ok := canonicalAddress(ep.Address)
		if !ok {
			f.EndpointsDropped++
			continue
		}
		port := ep.Port
		if port < 1 || port > 65535 {
			port = 0
		}
		e := Endpoint{Address: addr, Port: port, Label: cleanText(ep.Label, MaxLabelBytes)}
		if ip := net.ParseIP(addr); ip != nil && ms.addressSelected(ip) {
			selected = append(selected, e)
		} else {
			rest = append(rest, e)
		}
	}
	all := append(selected, rest...)
	if len(all) > MaxEndpoints {
		f.EndpointsDropped += len(all) - MaxEndpoints
		all = all[:MaxEndpoints]
	}
	f.Endpoints = all
	return f
}

// factBytes is the text payload of one fact, the unit MaxFactBytes counts.
// It counts the bytes each value has in its default encoding.
func factBytes(f Fact) int {
	n := len(f.ID.Value) + len(f.Name.Value) +
		len(f.InventoryCriticality) + len(f.ExecutorCriticality) + len(f.Enrollment) +
		len(f.OSFamily.Value) + len(f.OSRelease.Value)
	for _, e := range f.Endpoints {
		n += len(e.Address) + len(e.Label.Value) + len(strconv.Itoa(e.Port))
	}
	if !f.EnrollmentSince.IsZero() {
		n += len(f.EnrollmentSince.Format(time.RFC3339))
	}
	return n
}

// validDate keeps an enrollment date only when it is a real past date:
// at or after minEnrollmentYear and not after now. The result is the UTC
// midnight of that day, so its encoding is fixed. Otherwise it is zero.
func validDate(t time.Time, now time.Time) time.Time {
	if t.IsZero() {
		return time.Time{}
	}
	u := t.UTC()
	d := time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 0, 0, time.UTC)
	if d.Year() < minEnrollmentYear || d.After(now) {
		return time.Time{}
	}
	return d
}

// normaliseSourceAddresses validates the admin-set NOS source addresses
// and returns them in canonical form.
func normaliseSourceAddresses(in []string) ([]string, error) {
	if len(in) > MaxSourceAddresses {
		return nil, ErrTooManySourceAddresses
	}
	out := make([]string, 0, len(in))
	for i, s := range in {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("%w: entry %d", ErrInvalidSourceAddress, i)
		}
		out = append(out, ip.String())
	}
	return out, nil
}

// canonicalAddress validates an endpoint address: an IP literal in
// canonical form or a DNS host name, at most MaxAddressBytes long.
func canonicalAddress(s string) (string, bool) {
	if ip := net.ParseIP(s); ip != nil {
		return ip.String(), true
	}
	if len(s) <= MaxAddressBytes && hostnameRe.MatchString(s) {
		return asciiLower(s), true
	}
	return "", false
}

var hostnameRe = regexp.MustCompile(`(?i)^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)

// validCriticality accepts the four criticality classes of spec 12.
func validCriticality(s string) string {
	switch s {
	case "LOW", "MEDIUM", "HIGH", "CRITICAL":
		return s
	}
	return ""
}

// validEnrollment maps any value that is not an ADR 0014 D3 state to
// EnrollmentUnknown.
func validEnrollment(s EnrollmentState) EnrollmentState {
	switch s {
	case EnrollmentNotEnrolled, EnrollmentScriptRunUnknown, EnrollmentHostKeyPinned,
		EnrollmentLoginTestOK, EnrollmentBlocked:
		return s
	}
	return EnrollmentUnknown
}
