// SPDX-License-Identifier: AGPL-3.0-or-later

// Package helpfacts projects the minimised, fixed set of inventory facts
// the help assistant may put into a prompt (ADR 0014 D3, AS-06).
//
// Only hosts that the question names by a literal (IP address, CIDR,
// host name or ID) and that the caller's Visibility check admits are
// projected. The output is the fixed struct Fact and nothing else; no
// other store is reachable from this package. Every host value is
// untrusted: text is cleaned and marked, enums are validated, and the
// total size is bounded by MaxFactBytes.
package helpfacts

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Limits enforced by Project. They are the AS-06 bounds of ADR 0014 D3.
const (
	// MaxFactHosts is the maximum number of hosts in one projection.
	MaxFactHosts = 10
	// MaxFactBytes is the maximum payload of one projection, counted
	// as the text bytes of every field (not including JSON overhead).
	MaxFactBytes = 4 << 10
	// MaxQuestionBytes is the largest question Project scans.
	MaxQuestionBytes = 2 << 10
	// MaxEndpoints is the maximum number of endpoints per host.
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
)

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
// that the value was cleaned (control or format characters replaced,
// whitespace collapsed, cut to length, or dropped as invalid). Text is
// data: it is never an instruction and is rendered as plain text only.
type Text struct {
	Value   string
	Altered bool
}

// Endpoint is one validated address of a host.
type Endpoint struct {
	Address string
	Port    int
	Label   Text
}

// Fact is the fixed projection of one host. It has no other fields.
type Fact struct {
	ID                Text
	Name              Text
	Endpoints         []Endpoint
	EndpointsDropped  int
	Criticality       string
	CriticalitySource Text
	Enrollment        EnrollmentState
	EnrollmentSince   time.Time
	OSFamily          Text
	OSRelease         Text
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
	ID                string
	DisplayName       string
	Endpoints         []RawEndpoint
	Criticality       string
	CriticalitySource string
	Enrollment        EnrollmentState
	EnrollmentSince   time.Time
	OSFamily          string
	OSRelease         string
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
// facts. A host the Visibility check rejects is never read further and
// never appears; for a question that names only hidden hosts the result
// is the same as for a question naming hosts that do not exist.
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
		return Result{}, nil
	}
	records, err := req.Source.Hosts(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("helpfacts: list hosts: %w", err)
	}
	var visible []Record
	for i, r := range records {
		ok, err := req.Visible(ctx, r.ID)
		if err != nil {
			return Result{}, fmt.Errorf("helpfacts: check visibility of host %d: %w", i, err)
		}
		if ok {
			visible = append(visible, r)
		}
	}

	matched, notFound := match(visible, lits)
	sort.SliceStable(matched, func(i, j int) bool { return matched[i].ID < matched[j].ID })

	var res Result
	used := 0
	for _, r := range matched {
		if len(res.Hosts) == MaxFactHosts {
			res.Truncated = true
			break
		}
		f := buildFact(r)
		n := factBytes(f)
		if used+n > MaxFactBytes {
			res.Truncated = true
			continue
		}
		used += n
		res.Hosts = append(res.Hosts, f)
	}
	for _, s := range notFound {
		if len(res.NotInInventory) == MaxFactHosts || used+len(s) > MaxFactBytes {
			res.Truncated = true
			break
		}
		used += len(s)
		res.NotInInventory = append(res.NotInInventory, s)
	}
	if len(res.Hosts) == 0 && len(res.NotInInventory) == 0 {
		// Nothing the user may see or that the question names as absent:
		// no facts at all, not even the NOS source addresses.
		return Result{Truncated: res.Truncated || litTruncated}, nil
	}
	res.Truncated = res.Truncated || litTruncated
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

// match returns the visible hosts that a literal selects, and the
// distinct canonical addresses of the question that no visible host has.
func match(visible []Record, lits []literal) (matched []Record, notFound []string) {
	seen := make(map[string]bool)
	for _, l := range lits {
		if l.kind != litAddress || seen[l.key()] {
			continue
		}
		seen[l.key()] = true
		found := false
		for _, r := range visible {
			if hasAddress(r, l.ip) {
				found = true
				break
			}
		}
		if !found {
			notFound = append(notFound, l.ip.String())
		}
	}
	for _, r := range visible {
		for _, l := range lits {
			if selects(r, l) {
				matched = append(matched, r)
				break
			}
		}
	}
	return matched, notFound
}

// selects reports whether a literal selects a record.
func selects(r Record, l literal) bool {
	switch l.kind {
	case litAddress:
		return hasAddress(r, l.ip)
	case litCIDR:
		for _, ep := range r.Endpoints {
			if ip := net.ParseIP(ep.Address); ip != nil && l.network.Contains(ip) {
				return true
			}
		}
		return false
	default:
		return strings.EqualFold(r.ID, l.name) || strings.EqualFold(r.DisplayName, l.name)
	}
}

// hasAddress reports whether one endpoint of r is ip.
func hasAddress(r Record, ip net.IP) bool {
	for _, ep := range r.Endpoints {
		if e := net.ParseIP(ep.Address); e != nil && e.Equal(ip) {
			return true
		}
	}
	return false
}

// buildFact turns a visible record into the fixed struct, validating
// every field.
func buildFact(r Record) Fact {
	f := Fact{
		ID:                cleanText(r.ID, MaxIDBytes),
		Name:              cleanText(r.DisplayName, MaxNameBytes),
		Criticality:       validCriticality(r.Criticality),
		CriticalitySource: validCriticalitySource(r.CriticalitySource),
		Enrollment:        validEnrollment(r.Enrollment),
		EnrollmentSince:   r.EnrollmentSince,
		OSFamily:          cleanOS(r.OSFamily),
		OSRelease:         cleanOS(r.OSRelease),
	}
	for _, ep := range r.Endpoints {
		if len(f.Endpoints) == MaxEndpoints {
			f.EndpointsDropped++
			continue
		}
		addr, ok := canonicalAddress(ep.Address)
		if !ok || ep.Port < 1 || ep.Port > 65535 {
			f.EndpointsDropped++
			continue
		}
		f.Endpoints = append(f.Endpoints, Endpoint{
			Address: addr,
			Port:    ep.Port,
			Label:   cleanText(ep.Label, MaxLabelBytes),
		})
	}
	return f
}

// factBytes is the text payload of one fact, the unit MaxFactBytes counts.
func factBytes(f Fact) int {
	const dateLen = len("2006-01-02")
	n := len(f.ID.Value) + len(f.Name.Value) + len(f.Criticality) +
		len(f.CriticalitySource.Value) + len(f.Enrollment) +
		len(f.OSFamily.Value) + len(f.OSRelease.Value)
	for _, e := range f.Endpoints {
		n += len(e.Address) + len(e.Label.Value) + len("65535")
	}
	if !f.EnrollmentSince.IsZero() {
		n += dateLen
	}
	return n
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
// canonical form or a DNS host name.
func canonicalAddress(s string) (string, bool) {
	if ip := net.ParseIP(s); ip != nil {
		return ip.String(), true
	}
	if len(s) <= maxHostnameBytes && hostnameRe.MatchString(s) {
		return strings.ToLower(s), true
	}
	return "", false
}

// maxHostnameBytes is the DNS limit for a host name.
const maxHostnameBytes = 253

var hostnameRe = regexp.MustCompile(`(?i)^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)

// validCriticality accepts the four criticality classes of spec 12.
func validCriticality(s string) string {
	switch s {
	case "LOW", "MEDIUM", "HIGH", "CRITICAL":
		return s
	}
	return ""
}

// validCriticalitySource accepts the two sources of a criticality value.
func validCriticalitySource(s string) Text {
	switch s {
	case "inventory", "executor":
		return Text{Value: s}
	case "":
		return Text{}
	}
	return Text{Altered: true}
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
