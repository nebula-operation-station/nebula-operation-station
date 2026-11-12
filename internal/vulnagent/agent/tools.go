// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfeed"
)

// Tool names. The registry is exactly these seven; nothing adds a tool at
// run time.
const (
	ToolCVEDetails       = "cve_details"
	ToolAdvisoryText     = "advisory_text"
	ToolPackageHistory   = "package_history"
	ToolBackportCheck    = "backport_check"
	ToolExposure         = "exposure"
	ToolKEVEPSS          = "kev_epss"
	ToolSubmitAssessment = "submit_assessment"
)

// Input patterns (ADR 0011 D2; anchored, ASCII, bounded).
var (
	vulnIDRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:._-]{1,63}$`)
	findingKeyRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
	ecosystemRe  = regexp.MustCompile(`^[a-z][a-z0-9:._-]{1,63}$`)
	packageRe    = regexp.MustCompile(`^[A-Za-z0-9@][A-Za-z0-9@/._+:~-]{0,213}$`)
)

// Errors of tool argument handling. Their text never echoes model input.
var (
	// ErrUnknownTool reports a tool name outside the registry.
	ErrUnknownTool = errors.New("unknown tool")
	// ErrInvalidArguments reports arguments that break the tool's schema.
	ErrInvalidArguments = errors.New("invalid arguments")
	// ErrNotFound reports a lookup without a record.
	ErrNotFound = errors.New("no record")
)

// RecordRef is the identity of one feed record in the run's pinned
// snapshot: source ID and position. Results that carry feed free text are
// tagged with the one record whose text they carry.
type RecordRef struct {
	// SourceID is the NOS feed source ID.
	SourceID string `json:"source"`
	// Position is the record's position in the pinned snapshot.
	Position int64 `json:"position"`
}

// CVSS is one CVSS entry with its source.
type CVSS struct {
	// Version is the CVSS version, e.g. "3.1".
	Version string `json:"version"`
	// Vector is the CVSS vector string.
	Vector string `json:"vector"`
	// Score is the base score.
	Score float64 `json:"score"`
	// SourceID is the feed source of the entry.
	SourceID string `json:"source"`
}

// CVERecord is one source's record for a vulnerability ID.
type CVERecord struct {
	// Ref is the record identity.
	Ref RecordRef
	// CVSS are the record's CVSS entries.
	CVSS []CVSS
	// CWEs are the record's CWE IDs.
	CWEs []string
	// Aliases are the record's alias IDs.
	Aliases []string
	// Published and Modified are the record dates as text.
	Published, Modified string
	// Description is the record's free text.
	Description string
	// References are reference URLs, inert text that is never fetched.
	References []string
}

// AdvisoryRecord is one advisory record of the snapshot.
type AdvisoryRecord struct {
	// Ref is the record identity.
	Ref RecordRef
	// Text is the advisory's free text.
	Text string
	// Affected and Fixed are the affected and fixed versions.
	Affected, Fixed []string
}

// PackageRecord is one tracker or OSV record of a source package: bounded
// fields only, no notes.
type PackageRecord struct {
	// SourceID is the feed source ID.
	SourceID string `json:"source"`
	// RecordID is the vulnerability or advisory ID.
	RecordID string `json:"record_id"`
	// FixedVersion is the fixed version, if any.
	FixedVersion string `json:"fixed_version,omitempty"`
	// TrackerState is the tracker state, if any.
	TrackerState string `json:"tracker_state,omitempty"`
}

// Backport is the pipeline's own comparison result for a finding.
type Backport struct {
	// BasisVersion is the version the comparison used.
	BasisVersion string
	// FixedVersion is the fixed version compared against.
	FixedVersion string
	// Verdict is the internal/vulnver verdict, unchanged.
	Verdict string
	// TrackerNote is the tracker note of the finding's own record.
	TrackerNote string
	// NoteRef is the identity of the record the note comes from.
	NoteRef *RecordRef
}

// Exposure is what the export holds for a finding's subject. It has no
// field for addresses, host names, labels, listeners, flows or topology.
type Exposure struct {
	// SubjectKind is host, image or device.
	SubjectKind string `json:"subject_kind"`
	// Ecosystem is the component's ecosystem.
	Ecosystem string `json:"ecosystem"`
	// BinaryPackages are the component's binary package names.
	BinaryPackages []string `json:"binary_packages,omitempty"`
	// Kernel is "running", "installed_not_booted" or empty.
	Kernel string `json:"kernel,omitempty"`
}

// KEVEPSS holds the KEV entry and EPSS score of a vulnerability ID.
type KEVEPSS struct {
	// KEV reports a KEV listing.
	KEV bool `json:"kev"`
	// KEVDateAdded is the KEV date added, if listed.
	KEVDateAdded string `json:"kev_date_added,omitempty"`
	// EPSS is the EPSS probability, if scored.
	EPSS *float64 `json:"epss,omitempty"`
	// Percentile is the EPSS percentile, if scored.
	Percentile *float64 `json:"epss_percentile,omitempty"`
	// ScoreDate is the EPSS score date.
	ScoreDate string `json:"epss_date,omitempty"`
}

// Snapshot is the read-only, in-memory view of the run's pinned feed
// snapshot. Implementations perform no network or filesystem I/O.
type Snapshot interface {
	// CVERecords returns every source's record for a vulnerability ID.
	CVERecords(vulnID string) []CVERecord
	// AdvisoryRecords returns every source's record for an advisory ID.
	AdvisoryRecords(advisoryID string) []AdvisoryRecord
	// PackageHistory returns the records of a source package.
	PackageHistory(ecosystem, sourcePackage string) []PackageRecord
	// KEVEPSS returns the KEV and EPSS data of a vulnerability ID.
	KEVEPSS(vulnID string) (KEVEPSS, bool)
}

// RunView is the read-only, in-memory view of the run's pipeline results
// and export pages.
type RunView interface {
	// Backport returns the pipeline's comparison result of a finding.
	Backport(findingKey string) (Backport, bool)
	// Exposure returns the export fields of a finding's subject.
	Exposure(findingKey string) (Exposure, bool)
}

// ToolDef is one tool definition as sent to the model.
type ToolDef struct {
	// Name is the tool name.
	Name string
	// Description is the fixed description.
	Description string
	// Parameters is the fixed JSON schema of the arguments.
	Parameters json.RawMessage
}

// toolDefs are the fixed definitions, in registry order.
var toolDefs = []ToolDef{
	{ToolCVEDetails, "CVSS, CWE, aliases and dates of every source's record for a vulnerability ID, and the free text of one record (the named source's, or the first by source order).",
		json.RawMessage(`{"type":"object","properties":{"vuln_id":{"type":"string","maxLength":64},"source":{"type":"string","maxLength":64}},"required":["vuln_id"],"additionalProperties":false}`)},
	{ToolAdvisoryText, "Text and affected/fixed versions of one advisory record (DSA, DLA, USN, GHSA, OSV, Cisco, PAN-SA).",
		json.RawMessage(`{"type":"object","properties":{"advisory_id":{"type":"string","maxLength":64},"source":{"type":"string","maxLength":64}},"required":["advisory_id"],"additionalProperties":false}`)},
	{ToolPackageHistory, "Record IDs, fixed versions and tracker states for a source package in an ecosystem/release.",
		json.RawMessage(`{"type":"object","properties":{"ecosystem":{"type":"string","maxLength":64},"source_package":{"type":"string","maxLength":214}},"required":["ecosystem","source_package"],"additionalProperties":false}`)},
	{ToolBackportCheck, "The deterministic pipeline's version comparison for a finding of this run: basis version, fixed version, verdict and tracker note.",
		json.RawMessage(`{"type":"object","properties":{"finding_key":{"type":"string","pattern":"^[0-9a-f]{64}$"}},"required":["finding_key"],"additionalProperties":false}`)},
	{ToolExposure, "Subject kind, ecosystem, binary packages and kernel boot state of a finding's subject.",
		json.RawMessage(`{"type":"object","properties":{"finding_key":{"type":"string","pattern":"^[0-9a-f]{64}$"}},"required":["finding_key"],"additionalProperties":false}`)},
	{ToolKEVEPSS, "KEV listing with date added and EPSS probability, percentile and date for a vulnerability ID.",
		json.RawMessage(`{"type":"object","properties":{"vuln_id":{"type":"string","maxLength":64}},"required":["vuln_id"],"additionalProperties":false}`)},
	{ToolSubmitAssessment, "Submit the assessment. This is the only output; it ends the work on the finding.",
		json.RawMessage(`{"type":"object","properties":{"text":{"type":"string","maxLength":4096},"backport_checked":{"type":"boolean"},"likely_false_positive":{"type":"boolean"},"exploit_public":{"type":"boolean"},"rationale":{"type":"string","maxLength":1024}},"required":["text","backport_checked","likely_false_positive","exploit_public","rationale"],"additionalProperties":false}`)},
}

// ToolDefinitions returns a copy of the fixed tool definitions.
func ToolDefinitions() []ToolDef { return append([]ToolDef(nil), toolDefs...) }

// sourceOrder is the fixed NOS source list order used to pick the one
// record whose free text a result carries.
var sourceOrder = func() []string {
	var out []string
	seen := map[string]bool{}
	for _, f := range vulnfeed.Feeds() {
		if !seen[f.SourceID] {
			seen[f.SourceID] = true
			out = append(out, f.SourceID)
		}
	}
	return out
}()

func knownSource(id string) bool {
	for _, s := range sourceOrder {
		if s == id {
			return true
		}
	}
	return false
}

// tools executes the lookup tools over the run's views.
type tools struct {
	snap Snapshot
	view RunView
}

// lookupResult is a lookup result before encoding; record is set when the
// result carries one feed record's free text.
type lookupResult struct {
	data   any
	record *RecordRef
}

// execLookup validates the arguments of a lookup tool and runs it. The
// returned errors are ErrUnknownTool, ErrInvalidArguments or ErrNotFound.
func (t tools) execLookup(name, args string) (lookupResult, error) {
	switch name {
	case ToolCVEDetails:
		f, err := decodeArgs(args, []string{"vuln_id"}, []string{"source"})
		if err != nil {
			return lookupResult{}, err
		}
		if !vulnIDRe.MatchString(f["vuln_id"]) || !optionalSource(f["source"]) {
			return lookupResult{}, ErrInvalidArguments
		}
		return t.cveDetails(f["vuln_id"], f["source"])
	case ToolAdvisoryText:
		f, err := decodeArgs(args, []string{"advisory_id"}, []string{"source"})
		if err != nil {
			return lookupResult{}, err
		}
		if !vulnIDRe.MatchString(f["advisory_id"]) || !optionalSource(f["source"]) {
			return lookupResult{}, ErrInvalidArguments
		}
		return t.advisory(f["advisory_id"], f["source"])
	case ToolPackageHistory:
		f, err := decodeArgs(args, []string{"ecosystem", "source_package"}, nil)
		if err != nil {
			return lookupResult{}, err
		}
		if !ecosystemRe.MatchString(f["ecosystem"]) || !packageRe.MatchString(f["source_package"]) {
			return lookupResult{}, ErrInvalidArguments
		}
		recs := t.snap.PackageHistory(f["ecosystem"], f["source_package"])
		if len(recs) == 0 {
			return lookupResult{}, ErrNotFound
		}
		return lookupResult{data: map[string]any{"ecosystem": f["ecosystem"], "source_package": f["source_package"], "records": recs}}, nil
	case ToolBackportCheck:
		key, err := findingKeyArg(args)
		if err != nil {
			return lookupResult{}, err
		}
		b, ok := t.view.Backport(key)
		if !ok {
			return lookupResult{}, ErrNotFound
		}
		out := map[string]any{"finding_key": key, "basis_version": b.BasisVersion, "fixed_version": b.FixedVersion, "verdict": b.Verdict}
		if b.NoteRef != nil && b.TrackerNote != "" {
			out["tracker_note"] = b.TrackerNote
			ref := *b.NoteRef
			out["record"] = ref
			return lookupResult{data: out, record: &ref}, nil
		}
		return lookupResult{data: out}, nil
	case ToolExposure:
		key, err := findingKeyArg(args)
		if err != nil {
			return lookupResult{}, err
		}
		e, ok := t.view.Exposure(key)
		if !ok {
			return lookupResult{}, ErrNotFound
		}
		return lookupResult{data: e}, nil
	case ToolKEVEPSS:
		f, err := decodeArgs(args, []string{"vuln_id"}, nil)
		if err != nil {
			return lookupResult{}, err
		}
		if !vulnIDRe.MatchString(f["vuln_id"]) {
			return lookupResult{}, ErrInvalidArguments
		}
		k, ok := t.snap.KEVEPSS(f["vuln_id"])
		if !ok {
			return lookupResult{}, ErrNotFound
		}
		return lookupResult{data: k}, nil
	}
	return lookupResult{}, ErrUnknownTool
}

func optionalSource(s string) bool { return s == "" || knownSource(s) }

func findingKeyArg(args string) (string, error) {
	f, err := decodeArgs(args, []string{"finding_key"}, nil)
	if err != nil {
		return "", err
	}
	if !findingKeyRe.MatchString(f["finding_key"]) {
		return "", ErrInvalidArguments
	}
	return f["finding_key"], nil
}

// pickRecord returns the index of the named source's record, or of the
// first record in source order.
func pickRecord(refs []RecordRef, source string) int {
	if source != "" {
		for i, r := range refs {
			if r.SourceID == source {
				return i
			}
		}
		return -1
	}
	for _, s := range sourceOrder {
		for i, r := range refs {
			if r.SourceID == s {
				return i
			}
		}
	}
	return -1
}

func (t tools) cveDetails(vulnID, source string) (lookupResult, error) {
	recs := t.snap.CVERecords(vulnID)
	refs := make([]RecordRef, len(recs))
	type meta struct {
		Source    string   `json:"source"`
		CVSS      []CVSS   `json:"cvss,omitempty"`
		CWEs      []string `json:"cwe,omitempty"`
		Aliases   []string `json:"aliases,omitempty"`
		Published string   `json:"published,omitempty"`
		Modified  string   `json:"modified,omitempty"`
	}
	metas := make([]meta, len(recs))
	for i, r := range recs {
		refs[i] = r.Ref
		metas[i] = meta{r.Ref.SourceID, r.CVSS, r.CWEs, r.Aliases, r.Published, r.Modified}
	}
	i := pickRecord(refs, source)
	if i < 0 {
		return lookupResult{}, ErrNotFound
	}
	ref := recs[i].Ref
	out := map[string]any{"vuln_id": vulnID, "records": metas, "text": map[string]any{
		"record": ref, "description": recs[i].Description, "references": recs[i].References,
	}}
	return lookupResult{data: out, record: &ref}, nil
}

func (t tools) advisory(id, source string) (lookupResult, error) {
	recs := t.snap.AdvisoryRecords(id)
	refs := make([]RecordRef, len(recs))
	for i, r := range recs {
		refs[i] = r.Ref
	}
	i := pickRecord(refs, source)
	if i < 0 {
		return lookupResult{}, ErrNotFound
	}
	r := recs[i]
	ref := r.Ref
	out := map[string]any{"advisory_id": id, "record": ref, "text": r.Text, "affected": r.Affected, "fixed": r.Fixed}
	return lookupResult{data: out, record: &ref}, nil
}

// Assessment is a validated submit_assessment payload.
type Assessment struct {
	// Text is the assessment text (≤ MaxTextBytes printable UTF-8).
	Text string
	// BackportChecked, LikelyFalsePositive and ExploitPublic are hints.
	BackportChecked, LikelyFalsePositive, ExploitPublic bool
	// Rationale stays in the local audit log (≤ MaxRationaleBytes).
	Rationale string
	// PromptVersion is the prompt_version the assessment was made with.
	PromptVersion string
	// Language is the requested output language.
	Language Language
}

// parseSubmit validates submit_assessment arguments: exactly the five
// fields, each of its type, no unknown or duplicate field, bounded
// printable UTF-8 text.
func parseSubmit(args string) (Assessment, error) {
	if len(args) > MaxSubmitArgumentsBytes {
		return Assessment{}, ErrInvalidArguments
	}
	raw, err := decodeObject(args, map[string]bool{
		"text": true, "backport_checked": true, "likely_false_positive": true, "exploit_public": true, "rationale": true,
	})
	if err != nil || len(raw) != 5 {
		return Assessment{}, ErrInvalidArguments
	}
	var a Assessment
	if a.Text, err = rawString(raw["text"]); err != nil {
		return Assessment{}, err
	}
	if a.Rationale, err = rawString(raw["rationale"]); err != nil {
		return Assessment{}, err
	}
	for name, dst := range map[string]*bool{"backport_checked": &a.BackportChecked, "likely_false_positive": &a.LikelyFalsePositive, "exploit_public": &a.ExploitPublic} {
		v := bytes.TrimSpace(raw[name])
		switch string(v) {
		case "true":
			*dst = true
		case "false":
		default:
			return Assessment{}, ErrInvalidArguments
		}
	}
	if checkText(a.Text, MaxTextBytes) != nil || checkText(a.Rationale, MaxRationaleBytes) != nil {
		return Assessment{}, ErrInvalidArguments
	}
	return a, nil
}

// decodeArgs decodes a lookup tool's arguments: a JSON object of strings
// with all required and only the allowed names. Missing optional names
// map to "".
func decodeArgs(args string, required, optional []string) (map[string]string, error) {
	allowed := map[string]bool{}
	for _, n := range required {
		allowed[n] = true
	}
	for _, n := range optional {
		allowed[n] = true
	}
	raw, err := decodeObject(args, allowed)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for n, v := range raw {
		s, err := rawString(v)
		if err != nil {
			return nil, err
		}
		out[n] = s
	}
	for _, n := range required {
		if _, ok := raw[n]; !ok {
			return nil, ErrInvalidArguments
		}
	}
	return out, nil
}

// decodeObject decodes one JSON object with names from allowed, matched
// exactly (no case folding), each at most once, and no trailing data.
func decodeObject(s string, allowed map[string]bool) (map[string]json.RawMessage, error) {
	if !utf8.ValidString(s) {
		return nil, ErrInvalidArguments
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(s)))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, ErrInvalidArguments
	}
	out := map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, ErrInvalidArguments
		}
		name, ok := tok.(string)
		if !ok || !allowed[name] {
			return nil, ErrInvalidArguments
		}
		if _, dup := out[name]; dup {
			return nil, ErrInvalidArguments
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, ErrInvalidArguments
		}
		out[name] = v
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, ErrInvalidArguments
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, ErrInvalidArguments
	}
	return out, nil
}

// rawString decodes a JSON string value; null and other types fail.
func rawString(v json.RawMessage) (string, error) {
	v = bytes.TrimSpace(v)
	if len(v) == 0 || v[0] != '"' {
		return "", ErrInvalidArguments
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return "", ErrInvalidArguments
	}
	return s, nil
}

// Envelope kinds. Every user and tool message is one JSON object; data
// from feeds, exports and the finding is only ever a JSON value inside the
// "data" field of an untrusted_data envelope.
const (
	envelopeUntrusted = "untrusted_data"
	envelopeNotice    = "agent_notice"
	truncatedMarker   = "[result cut: tool result limit reached]"
)

// untrustedEnvelope encodes data as delimited untrusted data.
func untrustedEnvelope(kind string, data any) (string, error) {
	b, err := json.Marshal(struct {
		Envelope string `json:"envelope"`
		Kind     string `json:"kind"`
		Data     any    `json:"data"`
	}{envelopeUntrusted, kind, data})
	if err != nil {
		return "", fmt.Errorf("encode %s envelope: %w", kind, err)
	}
	return string(b), nil
}

// noticeEnvelope is a fixed agent notice; msg is always agent text.
func noticeEnvelope(msg string) string {
	b, _ := json.Marshal(struct {
		Envelope string `json:"envelope"`
		Notice   string `json:"notice"`
	}{envelopeNotice, msg})
	return string(b)
}

// toolResultContent encodes a lookup result as an untrusted_data envelope
// of at most limit bytes. An oversized result is replaced by a prefix of
// its encoded data, carried as one JSON string, plus a marker, so the
// envelope stays valid JSON and the cut never escapes the data field.
func toolResultContent(tool string, r lookupResult, limit int) (string, error) {
	full, err := untrustedEnvelope("tool_result:"+tool, r.data)
	if err != nil {
		return "", err
	}
	if len(full) <= limit {
		return full, nil
	}
	enc, err := json.Marshal(r.data)
	if err != nil {
		return "", fmt.Errorf("encode %s result: %w", tool, err)
	}
	build := func(n int) (string, error) {
		cut := map[string]any{"cut": truncatedMarker, "partial": string(enc[:n])}
		if r.record != nil {
			cut["record"] = *r.record
		}
		return untrustedEnvelope("tool_result:"+tool, cut)
	}
	lo, hi := 0, len(enc)
	best := ""
	for lo <= hi {
		mid := (lo + hi) / 2
		n := mid
		for n > 0 && n < len(enc) && !utf8.RuneStart(enc[n]) {
			n--
		}
		s, err := build(n)
		if err != nil {
			return "", err
		}
		if len(s) <= limit {
			best = s
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	if best == "" {
		return "", fmt.Errorf("tool result limit %d below envelope size: %w", limit, ErrInvalidConfig)
	}
	return best, nil
}
