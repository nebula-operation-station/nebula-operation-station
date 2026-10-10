// SPDX-License-Identifier: AGPL-3.0-or-later

// Package canonical turns an execution request into the exact byte sequence
// that an approval binds to, and hashes it.
//
// Canonical form: the request is validated, set-like lists (credential
// references, targets) are sorted, the result is marshalled to JSON and then
// transformed with RFC 8785 (JSON Canonicalization Scheme). The SHA-256 of
// those bytes is the execution digest. The executor always computes the
// digest itself; it never accepts a digest from the server.
package canonical

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gowebpki/jcs"
)

// RequestVersion is embedded in every canonical request so that a future
// change of the canonical form can never produce a colliding digest.
const RequestVersion = 1

// MaxPermitLifetime bounds the expiry of any execution request (spec: the
// planned rollout duration plus margin, at most 24 h).
const MaxPermitLifetime = 24 * time.Hour

// MaxTargets bounds the number of hosts one request may address.
const MaxTargets = 1000

// Risk is the effective risk class of an execution.
type Risk string

// Risk classes, ordered from lowest to highest.
const (
	RiskLow      Risk = "LOW"
	RiskMedium   Risk = "MEDIUM"
	RiskHigh     Risk = "HIGH"
	RiskCritical Risk = "CRITICAL"
)

// Rank returns the order of a risk class; 0 means unknown.
func (r Risk) Rank() int {
	switch r {
	case RiskLow:
		return 1
	case RiskMedium:
		return 2
	case RiskHigh:
		return 3
	case RiskCritical:
		return 4
	default:
		return 0
	}
}

// Target is one resolved host, bound to its pinned host key.
type Target struct {
	HostID             string `json:"host_id"`
	HostKeyFingerprint string `json:"host_key_fingerprint"`
}

// Request is the canonical execution request. Field names are part of the
// canonical form and must never change without bumping RequestVersion.
type Request struct {
	RequestVersion  int      `json:"request_version"`
	ExecutionID     string   `json:"execution_id"`
	ActionID        string   `json:"action_id"`
	ModuleVersion   string   `json:"module_version"`
	ArtifactSHA256  string   `json:"artifact_sha256"`
	ParametersHash  string   `json:"parameters_hash"`
	CredentialRefs  []string `json:"credential_refs"`
	RiskClass       Risk     `json:"risk_class"`
	StagePlanHash   string   `json:"stage_plan_hash"`
	ExpiryUnix      int64    `json:"expiry_unix"`
	ResolvedTargets []Target `json:"resolved_targets"`
}

// Digest is the SHA-256 of a canonical request.
type Digest [sha256.Size]byte

// String returns the lowercase hex form used as permit identifier.
func (d Digest) String() string { return hex.EncodeToString(d[:]) }

// ParseDigest parses the lowercase hex form of a digest.
func ParseDigest(s string) (Digest, error) {
	var d Digest
	if !hex64.MatchString(s) {
		return d, errors.New("digest must be 64 lowercase hex characters")
	}
	_, err := hex.Decode(d[:], []byte(s))
	return d, err
}

var (
	uuidRe        = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	actionRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}(\.[a-z0-9][a-z0-9_]{0,63})+$`)
	semverRe      = regexp.MustCompile(`^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$`)
	hex64         = regexp.MustCompile(`^[0-9a-f]{64}$`)
	credRefRe     = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	hostIDRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	fingerprintRe = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)
)

// ValidationError lists every problem found in a request.
type ValidationError struct{ Problems []string }

func (e *ValidationError) Error() string {
	return "invalid execution request: " + strings.Join(e.Problems, "; ")
}

// Normalize validates r against now and returns a copy with set-like lists
// sorted. It never mutates r.
func Normalize(r Request, now time.Time) (Request, error) {
	var p []string
	add := func(format string, args ...any) { p = append(p, fmt.Sprintf(format, args...)) }

	n := r
	n.RequestVersion = RequestVersion
	if r.RequestVersion != 0 && r.RequestVersion != RequestVersion {
		add("unsupported request_version %d", r.RequestVersion)
	}
	if !uuidRe.MatchString(r.ExecutionID) {
		add("execution_id must be a lowercase UUID")
	}
	if !actionRe.MatchString(r.ActionID) {
		add("action_id must look like module.action")
	}
	if !semverRe.MatchString(r.ModuleVersion) {
		add("module_version must be MAJOR.MINOR.PATCH")
	}
	if !hex64.MatchString(r.ArtifactSHA256) {
		add("artifact_sha256 must be 64 lowercase hex characters")
	}
	if !hex64.MatchString(r.ParametersHash) {
		add("parameters_hash must be 64 lowercase hex characters")
	}
	if !hex64.MatchString(r.StagePlanHash) {
		add("stage_plan_hash must be 64 lowercase hex characters")
	}
	if r.RiskClass.Rank() == 0 {
		add("risk_class %q is unknown", r.RiskClass)
	}

	expiry := time.Unix(r.ExpiryUnix, 0)
	switch {
	case !expiry.After(now):
		add("expiry is not in the future")
	case expiry.Sub(now) > MaxPermitLifetime:
		add("expiry exceeds the maximum permit lifetime of %s", MaxPermitLifetime)
	}

	if len(r.CredentialRefs) == 0 {
		add("at least one credential_ref is required")
	}
	n.CredentialRefs = slices.Clone(r.CredentialRefs)
	slices.Sort(n.CredentialRefs)
	for i, c := range n.CredentialRefs {
		if !credRefRe.MatchString(c) {
			add("credential_ref %q is malformed", c)
		}
		if i > 0 && n.CredentialRefs[i-1] == c {
			add("credential_ref %q is duplicated", c)
		}
	}

	switch {
	case len(r.ResolvedTargets) == 0:
		add("at least one resolved target is required")
	case len(r.ResolvedTargets) > MaxTargets:
		add("too many targets (%d > %d)", len(r.ResolvedTargets), MaxTargets)
	}
	n.ResolvedTargets = slices.Clone(r.ResolvedTargets)
	slices.SortFunc(n.ResolvedTargets, func(a, b Target) int { return strings.Compare(a.HostID, b.HostID) })
	for i, t := range n.ResolvedTargets {
		if !hostIDRe.MatchString(t.HostID) {
			add("host_id %q is malformed", t.HostID)
		}
		if !fingerprintRe.MatchString(t.HostKeyFingerprint) {
			add("host key fingerprint for %q is malformed", t.HostID)
		}
		if i > 0 && n.ResolvedTargets[i-1].HostID == t.HostID {
			add("host_id %q is duplicated", t.HostID)
		}
	}

	if len(p) > 0 {
		return Request{}, &ValidationError{Problems: p}
	}
	return n, nil
}

// Encode returns the RFC 8785 canonical JSON of an already normalized
// request.
func Encode(n Request) ([]byte, error) {
	raw, err := json.Marshal(n)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}
	return jcs.Transform(raw)
}

// Canonicalize normalizes r and returns the canonical bytes and their digest.
func Canonicalize(r Request, now time.Time) (Request, []byte, Digest, error) {
	n, err := Normalize(r, now)
	if err != nil {
		return Request{}, nil, Digest{}, err
	}
	b, err := Encode(n)
	if err != nil {
		return Request{}, nil, Digest{}, err
	}
	return n, b, sha256.Sum256(b), nil
}

// MaxParametersSize bounds the parameters document accepted for hashing.
const MaxParametersSize = 64 << 10

// HashParameters canonicalizes a JSON parameters object with RFC 8785 and
// returns the lowercase hex SHA-256. An empty input is treated as {}.
// See CanonicalParameters for the accepted input.
func HashParameters(raw []byte) (string, error) {
	_, h, err := CanonicalParameters(raw)
	return h, err
}

// CanonicalParameters returns the RFC 8785 form of a JSON parameters object
// and its lowercase hex SHA-256. Rules beyond plain JSON, so that one hash
// can never stand for two meanings:
//
//   - the top level must be an object; empty input means {},
//   - duplicate member names are rejected at any depth,
//   - numbers must already be in canonical form and exactly representable as
//     IEEE-754 doubles (1.0, 1e0, -0 and 9007199254740993 are rejected),
//   - at most MaxParametersSize bytes and 32 levels of nesting.
//
// Callers must pass the returned canonical bytes, not the raw input, to
// anything that executes.
func CanonicalParameters(raw []byte) ([]byte, string, error) {
	if len(raw) > MaxParametersSize {
		return nil, "", fmt.Errorf("parameters exceed %d bytes", MaxParametersSize)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		raw = []byte("{}")
	}
	if err := requireObjectWithoutDuplicates(raw); err != nil {
		return nil, "", err
	}
	c, err := jcs.Transform(raw)
	if err != nil {
		return nil, "", fmt.Errorf("canonicalize parameters: %w", err)
	}
	sum := sha256.Sum256(c)
	return c, hex.EncodeToString(sum[:]), nil
}

// checkNumber accepts a JSON number only if its literal equals the RFC 8785
// serialization of the double it denotes.
func checkNumber(n json.Number) error {
	f, err := strconv.ParseFloat(string(n), 64)
	if err != nil {
		return fmt.Errorf("parameters: number %s out of range", n)
	}
	canon, err := jcs.NumberToJSON(f)
	if err != nil || canon != string(n) {
		return fmt.Errorf("parameters: number %s must be written as %s or as a string", n, canon)
	}
	return nil
}

// requireObjectWithoutDuplicates rejects documents whose top level is not an
// object and any object, at any depth, with duplicate member names. Different
// JSON parsers resolve duplicates differently, which would let the hashed
// meaning differ from the executed meaning.
func requireObjectWithoutDuplicates(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("parameters: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return errors.New("parameters must be a JSON object")
	}
	if err := walkObject(dec, 1); err != nil {
		return err
	}
	if _, err := dec.Token(); err == nil {
		return errors.New("parameters: trailing data after object")
	}
	return nil
}

const maxDepth = 32

func walkObject(dec *json.Decoder, depth int) error {
	if depth > maxDepth {
		return errors.New("parameters nest too deeply")
	}
	seen := map[string]struct{}{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("parameters: %w", err)
		}
		key, ok := tok.(string)
		if !ok {
			return errors.New("parameters: object key is not a string")
		}
		if _, dup := seen[key]; dup {
			return fmt.Errorf("parameters: duplicate key %q", key)
		}
		seen[key] = struct{}{}
		if err := walkValue(dec, depth); err != nil {
			return err
		}
	}
	_, err := dec.Token() // closing '}'
	return err
}

func walkValue(dec *json.Decoder, depth int) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("parameters: %w", err)
	}
	if n, ok := tok.(json.Number); ok {
		return checkNumber(n)
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch d {
	case '{':
		return walkObject(dec, depth+1)
	case '[':
		if depth+1 > maxDepth {
			return errors.New("parameters nest too deeply")
		}
		for dec.More() {
			if err := walkValue(dec, depth+1); err != nil {
				return err
			}
		}
		_, err := dec.Token() // closing ']'
		return err
	default:
		return fmt.Errorf("parameters: unexpected delimiter %q", d)
	}
}
