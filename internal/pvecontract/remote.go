// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecontract

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ErrInvalid marks documents that fail strict decoding or validation.
// Callers can branch on it with errors.Is.
var ErrInvalid = errors.New("pvecontract: invalid document")

// Kind is the kind of a PVE remote.
type Kind string

// Remote kinds.
const (
	// KindCluster is one PVE cluster with ordered node API endpoints.
	KindCluster Kind = "cluster"
	// KindStandalone is one standalone PVE host with exactly one endpoint.
	KindStandalone Kind = "standalone"
)

// Endpoint is one ordered node API endpoint: an admin-approved HTTPS origin
// (normally port 8006). Discovery never adds dial targets.
type Endpoint struct {
	Host string `json:"host"`
	Port uint16 `json:"port"`
}

// Remote is the executor-owned identity of one PVE cluster or standalone
// host: an immutable remote_id, ordered endpoints, a trust pin and a trust
// generation.
//
// The trust pin is the lowercase hex SHA-256 of the cluster CA certificate
// DER for clusters, or of the served leaf certificate for standalone hosts.
// Names are labels and never authenticate a remote.
type Remote struct {
	RemoteID        string     `json:"remote_id"`
	Name            string     `json:"name,omitempty"`
	Kind            Kind       `json:"kind"`
	Endpoints       []Endpoint `json:"endpoints"`
	TrustPin        string     `json:"trust_pin"`
	TrustGeneration uint64     `json:"trust_generation"`
}

var (
	remoteIDRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	fingerprintRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
	dnsLabelRe    = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

// ValidRemoteID reports whether s is a well-formed remote_id slug.
func ValidRemoteID(s string) bool { return remoteIDRe.MatchString(s) }

// ValidTrustPin reports whether s is a well-formed SHA-256 hex pin.
func ValidTrustPin(s string) bool { return fingerprintRe.MatchString(s) }

// validEndpointHost reports whether s is a valid DNS name or IP literal.
func validEndpointHost(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	if net.ParseIP(s) != nil {
		return true
	}
	labels := strings.Split(s, ".")
	if len(labels) > 127 {
		return false
	}
	for _, l := range labels {
		if !dnsLabelRe.MatchString(l) {
			return false
		}
	}
	return true
}

// ValidationError lists every problem found in a remote or observation.
type ValidationError struct{ Problems []string }

func (e *ValidationError) Error() string {
	return "pvecontract: " + strings.Join(e.Problems, "; ")
}

// Is lets callers match *ValidationError with errors.Is(err, ErrInvalid).
func (e *ValidationError) Is(target error) bool { return target == ErrInvalid }

// ValidateRemote validates r and returns a copy with cloned endpoints. It
// never mutates r.
func ValidateRemote(r Remote) (Remote, error) {
	var p []string
	add := func(format string, args ...any) { p = append(p, fmt.Sprintf(format, args...)) }

	if !remoteIDRe.MatchString(r.RemoteID) {
		add("remote_id %q is malformed", r.RemoteID)
	}
	if len(r.Name) > MaxLabelBytes {
		add("name exceeds %d bytes", MaxLabelBytes)
	}
	switch r.Kind {
	case KindCluster, KindStandalone:
	default:
		add("kind %q is unknown", r.Kind)
	}

	switch {
	case len(r.Endpoints) == 0:
		add("at least one endpoint is required")
	case len(r.Endpoints) > MaxEndpointsPerRemote:
		add("too many endpoints (%d > %d)", len(r.Endpoints), MaxEndpointsPerRemote)
	case r.Kind == KindStandalone && len(r.Endpoints) != 1:
		add("standalone remote must have exactly one endpoint, got %d", len(r.Endpoints))
	}
	seen := map[string]struct{}{}
	for i, ep := range r.Endpoints {
		if !validEndpointHost(ep.Host) {
			add("endpoint %d: host %q is malformed", i, ep.Host)
		}
		if ep.Port == 0 {
			add("endpoint %d: port must be in 1..65535", i)
		}
		k := ep.Host + ":" + strconv.Itoa(int(ep.Port))
		if _, dup := seen[k]; dup {
			add("endpoint %d: %s is duplicated", i, k)
		}
		seen[k] = struct{}{}
	}

	if !fingerprintRe.MatchString(r.TrustPin) {
		add("trust_pin must be 64 lowercase hex characters")
	}
	switch {
	case r.TrustGeneration == 0:
		add("trust_generation must be at least 1")
	case r.TrustGeneration > MaxTrustGeneration:
		add("trust_generation out of range")
	}

	if len(p) > 0 {
		return Remote{}, &ValidationError{Problems: p}
	}
	n := r
	n.Endpoints = slices.Clone(r.Endpoints)
	return n, nil
}

// DecodeRemote strictly decodes and validates one remote document.
func DecodeRemote(raw []byte) (Remote, error) {
	var r Remote
	if err := decodeStrict(raw, &r); err != nil {
		return Remote{}, err
	}
	return ValidateRemote(r)
}

// MarshalRemote validates r and returns its strict JSON encoding.
func MarshalRemote(r Remote) ([]byte, error) {
	v, err := ValidateRemote(r)
	if err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

// decodeStrict enforces the document-wide limits on raw and decodes it into
// v, rejecting unknown fields. raw must be exactly one JSON document.
func decodeStrict(raw []byte, v any) error {
	if len(raw) > MaxResponseBytes {
		return fmt.Errorf("document of %d bytes exceeds %d", len(raw), MaxResponseBytes)
	}
	if !utf8.Valid(raw) {
		return errors.New("document is not valid UTF-8")
	}
	if err := walkDocument(raw); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if dec.More() {
		return errors.New("trailing data after JSON document")
	}
	return nil
}

// walkDocument enforces the document-wide limits: nesting depth, duplicate
// keys, per-string length and total object count. The decoder itself
// rejects invalid UTF-8 in strings.
func walkDocument(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var objects int
	var seenStack []map[string]struct{}
	if err := walkValue(dec, 0, &objects, &seenStack); err != nil {
		return err
	}
	if _, err := dec.Token(); err == nil {
		return errors.New("trailing data after JSON document")
	}
	return nil
}

func walkValue(dec *json.Decoder, depth int, objects *int, seenStack *[]map[string]struct{}) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("malformed JSON: %w", err)
	}
	switch v := tok.(type) {
	case string:
		if len(v) > MaxTextFieldBytes {
			return fmt.Errorf("string of %d bytes exceeds %d", len(v), MaxTextFieldBytes)
		}
	case json.Number:
		// numeric ranges are checked by the typed fields
	case json.Delim:
		switch v {
		case '{':
			if depth >= MaxNesting {
				return fmt.Errorf("nesting deeper than %d levels", MaxNesting)
			}
			*objects++
			if *objects > MaxObjectsPerDocument {
				return fmt.Errorf("more than %d objects in document", MaxObjectsPerDocument)
			}
			seen := map[string]struct{}{}
			*seenStack = append(*seenStack, seen)
			for dec.More() {
				ktok, err := dec.Token()
				if err != nil {
					return fmt.Errorf("malformed JSON: %w", err)
				}
				key, ok := ktok.(string)
				if !ok {
					return errors.New("object key is not a string")
				}
				if _, dup := seen[key]; dup {
					return fmt.Errorf("duplicate key %q", key)
				}
				seen[key] = struct{}{}
				if err := walkValue(dec, depth+1, objects, seenStack); err != nil {
					return err
				}
			}
			*seenStack = (*seenStack)[:len(*seenStack)-1]
			if _, err := dec.Token(); err != nil { // closing '}'
				return fmt.Errorf("malformed JSON: %w", err)
			}
		case '[':
			if depth >= MaxNesting {
				return fmt.Errorf("nesting deeper than %d levels", MaxNesting)
			}
			for dec.More() {
				if err := walkValue(dec, depth+1, objects, seenStack); err != nil {
					return err
				}
			}
			if _, err := dec.Token(); err != nil { // closing ']'
				return fmt.Errorf("malformed JSON: %w", err)
			}
		default:
			return fmt.Errorf("unexpected JSON delimiter %q", v)
		}
	default:
		// bool and null
	}
	return nil
}
