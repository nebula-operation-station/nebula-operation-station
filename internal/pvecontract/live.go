// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecontract

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"unicode/utf8"
)

// Bounded live handoff limits (ADR 0006 live chart). The server publishes a
// small want-list the collector reads, and the collector publishes small
// per-remote sample documents the server reads. Both are versioned, strict
// JSON documents with explicit size and count caps.
const (
	// MaxLiveWantBytes bounds one want-list document.
	MaxLiveWantBytes = 64 << 10
	// MaxLiveSamplesBytes bounds one per-remote samples document.
	MaxLiveSamplesBytes = 128 << 10
	// MaxLiveTargets bounds the number of targets in one want-list.
	MaxLiveTargets = 256
	// MaxLiveSamples bounds the number of samples in one samples document.
	MaxLiveSamples = 256
	// LiveWantMaxExpiry bounds expires_unix - written_unix, in seconds.
	LiveWantMaxExpiry = 30
	// LiveClockSkew is how far, in seconds, a live document's timestamps may
	// lie ahead of the reader's clock before the document is refused.
	LiveClockSkew = 5
	// LiveWantVersion is the only supported want-list version.
	LiveWantVersion = 1
	// LiveSamplesVersion is the only supported samples version.
	LiveSamplesVersion = 1
)

// Live target kinds, mirroring the telemetry provider kinds.
const (
	// LiveKindNode is a node-level live target or sample.
	LiveKindNode = "node"
	// LiveKindQEMU is a QEMU guest live target or sample.
	LiveKindQEMU = "qemu"
	// LiveKindLXC is an LXC container live target or sample.
	LiveKindLXC = "lxc"
)

// LiveTarget is one requested live target: a remote, node, kind and, for
// guests, the VMID. It is validated like a telemetry provider target.
type LiveTarget struct {
	Remote string `json:"remote"`
	Kind   string `json:"kind"`
	Node   string `json:"node"`
	VMID   uint64 `json:"vmid"`
}

// LiveWant is the server's want-list: the live targets it currently wants.
// It is versioned and time-bounded; an invalid or expired document means
// "no targets".
type LiveWant struct {
	Version     int64        `json:"version"`
	WrittenUnix int64        `json:"written_unix"`
	ExpiresUnix int64        `json:"expires_unix"`
	Targets     []LiveTarget `json:"targets"`
}

// LiveSample is one live metric sample for a target.
type LiveSample struct {
	Kind         string  `json:"kind"`
	Node         string  `json:"node"`
	VMID         uint64  `json:"vmid"`
	CPU          float64 `json:"cpu"`
	MemUsed      float64 `json:"mem_used"`
	MemTotal     float64 `json:"mem_total"`
	DiskUsed     float64 `json:"disk_used"`
	DiskTotal    float64 `json:"disk_total"`
	NetIn        float64 `json:"net_in"`
	NetOut       float64 `json:"net_out"`
	ObservedUnix int64   `json:"observed_unix"`
}

// LiveSamples is the collector's live samples for one remote. The remote
// must match the file name the document is stored under.
type LiveSamples struct {
	Version     int64        `json:"version"`
	Remote      string       `json:"remote"`
	WrittenUnix int64        `json:"written_unix"`
	Samples     []LiveSample `json:"samples"`
}

// Expired reports whether the want-list is no longer valid at nowUnix. The
// document is valid during [written_unix, expires_unix).
func (w LiveWant) Expired(nowUnix int64) bool {
	return nowUnix >= w.ExpiresUnix
}

// CheckClock rejects a want-list that is dated in the future relative to
// the reader's clock nowUnix: written_unix may be at most LiveClockSkew
// seconds ahead and expires_unix at most LiveWantMaxExpiry seconds ahead
// (the skew never extends how long a want-list stays in force). Without it a future-dated document would stay live far
// longer than LiveWantMaxExpiry.
func (w LiveWant) CheckClock(nowUnix int64) error {
	var p []string
	if w.WrittenUnix > nowUnix+LiveClockSkew {
		p = append(p, fmt.Sprintf("written_unix is more than %d s in the future", LiveClockSkew))
	}
	if w.ExpiresUnix > nowUnix+LiveWantMaxExpiry {
		p = append(p, fmt.Sprintf("expires_unix is more than %d s in the future", LiveWantMaxExpiry))
	}
	if len(p) > 0 {
		return &ValidationError{Problems: p}
	}
	return nil
}

// Live reports whether the want-list is in force at nowUnix: not dated in
// the future (CheckClock) and not expired.
func (w LiveWant) Live(nowUnix int64) bool {
	return w.CheckClock(nowUnix) == nil && !w.Expired(nowUnix)
}

// validLiveTarget appends problems for one live target, validated like a
// telemetry provider target.
func validLiveTarget(i int, t LiveTarget, add func(string, ...any)) {
	if !ValidRemoteID(t.Remote) {
		add("target %d: remote %q is malformed", i, t.Remote)
	}
	if !ValidNodeName(t.Node) {
		add("target %d: node %q is malformed", i, t.Node)
	}
	switch t.Kind {
	case LiveKindNode:
		if t.VMID != 0 {
			add("target %d: vmid must be 0 for kind node", i)
		}
	case LiveKindQEMU, LiveKindLXC:
		if t.VMID < MinVMID || t.VMID > MaxVMID {
			add("target %d: vmid %d out of range", i, t.VMID)
		}
	default:
		add("target %d: kind %q is unknown", i, t.Kind)
	}
}

// ValidateLiveWant validates w and returns a copy with duplicate targets
// removed (first occurrence wins). It never mutates w.
func ValidateLiveWant(w LiveWant) (LiveWant, error) {
	var p []string
	add := func(format string, args ...any) { p = append(p, fmt.Sprintf(format, args...)) }

	if w.Version != LiveWantVersion {
		add("version must be %d", LiveWantVersion)
	}
	if w.WrittenUnix < 0 {
		add("written_unix must be non-negative")
	}
	if w.ExpiresUnix < 0 {
		add("expires_unix must be non-negative")
	}
	if w.WrittenUnix >= 0 && w.ExpiresUnix >= 0 {
		switch {
		case w.ExpiresUnix < w.WrittenUnix:
			add("expires_unix must be at least written_unix")
		case w.ExpiresUnix-w.WrittenUnix > LiveWantMaxExpiry:
			add("expires_unix is more than %d s after written_unix", LiveWantMaxExpiry)
		}
	}
	if len(w.Targets) > MaxLiveTargets {
		add("too many targets (%d > %d)", len(w.Targets), MaxLiveTargets)
	}
	seen := make(map[string]struct{}, len(w.Targets))
	targets := make([]LiveTarget, 0, len(w.Targets))
	for i, t := range w.Targets {
		validLiveTarget(i, t, add)
		key := t.Remote + "\x00" + t.Kind + "\x00" + t.Node + "\x00" + strconv.FormatUint(t.VMID, 10)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		targets = append(targets, t)
	}
	if len(p) > 0 {
		return LiveWant{}, &ValidationError{Problems: p}
	}
	w.Targets = targets
	return w, nil
}

// DecodeLiveWant strictly decodes and validates a want-list document.
func DecodeLiveWant(raw []byte) (LiveWant, error) {
	var w LiveWant
	if err := decodeLiveStrict(raw, MaxLiveWantBytes, &w); err != nil {
		return LiveWant{}, err
	}
	return ValidateLiveWant(w)
}

// MarshalLiveWant validates w and returns its strict JSON encoding.
func MarshalLiveWant(w LiveWant) ([]byte, error) {
	v, err := ValidateLiveWant(w)
	if err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

// validLiveSample appends problems for one live sample. All numbers must be
// finite and non-negative; cpu must additionally lie in [0,1].
func validLiveSample(i int, s LiveSample, add func(string, ...any)) {
	if !ValidNodeName(s.Node) {
		add("sample %d: node %q is malformed", i, s.Node)
	}
	switch s.Kind {
	case LiveKindNode:
		if s.VMID != 0 {
			add("sample %d: vmid must be 0 for kind node", i)
		}
	case LiveKindQEMU, LiveKindLXC:
		if s.VMID < MinVMID || s.VMID > MaxVMID {
			add("sample %d: vmid %d out of range", i, s.VMID)
		}
	default:
		add("sample %d: kind %q is unknown", i, s.Kind)
	}
	if math.IsNaN(s.CPU) || s.CPU < 0 || s.CPU > 1 {
		add("sample %d: cpu must be in [0,1]", i)
	}
	for _, fv := range []struct {
		name  string
		value float64
	}{
		{"mem_used", s.MemUsed},
		{"mem_total", s.MemTotal},
		{"disk_used", s.DiskUsed},
		{"disk_total", s.DiskTotal},
		{"net_in", s.NetIn},
		{"net_out", s.NetOut},
	} {
		if math.IsNaN(fv.value) || math.IsInf(fv.value, 0) || fv.value < 0 {
			add("sample %d: %s must be finite and non-negative", i, fv.name)
		}
	}
	if s.ObservedUnix < 0 {
		add("sample %d: observed_unix must be non-negative", i)
	}
}

// ValidateLiveSamples validates s and returns it. It never mutates s.
func ValidateLiveSamples(s LiveSamples) (LiveSamples, error) {
	var p []string
	add := func(format string, args ...any) { p = append(p, fmt.Sprintf(format, args...)) }

	if s.Version != LiveSamplesVersion {
		add("version must be %d", LiveSamplesVersion)
	}
	if !ValidRemoteID(s.Remote) {
		add("remote %q is malformed", s.Remote)
	}
	if s.WrittenUnix < 0 {
		add("written_unix must be non-negative")
	}
	if len(s.Samples) > MaxLiveSamples {
		add("too many samples (%d > %d)", len(s.Samples), MaxLiveSamples)
	}
	for i, smp := range s.Samples {
		validLiveSample(i, smp, add)
	}
	if len(p) > 0 {
		return LiveSamples{}, &ValidationError{Problems: p}
	}
	return s, nil
}

// CheckClock rejects a samples document dated in the future relative to the
// reader's clock nowUnix: written_unix and every sample's observed_unix may
// be at most LiveClockSkew seconds ahead, so a future-dated document cannot
// look fresh for longer than it is.
func (s LiveSamples) CheckClock(nowUnix int64) error {
	var p []string
	if s.WrittenUnix > nowUnix+LiveClockSkew {
		p = append(p, fmt.Sprintf("written_unix is more than %d s in the future", LiveClockSkew))
	}
	for i, smp := range s.Samples {
		if smp.ObservedUnix > nowUnix+LiveClockSkew {
			p = append(p, fmt.Sprintf("sample %d: observed_unix is more than %d s in the future", i, LiveClockSkew))
		}
	}
	if len(p) > 0 {
		return &ValidationError{Problems: p}
	}
	return nil
}

// DecodeLiveSamples strictly decodes and validates a samples document.
func DecodeLiveSamples(raw []byte) (LiveSamples, error) {
	var s LiveSamples
	if err := decodeLiveStrict(raw, MaxLiveSamplesBytes, &s); err != nil {
		return LiveSamples{}, err
	}
	return ValidateLiveSamples(s)
}

// MarshalLiveSamples validates s and returns its strict JSON encoding.
func MarshalLiveSamples(s LiveSamples) ([]byte, error) {
	v, err := ValidateLiveSamples(s)
	if err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

// decodeLiveStrict enforces the document-wide limits on raw (bounded by
// limit) and decodes it into v, rejecting unknown fields. raw must be
// exactly one JSON document.
func decodeLiveStrict(raw []byte, limit int, v any) error {
	if len(raw) > limit {
		return fmt.Errorf("document of %d bytes exceeds %d", len(raw), limit)
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
