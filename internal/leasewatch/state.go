// SPDX-License-Identifier: AGPL-3.0-or-later

package leasewatch

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

// MaxStateBytes is the maximum size of an encoded or decoded State.
const MaxStateBytes = 1 << 20

// Errors returned by the state codec.
var (
	// ErrStateInvalid reports a malformed or inconsistent encoded state.
	ErrStateInvalid = errors.New("leasewatch: invalid state")
	// ErrStateTooLarge reports an encoded state larger than MaxStateBytes.
	ErrStateTooLarge = errors.New("leasewatch: state too large")
)

// State is what the watcher remembers between runs. It holds no grant details,
// only what is needed to avoid repeating an event. The zero value is an empty state.
type State struct {
	// Expiry holds the expiry thresholds already reported, keyed by grant ID.
	Expiry map[string]ExpiryMarks `json:"expiry,omitempty"`
	// Episodes holds the open run-failure episodes.
	Episodes []Episode `json:"episodes,omitempty"`
	// Seq is the last episode sequence number handed out. It orders episodes
	// for eviction and does not depend on the clock.
	Seq uint64 `json:"seq,omitempty"`
}

// ExpiryMarks records which expiry thresholds were already reported for a grant.
type ExpiryMarks struct {
	// Long is set once the ExpiryWarnLong event was emitted or the grant was seen inside it.
	Long bool `json:"long,omitempty"`
	// Short is set once the ExpiryWarnShort event was emitted.
	Short bool `json:"short,omitempty"`
}

// Episode is an open run-failure episode for one grant, action and host.
type Episode struct {
	// GrantID is the grant of the failing run.
	GrantID string `json:"grant"`
	// Action is the failing action.
	Action string `json:"action"`
	// HostLabel is the host of the failing run.
	HostLabel string `json:"host"`
	// Seq orders episodes by when they opened. Starts at 1.
	Seq uint64 `json:"seq"`
}

// EncodeState validates st and returns its JSON encoding. The encoding is
// deterministic: map keys are sorted by encoding/json.
func EncodeState(st State) ([]byte, error) {
	if err := validateState(st); err != nil {
		return nil, err
	}
	data, err := json.Marshal(st)
	if err != nil {
		return nil, fmt.Errorf("encode state: %w", err)
	}
	if len(data) > MaxStateBytes {
		return nil, fmt.Errorf("%w: %d > %d bytes", ErrStateTooLarge, len(data), MaxStateBytes)
	}
	return data, nil
}

// DecodeState parses and validates an encoded State. Unknown fields, trailing
// data, invalid UTF-8 and anything over the limits are rejected.
func DecodeState(data []byte) (State, error) {
	if len(data) > MaxStateBytes {
		return State{}, fmt.Errorf("%w: %d > %d bytes", ErrStateTooLarge, len(data), MaxStateBytes)
	}
	if !utf8.Valid(data) {
		return State{}, fmt.Errorf("%w: not valid UTF-8", ErrStateInvalid)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var st State
	if err := dec.Decode(&st); err != nil {
		return State{}, fmt.Errorf("%w: %v", ErrStateInvalid, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return State{}, fmt.Errorf("%w: trailing data", ErrStateInvalid)
	}
	if len(st.Expiry) == 0 {
		st.Expiry = nil
	}
	if len(st.Episodes) == 0 {
		st.Episodes = nil
	}
	if err := validateState(st); err != nil {
		return State{}, err
	}
	return st, nil
}

// validateState checks the limits and consistency rules of a State.
func validateState(st State) error {
	if len(st.Expiry) > MaxTrackedGrants {
		return fmt.Errorf("%w: %d expiry entries > %d", ErrTooManyGrants, len(st.Expiry), MaxTrackedGrants)
	}
	for id := range st.Expiry {
		if err := checkText(id, MaxIDLen); err != nil {
			return fmt.Errorf("%w: expiry grant id: %v", ErrStateInvalid, err)
		}
	}
	if len(st.Episodes) > MaxOpenEpisodes {
		return fmt.Errorf("%w: %d episodes > %d", ErrStateInvalid, len(st.Episodes), MaxOpenEpisodes)
	}
	type episodeKey struct{ grant, action, host string }
	seen := make(map[episodeKey]struct{}, len(st.Episodes))
	seq := make(map[uint64]struct{}, len(st.Episodes))
	for _, ep := range st.Episodes {
		if err := checkText(ep.GrantID, MaxIDLen); err != nil {
			return fmt.Errorf("%w: episode grant id: %v", ErrStateInvalid, err)
		}
		if err := checkText(ep.Action, MaxActionLen); err != nil {
			return fmt.Errorf("%w: episode action: %v", ErrStateInvalid, err)
		}
		if err := checkText(ep.HostLabel, MaxLabelLen); err != nil {
			return fmt.Errorf("%w: episode host label: %v", ErrStateInvalid, err)
		}
		if ep.Seq == 0 || ep.Seq > st.Seq {
			return fmt.Errorf("%w: episode seq %d outside 1..%d", ErrStateInvalid, ep.Seq, st.Seq)
		}
		key := episodeKey{ep.GrantID, ep.Action, ep.HostLabel}
		if _, dup := seen[key]; dup {
			return fmt.Errorf("%w: duplicate episode for grant %q", ErrStateInvalid, ep.GrantID)
		}
		if _, dup := seq[ep.Seq]; dup {
			return fmt.Errorf("%w: duplicate episode seq %d", ErrStateInvalid, ep.Seq)
		}
		seen[key] = struct{}{}
		seq[ep.Seq] = struct{}{}
	}
	return nil
}
