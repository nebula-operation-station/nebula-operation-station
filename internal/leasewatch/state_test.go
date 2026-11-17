// SPDX-License-Identifier: AGPL-3.0-or-later

package leasewatch

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func sampleState() State {
	return State{
		Expiry: map[string]ExpiryMarks{
			"g1": {Long: true},
			"g2": {Long: true, Short: true},
		},
		Episodes: []Episode{
			{GrantID: "g1", Action: "apt.upgrade", HostLabel: "web-1", Seq: 1},
		},
		Seq: 1,
	}
}

func TestStateRoundTrip(t *testing.T) {
	st := sampleState()
	data, err := EncodeState(st)
	if err != nil {
		t.Fatalf("EncodeState: %v", err)
	}
	got, err := DecodeState(data)
	if err != nil {
		t.Fatalf("DecodeState: %v", err)
	}
	if !reflect.DeepEqual(got, st) {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, st)
	}
	again, err := EncodeState(got)
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	if !bytes.Equal(data, again) {
		t.Fatalf("encoding not deterministic:\n%s\n%s", data, again)
	}
}

func TestZeroStateRoundTrip(t *testing.T) {
	data, err := EncodeState(State{})
	if err != nil {
		t.Fatalf("EncodeState: %v", err)
	}
	if _, err := DecodeState(data); err != nil {
		t.Fatalf("DecodeState(zero): %v", err)
	}
}

func TestDecodeStateRejects(t *testing.T) {
	long := strings.Repeat("x", MaxIDLen+1)
	manyExpiry := State{Expiry: map[string]ExpiryMarks{}}
	for i := 0; i <= MaxTrackedGrants; i++ {
		manyExpiry.Expiry[strconv.Itoa(i)] = ExpiryMarks{Long: true}
	}
	manyEpisodes := State{Seq: MaxOpenEpisodes + 1}
	for i := 0; i <= MaxOpenEpisodes; i++ {
		manyEpisodes.Episodes = append(manyEpisodes.Episodes, Episode{GrantID: strconv.Itoa(i), Action: "a", HostLabel: "h", Seq: uint64(i + 1)})
	}

	tests := []struct {
		name string
		data string
		want error
	}{
		{"not json", `{"expiry":`, ErrStateInvalid},
		{"unknown field", `{"expiry":{},"bogus":1}`, ErrStateInvalid},
		{"trailing data", `{} {}`, ErrStateInvalid},
		{"empty grant id in expiry", `{"expiry":{"":{"long":true}}}`, ErrStateInvalid},
		{"overlong grant id", `{"expiry":{"` + long + `":{"long":true}}}`, ErrStateInvalid},
		{"invalid utf-8 id", "{\"expiry\":{\"\xff\":{\"long\":true}}}", ErrStateInvalid},
		{"duplicate episode", `{"episodes":[{"grant":"g","action":"a","host":"h","seq":1},{"grant":"g","action":"a","host":"h","seq":2}],"seq":2}`, ErrStateInvalid},
		{"episode seq zero", `{"episodes":[{"grant":"g","action":"a","host":"h","seq":0}],"seq":1}`, ErrStateInvalid},
		{"episode seq above state seq", `{"episodes":[{"grant":"g","action":"a","host":"h","seq":5}],"seq":1}`, ErrStateInvalid},
		{"too many grants", mustEncodeRaw(t, manyExpiry), ErrTooManyGrants},
		{"too many episodes", mustEncodeRaw(t, manyEpisodes), ErrStateInvalid},
		{"too large", strings.Repeat(" ", MaxStateBytes+1), ErrStateTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeState([]byte(tt.data))
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestEncodeStateRejectsInvalid(t *testing.T) {
	st := State{Expiry: map[string]ExpiryMarks{"": {Long: true}}}
	if _, err := EncodeState(st); !errors.Is(err, ErrStateInvalid) {
		t.Fatalf("err = %v, want ErrStateInvalid", err)
	}
}

// mustEncodeRaw marshals a state without validation so decoder limits can be tested.
func mustEncodeRaw(t *testing.T, st State) string {
	t.Helper()
	data, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(data)
}

// FuzzDecodeState checks that the decoder never panics, respects its limits,
// and that every accepted state re-encodes to an equal state.
func FuzzDecodeState(f *testing.F) {
	seed, err := EncodeState(sampleState())
	if err != nil {
		f.Fatalf("seed: %v", err)
	}
	f.Add(seed)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"expiry":{"g":{"long":true,"short":true}},"episodes":[{"grant":"g","action":"a","host":"h","seq":1}],"seq":1}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		st, err := DecodeState(data)
		if err != nil {
			return
		}
		out, err := EncodeState(st)
		if err != nil {
			t.Fatalf("accepted state does not encode: %v", err)
		}
		if len(out) > MaxStateBytes {
			t.Fatalf("encoded state %d bytes exceeds limit", len(out))
		}
		back, err := DecodeState(out)
		if err != nil {
			t.Fatalf("re-decode: %v", err)
		}
		if !reflect.DeepEqual(back, st) {
			t.Fatalf("round trip changed state")
		}
	})
}
