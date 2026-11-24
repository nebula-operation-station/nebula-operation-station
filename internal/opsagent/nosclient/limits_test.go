// SPDX-License-Identifier: AGPL-3.0-or-later

package nosclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

// noteOfBytes returns a note whose JSON encoding is exactly n bytes long.
func noteOfBytes(t *testing.T, n int) Draft {
	t.Helper()
	probe := Draft{Kind: "summary", Ref: "r", Digest: "d", Text: "x"}
	base, err := json.Marshal(probe)
	if err != nil {
		t.Fatal(err)
	}
	if n < len(base) {
		t.Fatalf("n = %d, smaller than the frame %d", n, len(base))
	}
	probe.Text = strings.Repeat("a", n-len(base)+1)
	got, err := json.Marshal(probe)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != n {
		t.Fatalf("note is %d bytes, want %d", len(got), n)
	}
	return probe
}

// TestNoteOverRequestLimitIsRefusedBeforeSend: the agent never sends a note
// the server refuses for size. The server reads at most opsnotes.MaxNoteBytes
// (16 KiB), so a note one byte over the agent's limit must not reach the wire.
func TestNoteOverRequestLimitIsRefusedBeforeSend(t *testing.T) {
	tests := []struct {
		name     string
		size     int
		wantSent bool
	}{
		{"at the limit is sent", MaxNoteRequestBytes, true},
		{"one byte over is refused", MaxNoteRequestBytes + 1, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var posts atomic.Int32
			c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				posts.Add(1)
				w.WriteHeader(http.StatusNoContent)
			})
			err := c.PostNote(context.Background(), noteOfBytes(t, tc.size))
			if tc.wantSent {
				if err != nil {
					t.Fatalf("PostNote: %v, want sent", err)
				}
			} else if !errors.Is(err, ErrTooLarge) {
				t.Fatalf("PostNote: %v, want ErrTooLarge", err)
			}
			want := int32(0)
			if tc.wantSent {
				want = 1
			}
			if got := posts.Load(); got != want {
				t.Errorf("server saw %d posts, want %d", got, want)
			}
		})
	}
}

// TestRequestLimitsAreNamedAndPositive: the limits are the bounds the
// requests are checked against; zero or negative values would refuse all.
func TestRequestLimitsAreNamedAndPositive(t *testing.T) {
	for name, v := range map[string]int{
		"MaxNoteRequestBytes":   MaxNoteRequestBytes,
		"MaxStatusRequestBytes": MaxStatusRequestBytes,
		"MaxNoteReplyBytes":     MaxNoteReplyBytes,
		"MaxConfigBytes":        MaxConfigBytes,
		"MaxWorkBytes":          MaxWorkBytes,
	} {
		if v <= 0 {
			t.Errorf("%s = %d, want > 0", name, v)
		}
	}
}
