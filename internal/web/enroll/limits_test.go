// SPDX-License-Identifier: AGPL-3.0-or-later

package enroll

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc"

	"github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// offerAlphabet is the offer ID alphabet: lowercase RFC 4648 base32, no
// padding (ADR 0013 D2).
const offerAlphabet = "abcdefghijklmnopqrstuvwxyz234567"

// sizedExecutor releases the same script on every call and counts calls.
type sizedExecutor struct {
	mu     sync.Mutex
	script []byte
	calls  int
}

func (s *sizedExecutor) FetchEnrollScript(_ context.Context, _ *executorv1.FetchEnrollScriptRequest, _ ...grpc.CallOption) (*executorv1.FetchEnrollScriptResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	sum := sha256.Sum256(s.script)
	return &executorv1.FetchEnrollScriptResponse{
		Script:       append([]byte(nil), s.script...),
		ScriptSha256: hex.EncodeToString(sum[:]),
	}, nil
}

// scriptOfSize returns n bytes of a deterministic, non-constant pattern.
func scriptOfSize(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte('a' + i%26)
	}
	return b
}

// TestScriptSizeBoundary: an empty script and one above MaxScriptBytes are
// the uniform 404; exactly MaxScriptBytes is served unchanged.
func TestScriptSizeBoundary(t *testing.T) {
	cases := []struct {
		name    string
		size    int
		want200 bool
	}{
		{"empty script refused", 0, false},
		{"script of exactly MaxScriptBytes served", MaxScriptBytes, true},
		{"script of MaxScriptBytes plus one refused", MaxScriptBytes + 1, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			script := scriptOfSize(tc.size)
			ex := &sizedExecutor{script: script}
			s := newServer(t, trustedP(), ex, NewLimiter(0, newClock().now), nil)
			r := s.get(t, PathPrefix+strings.Repeat("a", OfferIDLen), addrA)
			if !tc.want200 {
				assertUniform404(t, r)
				return
			}
			assert200(t, r)
			if !bytes.Equal(r.body, script) {
				t.Fatalf("body differs from the executor's script: got %d bytes, want %d", len(r.body), len(script))
			}
		})
	}
}

// malformedOfferIDs are IDs whose syntax is wrong; none may reach the store.
func malformedOfferIDs() map[string]string {
	valid := strings.Repeat("a", OfferIDLen)
	replaceAt := func(c byte) string { return valid[:10] + string(c) + valid[11:] }
	return map[string]string{
		"one character short":    valid[:OfferIDLen-1],
		"one character long":     valid + "a",
		"digit 0 outside base32": replaceAt('0'),
		"digit 1 outside base32": replaceAt('1'),
		"digit 8 outside base32": replaceAt('8'),
		"digit 9 outside base32": replaceAt('9'),
		"uppercase letter":       replaceAt('A'),
		"padding character":      replaceAt('='),
	}
}

// TestMalformedOfferIDNeverReachesStore: wrong length or a character outside
// the alphabet is refused as a 404 without asking the executor.
func TestMalformedOfferIDNeverReachesStore(t *testing.T) {
	for name, id := range malformedOfferIDs() {
		t.Run(name, func(t *testing.T) {
			ex := newStub()
			s := newServer(t, trustedP(), ex, NewLimiter(0, newClock().now), nil)
			assertUniform404(t, s.get(t, PathPrefix+id, addrA))
			if n := ex.callCount(); n != 0 {
				t.Fatalf("executor called %d times for malformed ID", n)
			}
		})
	}
}

// TestWellFormedOfferIDReachesStore is the control for the test above: a
// well-formed ID is looked up, both when open and when unknown.
func TestWellFormedOfferIDReachesStore(t *testing.T) {
	ex := newStub()
	s := newServer(t, trustedP(), ex, NewLimiter(0, newClock().now), nil)
	assert200(t, s.get(t, PathPrefix+ex.offer(), addrA))
	if n := ex.callCount(); n != 1 {
		t.Fatalf("executor calls = %d, want 1 for an open offer", n)
	}
	assertUniform404(t, s.get(t, PathPrefix+strings.Repeat("2", OfferIDLen), addrA))
	if n := ex.callCount(); n != 2 {
		t.Fatalf("executor calls = %d, want 2 after an unknown well-formed ID", n)
	}
}

// TestRejectedOfferIDIndistinguishableFromUnknown: a malformed ID answers
// with the same status, headers and body as a well-formed unknown ID.
func TestRejectedOfferIDIndistinguishableFromUnknown(t *testing.T) {
	for name, id := range malformedOfferIDs() {
		t.Run(name, func(t *testing.T) {
			ex := newStub()
			s := newServer(t, trustedP(), ex, NewLimiter(0, newClock().now), nil)
			rejected := s.get(t, PathPrefix+id, addrA)
			unknown := s.get(t, PathPrefix+strings.Repeat("a", OfferIDLen), addrA)
			if !reflect.DeepEqual(rejected, unknown) {
				t.Fatalf("rejected %+v differs from unknown %+v", rejected, unknown)
			}
		})
	}
}

// FuzzValidOfferID: no input panics, and the result is true exactly when the
// input is OfferIDLen bytes, all from the offer alphabet.
func FuzzValidOfferID(f *testing.F) {
	f.Add(strings.Repeat("a", OfferIDLen))
	f.Add(strings.Repeat("2", OfferIDLen))
	f.Add(strings.Repeat("7", OfferIDLen))
	f.Add(strings.Repeat("a", OfferIDLen-1))
	f.Add(strings.Repeat("a", OfferIDLen+1))
	f.Add(strings.Repeat("A", OfferIDLen))
	f.Add(strings.Repeat("0", OfferIDLen))
	f.Add(strings.Repeat("a", OfferIDLen-1) + "=")
	f.Add("")
	f.Add("ü" + strings.Repeat("a", OfferIDLen-1))
	f.Fuzz(func(t *testing.T, id string) {
		want := len(id) == OfferIDLen
		for i := 0; want && i < len(id); i++ {
			want = strings.IndexByte(offerAlphabet, id[i]) >= 0
		}
		if got := validOfferID(id); got != want {
			t.Fatalf("validOfferID(%q) = %v, want %v", id, got, want)
		}
	})
}
