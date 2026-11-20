// SPDX-License-Identifier: AGPL-3.0-or-later

package prompt

import (
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/helpdocs"
	"github.com/nebula-operation-station/nebula-operation-station/internal/helpfacts"
)

// payloadBytes counts the payload of r the way helpfacts counts
// MaxFactBytes: the text of every field, the port digits and the
// enrollment date as RFC 3339, without JSON keys or punctuation.
func payloadBytes(r *helpfacts.Result) int {
	n := 0
	for _, f := range r.Hosts {
		n += len(f.ID.Value) + len(f.Name.Value) +
			len(f.InventoryCriticality) + len(f.ExecutorCriticality) + len(f.Enrollment) +
			len(f.OSFamily.Value) + len(f.OSRelease.Value)
		for _, e := range f.Endpoints {
			n += len(e.Address) + len(e.Label.Value) + len(strconv.Itoa(e.Port))
		}
		if !f.EnrollmentSince.IsZero() {
			n += len(f.EnrollmentSince.Format(time.RFC3339))
		}
	}
	for _, s := range r.NotInInventory {
		n += len(s)
	}
	for _, s := range r.SourceAddresses {
		n += len(s)
	}
	return n
}

// fullFacts returns the projection whose JSON encoding exceeds its
// helpfacts.MaxFactBytes payload the most, for plain text: everything
// the payload does not count, or counts below its encoded size, is at
// its largest. That is: helpfacts.MaxFactHosts hosts of
// helpfacts.MaxEndpoints endpoints each, helpfacts.MaxFactHosts
// NotInInventory entries and helpfacts.MaxSourceAddresses source
// addresses (each list item adds quotes, a comma or an object), every
// field set, EndpointsDropped at math.MaxInt (19 digits, not counted by
// the payload), a zero EnrollmentSince (encoded as the 20-byte
// "0001-01-01T00:00:00Z", but counted as 0 bytes), and Altered and
// Truncated false (5 bytes, "true" is 4). The payload is exactly
// helpfacts.MaxFactBytes. Every text is built from fill, so the caller
// chooses how much the encoding grows.
func fullFacts(t *testing.T, fill string) *helpfacts.Result {
	t.Helper()
	text := func(n int) helpfacts.Text {
		return helpfacts.Text{Value: strings.Repeat(fill, n/len(fill)+1)[:n]}
	}
	r := &helpfacts.Result{}
	for i := 0; i < helpfacts.MaxSourceAddresses; i++ {
		r.SourceAddresses = append(r.SourceAddresses, "10.0.0."+strconv.Itoa(250+i))
	}
	for i := 0; i < helpfacts.MaxFactHosts; i++ {
		r.NotInInventory = append(r.NotInInventory, "10.0.1."+strconv.Itoa(i))
	}
	for h := 0; h < helpfacts.MaxFactHosts; h++ {
		f := helpfacts.Fact{
			ID:                   text(12),
			Name:                 text(24),
			EndpointsDropped:     math.MaxInt,
			InventoryCriticality: "critical",
			ExecutorCriticality:  "critical",
			Enrollment:           helpfacts.EnrollmentScriptRunUnknown,
			OSFamily:             text(16),
			OSRelease:            text(24),
		}
		for e := 0; e < helpfacts.MaxEndpoints; e++ {
			f.Endpoints = append(f.Endpoints, helpfacts.Endpoint{
				Address: "fd00:1234:5678:9abc::" + strconv.Itoa(1000+10*h+e),
				Port:    65535,
				Label:   text(32),
			})
		}
		r.Hosts = append(r.Hosts, f)
	}
	// Spread the rest of the payload over the host names.
	rest := helpfacts.MaxFactBytes - payloadBytes(r)
	if rest < 0 {
		t.Fatalf("base payload %d bytes already over MaxFactBytes", payloadBytes(r))
	}
	for i := range r.Hosts {
		share := rest / (len(r.Hosts) - i)
		r.Hosts[i].Name = text(len(r.Hosts[i].Name.Value) + share)
		rest -= share
	}
	if got := payloadBytes(r); got != helpfacts.MaxFactBytes {
		t.Fatalf("payload = %d bytes, want %d", got, helpfacts.MaxFactBytes)
	}
	return r
}

// fullDocs returns MaxChunks plain chunks whose rendered entries fill
// MaxContextDocBytes exactly.
func fullDocs(t *testing.T) []helpdocs.Chunk {
	t.Helper()
	chunks := make([]helpdocs.Chunk, MaxChunks)
	rest := MaxContextDocBytes
	for i := range chunks {
		c := testChunk(i+1, "")
		share := rest / (MaxChunks - i)
		c.Text = strings.Repeat("x", share-len(renderEntry("c"+strconv.Itoa(i+1), c)))
		rest -= share
		chunks[i] = c
	}
	return chunks
}

// TestLargestLegitimatePromptFits builds the largest prompt the shipped
// limits allow for plain data: full docs, the worst-case facts of
// fullFacts, and a question of MaxQuestionBytes. Build must accept it,
// and its estimate, message overhead included, must fit MaxPromptTokens.
func TestLargestLegitimatePromptFits(t *testing.T) {
	in := Input{
		Chunks:   fullDocs(t),
		Facts:    fullFacts(t, "pve-node-"),
		Question: strings.Repeat("Wie ", MaxQuestionBytes/4),
		Language: langDE,
	}
	if len(in.Question) != MaxQuestionBytes {
		t.Fatalf("question is %d bytes, want %d", len(in.Question), MaxQuestionBytes)
	}
	p, err := Build(in)
	if err != nil {
		t.Fatalf("Build of the largest legitimate prompt: %v", err)
	}
	if len(p.Citations) != MaxChunks {
		t.Fatalf("got %d citations, want %d (docs not full)", len(p.Citations), MaxChunks)
	}
	if got := len(blockBody(t, p.User, "docs")) - 1; got != MaxContextDocBytes {
		t.Fatalf("docs block is %d bytes, want %d", got, MaxContextDocBytes)
	}
	facts := blockBody(t, p.User, "facts")
	if len(facts) > MaxFactsBlockBytes {
		t.Fatalf("facts block is %d bytes, cap %d", len(facts), MaxFactsBlockBytes)
	}
	for _, want := range []string{`"0001-01-01T00:00:00Z"`, strconv.Itoa(math.MaxInt), `"Truncated":false`} {
		if !strings.Contains(facts, want) {
			t.Fatalf("facts block lacks %s: fixture is not the worst case", want)
		}
	}
	n := EstimateMessageTokens(p.System, p.User)
	if n > MaxPromptTokens {
		t.Fatalf("prompt estimated at %d tokens, limit %d", n, MaxPromptTokens)
	}
	t.Logf("system %d B, user %d B, facts block %d B, estimate %d of %d tokens",
		len(p.System), len(p.User), len(facts), n, MaxPromptTokens)
}

// TestOversizedFactsBlockFailsClosed checks that a facts payload within
// helpfacts.MaxFactBytes but full of characters the encoding expands is
// refused with ErrTooLarge by the facts cap, even when the whole prompt
// would still fit MaxPromptTokens.
func TestOversizedFactsBlockFailsClosed(t *testing.T) {
	in := testInput(testChunk(1, "text"))
	in.Facts = fullFacts(t, "[<]>")
	enc, err := encodeFacts(in.Facts)
	if err != nil {
		t.Fatalf("encodeFacts: %v", err)
	}
	if len(enc) <= MaxFactsBlockBytes {
		t.Fatalf("test payload encodes to %d bytes, want more than the cap %d", len(enc), MaxFactsBlockBytes)
	}
	if n := EstimateTokens(len(SystemPrompt)+FramingBytes+len(enc)) + 2*PromptMessageOverheadTokens; n > MaxPromptTokens {
		t.Fatalf("test payload (%d tokens) would also fail the total budget; it must isolate the facts cap", n)
	}
	p, err := Build(in)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Build error = %v, want ErrTooLarge", err)
	}
	if p.User != "" || p.System != "" || p.Citations != nil {
		t.Fatal("Build returned a prompt together with the error")
	}
}

// TestFactsBlockCapBoundary checks the cap at and one byte above
// MaxFactsBlockBytes.
func TestFactsBlockCapBoundary(t *testing.T) {
	if err := checkFactsBlock(strings.Repeat("a", MaxFactsBlockBytes)); err != nil {
		t.Fatalf("block at the cap: %v", err)
	}
	if err := checkFactsBlock(strings.Repeat("a", MaxFactsBlockBytes+1)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("block over the cap: error = %v, want ErrTooLarge", err)
	}
}

// TestCheckFitReservesFactsBlock checks that CheckFit counts the whole
// worst case: the system prompt as one message, and MaxContextDocBytes,
// MaxQuestionBytes, FramingBytes and MaxFactsBlockBytes as the user
// message, each message rounded up and with PromptMessageOverheadTokens.
// A token limit one below the sum fails; the sum itself passes.
func TestCheckFitReservesFactsBlock(t *testing.T) {
	user := MaxContextDocBytes + MaxQuestionBytes + FramingBytes + MaxFactsBlockBytes
	need := EstimateTokens(len(SystemPrompt)) + EstimateTokens(user) + 2*PromptMessageOverheadTokens
	if err := checkFit(SystemPrompt, need, MaxContextDocBytes, MaxQuestionBytes, MaxFactsBlockBytes); err != nil {
		t.Fatalf("checkFit at %d tokens: %v", need, err)
	}
	if err := checkFit(SystemPrompt, need-1, MaxContextDocBytes, MaxQuestionBytes, MaxFactsBlockBytes); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("checkFit at %d tokens: error = %v, want ErrTooLarge", need-1, err)
	}
	if need > MaxPromptTokens {
		t.Fatalf("worst case %d tokens exceeds MaxPromptTokens %d", need, MaxPromptTokens)
	}
}
