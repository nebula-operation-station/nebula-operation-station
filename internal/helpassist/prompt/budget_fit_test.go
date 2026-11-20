// SPDX-License-Identifier: AGPL-3.0-or-later

package prompt

import (
	"errors"
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

// fullFacts returns a projection with helpfacts.MaxFactHosts hosts of
// helpfacts.MaxEndpoints endpoints each, every field set and marked
// altered, the most source addresses, and a payload of exactly
// helpfacts.MaxFactBytes. Every text is built from fill, so the caller
// chooses how much the encoding grows.
func fullFacts(t *testing.T, fill string) *helpfacts.Result {
	t.Helper()
	text := func(n int) helpfacts.Text {
		return helpfacts.Text{Value: strings.Repeat(fill, n/len(fill)+1)[:n], Altered: true}
	}
	since := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	r := &helpfacts.Result{Truncated: true}
	for i := 0; i < helpfacts.MaxSourceAddresses; i++ {
		r.SourceAddresses = append(r.SourceAddresses, "10.0.0."+strconv.Itoa(250+i))
	}
	for h := 0; h < helpfacts.MaxFactHosts; h++ {
		f := helpfacts.Fact{
			ID:                   text(12),
			Name:                 text(24),
			EndpointsDropped:     1 << 20,
			InventoryCriticality: "critical",
			ExecutorCriticality:  "critical",
			Enrollment:           helpfacts.EnrollmentScriptRunUnknown,
			EnrollmentSince:      since,
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
// limits allow for plain data: full docs, MaxFactHosts hosts with
// MaxEndpoints endpoints and the full facts payload, and a question of
// MaxQuestionBytes. Build must accept it.
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
	n := EstimateTokens(len(p.System) + len(p.User))
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
	if n := EstimateTokens(len(SystemPrompt) + FramingBytes + len(enc)); n > MaxPromptTokens {
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
// worst case: the system prompt, MaxContextDocBytes, MaxQuestionBytes,
// FramingBytes and MaxFactsBlockBytes. A token limit one below the sum
// fails; the sum itself passes.
func TestCheckFitReservesFactsBlock(t *testing.T) {
	worst := len(SystemPrompt) + MaxContextDocBytes + MaxQuestionBytes + FramingBytes + MaxFactsBlockBytes
	need := EstimateTokens(worst)
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
