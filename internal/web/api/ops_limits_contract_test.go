// SPDX-License-Identifier: AGPL-3.0-or-later

package api_test

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/opsagent/nosclient"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsagent/run"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsnotes"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/api"
)

// TestAgentRequestLimitsNeverExceedServer: the agent may send no request the
// server would refuse for size, and it must be able to read every answer the
// server can produce.
func TestAgentRequestLimitsNeverExceedServer(t *testing.T) {
	atMost := []struct {
		name          string
		agent, server int
	}{
		{"note request vs opsnotes.MaxNoteBytes", nosclient.MaxNoteRequestBytes, opsnotes.MaxNoteBytes},
		{"status request vs api.MaxOpsStatusBytes", nosclient.MaxStatusRequestBytes, api.MaxOpsStatusBytes},
	}
	for _, tc := range atMost {
		if tc.agent > tc.server {
			t.Errorf("%s: agent %d > server %d", tc.name, tc.agent, tc.server)
		}
	}
	if min := api.MaxOpsWorkItems * api.MaxOpsItemBytes; nosclient.MaxWorkBytes < min {
		t.Errorf("work answer limit %d < %d items x %d bytes", nosclient.MaxWorkBytes, api.MaxOpsWorkItems, api.MaxOpsItemBytes)
	}
}

// TestAgentTextLimitsNeverExceedServer: every free-text bound the agent
// applies to model output is no larger than the bound the server applies to
// the same field (internal/opsnotes/limits.go).
func TestAgentTextLimitsNeverExceedServer(t *testing.T) {
	pairs := []struct {
		name          string
		agent, server int
	}{
		{"summary bytes", run.MaxSummaryBytes, opsnotes.MaxSummaryBytes},
		{"text bytes", run.MaxTextBytes, opsnotes.MaxTextBytes},
		{"urgency bytes", run.MaxUrgencyBytes, opsnotes.MaxUrgencyBytes},
		{"step why bytes", run.MaxWhyBytes, opsnotes.MaxStepWhyBytes},
		{"mitigation bytes", run.MaxMitigationBytes, opsnotes.MaxMitigationBytes},
		{"steps per note", run.MaxSteps, opsnotes.MaxStepsPerNote},
		{"mitigations per note", run.MaxMitigations, opsnotes.MaxMitigations},
		{"citations per note", run.MaxCitations, opsnotes.MaxCitations},
	}
	for _, p := range pairs {
		if p.agent > p.server {
			t.Errorf("%s: agent %d > server %d", p.name, p.agent, p.server)
		}
	}
}

// fillTo repeats fill as often as fits into n bytes.
func fillTo(fill string, n int) string {
	return strings.Repeat(fill, n/len(fill))
}

// largestFixNote is the largest fix note the agent can build from its parse
// limits (internal/opsagent/run/parse.go): every free-text field at its bound
// and every identifier at MaxIDBytes, with the characters that grow most when
// JSON encodes them.
func largestFixNote(fill string) nosclient.Draft {
	id := strings.Repeat("a", opsnotes.MaxIDBytes)
	d := nosclient.Draft{
		Kind:      string(opsnotes.KindFix),
		Ref:       id,
		Digest:    id,
		Summary:   fillTo(fill, run.MaxSummaryBytes),
		Urgency:   fillTo(fill, run.MaxUrgencyBytes),
		Citations: make([]string, 0, run.MaxCitations),
	}
	for i := 0; i < run.MaxSteps; i++ {
		d.Steps = append(d.Steps, nosclient.Step{ActionID: id, HostID: id, Why: fillTo(fill, run.MaxWhyBytes)})
	}
	for i := 0; i < run.MaxMitigations; i++ {
		d.Mitigations = append(d.Mitigations, fillTo(fill, run.MaxMitigationBytes))
	}
	for i := 0; i < run.MaxCitations; i++ {
		d.Citations = append(d.Citations, id)
	}
	return d
}

// TestLargestAgentFixNoteFitsServerNoteLimit sends the largest fix note through
// the real client and reads the body the server would get. The note must pass
// the client limit and the server's own size check (opsnotes.Decode). If it
// does not, the test fails and names the size; the limit is then the item to
// change, not this test.
func TestLargestAgentFixNoteFitsServerNoteLimit(t *testing.T) {
	fills := map[string]string{
		"angle brackets, which JSON writes as six bytes": "<",
		"U+2028, three bytes that JSON writes as six":    " ",
		"newlines, which JSON writes as two bytes":       "\n",
	}
	for name, fill := range fills {
		t.Run(name, func(t *testing.T) {
			got := make(chan []byte, 1)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("read body: %v", err)
				}
				got <- b
				w.WriteHeader(http.StatusNoContent)
			}))
			t.Cleanup(srv.Close)
			c := newAgentClient(t, srv.URL)
			if err := c.PostNote(t.Context(), largestFixNote(fill)); err != nil {
				t.Fatalf("largest fix note refused by the agent: %v", err)
			}
			body := <-got
			if _, err := opsnotes.Decode(body); errors.Is(err, opsnotes.ErrLimit) {
				t.Fatalf("server refuses the largest fix note (%d bytes): %v", len(body), err)
			}
			if len(body) > opsnotes.MaxNoteBytes {
				t.Fatalf("largest fix note is %d bytes, server limit %d", len(body), opsnotes.MaxNoteBytes)
			}
		})
	}
}
