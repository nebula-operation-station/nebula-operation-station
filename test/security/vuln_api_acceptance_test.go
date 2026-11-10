// SPDX-License-Identifier: AGPL-3.0-or-later

package security

// Vulnerability agent API acceptance tests (ADR 0011 D1, D2, D3, D5, D6;
// VU-16 part 2; rules V1 and V9 of docs/implementation/
// vulnerability-management.md).
//
// Like part 1 (vuln_store_acceptance_test.go, whose environment and record
// helpers these tests reuse), every test drives the real agent API over a
// loopback HTTP server with the hermes-vuln token on the real findings
// store and reads the outcome back from the store, the audit log and
// server.db. The tests cover:
//
//   - hostile assessment text: markup is stored byte for byte as inert text
//     (the pages render it, test/browser/vuln.spec.js), control and bidi
//     characters, invalid UTF-8 and over-long text reject the whole batch,
//     are never echoed or logged, and the rejected batch blocks every run
//     closure (D5 precondition 5e);
//   - oversized bodies and over-limit counts are refused, and the server
//     stops reading an oversized body after the limit (bounded memory);
//   - the agent token cannot leave its scope: no read API, no other
//     subject, no NOS-owned or admin field, no human state, no mark reset,
//     no allowlist bypass;
//   - rule V1: no finding creates a proposal, permit, lease or schedule,
//     and the agent API's code cannot reach the executor at all.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/api"
)

// hostileMarker is part of every hostile string below, so a test can look
// for any echo of it in responses and audit entries.
const hostileMarker = "VU16BMARK"

// rawPlaceholder is replaced by raw bytes after JSON encoding, for input
// that encoding/json would repair (invalid UTF-8, lone surrogates).
const rawPlaceholder = "@@VU16B-RAW@@"

// --- helpers ---

// postBatch posts body as a findings batch of runID and returns the status
// and response.
func (e *vulnEnv) postBatch(runID string, body []byte) (int, []byte) {
	e.t.Helper()
	return e.do(http.MethodPost, "/api/v1/vuln/runs/"+runID+"/findings", body)
}

// batchBody is a batch with the next batch_seq that covers cover and
// carries recs, JSON encoded; raw, when set, replaces rawPlaceholder.
func (e *vulnEnv) batchBody(cover []vulnstore.Subject, raw []byte, recs ...map[string]any) []byte {
	e.t.Helper()
	subs := []any{}
	for _, s := range cover {
		ref := map[string]any{"id": s.ID}
		if s.ImageDigest != "" {
			ref["image_digest"] = s.ImageDigest
		}
		subs = append(subs, map[string]any{"subject_kind": s.Kind, "subject_ref": ref, "part": 1, "last_part": true})
	}
	if recs == nil {
		recs = []map[string]any{}
	}
	e.batchSeq++
	b := mustMarshal(e.t, map[string]any{"batch_seq": e.batchSeq, "subjects": subs, "findings": recs})
	if raw != nil {
		if !bytes.Contains(b, []byte(rawPlaceholder)) {
			e.t.Fatal("fixture: no placeholder in the batch")
		}
		b = bytes.ReplaceAll(b, []byte(rawPlaceholder), raw)
	}
	return b
}

// findings returns every stored finding of cve on any subject.
func (e *vulnEnv) findings(cve string) []vulnstore.Finding {
	e.t.Helper()
	fs, _, err := e.st.List(e.t.Context(), vulnstore.ListQuery{VulnID: cve, Limit: 10})
	if err != nil {
		e.t.Fatal(err)
	}
	return fs
}

func (e *vulnEnv) wantAbsent(cves ...string) {
	e.t.Helper()
	for _, c := range cves {
		if fs := e.findings(c); len(fs) != 0 {
			e.t.Errorf("%s stored (%d findings, first in state %s), want nothing stored", c, len(fs), fs[0].State)
		}
	}
}

// wantNoEcho fails if a response or the audit log repeats hostile input.
func (e *vulnEnv) wantNoEcho(what string, resp []byte) {
	e.t.Helper()
	if bytes.Contains(resp, []byte(hostileMarker)) {
		e.t.Errorf("%s: the response echoes hostile input: %s", what, resp)
	}
	if strings.Contains(e.log.String(), hostileMarker) {
		e.t.Errorf("%s: the audit log contains hostile input", what)
	}
}

// openBaseline opens cveN(0) on web01 in a complete run, so that a later
// complete run covering web01 without reporting it would close it.
func (e *vulnEnv) openBaseline() string {
	e.t.Helper()
	c := cveN(0)
	e.run(e.fresh(nil), host(), vulnRecord(c))
	e.wantOpen(subjWeb01, c)
	return c
}

// wantRejectedBatchBlocksClosure runs a complete run that covers web01
// without reporting baseline (an omission closure) and lets send post one
// more batch that must be rejected as a whole; the run must then close
// nothing (D5 precondition 5e).
func (e *vulnEnv) wantRejectedBatchBlocksClosure(baseline string, send func(runID string) (int, []byte)) {
	e.t.Helper()
	s := e.start(e.fresh(nil))
	e.batch(s.RunID, host())
	code, body := send(s.RunID)
	if code < 400 || code == http.StatusUnauthorized || code == http.StatusForbidden || code == http.StatusTooManyRequests {
		e.t.Fatalf("hostile batch: %d %s, want rejected as input", code, body)
	}
	c := e.complete(s.RunID)
	e.clk.Add(10 * time.Minute)
	if !c.BatchRejected || c.ClosedUnconfirmed != 0 || c.ClosedEvidenced != 0 || len(c.Held) != 0 {
		e.t.Errorf("a run with a rejected batch closed findings: %+v", c)
	}
	e.wantOpen(subjWeb01, baseline)
}

// --- hostile assessment text (V9) ---

// Markup, template syntax, Markdown and links are printable text: the
// record is accepted and the text stored byte for byte, as data, never
// interpreted or rewritten by the API or the store. The agent API never
// returns the text and the audit log never contains it (D5: assessment
// text is not logged). The pages show it as literal text
// (test/browser/vuln.spec.js).
func TestVulnHostileMarkupInAssessmentIsStoredAsInertText(t *testing.T) {
	texts := []string{
		`<script>window.__pwned='script'</script>` + hostileMarker,
		`<img src=x onerror="window.__pwned='img'">` + hostileMarker,
		`"'><svg/onload=alert(1)>` + hostileMarker + "\n\tsecond line",
		`[click me](javascript:alert(1)) **bold** <a href="https://evil.example/">x</a> ` + hostileMarker,
		`{{.Token}} {{template "x"}} ${7*7} %s %n %!v ` + hostileMarker,
		`</textarea></pre><iframe srcdoc="<script>parent.__pwned=1</script>">` + hostileMarker,
		`&lt;script&gt; &#60;b&#62; ` + hostileMarker,
		strings.Repeat("A", vulnfinding.MaxAssessmentBytes-len(hostileMarker)) + hostileMarker,
	}
	e := newVulnEnv(t, nil)
	s := e.start(e.fresh(nil))
	var recs []map[string]any
	for i, tx := range texts {
		recs = append(recs, vulnRecord(cveN(100+i), withText(tx)))
	}
	code, body := e.postBatch(s.RunID, e.batchBody(host(), nil, recs...))
	if code != http.StatusOK {
		t.Fatalf("batch with markup text: %d %s", code, body)
	}
	var res batchResult
	if err := json.Unmarshal(body, &res); err != nil || res.Opened != len(texts) || res.Rejected != 0 {
		t.Fatalf("batch result %s (%v), want %d opened", body, err, len(texts))
	}
	e.complete(s.RunID)
	for i, tx := range texts {
		f := e.finding(cveN(100+i), subjWeb01)
		if f.Record.Assessment.Text != tx {
			t.Errorf("text %d stored as %q, want it byte for byte", i, f.Record.Assessment.Text)
		}
		if f.State != vulnstore.StateOpen {
			t.Errorf("text %d: state %s, want open", i, f.State)
		}
	}
	e.wantNoEcho("markup text", body)
}

// Control characters, bidi controls, U+FFFD, invalid UTF-8 (raw or as an
// escaped lone surrogate) and text over 4 KiB reject the whole batch: no
// record of it is stored, the reason does not quote the text, the audit
// entry carries only size and hash, and the run that received the batch
// closes nothing.
func TestVulnHostileAssessmentTextRejectsTheBatch(t *testing.T) {
	cases := []struct {
		name string
		text string
		raw  []byte // replaces rawPlaceholder in the encoded body
	}{
		{name: "NUL", text: "a\x00" + hostileMarker},
		{name: "ESC sequence", text: "\x1b[2J\x1b[31m" + hostileMarker},
		{name: "carriage return", text: "line\r" + hostileMarker},
		{name: "DEL", text: "a\x7f" + hostileMarker},
		{name: "C1 NEL", text: "a\u0085" + hostileMarker},
		// UTF-8 of U+202E, U+2066, U+200E and U+FFFD, written as bytes.
		{name: "bidi override", text: "safe\xe2\x80\xae" + hostileMarker},
		{name: "bidi isolate", text: "safe\xe2\x81\xa6" + hostileMarker},
		{name: "left-to-right mark", text: "safe\xe2\x80\x8e" + hostileMarker},
		{name: "replacement character", text: "a\xef\xbf\xbd" + hostileMarker},
		{name: "invalid UTF-8", text: rawPlaceholder + hostileMarker, raw: []byte("\xff\xfe")},
		{name: "overlong UTF-8 for <", text: rawPlaceholder + hostileMarker, raw: []byte("\xc0\xbcscript")},
		{name: "UTF-8 encoded surrogate", text: rawPlaceholder + hostileMarker, raw: []byte("\xed\xa0\x80")},
		{name: "escaped lone surrogate", text: rawPlaceholder + hostileMarker, raw: []byte(`\ud800`)},
		{name: "over 4 KiB", text: strings.Repeat("B", vulnfinding.MaxAssessmentBytes+1-len(hostileMarker)) + hostileMarker},
		{name: "over 4 KiB in multibyte runes", text: strings.Repeat("ä", vulnfinding.MaxAssessmentBytes/2) + hostileMarker},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newVulnEnv(t, nil)
			base := e.openBaseline()
			hostile := cveN(200)
			e.wantRejectedBatchBlocksClosure(base, func(runID string) (int, []byte) {
				code, body := e.postBatch(runID, e.batchBody(nil, tc.raw, vulnRecord(cveN(201)), vulnRecord(hostile, withText(tc.text))))
				e.wantNoEcho(tc.name, body)
				return code, body
			})
			// Neither the hostile record nor its valid neighbour was stored.
			e.wantAbsent(hostile, cveN(201))
			if !strings.Contains(e.log.String(), `"kind":"vuln_batch_rejected"`) {
				t.Error("the rejected batch was not audited")
			}
		})
	}
}

// Other record fields from Hermes are not free text: IDs, package names,
// versions and subject refs are pattern-checked, and markup, control
// characters or URLs in them reject the batch.
func TestVulnHostileRecordFieldsRejectTheBatch(t *testing.T) {
	set := func(path string, v any) recOpt {
		return func(r map[string]any) {
			keys := strings.Split(path, ".")
			m := r
			for _, k := range keys[:len(keys)-1] {
				m = m[k].(map[string]any)
			}
			m[keys[len(keys)-1]] = v
		}
	}
	aliases := make([]string, vulnfinding.MaxAliases+1)
	for i := range aliases {
		aliases[i] = fmt.Sprintf("DSA-%d-1", 5000+i)
	}
	cases := []struct {
		name string
		opt  recOpt
	}{
		{"vuln id markup", set("vuln.id", "<script>"+hostileMarker)},
		{"vuln id URL", set("vuln.id", "https://evil.example/"+hostileMarker)},
		{"vuln id over 64", set("vuln.id", "CVE-2026-"+strings.Repeat("1", 60)+hostileMarker)},
		{"alias markup", set("vuln.aliases", []string{"<b>" + hostileMarker})},
		{"17 aliases", set("vuln.aliases", aliases)},
		{"source package markup", set("component.source_package", "openssl<img>"+hostileMarker)},
		{"source version control", set("component.source_version", opensslInstalled+"\x1b"+hostileMarker)},
		{"fixed version markup", set("fix.version", "<svg>"+hostileMarker)},
		{"ecosystem newline", set("ecosystem", "debian:bookworm\n"+hostileMarker)},
		{"subject traversal", set("subject_ref.id", "../web01/"+hostileMarker)},
		{"image digest markup", func(r map[string]any) {
			onImage()(r)
			r["subject_ref"].(map[string]any)["image_digest"] = "sha256:<script>" + hostileMarker
		}},
		{"matcher version markup", set("evidence.matcher_version", "<i>"+hostileMarker)},
		{"basis snapshot markup", set("evidence.basis_sources", []any{map[string]any{"source_id": "debian-tracker",
			"snapshot_id": "<script>" + hostileMarker, "integrity": "none"}})},
		{"advisory URL field", set("vuln.url", "https://evil.example/"+hostileMarker)},
		{"links field", set("links", []string{"https://evil.example/" + hostileMarker})},
		{"CVSS vector markup", func(r map[string]any) {
			withCVSS(9.8)(r)
			r["scores"].(map[string]any)["cvss"].(map[string]any)["vector"] = "<script>" + hostileMarker
		}},
		{"KEV date markup", set("scores.kev", map[string]any{"date_added": "<b>" + hostileMarker})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newVulnEnv(t, nil)
			base := e.openBaseline()
			bad := cveN(300)
			e.wantRejectedBatchBlocksClosure(base, func(runID string) (int, []byte) {
				code, body := e.postBatch(runID, e.batchBody(nil, nil, vulnRecord(bad, tc.opt)))
				e.wantNoEcho(tc.name, body)
				return code, body
			})
			e.wantAbsent(bad)
		})
	}
}

// --- oversized batches and over-limit counts ---

// countingReader yields n bytes of filler after prefix and counts what
// the transport took; it never holds the body in memory.
type countingReader struct {
	prefix []byte
	n      int64
	read   atomic.Int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	off := c.read.Load()
	if off >= int64(len(c.prefix))+c.n {
		return 0, io.EOF
	}
	k := 0
	for k < len(p) && off < int64(len(c.prefix))+c.n {
		if off < int64(len(c.prefix)) {
			p[k] = c.prefix[off]
		} else {
			p[k] = ' '
		}
		k++
		off++
	}
	c.read.Add(int64(k))
	return k, nil
}

// A batch body over 1 MiB is refused with 413 after the server read at most
// the limit: a 256 MiB body, with and without a declared length, is not
// read to the end (the bytes the client got rid of stay a small multiple of
// the limit, socket buffers included). The refusal is recorded, so the run
// closes nothing.
func TestVulnOversizedBatchIsRefusedAfterABoundedRead(t *testing.T) {
	const total = 256 << 20
	// Loopback socket buffers and the transports' buffers hold a few MiB;
	// reading the body to the end would move 256 MiB.
	const maxMoved = 32 << 20
	for _, declared := range []bool{false, true} {
		t.Run("declared length "+strconv.FormatBool(declared), func(t *testing.T) {
			e := newVulnEnv(t, nil)
			base := e.openBaseline()
			e.wantRejectedBatchBlocksClosure(base, func(runID string) (int, []byte) {
				body := &countingReader{prefix: []byte(`{"batch_seq":2,"subjects":[],"findings":[` + `"` + hostileMarker + `"`), n: total}
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, e.srv.URL+"/api/v1/vuln/runs/"+runID+"/findings", body)
				if err != nil {
					t.Fatal(err)
				}
				if declared {
					req.ContentLength = int64(len(body.prefix)) + total
				} else {
					req.ContentLength = -1
				}
				req.Header.Set("Authorization", "Bearer "+vulnAgentToken)
				req.Header.Set("Content-Type", "application/json")
				resp, err := e.srv.Client().Do(req)
				moved := body.read.Load()
				if moved > maxMoved {
					t.Errorf("the server read on: %d bytes of the body moved, limit %d", moved, maxMoved)
				}
				if err != nil {
					// The server answered and closed while the client was
					// still writing; the refusal is checked by the closure
					// and the audit entry.
					t.Logf("transport: %v (after %d bytes)", err, moved)
					return http.StatusRequestEntityTooLarge, nil
				}
				defer resp.Body.Close()
				out, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
				if resp.StatusCode != http.StatusRequestEntityTooLarge {
					t.Errorf("oversized batch: %d %s, want 413", resp.StatusCode, out)
				}
				return resp.StatusCode, out
			})
			if !strings.Contains(e.log.String(), "body over 1 MiB") {
				t.Error("the oversized batch was not audited")
			}
			e.wantNoEcho("oversized batch", nil)
		})
	}
}

// Over-limit counts are refused as a whole and close nothing: more than
// 1,000 findings or covered subjects in one batch, a batch that would take
// the run past 200,000 findings, and run starts beyond the source list,
// the start body limit, the JSON depth limit or two concurrent runs. The
// limits themselves are accepted (control).
func TestVulnOverLimitCountsAreRefused(t *testing.T) {
	t.Run("1001 findings in a batch", func(t *testing.T) {
		e := newVulnEnv(t, nil)
		base := e.openBaseline()
		recs, cves := vulnRecords(1000, 1000+vulnstore.MaxFindingsPerBatch+1)
		e.wantRejectedBatchBlocksClosure(base, func(runID string) (int, []byte) {
			b := e.batchBody(nil, nil, recs...)
			if len(b) > api.MaxBatchBytes {
				t.Fatalf("fixture: %d bytes is over the body limit; the test must hit the count limit", len(b))
			}
			return e.postBatch(runID, b)
		})
		e.wantAbsent(cves[0], cves[len(cves)-1])

		// Control: exactly 1,000 are accepted.
		s := e.start(e.fresh(nil))
		recs, cves = vulnRecords(1000, 1000+vulnstore.MaxFindingsPerBatch)
		if r := e.batch(s.RunID, nil, recs...); r.Opened != vulnstore.MaxFindingsPerBatch {
			t.Fatalf("control: %+v", r)
		}
		e.wantOpen(subjWeb01, cves[0], cves[len(cves)-1])
	})

	t.Run("1001 covered subjects in a batch", func(t *testing.T) {
		e := newVulnEnv(t, nil)
		base := e.openBaseline()
		cover := make([]vulnstore.Subject, vulnstore.MaxCoveredPerBatch+1)
		for i := range cover {
			cover[i] = subjWeb01
		}
		e.wantRejectedBatchBlocksClosure(base, func(runID string) (int, []byte) {
			code, body := e.postBatch(runID, e.batchBody(cover, nil))
			if code != http.StatusRequestEntityTooLarge {
				t.Errorf("1001 subjects: %d %s, want 413", code, body)
			}
			return code, body
		})
	})

	t.Run("run past 200000 findings", func(t *testing.T) {
		e := newVulnEnv(t, nil)
		base := e.openBaseline()
		e.wantRejectedBatchBlocksClosure(base, func(runID string) (int, []byte) {
			// Bring the run to one below its limit without posting 199,999
			// records; the store counts per run.
			if _, err := e.db.ExecContext(t.Context(), `UPDATE vuln_runs SET finding_count = ? WHERE id = ?`, vulnstore.MaxFindingsPerRun-1, runID); err != nil {
				t.Fatal(err)
			}
			code, body := e.postBatch(runID, e.batchBody(nil, nil, vulnRecord(cveN(400)), vulnRecord(cveN(401))))
			if code != http.StatusRequestEntityTooLarge {
				t.Errorf("past the run limit: %d %s, want 413", code, body)
			}
			return code, body
		})
		e.wantAbsent(cveN(400), cveN(401))
	})

	t.Run("run starts", func(t *testing.T) {
		e := newVulnEnv(t, nil)
		snap := e.inv.take(e.clk.Now())
		srcs := func(specs []srcSpec) []map[string]any {
			var out []map[string]any
			for _, s := range specs {
				out = append(out, s.json())
			}
			return out
		}
		tooMany := e.fresh(nil, srcSpec{id: "extra-source", at: e.clk.Now().Add(-time.Hour)})
		deep := strings.Repeat(`{"a":`, 64) + `1` + strings.Repeat(`}`, 64)
		cases := []struct {
			name string
			body []byte
			want int
		}{
			{"more sources than listed", mustMarshal(t, map[string]any{"inventory_snapshot_id": snap, "matcher_version": "1.4.0", "sources": srcs(tooMany)}), http.StatusBadRequest},
			{"no sources", mustMarshal(t, map[string]any{"inventory_snapshot_id": snap, "matcher_version": "1.4.0", "sources": []any{}}), http.StatusBadRequest},
			{"body over 64 KiB", mustMarshal(t, map[string]any{"inventory_snapshot_id": snap, "matcher_version": strings.Repeat("1", 70<<10), "sources": srcs(e.fresh(nil))}), http.StatusRequestEntityTooLarge},
			{"nesting over the depth limit", []byte(`{"inventory_snapshot_id":"` + snap + `","matcher_version":"1.4.0","sources":[],"x":` + deep + `}`), http.StatusBadRequest},
			{"source ID markup", mustMarshal(t, map[string]any{"inventory_snapshot_id": snap, "matcher_version": "1.4.0",
				"sources": []any{map[string]any{"source_id": "<b>" + hostileMarker, "snapshot_id": "s", "integrity": "none", "date_kind": "none"}}}), http.StatusBadRequest},
		}
		for _, tc := range cases {
			code, body := e.do(http.MethodPost, "/api/v1/vuln/runs", tc.body)
			if code != tc.want {
				t.Errorf("%s: %d %s, want %d", tc.name, code, body, tc.want)
			}
			e.wantNoEcho(tc.name, body)
		}
		if n := strings.Count(e.log.String(), `"kind":"vuln_run_started"`); n != 0 {
			t.Errorf("%d runs started from refused starts", n)
		}
	})

	t.Run("third concurrent run", func(t *testing.T) {
		e := newVulnEnv(t, nil)
		for i := 0; i < vulnstore.MaxRunningPerToken; i++ {
			e.start(e.fresh(nil))
		}
		snap := e.inv.take(e.clk.Now())
		var srcs []map[string]any
		for _, s := range e.fresh(nil) {
			srcs = append(srcs, s.json())
		}
		code, body := e.do(http.MethodPost, "/api/v1/vuln/runs", mustMarshal(t, map[string]any{
			"inventory_snapshot_id": snap, "matcher_version": "1.4.0", "sources": srcs}))
		if code != http.StatusTooManyRequests {
			t.Fatalf("third concurrent run: %d %s, want 429", code, body)
		}
	})

	t.Run("write rate limit", func(t *testing.T) {
		e := newVulnEnv(t, nil)
		s := e.start(e.fresh(nil))
		limited := 0
		for i := 0; i < api.MaxWriteRequests+5; i++ {
			code, _ := e.postBatch(s.RunID, e.batchBody(nil, nil))
			if code == http.StatusTooManyRequests {
				limited++
			}
		}
		// The run start used one request of the window.
		if limited != 6 {
			t.Fatalf("%d requests rate limited, want 6", limited)
		}
	})
}

// --- token scope (D3, D5, D6) ---

// The agent token reads nothing of the read-only API: inventory, operations
// and execution logs all answer 403 and the backends are never called,
// also when the paths are reached through the shared /api/v1 mount.
func TestVulnAgentTokenCannotUseTheReadOnlyAPI(t *testing.T) {
	var calls atomic.Int64
	tokens := []serverconfig.APIToken{{Name: serverconfig.DefaultVulnTokenName, SHA256: api.HashToken(vulnAgentToken),
		Scopes:          []string{serverconfig.ScopeVulnInventoryRead, serverconfig.ScopeVulnFindingsWrite},
		SourceAddresses: []string{"127.0.0.1"}}}
	read, err := api.New(api.Options{Tokens: tokens, Operations: countingOps{&calls},
		Hosts: func(context.Context) ([]inventory.Host, error) { calls.Add(1); return nil, nil },
		Log:   slog.New(slog.NewJSONHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	e := newVulnEnv(t, nil)
	srv := httptest.NewServer(api.Mount(read, http.NotFoundHandler()))
	t.Cleanup(srv.Close)
	for _, p := range []string{"/api/v1/hosts", "/api/v1/hosts/web01", "/api/v1/operations", "/api/v1/operations/op-1"} {
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+p, nil)
		req.Header.Set("Authorization", "Bearer "+vulnAgentToken)
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("GET %s with the agent token: %d, want 403", p, resp.StatusCode)
		}
	}
	if n := calls.Load(); n != 0 {
		t.Fatalf("the read API called its backends %d times for the agent token", n)
	}
	// Control: the same token is accepted by the agent API.
	e.inv.take(e.clk.Now())
	if code, body := e.do(http.MethodGet, "/api/v1/vuln/inventory", nil); code != http.StatusOK {
		t.Fatalf("control: %d %s", code, body)
	}
}

type countingOps struct{ n *atomic.Int64 }

func (o countingOps) Get(context.Context, string) (executions.Execution, error) {
	o.n.Add(1)
	return executions.Execution{}, errors.New("not used")
}

func (o countingOps) List(context.Context, int) ([]executions.Summary, error) {
	o.n.Add(1)
	return nil, nil
}

func (o countingOps) AllUpdates(context.Context) (map[string]executions.HostUpdates, error) {
	o.n.Add(1)
	return nil, nil
}

func (o countingOps) AllOpsStates(context.Context) (map[string]executions.OpsState, error) {
	o.n.Add(1)
	return nil, nil
}

// The vuln scopes stay with one token that holds nothing else: the agent
// API refuses a configuration that adds a read scope to it or gives a vuln
// scope to a second token.
func TestVulnScopesCannotBeWidenedByConfiguration(t *testing.T) {
	e := newVulnEnv(t, nil)
	hash := api.HashToken(vulnAgentToken)
	vuln := []string{serverconfig.ScopeVulnInventoryRead, serverconfig.ScopeVulnFindingsWrite}
	cases := map[string][]serverconfig.APIToken{
		"agent token with operations.read": {{Name: serverconfig.DefaultVulnTokenName, SHA256: hash,
			Scopes: append(append([]string{}, vuln...), serverconfig.ScopeOperationsRead)}},
		"agent token with execution_logs.read": {{Name: serverconfig.DefaultVulnTokenName, SHA256: hash,
			Scopes: append(append([]string{}, vuln...), serverconfig.ScopeExecutionLogsRead)}},
		"agent token with inventory.read": {{Name: serverconfig.DefaultVulnTokenName, SHA256: hash,
			Scopes: append(append([]string{}, vuln...), serverconfig.ScopeInventoryRead)}},
		"vuln scope on a second token": {
			{Name: serverconfig.DefaultVulnTokenName, SHA256: hash, Scopes: vuln},
			{Name: "dashboard", SHA256: api.HashToken("nos_vu16b-other-token"), Scopes: []string{serverconfig.ScopeVulnFindingsWrite}}},
	}
	for name, toks := range cases {
		if _, err := api.NewVuln(api.VulnOptions{Tokens: toks, Inventory: e.inv, Store: e.st, Sources: vulnListedSources}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Only the token from the allowlisted address authenticates: other tokens,
// the token outside the Authorization header, and the token from another
// address (forwarding headers ignored) are refused before any endpoint.
func TestVulnAgentAPIRefusesOtherCredentialsAndAddresses(t *testing.T) {
	e := newVulnEnv(t, nil)
	e.inv.take(e.clk.Now())
	tokens := []serverconfig.APIToken{{Name: serverconfig.DefaultVulnTokenName, SHA256: api.HashToken(vulnAgentToken),
		Scopes:          []string{serverconfig.ScopeVulnInventoryRead, serverconfig.ScopeVulnFindingsWrite},
		SourceAddresses: []string{"127.0.0.1"}}}
	h, err := api.NewVuln(api.VulnOptions{Tokens: tokens, Inventory: e.inv, Store: e.st, Sources: vulnListedSources,
		Log: slog.New(slog.NewJSONHandler(io.Discard, nil)), Now: e.clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	serve := func(remote string, mod func(*http.Request)) int {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/vuln/inventory", nil)
		r.RemoteAddr = remote
		mod(r)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	bearer := func(tok string) func(*http.Request) {
		return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tok) }
	}
	cases := []struct {
		name   string
		remote string
		mod    func(*http.Request)
		want   int
	}{
		{"no token", "127.0.0.1:4000", func(*http.Request) {}, http.StatusUnauthorized},
		{"other token", "127.0.0.1:4000", bearer("nos_vu16b-not-the-agent-token"), http.StatusUnauthorized},
		{"token with a suffix", "127.0.0.1:4000", bearer(vulnAgentToken + "x"), http.StatusUnauthorized},
		{"token in the query", "127.0.0.1:4000", func(r *http.Request) { r.URL.RawQuery = "access_token=" + vulnAgentToken }, http.StatusUnauthorized},
		{"token as basic auth", "127.0.0.1:4000", func(r *http.Request) { r.SetBasicAuth("hermes-vuln", vulnAgentToken) }, http.StatusUnauthorized},
		{"other address", "192.0.2.10:4000", bearer(vulnAgentToken), http.StatusForbidden},
		{"other address with forwarding headers", "192.0.2.10:4000", func(r *http.Request) {
			bearer(vulnAgentToken)(r)
			r.Header.Set("X-Forwarded-For", "127.0.0.1")
			r.Header.Set("X-Real-IP", "127.0.0.1")
			r.Header.Set("Forwarded", "for=127.0.0.1")
		}, http.StatusForbidden},
		{"control", "127.0.0.1:4000", bearer(vulnAgentToken), http.StatusOK},
	}
	for _, tc := range cases {
		if got := serve(tc.remote, tc.mod); got != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, got, tc.want)
		}
	}
}

// A record or batch cannot reach a subject outside the run's inventory
// snapshot: such records are rejected (and block that finding's closure),
// a batch covering such a subject is rejected as a whole, and nothing is
// stored for the foreign subject.
func TestVulnAgentCannotWriteOtherSubjects(t *testing.T) {
	otherImage := "sha256:" + strings.Repeat("9", 64)
	t.Run("records", func(t *testing.T) {
		e := newVulnEnv(t, nil)
		s := e.start(e.fresh(nil))
		recs := []map[string]any{
			vulnRecord(cveN(500), func(r map[string]any) { r["subject_ref"] = map[string]any{"id": "db99"} }),
			vulnRecord(cveN(501), onImage(), func(r map[string]any) {
				r["subject_ref"] = map[string]any{"id": "web01", "image_digest": otherImage}
			}),
			vulnRecord(cveN(502), func(r map[string]any) {
				r["subject_kind"] = "device"
				r["subject_ref"] = map[string]any{"id": "web01"}
				r["ecosystem"] = "vendor:cisco:ios-xe"
				r["component"] = map[string]any{"model": "c9300", "firmware": "17.9.4"}
				r["match_basis"] = "vendor_advisory"
				r["fix"] = map[string]any{"state": "no_fix_yet"}
				delete(r, "tracker_state")
			}),
		}
		code, body := e.postBatch(s.RunID, e.batchBody(nil, nil, recs...))
		if code != http.StatusOK {
			t.Fatalf("batch: %d %s", code, body)
		}
		var res batchResult
		if err := json.Unmarshal(body, &res); err != nil || res.Rejected != len(recs) || res.Opened != 0 {
			t.Fatalf("result %s (%v), want every record rejected", body, err)
		}
		e.complete(s.RunID)
		e.wantAbsent(cveN(500), cveN(501), cveN(502))
	})
	for name, subj := range map[string]vulnstore.Subject{
		"covered host":  {Kind: vulnfinding.SubjectHost, ID: "db99"},
		"covered image": {Kind: vulnfinding.SubjectImage, ID: "web01", ImageDigest: otherImage},
	} {
		t.Run(name, func(t *testing.T) {
			e := newVulnEnv(t, nil)
			base := e.openBaseline()
			e.wantRejectedBatchBlocksClosure(base, func(runID string) (int, []byte) {
				return e.postBatch(runID, e.batchBody([]vulnstore.Subject{subj}, nil))
			})
		})
	}
}

// NOS-owned and admin fields cannot be written by the agent: a record that
// carries a finding key, state, human decision, closure source, tier,
// observer or nos_checked, a batch that carries closures, and a complete
// body with anything but {} are refused, and the findings are unchanged.
func TestVulnAgentCannotSetNOSOwnedOrAdminFields(t *testing.T) {
	fields := map[string]any{
		"finding_key":    strings.Repeat("ab", 32),
		"state":          "accepted_risk",
		"human_state":    "false_positive",
		"accepted_risk":  map[string]any{"reason": "agent", "expires": "2027-11-09"},
		"false_positive": map[string]any{"category": "backport_fixed", "reason": "agent"},
		"closed_by":      "admin_confirmed",
		"tier":           "low",
		"priority":       0,
		"observer":       "admin",
		"nos_checked":    true,
		"state_run_seq":  999999,
		"approver":       "admin",
	}
	for name, v := range fields {
		t.Run("record "+name, func(t *testing.T) {
			e := newVulnEnv(t, nil)
			base := e.openBaseline()
			e.wantRejectedBatchBlocksClosure(base, func(runID string) (int, []byte) {
				return e.postBatch(runID, e.batchBody(nil, nil, vulnRecord(base, func(r map[string]any) { r[name] = v })))
			})
			if f := e.finding(base, subjWeb01); f.Human != nil || f.State != vulnstore.StateOpen {
				t.Fatalf("finding changed: state %s human %+v", f.State, f.Human)
			}
		})
	}
	for name, v := range map[string]any{
		"closures":      []any{map[string]any{"vuln_id": cveN(0), "subject": "web01"}},
		"close":         []string{cveN(0)},
		"human_states":  []any{map[string]any{"vuln_id": cveN(0), "state": "accepted_risk"}},
		"mark_reset":    map[string]any{"source_id": "dsa"},
		"high_water":    map[string]any{"dsa": "2020-01-01T00:00:00Z"},
		"observer":      "admin",
		"run_seq":       1,
		"held_confirms": []string{cveN(0)},
	} {
		t.Run("batch "+name, func(t *testing.T) {
			e := newVulnEnv(t, nil)
			base := e.openBaseline()
			e.wantRejectedBatchBlocksClosure(base, func(runID string) (int, []byte) {
				var m map[string]any
				if err := json.Unmarshal(e.batchBody(nil, nil), &m); err != nil {
					t.Fatal(err)
				}
				m[name] = v
				return e.postBatch(runID, mustMarshal(t, m))
			})
		})
	}
	t.Run("complete body", func(t *testing.T) {
		e := newVulnEnv(t, nil)
		base := e.openBaseline()
		s := e.start(e.fresh(nil))
		for _, b := range []string{`{"close":["` + base + `"]}`, `{"force":true}`, `{"held":"confirm"}`, `[]`} {
			if code, out := e.do(http.MethodPost, "/api/v1/vuln/runs/"+s.RunID+"/complete", []byte(b)); code < 400 || code == http.StatusUnauthorized {
				t.Errorf("complete with %s: %d %s, want refused", b, code, out)
			}
		}
		e.wantOpen(subjWeb01, base)
	})
}

// Human states belong to the admin (D6): with the agent token there is no
// endpoint for accept risk, false positive, held-closure confirmation or
// discard, and no Hermes run changes a finding the admin decided: omitting
// it closes nothing, reporting it again (also with the
// likely_false_positive hint) keeps the decision, and the hint never makes
// an open finding a false positive.
func TestVulnAgentCannotSetOrClearHumanStates(t *testing.T) {
	e := newVulnEnv(t, nil)
	accepted, falsePos, hinted := cveN(600), cveN(601), cveN(602)
	e.run(e.fresh(nil), host(), vulnRecord(accepted), vulnRecord(falsePos), vulnRecord(hinted))
	ka, kf := e.finding(accepted, subjWeb01).Key, e.finding(falsePos, subjWeb01).Key
	if err := e.st.SetAcceptedRisk(t.Context(), ka, vulnstore.AcceptRisk{Approver: "admin", Reason: "mitigated by the firewall",
		BasisVersion: opensslInstalled}); err != nil {
		t.Fatal(err)
	}
	if err := e.st.SetFalsePositive(t.Context(), kf, vulnstore.MarkFalsePositive{By: "admin", Category: "backport_fixed",
		Reason: "patched in the backport", BasisVersion: opensslInstalled}); err != nil {
		t.Fatal(err)
	}
	wantHuman := func(stage string) {
		t.Helper()
		if f := e.finding(accepted, subjWeb01); f.State != vulnstore.StateAcceptedRisk || f.Human == nil || f.Human.By != "admin" {
			t.Errorf("%s: accepted finding is %s (%+v)", stage, f.State, f.Human)
		}
		if f := e.finding(falsePos, subjWeb01); f.State != vulnstore.StateFalsePositive || f.Human == nil || f.Human.By != "admin" {
			t.Errorf("%s: false positive is %s (%+v)", stage, f.State, f.Human)
		}
	}
	wantHuman("decided")

	body := mustMarshal(t, map[string]any{"state": "open", "reason": "agent", "category": "other", "approver": "hermes-vuln"})
	for _, key := range []string{ka.String(), kf.String()} {
		for _, p := range []struct{ method, path string }{
			{http.MethodPost, "/api/v1/vuln/findings/" + key + "/accept_risk"},
			{http.MethodPost, "/api/v1/vuln/findings/" + key + "/false_positive"},
			{http.MethodPost, "/api/v1/vuln/findings/" + key + "/reopen"},
			{http.MethodPatch, "/api/v1/vuln/findings/" + key},
			{http.MethodPut, "/api/v1/vuln/findings/" + key + "/state"},
			{http.MethodDelete, "/api/v1/vuln/findings/" + key},
			{http.MethodPost, "/api/v1/vuln/holds/" + key + "/confirm"},
			{http.MethodPost, "/api/v1/vuln/holds/" + key + "/discard"},
			{http.MethodPost, "/api/v1/vuln/decide/begin"},
			{http.MethodPost, "/api/v1/vuln/decide/commit"},
			{http.MethodPost, "/api/v1/vulnerabilities/decide/commit"},
			{http.MethodPost, "/api/v1/vuln/../../vulnerabilities/decide/commit"},
		} {
			if code, out := e.do(p.method, p.path, body); code < 400 || code == http.StatusUnauthorized {
				t.Errorf("%s %s: %d %s, want refused with the token accepted", p.method, p.path, code, out)
			}
		}
	}
	wantHuman("after the agent's requests")

	// A run that omits both closes neither.
	e.run(e.fresh(nil), host(), vulnRecord(hinted))
	wantHuman("after an omitting run")
	// A run that reports both again, with the hint, keeps the decisions;
	// the hint alone never sets false_positive.
	hint := func(r map[string]any) { r["assessment"].(map[string]any)["likely_false_positive"] = true }
	e.run(e.fresh(nil), host(), vulnRecord(accepted, hint), vulnRecord(falsePos, hint), vulnRecord(hinted, hint))
	wantHuman("after a reporting run")
	if f := e.finding(hinted, subjWeb01); f.State != vulnstore.StateOpen || f.Human != nil {
		t.Fatalf("the likely_false_positive hint changed the state: %s %+v", f.State, f.Human)
	}
}

// --- rule V1: findings never cause an action ---

// containsWord reports whether s contains w at a word start ("lease" in
// "release" does not count; "proposals" does).
func containsWord(s, w string) bool {
	for i := 0; ; {
		j := strings.Index(s[i:], w)
		if j < 0 {
			return false
		}
		j += i
		if j == 0 || s[j-1] < 'a' || s[j-1] > 'z' {
			return true
		}
		i = j + 1
	}
}

// tableCounts returns the row count of every server.db table outside the
// findings store.
func tableCounts(t *testing.T, e *vulnEnv) map[string]int64 {
	t.Helper()
	rows, err := e.db.QueryContext(t.Context(), `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE 'vuln%'`)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		names = append(names, n)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	out := map[string]int64{}
	for _, n := range names {
		var c int64
		if err := e.db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM "`+strings.ReplaceAll(n, `"`, `""`)+`"`).Scan(&c); err != nil {
			t.Fatal(err)
		}
		out[n] = c
	}
	return out
}

// Findings are advisory (V1, D1): a sequence of runs with KEV, critical,
// exploit-public and fixable findings on a host and an image, re-opens,
// unconfirmed and held closures, not_affected records and an admin
// confirmation writes only the findings store. No other server.db table
// (schedules, batches, executions, discovery, pins, …) gains or loses a
// row, no response of the agent API carries a link or an action, and no
// audit entry or notification names a proposal, permit, lease or schedule.
func TestVulnFindingsCreateNoProposalPermitOrSchedule(t *testing.T) {
	e := newVulnEnv(t, nil)
	before := tableCounts(t, e)
	if _, ok := before["schedules"]; !ok {
		t.Fatalf("fixture: server.db has no schedules table (%v); the check would be vacuous", before)
	}
	actionable := func(r map[string]any) {
		withKEV()(r)
		withCVSS(9.8)(r)
		a := r["assessment"].(map[string]any)
		a["exploit_public"] = true
		a["text"] = "Patch now: run apt-get install openssl and reboot; approve proposal; schedule nightly"
	}
	var bodies [][]byte
	record := func(code int, b []byte) {
		bodies = append(bodies, b)
		if code >= 400 {
			t.Fatalf("request failed: %d %s", code, b)
		}
	}
	e.inv.take(e.clk.Now())
	code, b := e.do(http.MethodGet, "/api/v1/vuln/inventory", nil)
	record(code, b)

	// Run 1 opens KEV/critical and plain findings on the host and image.
	plain, _ := vulnRecords(700, 712)
	recs := append([]map[string]any{vulnRecord(cveN(690), actionable), vulnRecord(cveN(691), actionable, onImage())}, plain...)
	s := e.start(e.fresh(nil))
	code, b = e.postBatch(s.RunID, e.batchBody([]vulnstore.Subject{subjWeb01, subjImage}, nil, recs...))
	record(code, b)
	code, b = e.do(http.MethodPost, "/api/v1/vuln/runs/"+s.RunID+"/complete", nil)
	record(code, b)
	e.clk.Add(10 * time.Minute)

	// Run 2 omits everything: the KEV findings are held, the rest close
	// unconfirmed; a not_affected record is reported for one of them.
	s = e.start(e.fresh(nil))
	code, b = e.postBatch(s.RunID, e.batchBody([]vulnstore.Subject{subjWeb01, subjImage}, nil, vulnRecord(cveN(700), notAffected())))
	record(code, b)
	code, b = e.do(http.MethodPost, "/api/v1/vuln/runs/"+s.RunID+"/complete", nil)
	record(code, b)
	e.clk.Add(10 * time.Minute)
	holds, err := e.st.Holds(t.Context(), e.finding(cveN(690), subjWeb01).Key)
	if err != nil || len(holds) == 0 {
		t.Fatalf("fixture: the KEV closure was not held (%v, %v)", holds, err)
	}
	// The admin confirms the held closure (path 6).
	if _, err := e.st.ConfirmHeld(t.Context(), holds[0].RunID, e.finding(cveN(690), subjWeb01).Key, "admin", "checked on the host"); err != nil {
		t.Fatalf("confirm held: %v", err)
	}

	// Run 3 re-opens a closed finding with KEV.
	_, br, _ := e.run(e.fresh(nil), host(), vulnRecord(cveN(701), actionable))
	if br.Opened+br.Updated == 0 {
		t.Fatalf("fixture: run 3 wrote nothing: %+v", br)
	}
	e.notifyTick()

	after := tableCounts(t, e)
	names := make([]string, 0, len(after))
	for n := range after {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if after[n] != before[n] {
			t.Errorf("table %s: %d rows before the runs, %d after; findings must not write outside the store", n, before[n], after[n])
		}
	}
	for n := range before {
		if _, ok := after[n]; !ok {
			t.Errorf("table %s disappeared", n)
		}
	}

	for _, b := range bodies {
		low := strings.ToLower(string(b))
		for _, w := range []string{"http://", "https://", "href", "proposal", "permit", "schedule", "approve", "lease"} {
			if containsWord(low, w) {
				t.Errorf("agent API response contains %q: %s", w, b)
			}
		}
	}
	log := strings.ToLower(e.log.String())
	for _, w := range []string{"proposal", "permit", "schedule", "lease", "execution", "approve"} {
		if containsWord(log, w) {
			t.Errorf("audit log mentions %q after vulnerability runs", w)
		}
	}
	for _, ev := range e.sink.all() {
		s := strings.ToLower(fmt.Sprintf("%+v", ev))
		for _, w := range []string{"proposal", "permit", "apt-get", "approve"} {
			if containsWord(s, w) {
				t.Errorf("notification carries %q: %+v", w, ev)
			}
		}
	}
}

// The agent API and the findings store cannot reach the executor at all:
// no package the vuln handler files or the vuln packages import, directly
// or through other packages of this module, is an executor, executor
// client, execution, permit, proposal, schedule, SSH, vault or host-run
// package, and none of them imports gRPC (the only way to call the
// executor), x/crypto/ssh or os/exec. The generated executor message
// package (internal/rpc/executorv1) is reachable through internal/notify,
// which uses its HostKeyPin type for the host key notifier; it holds
// message types and client stubs that need a gRPC connection, so the walk
// allows it but does not descend into it, and no walked package may import
// gRPC to make one. Imports are read from every non-test Go file, whatever
// its build tags. The walk starts from the vuln handler files of
// internal/web/api, not the whole package: the package also holds the
// read-only API, whose api.go imports internal/executions for the
// operations endpoints; the vuln handler shares only its token type and
// JSON helpers with it.
func TestVulnAgentPathImportsNoActionPackage(t *testing.T) {
	const module = "github.com/nebula-operation-station/nebula-operation-station/"
	const generatedTypes = "internal/rpc/executorv1"
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	forbidden := []string{
		"internal/executor", "internal/executorclient", "internal/executordb", "internal/executions", "internal/permit",
		"internal/hostrun", "internal/sshtransport", "internal/keyring", "internal/vault", "internal/schedgrant",
		"internal/stageplan", "internal/riskpolicy", "internal/runbooks", "internal/pveapi", "internal/panapi",
		"internal/webauthnverify", "internal/web/auth", "internal/web/ui",
	}
	forbiddenExternal := []string{"google.golang.org/grpc", "os/exec", "golang.org/x/crypto/ssh"}
	// importsOf returns the module-internal imports (relative) and the
	// other imports of files.
	importsOf := func(files []string) (internal, external []string) {
		fset := token.NewFileSet()
		for _, f := range files {
			af, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatalf("parse %s: %v", f, err)
			}
			for _, im := range af.Imports {
				p, _ := strconv.Unquote(im.Path.Value)
				if rel, ok := strings.CutPrefix(p, module); ok {
					internal = append(internal, rel)
				} else {
					external = append(external, p)
				}
			}
		}
		return internal, external
	}
	checkExternal := func(pkg string, ext []string) {
		for _, x := range ext {
			for _, f := range forbiddenExternal {
				if x == f || strings.HasPrefix(x, f+"/") {
					t.Errorf("%s imports %s", pkg, x)
				}
			}
		}
	}
	pkgFiles := func(rel string) []string {
		ents, err := os.ReadDir(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		var fs []string
		for _, en := range ents {
			n := en.Name()
			if !en.IsDir() && strings.HasSuffix(n, ".go") && !strings.HasSuffix(n, "_test.go") {
				fs = append(fs, filepath.Join(root, rel, n))
			}
		}
		return fs
	}
	apiFiles, err := filepath.Glob(filepath.Join(root, "internal", "web", "api", "vuln*.go"))
	if err != nil || len(apiFiles) == 0 {
		t.Fatalf("no vuln handler files (%v)", err)
	}
	var start []string
	for _, f := range apiFiles {
		if !strings.HasSuffix(f, "_test.go") {
			start = append(start, f)
		}
	}
	queue, ext := importsOf(start)
	checkExternal("internal/web/api (vuln handler)", ext)
	queue = append(queue, "internal/vulnstore", "internal/vulnfinding", "internal/vulnver", "internal/vulnprio", "internal/vulnnotify")
	via := map[string]string{}
	for _, q := range queue {
		via[q] = "internal/web/api (vuln handler)"
	}
	seen := map[string]bool{}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		if seen[p] {
			continue
		}
		seen[p] = true
		if p == generatedTypes {
			continue
		}
		for _, f := range forbidden {
			if p == f || strings.HasPrefix(p, f+"/") {
				t.Errorf("the agent path imports %s (via %s)", p, via[p])
			}
		}
		in, ext := importsOf(pkgFiles(p))
		checkExternal(p, ext)
		for _, n := range in {
			if !seen[n] {
				if _, ok := via[n]; !ok {
					via[n] = p
				}
				queue = append(queue, n)
			}
		}
	}
	if !seen["internal/vulnstore"] || !seen["internal/serverconfig"] || len(seen) < 6 {
		t.Fatalf("import walk too small: %v", seen)
	}
}
