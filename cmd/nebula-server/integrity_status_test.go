// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executorclient"
	"github.com/nebula-operation-station/nebula-operation-station/internal/integrity"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// integrityFake is the executor stand-in behind the real client. It
// answers the dial probe (GetStatus) and GetIntegrityStatus as configured.
type integrityFake struct {
	pb.UnimplementedExecutorServiceServer
	resp  *pb.GetIntegrityStatusResponse
	err   error
	block bool
}

// GetStatus answers the dial probe of executorclient.New.
func (f *integrityFake) GetStatus(context.Context, *pb.GetStatusRequest) (*pb.GetStatusResponse, error) {
	return &pb.GetStatusResponse{}, nil
}

// GetIntegrityStatus implements pb.ExecutorServiceServer.
func (f *integrityFake) GetIntegrityStatus(ctx context.Context, _ *pb.GetIntegrityStatusRequest) (*pb.GetIntegrityStatusResponse, error) {
	if f.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if f.err != nil {
		return nil, f.err
	}
	return f.resp, nil
}

// integrityLazy returns a lazyExecutor connected to a fake executor over a
// Unix socket, through the real client.
func integrityLazy(t *testing.T, f *integrityFake) *lazyExecutor {
	t.Helper()
	// Short path: Unix socket paths are limited to about 100 bytes.
	dir, err := os.MkdirTemp("", "nos-is-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "e.sock")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	pb.RegisterExecutorServiceServer(srv, f)
	go srv.Serve(lis) //nolint:errcheck
	t.Cleanup(srv.Stop)
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	c, err := executorclient.New(context.Background(), executorclient.Options{SocketPath: sock, ExecutorUser: u.Username})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	l := &lazyExecutor{}
	l.c.Store(c)
	return l
}

// releaseMonitorRun returns a monitor that has run once: a release build
// without an admitted reference, so the server block reads
// incomplete/no-admitted-reference.
func releaseMonitorRun(t *testing.T) *integrity.Monitor {
	t.Helper()
	m := newIntegrityMonitorAt(slog.New(slog.DiscardHandler), "v1.2.3", t.TempDir())
	m.RunOnce(context.Background())
	return m
}

// fetchIntegrityPage GETs the status page over real HTTP and returns the
// status and body. accept is sent as the Accept header when non-empty.
func fetchIntegrityPage(t *testing.T, base, accept string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, base+integrityStatusPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(b)
}

// integrityHTML serves the status page for m and read over real HTTP.
func integrityHTML(t *testing.T, m *integrity.Monitor, read integrityStatusReader) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mountIntegrityStatus(mux, m, read)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// pageSection returns the HTML from the section with id start up to the
// section with id end (or the end of the page when end is "").
func pageSection(t *testing.T, body, start, end string) string {
	t.Helper()
	i := strings.Index(body, `id="`+start+`"`)
	if i < 0 {
		t.Fatalf("section %q missing", start)
	}
	rest := body[i:]
	if end == "" {
		return rest
	}
	j := strings.Index(rest, `id="`+end+`"`)
	if j < 0 {
		t.Fatalf("section %q missing", end)
	}
	return rest[:j]
}

// TestIntegrityPageShowsExecutorStatusInItsOwnBlock: the executor's
// status appears in the executor block only, the server block keeps its
// own check, and both carry their source.
func TestIntegrityPageShowsExecutorStatusInItsOwnBlock(t *testing.T) {
	m := releaseMonitorRun(t)
	last := time.Date(2026, 11, 26, 9, 0, 0, 0, time.UTC).Unix()
	l := integrityLazy(t, &integrityFake{resp: &pb.GetIntegrityStatusResponse{
		Configured: true,
		Running:    true,
		TotalRuns:  7,
		LastRun: &pb.IntegrityRun{StartedUnix: last, FinishedUnix: last + 60,
			Complete: true, ReleaseVersion: "9.8.7", Files: 4321},
	}})
	srv := integrityHTML(t, m, lazyIntegrityStatus(l))

	code, body := fetchIntegrityPage(t, srv.URL, "text/html")
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	server := pageSection(t, body, "server-self-check", "executor-status")
	exec := pageSection(t, body, "executor-status", "")
	for _, want := range []string{"Server-Selbstprüfung", "nebula-server", "no-admitted-reference"} {
		if !strings.Contains(server, want) {
			t.Errorf("server block lacks %q", want)
		}
	}
	for _, want := range []string{"Executor-Status", "nebula-executor", "4321", "9.8.7"} {
		if !strings.Contains(exec, want) {
			t.Errorf("executor block lacks %q", want)
		}
	}
	if strings.Contains(server, "4321") || strings.Contains(server, "9.8.7") {
		t.Errorf("executor result shown in the server block")
	}
	if strings.Contains(exec, "no-admitted-reference") {
		t.Errorf("server result shown in the executor block")
	}
}

// TestIntegrityStatusJSONKeepsServerFieldsAndAddsExecutor: the JSON
// response keeps the server fields at the top level, labels its source,
// and carries the executor status under its own key.
func TestIntegrityStatusJSONKeepsServerFieldsAndAddsExecutor(t *testing.T) {
	m := releaseMonitorRun(t)
	l := integrityLazy(t, &integrityFake{resp: &pb.GetIntegrityStatusResponse{Configured: true, TotalRuns: 3}})
	srv := integrityHTML(t, m, lazyIntegrityStatus(l))

	code, body := fetchIntegrityPage(t, srv.URL, "")
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	var got integrityStatusJSON
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("decode %q: %v", body, err)
	}
	if got.Source != serverSourceLabel || got.State != integrity.StateIncomplete ||
		got.Cause != integrity.CauseNoAdmittedReference {
		t.Fatalf("server part %+v", got)
	}
	if !got.Executor.Available || got.Executor.Source != executorSourceLabel ||
		got.Executor.TotalRuns != 3 || !got.Executor.Configured {
		t.Fatalf("executor part %+v", got.Executor)
	}
}

// TestIntegrityPageExecutorFailureIsUnavailable: a failing, timed-out or
// missing executor shows "nicht verfügbar" with the time of the attempt,
// never an ok result or the last good value, and the error text of the
// call does not leak into the page.
func TestIntegrityPageExecutorFailureIsUnavailable(t *testing.T) {
	cases := []struct {
		name string
		read func(t *testing.T) integrityStatusReader
	}{
		{"not connected", func(*testing.T) integrityStatusReader { return lazyIntegrityStatus(&lazyExecutor{}) }},
		{"call error", func(t *testing.T) integrityStatusReader {
			return lazyIntegrityStatus(integrityLazy(t, &integrityFake{err: status.Error(codes.Internal, "boom /secret/path")}))
		}},
		{"timeout", func(t *testing.T) integrityStatusReader {
			return lazyIntegrityStatus(integrityLazy(t, &integrityFake{block: true}))
		}},
	}
	okWord := regexp.MustCompile(`(?i)\bok\b`)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := releaseMonitorRun(t)
			srv := integrityHTML(t, m, tc.read(t))
			code, body := fetchIntegrityPage(t, srv.URL, "text/html")
			if code != http.StatusOK {
				t.Fatalf("status %d", code)
			}
			exec := pageSection(t, body, "executor-status", "")
			if !strings.Contains(exec, "nicht verfügbar") {
				t.Errorf("executor block does not say unavailable")
			}
			if okWord.MatchString(exec) {
				t.Errorf("executor block says ok: %q", exec)
			}
			if strings.Contains(body, "/secret/path") {
				t.Errorf("call error text shown")
			}
			_, jsonBody := fetchIntegrityPage(t, srv.URL, "")
			var got integrityStatusJSON
			if err := json.Unmarshal([]byte(jsonBody), &got); err != nil {
				t.Fatal(err)
			}
			if got.Executor.Available || got.Executor.TotalRuns != 0 || len(got.Executor.Findings) != 0 {
				t.Fatalf("executor part %+v, want unavailable", got.Executor)
			}
		})
	}
}

// TestIntegrityPageUnavailableShowsAttemptTime: the unavailable block
// names the time of the failed attempt, in UTC.
func TestIntegrityPageUnavailableShowsAttemptTime(t *testing.T) {
	m := releaseMonitorRun(t)
	at := time.Date(2026, 11, 26, 10, 15, 0, 0, time.UTC)
	p := integrityStatusPage{monitor: m, read: lazyIntegrityStatus(&lazyExecutor{}), now: func() time.Time { return at }}
	srv := httptest.NewServer(http.HandlerFunc(p.serve))
	t.Cleanup(srv.Close)
	_, body := fetchIntegrityPage(t, srv.URL, "text/html")
	exec := pageSection(t, body, "executor-status", "")
	if !strings.Contains(exec, "nicht verfügbar") || !strings.Contains(exec, "2026-11-26T10:15:00Z") {
		t.Fatalf("executor block %q", exec)
	}
}

// TestIntegrityPageEscapesExecutorText: executor text is rendered as text;
// HTML in a finding is escaped, not interpreted.
func TestIntegrityPageEscapesExecutorText(t *testing.T) {
	m := releaseMonitorRun(t)
	l := integrityLazy(t, &integrityFake{resp: &pb.GetIntegrityStatusResponse{
		Findings: []*pb.IntegrityFinding{{Id: "f1", Class: "x", Path: "/usr/bin/nebula",
			Reason: `<script>alert("x")</script>`, Count: 1}},
	}})
	srv := integrityHTML(t, m, lazyIntegrityStatus(l))
	_, body := fetchIntegrityPage(t, srv.URL, "text/html")
	if strings.Contains(body, `<script>alert`) {
		t.Fatalf("finding text rendered as HTML")
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Fatalf("finding text not escaped in page")
	}
}

// TestIntegrityPageClipsExecutorText: long or malformed executor text is
// cut to integrityTextLimit runes and made valid UTF-8, and the findings
// shown are limited to integrityFindingsLimit.
func TestIntegrityPageClipsExecutorText(t *testing.T) {
	long := strings.Repeat("a", 10*integrityTextLimit)
	var findings []*pb.IntegrityFinding
	for i := 0; i < integrityFindingsLimit+5; i++ {
		findings = append(findings, &pb.IntegrityFinding{Id: "f", Reason: long})
	}
	m := releaseMonitorRun(t)
	l := integrityLazy(t, &integrityFake{resp: &pb.GetIntegrityStatusResponse{Findings: findings}})
	srv := integrityHTML(t, m, lazyIntegrityStatus(l))

	_, jsonBody := fetchIntegrityPage(t, srv.URL, "")
	var got integrityStatusJSON
	if err := json.Unmarshal([]byte(jsonBody), &got); err != nil {
		t.Fatal(err)
	}
	if n := len(got.Executor.Findings); n != integrityFindingsLimit {
		t.Fatalf("%d findings shown, want %d", n, integrityFindingsLimit)
	}
	if want := len(findings) - integrityFindingsLimit; got.Executor.FindingsOmitted != want {
		t.Fatalf("omitted %d, want %d", got.Executor.FindingsOmitted, want)
	}
	if r := got.Executor.Findings[0].Reason; len([]rune(r)) != integrityTextLimit+1 || !strings.HasSuffix(r, "…") {
		t.Fatalf("reason not clipped to %d runes plus mark: %d runes", integrityTextLimit, len([]rune(r)))
	}
}

// TestClipTextRepairsAndLimits: malformed UTF-8 and control characters
// are repaired, and text longer than integrityTextLimit is cut and
// marked. Protobuf rejects invalid UTF-8 on the wire, so this is the
// defence for the text that does get through.
// TestExecutorTamperFindingsAreNotClean: open I2 baseline tamper findings
// make the executor's verdict "offene Befunde" and are shown, even with the
// lock open and no I1 finding (ADR 0015 D7). The executor refuses the whole
// status in that case, so the page must never show it as clean.
func TestExecutorTamperFindingsAreNotClean(t *testing.T) {
	m := releaseMonitorRun(t)
	last := time.Date(2026, 11, 26, 9, 0, 0, 0, time.UTC).Unix()
	l := integrityLazy(t, &integrityFake{resp: &pb.GetIntegrityStatusResponse{
		Configured: true,
		LastRun:    &pb.IntegrityRun{StartedUnix: last, FinishedUnix: last + 60, Complete: true},
		BaselineTamperFindings: []*pb.BaselineTamperFinding{{
			HostId: "host-7", PresentedDigest: "sha256:abcdef", FirstSeenUnix: last, LastSeenUnix: last, Count: 2,
		}},
	}})
	srv := integrityHTML(t, m, lazyIntegrityStatus(l))

	_, body := fetchIntegrityPage(t, srv.URL, "text/html")
	exec := pageSection(t, body, "executor-status", "")
	if !strings.Contains(exec, "host-7") || !strings.Contains(exec, "offene Befunde") {
		t.Errorf("tamper finding not shown as open: %q", exec)
	}
	if strings.Contains(exec, "sauber") {
		t.Errorf("executor with open tamper finding shown as clean")
	}

	_, jsonBody := fetchIntegrityPage(t, srv.URL, "")
	var got integrityStatusJSON
	if err := json.Unmarshal([]byte(jsonBody), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Executor.Available || got.Executor.Verdict != verdictOpen {
		t.Fatalf("executor part %+v, want available with verdict %q", got.Executor, verdictOpen)
	}
	if len(got.Executor.BaselineTamper) != 1 || got.Executor.BaselineTamper[0].HostID != "host-7" ||
		got.Executor.BaselineTamper[0].Count != 2 {
		t.Fatalf("tamper findings %+v", got.Executor.BaselineTamper)
	}
}

// TestExecutorWithoutOpenFindingsIsClean: a complete last run with no open
// I1 or I2 findings and an open lock is the only way to a clean verdict.
func TestExecutorWithoutOpenFindingsIsClean(t *testing.T) {
	m := releaseMonitorRun(t)
	l := integrityLazy(t, &integrityFake{resp: &pb.GetIntegrityStatusResponse{
		Configured: true,
		LastRun:    &pb.IntegrityRun{Complete: true, Files: 10},
	}})
	srv := integrityHTML(t, m, lazyIntegrityStatus(l))

	_, jsonBody := fetchIntegrityPage(t, srv.URL, "")
	var got integrityStatusJSON
	if err := json.Unmarshal([]byte(jsonBody), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Executor.Available || got.Executor.Verdict != verdictClean || len(got.Executor.BaselineTamper) != 0 {
		t.Fatalf("executor part %+v, want available and clean", got.Executor)
	}
}

// TestExecutorWithoutCompleteRunIsNotClean: with no last run, or an
// incomplete one, the executor has not confirmed anything, so the verdict
// is "nicht bestätigt", never "sauber".
func TestExecutorWithoutCompleteRunIsNotClean(t *testing.T) {
	cases := []struct {
		name string
		resp *pb.GetIntegrityStatusResponse
	}{
		{"no last run", &pb.GetIntegrityStatusResponse{Configured: true, TotalRuns: 1}},
		{"incomplete last run", &pb.GetIntegrityStatusResponse{Configured: true,
			LastRun: &pb.IntegrityRun{Complete: false, Incomplete: "no-admitted-reference"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := releaseMonitorRun(t)
			srv := integrityHTML(t, m, lazyIntegrityStatus(integrityLazy(t, &integrityFake{resp: tc.resp})))
			_, jsonBody := fetchIntegrityPage(t, srv.URL, "")
			var got integrityStatusJSON
			if err := json.Unmarshal([]byte(jsonBody), &got); err != nil {
				t.Fatal(err)
			}
			if got.Executor.Verdict != verdictUnconfirmed {
				t.Fatalf("verdict %q, want %q", got.Executor.Verdict, verdictUnconfirmed)
			}
		})
	}
}

// TestExecutorEmptyReplyIsUnavailable: a reply without any field set is not
// a status; it gives the unavailable view and never Available=true.
func TestExecutorEmptyReplyIsUnavailable(t *testing.T) {
	m := releaseMonitorRun(t)
	srv := integrityHTML(t, m, lazyIntegrityStatus(integrityLazy(t, &integrityFake{resp: &pb.GetIntegrityStatusResponse{}})))
	_, body := fetchIntegrityPage(t, srv.URL, "text/html")
	if exec := pageSection(t, body, "executor-status", ""); !strings.Contains(exec, "nicht verfügbar") {
		t.Errorf("empty reply not shown as unavailable: %q", exec)
	}
	_, jsonBody := fetchIntegrityPage(t, srv.URL, "")
	var got integrityStatusJSON
	if err := json.Unmarshal([]byte(jsonBody), &got); err != nil {
		t.Fatal(err)
	}
	if got.Executor.Available || got.Executor.Verdict != "" {
		t.Fatalf("executor part %+v, want unavailable", got.Executor)
	}
}

// TestExecutorRunStateIsCarried: the executor's own verdict for its last run
// (state) and the manifest digest are shown, not only the counts.
func TestExecutorRunStateIsCarried(t *testing.T) {
	m := releaseMonitorRun(t)
	const digest = "sha256:0123456789abcdef"
	l := integrityLazy(t, &integrityFake{resp: &pb.GetIntegrityStatusResponse{
		Configured: true,
		LastRun:    &pb.IntegrityRun{Complete: true, State: "differences-found", ManifestSha256: digest},
	}})
	srv := integrityHTML(t, m, lazyIntegrityStatus(l))

	_, body := fetchIntegrityPage(t, srv.URL, "text/html")
	exec := pageSection(t, body, "executor-status", "")
	if !strings.Contains(exec, "differences-found") || !strings.Contains(exec, digest) {
		t.Errorf("executor run state or digest missing: %q", exec)
	}
	_, jsonBody := fetchIntegrityPage(t, srv.URL, "")
	var got integrityStatusJSON
	if err := json.Unmarshal([]byte(jsonBody), &got); err != nil {
		t.Fatal(err)
	}
	if got.Executor.LastRun == nil || got.Executor.LastRun.State != "differences-found" ||
		got.Executor.LastRun.ManifestSHA256 != digest {
		t.Fatalf("last run %+v", got.Executor.LastRun)
	}
}

// TestExecutorReadFailureIsLogged: a failed executor read leaves a fixed
// warning in the log, without the error text (which may hold secrets).
func TestExecutorReadFailureIsLogged(t *testing.T) {
	var buf bytes.Buffer
	lg := slog.New(slog.NewTextHandler(&buf, nil))
	m := releaseMonitorRun(t)
	read := lazyIntegrityStatus(integrityLazy(t, &integrityFake{err: status.Error(codes.Internal, "boom /secret/path")}))
	p := integrityStatusPage{monitor: m, read: read, now: time.Now, log: lg}
	srv := httptest.NewServer(http.HandlerFunc(p.serve))
	t.Cleanup(srv.Close)
	_, body := fetchIntegrityPage(t, srv.URL, "text/html")
	if !strings.Contains(pageSection(t, body, "executor-status", ""), "nicht verfügbar") {
		t.Fatalf("executor block does not say unavailable")
	}
	if !strings.Contains(buf.String(), integrityReadFailedMsg) {
		t.Errorf("failed read not logged: %q", buf.String())
	}
	if strings.Contains(buf.String(), "/secret/path") || strings.Contains(buf.String(), "boom") {
		t.Errorf("error text logged: %q", buf.String())
	}
}

func TestClipTextRepairsAndLimits(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "ok-text", "ok-text"},
		{"invalid utf-8 and nul", "x\xff\x00y", "x�" + " y"},
		{"control characters", "a\tb\nc", "a b c"},
		{"exact limit", strings.Repeat("é", integrityTextLimit), strings.Repeat("é", integrityTextLimit)},
		{"over limit", strings.Repeat("é", integrityTextLimit+3), strings.Repeat("é", integrityTextLimit) + "…"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := clipText(tc.in)
			if got != tc.want {
				t.Fatalf("clipText(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if !utf8.ValidString(got) {
				t.Fatalf("result not valid UTF-8: %q", got)
			}
		})
	}
}
