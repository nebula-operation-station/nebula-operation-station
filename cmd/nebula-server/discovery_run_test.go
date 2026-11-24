// SPDX-License-Identifier: AGPL-3.0-or-later

// Wiring test of network discovery through runServer: a logged-in user's
// form POST queues a scan, the spool is read with the same discoveryjob code
// nebula-discovery uses, a result is written with that code (ParseNmapXML,
// WriteResult), and the server takes it over through its poll. Nothing runs
// nmap and nothing touches the network: the test plays the nebula-discovery
// side with the production spool code only.

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/discoveryjob"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
)

const (
	drNet    = "lan"
	drPrefix = "192.168.10.0/24"
	drKnown  = "192.168.10.21" // already in the IPAM as an asset: EXISTING
	drNew    = "192.168.10.22" // not in the IPAM: NEW, imported by the test
	drEvil   = "https://evil.example"
)

// drNmapXML is what nmap writes for a ping scan with two hosts up.
const drNmapXML = `<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sn 192.168.10.0/24" start="1700000000" version="7.94">
<host><status state="up" reason="arp-response"/><address addr="192.168.10.21" addrtype="ipv4"/><hostnames><hostname name="nas.lan" type="PTR"/></hostnames></host>
<host><status state="up" reason="arp-response"/><address addr="192.168.10.22" addrtype="ipv4"/></host>
<runstats><finished exit="success" summary="Nmap done"/><hosts up="2" down="0" total="2"/></runstats>
</nmaprun>`

// drEnv is one data directory with its discovery spool and the session of
// alice, who runs the scans.
type drEnv struct {
	t     *testing.T
	dir   string
	spool discoveryjob.Spool
	alice string
	sock  string
}

func newDREnv(t *testing.T) *drEnv {
	t.Helper()
	dir := t.TempDir()
	spoolDir := filepath.Join(dir, "discovery")
	for _, sub := range []string{"jobs", "results"} {
		if err := os.MkdirAll(filepath.Join(spoolDir, sub), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	alice, _ := vrSessions(t, dir)
	return &drEnv{t: t, dir: dir, spool: discoveryjob.Spool{Dir: spoolDir}, alice: alice, sock: serveVTExecutor(t)}
}

// start runs the server on the data directory with the spool as
// discovery_dir. A restart reads the same database and spool.
func (e *drEnv) start() *vrServer {
	e.t.Helper()
	cfg := vrConfig(e.t, e.dir, e.sock, nil)
	cfg["discovery_dir"] = e.spool.Dir
	return startVR(e.t, e.dir, cfg)
}

// jobFiles lists the entries of jobs/ as they are on disk.
func (e *drEnv) jobFiles() []string {
	e.t.Helper()
	entries, err := os.ReadDir(e.spool.JobsDir())
	if err != nil {
		e.t.Fatal(err)
	}
	var names []string
	for _, en := range entries {
		names = append(names, en.Name())
	}
	return names
}

// pending returns the one job the spool holds; it fails on anything else.
func (e *drEnv) pending() discoveryjob.Job {
	e.t.Helper()
	jobs, bad, err := e.spool.PendingJobs()
	if err != nil {
		e.t.Fatal(err)
	}
	if len(bad) != 0 {
		e.t.Fatalf("job files the reader rejects: %v", bad)
	}
	if len(jobs) != 1 {
		e.t.Fatalf("%d pending jobs, want 1", len(jobs))
	}
	return jobs[0]
}

// drPost sends a JSON POST. origin "" sends no Origin header; token is a
// session cookie. It returns the status, the Location header and the body.
func drPost(t *testing.T, s *vrServer, path, token, origin string, body any) (int, string, []byte) {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, s.base+path, bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if token != "" {
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header.Get("Location"), out
}

// drGet returns the status and body of a page for alice.
func drGet(t *testing.T, s *vrServer, path, token string) (int, string) {
	t.Helper()
	code, body := s.do(t, http.MethodGet, path, token, "", nil)
	return code, string(body)
}

// drJobID decodes the answer of a successful submit.
func drJobID(t *testing.T, body []byte) string {
	t.Helper()
	var out struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.ID == "" {
		t.Fatalf("submit answer %s: %v", body, err)
	}
	return out.ID
}

// drWaitPage waits until the page for path contains want.
func drWaitPage(t *testing.T, s *vrServer, path, token, want string) string {
	t.Helper()
	var body string
	waitFor(t, path+" to show "+want, func() bool {
		_, body = drGet(t, s, path, token)
		return strings.Contains(body, want)
	})
	return body
}

// drRow matches a staged row of the job page: the address, then its class
// (label as shown, key as the template writes it: spaces become underscores).
func drRow(addr, label string) *regexp.Regexp {
	key := strings.ReplaceAll(label, " ", "_")
	return regexp.MustCompile(`(?s)<td>` + regexp.QuoteMeta(addr) + `</td>\s*<td class="class--` + regexp.QuoteMeta(key) + `">` + regexp.QuoteMeta(label) + `</td>`)
}

// drTable returns the staged-hosts table of a job page, for failure output.
func drTable(page string) string {
	i := strings.Index(page, `<table class="inventory" id="staging"`)
	if i < 0 {
		return "(no staged hosts table)"
	}
	j := strings.Index(page[i:], "</table>")
	if j < 0 {
		return page[i:]
	}
	return page[i : i+j]
}

// TestDiscoveryFromFormPostThroughRunServer runs the whole chain in order:
// the submit through runServer (session, origin), the job read by the
// discovery side, the result written with the production code, the take-over
// by the server's poll after a restart, the import into the IPAM, cancel, the
// limits of the result and the unwritable spool.
func TestDiscoveryFromFormPostThroughRunServer(t *testing.T) {
	e := newDREnv(t)
	s := e.start()

	// Network and the asset that already holds drKnown.
	if code, _, body := drPost(t, s, "/network/save", e.alice, vrOrigin,
		map[string]any{"id": drNet, "name": "LAN", "prefix": drPrefix}); code != http.StatusOK {
		t.Fatalf("save network = %d %s", code, body)
	}
	if code, _, body := drPost(t, s, "/network/a/save", e.alice, vrOrigin,
		map[string]any{"id": "nas1", "name": "NAS", "kind": "nas", "addresses": []string{drKnown}}); code != http.StatusOK {
		t.Fatalf("save asset = %d %s", code, body)
	}

	// Step 2: the submit. Each refusal leaves no job behind.
	submit := map[string]any{"mode": discoveryjob.ModePing, "targets": []string{drPrefix}}
	drRefusals(t, s, "/network/discovery/submit", e.alice, submit)
	if n := len(e.jobFiles()); n != 0 {
		t.Fatalf("%d job files after the refused submits", n)
	}
	code, _, body := drPost(t, s, "/network/discovery/submit", e.alice, vrOrigin, submit)
	if code != http.StatusOK {
		t.Fatalf("submit = %d %s", code, body)
	}
	id := drJobID(t, body)

	// Step 3: the reader of nebula-discovery sees exactly this job.
	job := e.pending()
	if job.ID != id || job.Mode != discoveryjob.ModePing || len(job.Targets) != 1 || job.Targets[0] != drPrefix {
		t.Fatalf("job %+v, want %s ping %s", job, id, drPrefix)
	}
	if files := e.jobFiles(); len(files) != 1 {
		t.Fatalf("jobs/ holds %v, want one file", files)
	}
	hosts, err := discoveryjob.ParseNmapXML(strings.NewReader(drNmapXML))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	// nebula-discovery only writes the result; it never removes the job.
	if err := e.spool.WriteResult(discoveryjob.Result{Format: discoveryjob.ResultFormat, Job: job.ID, StartedAt: now - 30, FinishedAt: now, OK: true, Hosts: hosts}); err != nil {
		t.Fatal(err)
	}

	// Step 4: the server takes the result over. The first poll of a started
	// server runs at once; the running server's own poll is every 30 s.
	s.stop()
	s = e.start()
	jobPage := "/network/discovery/" + job.ID
	page := drWaitPage(t, s, jobPage, e.alice, "State: done")
	// The server's poll, not the test, removes the job file after the take-over.
	waitFor(t, "the server to remove the job file of "+job.ID, func() bool { return len(e.jobFiles()) == 0 })
	// The asset has no MAC, so an address-only match is a POSSIBLE MATCH, not EXISTING.
	if !drRow(drKnown, "POSSIBLE MATCH").MatchString(page) {
		t.Fatalf("%s is not shown as POSSIBLE MATCH:\n%s", drKnown, drTable(page))
	}
	if !drRow(drNew, "NEW").MatchString(page) {
		t.Fatalf("%s is not shown as NEW:\n%s", drNew, page)
	}
	// The import refusals change nothing: the new address is still not imported.
	importBody := map[string]any{"id": job.ID, "addresses": []string{drNew}, "all": false}
	drRefusals(t, s, "/network/discovery/import", e.alice, importBody)
	if _, page := drGet(t, s, jobPage, e.alice); strings.Contains(page, `imported as <a href="/network/a/`) {
		t.Fatal("a refused import changed the job page")
	}
	// Import the new address only. drKnown is not in the list and must stay
	// out of the import: the answer lists exactly one created host, no update
	// and no skip.
	code, _, body = drPost(t, s, "/network/discovery/import", e.alice, vrOrigin, importBody)
	if code != http.StatusOK {
		t.Fatalf("import = %d %s", code, body)
	}
	var rep struct {
		Created []string          `json:"created"`
		Updated []string          `json:"updated"`
		Skipped map[string]string `json:"skipped"`
	}
	if err := json.Unmarshal(body, &rep); err != nil {
		t.Fatalf("import answer %s: %v", body, err)
	}
	if len(rep.Created) != 1 || len(rep.Updated) != 0 || len(rep.Skipped) != 0 {
		t.Fatalf("import answer %s: want exactly one created host and nothing else (%s was not in the list)", body, drKnown)
	}
	if _, page := drGet(t, s, jobPage, e.alice); !strings.Contains(page, `imported as <a href="/network/a/`) {
		t.Fatal("the job page does not show the import")
	}
	if _, netPage := drGet(t, s, "/network/n/"+drNet, e.alice); !strings.Contains(netPage, drNew) {
		t.Fatalf("network page does not show %s after the import", drNew)
	}
	if _, netPage := drGet(t, s, "/network/n/"+drNet, e.alice); strings.Count(netPage, drKnown) == 0 {
		t.Fatalf("network page lost %s", drKnown)
	}

	// Step 5a: cancel removes a waiting job from jobs/.
	code, _, body = drPost(t, s, "/network/discovery/submit", e.alice, vrOrigin, submit)
	if code != http.StatusOK {
		t.Fatalf("submit for cancel = %d %s", code, body)
	}
	cancelled := drJobID(t, body)
	// The refused cancels leave the queued job in jobs/.
	cancelBody := map[string]any{"id": cancelled}
	drRefusals(t, s, "/network/discovery/cancel", e.alice, cancelBody)
	if n := len(e.jobFiles()); n != 1 {
		t.Fatalf("%d job files after the refused cancels, want the queued job", n)
	}
	if code, _, body = drPost(t, s, "/network/discovery/cancel", e.alice, vrOrigin, cancelBody); code != http.StatusOK {
		t.Fatalf("cancel = %d %s", code, body)
	}
	if n := len(e.jobFiles()); n != 0 {
		t.Fatalf("%d job files after cancel", n)
	}

	// Step 5b: a result over the limit and a result for another job are
	// refused by the server and shown as failed, without data.
	submitted := func() string {
		code, _, body := drPost(t, s, "/network/discovery/submit", e.alice, vrOrigin, submit)
		if code != http.StatusOK {
			t.Fatalf("submit = %d %s", code, body)
		}
		return drJobID(t, body)
	}
	big := submitted()
	foreign := submitted()
	if err := os.WriteFile(filepath.Join(e.spool.ResultsDir(), big+".json"), drOversized(t, big), 0o640); err != nil {
		t.Fatal(err)
	}
	other := foreignResult(t, cancelled, discoveryjob.ResultFormat)
	if err := os.WriteFile(filepath.Join(e.spool.ResultsDir(), foreign+".json"), other, 0o640); err != nil {
		t.Fatal(err)
	}
	s.stop()
	s = e.start()
	for _, j := range []string{big, foreign} {
		page := drWaitPage(t, s, "/network/discovery/"+j, e.alice, "State: failed")
		if !strings.Contains(page, "the result could not be read") || strings.Contains(page, `class="class--`) {
			t.Fatalf("job %s: want a failed state without data:\n%s", j, page)
		}
	}
	// The page does not say why. The server's log does: the size limit refuses
	// the oversized result, and the other job's result is refused by its ID.
	s.stop()
	if logged := s.stderr.String(); !strings.Contains(logged, "file too large") || !strings.Contains(logged, "result for another job") {
		t.Fatalf("log does not name the size limit and the job mismatch:\n%s", logged)
	}
	s = e.start()

	// Step 5c: the server cannot write jobs/. The submit answers with an
	// error text, not an empty 500.
	jobsDir := e.spool.JobsDir()
	if err := os.Chmod(jobsDir, 0o550); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(jobsDir, 0o750) })
	if probe, err := os.CreateTemp(jobsDir, "probe"); err == nil {
		_ = probe.Close()
		_ = os.Remove(probe.Name())
		t.Fatal("jobs/ is still writable after chmod; run this test as a non-root user")
	}
	code, _, body = drPost(t, s, "/network/discovery/submit", e.alice, vrOrigin, submit)
	var fail struct {
		Error string `json:"error"`
	}
	if code < 400 || json.Unmarshal(body, &fail) != nil || fail.Error == "" {
		t.Fatalf("submit to an unwritable spool = %d %s, want an error text", code, body)
	}
	if n := len(e.jobFiles()); n != 0 {
		t.Fatalf("%d job files in an unwritable spool", n)
	}
}

// drRefusals sends a state-changing POST to path without an Origin, with
// another site's Origin, and without a session. The Origin cases must be
// refused with 403 and the session case with 401. The caller checks that
// nothing changed.
func drRefusals(t *testing.T, s *vrServer, path, alice string, body any) {
	t.Helper()
	for _, c := range []struct {
		name, token, origin string
		want                int
	}{
		{"without origin", alice, "", http.StatusForbidden},
		{"with a cross-site origin", alice, drEvil, http.StatusForbidden},
		{"without session", "", vrOrigin, http.StatusUnauthorized},
	} {
		if code, _, b := drPost(t, s, path, c.token, c.origin, body); code != c.want {
			t.Fatalf("POST %s %s = %d %s, want %d", path, c.name, code, b, c.want)
		}
	}
}

// drOversized is a valid result of exactly MaxResultBytes+1 bytes. JSON
// whitespace pads the object, so only the size limit can refuse it.
func drOversized(t *testing.T, job string) []byte {
	t.Helper()
	b, err := json.Marshal(discoveryjob.Result{Format: discoveryjob.ResultFormat, Job: job, StartedAt: 1, FinishedAt: 2, OK: true})
	if err != nil {
		t.Fatal(err)
	}
	pad := discoveryjob.MaxResultBytes + 1 - len(b)
	if pad < 1 {
		t.Fatalf("result of %d bytes leaves no room to pad", len(b))
	}
	out := append(append([]byte{}, b[:len(b)-1]...), bytes.Repeat([]byte(" "), pad)...)
	out = append(out, '}')
	if len(out) != discoveryjob.MaxResultBytes+1 || !json.Valid(out) {
		t.Fatalf("padded result: %d bytes, valid JSON %v", len(out), json.Valid(out))
	}
	return out
}

// foreignResult is a valid result that names another job.
func foreignResult(t *testing.T, job, format string) []byte {
	t.Helper()
	b, err := json.Marshal(discoveryjob.Result{Format: format, Job: job, StartedAt: 1, FinishedAt: 2, OK: true, Hosts: []discoveryjob.Host{{Address: drNew}}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestDiscoveryPathStandardsAgree reads the spool path from every place it
// is written down and requires the same path (or its jobs/ and results/
// subdirectories). Only reads; the deploy files are not changed here.
func TestDiscoveryPathStandardsAgree(t *testing.T) {
	base := serverconfig.DefaultDiscoveryDir
	if base == "" {
		t.Fatal("serverconfig.DefaultDiscoveryDir is empty")
	}
	read := func(path string) string {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	match := func(path, re string) string {
		t.Helper()
		m := regexp.MustCompile(re).FindStringSubmatch(read(path))
		if m == nil {
			t.Fatalf("%s: no match for %s", path, re)
		}
		return m[1]
	}

	if got := match("../nebula-discovery/main.go", `(?m)^\s*defaultSpool\s*=\s*"([^"]+)"`); got != base {
		t.Errorf("cmd/nebula-discovery defaultSpool = %q, server default %q", got, base)
	}
	if got := match("../../deploy/systemd/nebula-discovery.service", `ExecStart=\S+\s+.*?-spool\s+(\S+)`); got != base {
		t.Errorf("nebula-discovery.service -spool = %q, want %q", got, base)
	}
	if got := match("../../deploy/systemd/nebula-discovery.service", `(?m)^ReadWritePaths=(\S+)`); got != base+"/results" {
		t.Errorf("nebula-discovery.service ReadWritePaths = %q, want the results directory %q", got, base+"/results")
	}
	if got := match("../../deploy/systemd/nebula-discovery.path", `(?m)^PathChanged=(\S+)`); got != base+"/jobs" {
		t.Errorf("nebula-discovery.path PathChanged = %q, want the jobs directory %q", got, base+"/jobs")
	}
	// The server drop-in is written by install.sh with its variable expanded.
	varLib := match("../../deploy/install.sh", `(?m)^var_lib=(\S+)$`)
	if got := match("../../deploy/install.sh", `(?m)^ReadWritePaths=\$\{var_lib\}(/\S+)`); varLib+got != base+"/jobs" {
		t.Errorf("install.sh server drop-in ReadWritePaths = %q, want the jobs directory %q", varLib+got, base+"/jobs")
	}
}
