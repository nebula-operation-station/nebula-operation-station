// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// testToken is the Authorization header value the test supplier returns.
const testToken = "PVE token=abc123secret"

// newTestClient returns a Client pointed at a loopback httptest server and
// the server itself. The client uses the default limits and a 5 s timeout.
func newTestClient(t *testing.T, handler http.Handler) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c, err := NewClient(srv.URL+"/api2/json", srv.Client(), func() string { return testToken })
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	c.Timeout = 5 * time.Second
	return c, srv
}

// loadFixture reads a testdata file.
func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return b
}

// jsonServer serves the given bodies by path prefix.
func jsonServer(t *testing.T, bodies map[string][]byte) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for prefix, body := range bodies {
			if strings.HasPrefix(r.URL.Path, prefix) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(body)
				return
			}
		}
		http.NotFound(w, r)
	})
}

// --- NewClient ------------------------------------------------------------

func TestNewClientRejectsInvalidBaseURL(t *testing.T) {
	for _, base := range []string{
		"",
		"ftp://pve1:8006/api2/json",
		"http://",
		"not a url",
		"https://pve1:8006/api", // wrong API root
	} {
		if _, err := NewClient(base, nil, func() string { return "t" }); err == nil {
			t.Errorf("NewClient(%q): expected error, got nil", base)
		}
	}
	if _, err := NewClient("http://127.0.0.1:8006/api2/json", nil, nil); err == nil {
		t.Error("NewClient with nil token supplier: expected error, got nil")
	}
	if _, err := NewClient("http://127.0.0.1:8006/api2/json", nil, func() string { return "t" }); err != nil {
		t.Errorf("NewClient(valid): %v", err)
	}
}

// --- getJSON transport behavior --------------------------------------------

func TestGetJSONDecodesDataEnvelope(t *testing.T) {
	c, _ := newTestClient(t, jsonServer(t, map[string][]byte{
		"/api2/json/cluster/backup": loadFixture(t, "jobs-pve8.json"),
	}))
	var out []rawJob
	if err := c.getJSON(context.Background(), "/cluster/backup", nil, &out); err != nil {
		t.Fatalf("getJSON: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("entries = %d, want 2", len(out))
	}
}

func TestGetJSONDeniedReturnsErrDenied(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "authentication failed", http.StatusForbidden)
	}))
	err := c.getJSON(context.Background(), "/cluster/backup", nil, &struct{}{})
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("error = %v, want ErrDenied", err)
	}
	if strings.Contains(err.Error(), testToken) {
		t.Error("error message contains the token")
	}
}

func TestGetJSONUnauthorizedReturnsErrDenied(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	err := c.getJSON(context.Background(), "/cluster/backup", nil, &struct{}{})
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("error = %v, want ErrDenied", err)
	}
}

func TestGetJSONServerErrorIsNotDenied(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	err := c.getJSON(context.Background(), "/cluster/backup", nil, &struct{}{})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if errors.Is(err, ErrDenied) {
		t.Error("500 must not be ErrDenied")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error %q does not carry the status code", err)
	}
}

func TestGetJSONRejectsOversizedBody(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(make([]byte, 64))
	}))
	c.MaxResponseBytes = 16
	err := c.getJSON(context.Background(), "/cluster/backup", nil, &struct{}{})
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("error = %v, want size-limit error", err)
	}
}

func TestGetJSONEnforcesPerCallTimeout(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
	}))
	c.Timeout = 50 * time.Millisecond
	err := c.getJSON(context.Background(), "/cluster/backup", nil, &struct{}{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context.DeadlineExceeded", err)
	}
}

func TestGetJSONRejectsDuplicateKeys(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"volid":"a","volid":"b"}]}`))
	}))
	err := c.getJSON(context.Background(), "/cluster/backup", nil, &[]struct{}{})
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("error = %v, want duplicate-key error", err)
	}
}

func TestGetJSONRejectsTrailingData(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[]}x`))
	}))
	err := c.getJSON(context.Background(), "/cluster/backup", nil, &[]struct{}{})
	if err == nil {
		t.Fatal("expected error for trailing data, got nil")
	}
}

func TestGetJSONRejectsMissingOrExtraEnvelopeKeys(t *testing.T) {
	for _, body := range []string{`{}`, `{"data":[],"extra":1}`} {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(body))
		}))
		if err := c.getJSON(context.Background(), "/cluster/backup", nil, &[]struct{}{}); err == nil {
			t.Errorf("body %s: expected error, got nil", body)
		}
	}
}

func TestGetJSONRequiresTokenBeforeRequest(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
	}))
	t.Cleanup(srv.Close)
	c, err := NewClient(srv.URL+"/api2/json", srv.Client(), func() string { return "" })
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := c.getJSON(context.Background(), "/cluster/backup", nil, &struct{}{}); err == nil {
		t.Fatal("expected error for empty token, got nil")
	}
	if calls.Load() != 0 {
		t.Errorf("server called %d times, want 0", calls.Load())
	}
}

func TestGetJSONSendsTokenHeader(t *testing.T) {
	var got atomic.String
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.Header.Get("Authorization"))
		http.NotFound(w, r)
	}))
	_ = c.getJSON(context.Background(), "/cluster/backup", nil, &struct{}{})
	if got.Load() != testToken {
		t.Errorf("Authorization = %q, want %q", got.Load(), testToken)
	}
}

// --- ReadBackups: catalog ---------------------------------------------------

func TestReadBackupsVZDumpCatalog(t *testing.T) {
	c, _ := newTestClient(t, jsonServer(t, map[string][]byte{
		"/api2/json/nodes/pve1/storage/local/content": loadFixture(t, "content-vzdump-pve8.json"),
		"/api2/json/cluster/backup":                   loadFixture(t, "jobs-empty.json"),
	}))
	obs, err := c.ReadBackups(context.Background(), BackupsOptions{
		Sources: []BackupSource{{Node: "pve1", Storage: "local", Type: "local"}},
		Scope:   ReadScope{FullContent: true},
	})
	if err != nil {
		t.Fatalf("ReadBackups: %v", err)
	}
	if !obs.Catalog.IsAvailable() {
		t.Fatalf("catalog state = %s (%s), want available", obs.Catalog.State, obs.Catalog.Reason)
	}
	got := obs.Catalog.Value
	if len(got) != 2 {
		t.Fatalf("catalog entries = %d, want 2", len(got))
	}
	want0 := CatalogEntry{
		VolID:       "local:backup/vm-100-disk-0.vzdump",
		VMID:        100,
		Source:      SourceVZDump,
		CTimeUnix:   1761621600,
		SizeBytes:   1073741824,
		NotesLength: len("nightly vzdump"),
		Verified:    TriUnknown,
	}
	if got[0] != want0 {
		t.Errorf("entry[0] = %+v, want %+v", got[0], want0)
	}
	if got[1].VMID != 200 || got[1].NotesLength != 0 {
		t.Errorf("entry[1] = %+v, want vmid 200 with no notes", got[1])
	}
	// Per-guest correlation.
	if len(obs.Guests) != 2 || obs.Guests[0].VMID != 100 || obs.Guests[1].VMID != 200 {
		t.Fatalf("guests = %+v, want vmids 100 and 200 in order", obs.Guests)
	}
	g := obs.Guests[0]
	if !g.Catalog.IsAvailable() || len(g.Catalog.Value) != 1 {
		t.Fatalf("guest 100 catalog = %+v, want 1 entry", g.Catalog)
	}
	ev := g.Catalog.Value[0]
	if ev.Source != SourceVZDump || ev.Kind != KindCatalog || ev.Status != StatusCatalog {
		t.Errorf("evidence = %+v, want vzdump/catalog/catalog", ev)
	}
	if ev.Name != want0.VolID || ev.FinishedUnix != want0.CTimeUnix {
		t.Errorf("evidence name/finished = %q/%d, want %q/%d", ev.Name, ev.FinishedUnix, want0.VolID, want0.CTimeUnix)
	}
	if g.Tasks.IsAvailable() {
		t.Errorf("guest 100 tasks available = %+v, want unavailable (no summaries)", g.Tasks)
	}
	if g.Tasks.Reason != ReasonNoTasks {
		t.Errorf("guest 100 tasks reason = %q, want %q", g.Tasks.Reason, ReasonNoTasks)
	}
	if !g.Jobs.IsAvailable() || len(g.Jobs.Value) != 0 {
		t.Errorf("guest 100 jobs = %+v, want available empty", g.Jobs)
	}
}

func TestReadBackupsPBSVerifiedStates(t *testing.T) {
	c, _ := newTestClient(t, jsonServer(t, map[string][]byte{
		"/api2/json/nodes/pve1/storage/pbs1/content": loadFixture(t, "content-pbs-pve9.json"),
		"/api2/json/cluster/backup":                   loadFixture(t, "jobs-empty.json"),
	}))
	obs, err := c.ReadBackups(context.Background(), BackupsOptions{
		Sources: []BackupSource{{Node: "pve1", Storage: "pbs1", Type: "pbs"}},
		Scope:   ReadScope{FullContent: true},
	})
	if err != nil {
		t.Fatalf("ReadBackups: %v", err)
	}
	got := obs.Catalog.Value
	if len(got) != 3 {
		t.Fatalf("catalog entries = %d, want 3", len(got))
	}
	// 0/1 integers and JSON booleans must both decode.
	if got[0].Verified != TriYes || got[1].Verified != TriNo || got[2].Verified != TriYes {
		t.Errorf("verified = %v %v %v, want yes no yes", got[0].Verified, got[1].Verified, got[2].Verified)
	}
	for _, e := range got {
		if e.Source != SourcePBS {
			t.Errorf("entry %s source = %s, want pbs", e.VolID, e.Source)
		}
	}
	// Guest 100 has one verified and one unverified catalog entry.
	if len(obs.Guests) != 2 || obs.Guests[0].VMID != 100 {
		t.Fatalf("guests = %+v, want 100 first", obs.Guests)
	}
	evs := obs.Guests[0].Catalog.Value
	if len(evs) != 2 {
		t.Fatalf("guest 100 catalog evidence = %d, want 2", len(evs))
	}
	// Newest first is not required; check the set of statuses.
	statuses := map[string]bool{evs[0].Status: true, evs[1].Status: true}
	if !statuses[StatusVerified] || !statuses[StatusCatalog] {
		t.Errorf("statuses = %v, want verified and catalog", statuses)
	}
}

func TestReadBackupsPBSWithoutVerifiedField(t *testing.T) {
	c, _ := newTestClient(t, jsonServer(t, map[string][]byte{
		"/api2/json/nodes/pve1/storage/pbs1/content": loadFixture(t, "content-pbs-pve8.json"),
		"/api2/json/cluster/backup":                   loadFixture(t, "jobs-empty.json"),
	}))
	obs, err := c.ReadBackups(context.Background(), BackupsOptions{
		Sources: []BackupSource{{Node: "pve1", Storage: "pbs1", Type: "pbs"}},
		Scope:   ReadScope{FullContent: true},
	})
	if err != nil {
		t.Fatalf("ReadBackups: %v", err)
	}
	if len(obs.Catalog.Value) != 1 {
		t.Fatalf("catalog entries = %d, want 1", len(obs.Catalog.Value))
	}
	if obs.Catalog.Value[0].Verified != TriUnknown {
		t.Errorf("verified = %s, want unknown when the field is absent", obs.Catalog.Value[0].Verified)
	}
	if obs.Guests[0].Catalog.Value[0].Status != StatusCatalog {
		t.Errorf("status = %s, want catalog", obs.Guests[0].Catalog.Value[0].Status)
	}
}

func TestReadBackupsEmptyContentIsAvailableEmpty(t *testing.T) {
	c, _ := newTestClient(t, jsonServer(t, map[string][]byte{
		"/api2/json/nodes/pve1/storage/local/content": loadFixture(t, "content-empty.json"),
		"/api2/json/cluster/backup":                   loadFixture(t, "jobs-empty.json"),
	}))
	obs, err := c.ReadBackups(context.Background(), BackupsOptions{
		Sources: []BackupSource{{Node: "pve1", Storage: "local", Type: "local"}},
		Scope:   ReadScope{FullContent: true},
	})
	if err != nil {
		t.Fatalf("ReadBackups: %v", err)
	}
	if !obs.Catalog.IsAvailable() {
		t.Fatalf("catalog = %+v, want available", obs.Catalog)
	}
	if len(obs.Catalog.Value) != 0 {
		t.Errorf("catalog entries = %d, want 0", len(obs.Catalog.Value))
	}
	if len(obs.Guests) != 0 {
		t.Errorf("guests = %+v, want none", obs.Guests)
	}
}

func TestReadBackupsDeniedContentIsUnavailable(t *testing.T) {
	var contentCalls atomic.Int64
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/api2/json/nodes/"):
			contentCalls.Add(1)
			http.Error(w, "no permission", http.StatusForbidden)
		case strings.HasPrefix(r.URL.Path, "/api2/json/cluster/backup"):
			w.Write(loadFixture(t, "jobs-empty.json"))
		default:
			http.NotFound(w, r)
		}
	}))
	obs, err := c.ReadBackups(context.Background(), BackupsOptions{
		Sources: []BackupSource{{Node: "pve1", Storage: "local", Type: "local"}},
		Scope:   ReadScope{FullContent: true},
		Tasks:   []TaskSummary{{Node: "pve1", Type: "backup", Target: "qemu/100", VMID: 100, StartedUnix: 1, FinishedUnix: 2, ExitStatus: TaskExitOK}},
	})
	if err != nil {
		t.Fatalf("ReadBackups: %v", err)
	}
	if obs.Catalog.IsAvailable() {
		t.Fatal("catalog available after denial, want unavailable")
	}
	if obs.Catalog.Reason != ReasonDenied {
		t.Errorf("catalog reason = %q, want %q", obs.Catalog.Reason, ReasonDenied)
	}
	// The guest is known from the task summary; its catalog stays unavailable.
	if len(obs.Guests) != 1 || obs.Guests[0].VMID != 100 {
		t.Fatalf("guests = %+v, want [100]", obs.Guests)
	}
	if obs.Guests[0].Catalog.IsAvailable() {
		t.Error("guest catalog available after denial, want unavailable")
	}
	if obs.Guests[0].Catalog.Reason != ReasonDenied {
		t.Errorf("guest catalog reason = %q, want %q", obs.Guests[0].Catalog.Reason, ReasonDenied)
	}
	if contentCalls.Load() != 1 {
		t.Errorf("content calls = %d, want 1", contentCalls.Load())
	}
}

func TestReadBackupsFilteredScopeIsUnavailable(t *testing.T) {
	var contentCalls atomic.Int64
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/api2/json/nodes/"):
			contentCalls.Add(1)
			w.Write(loadFixture(t, "content-vzdump-pve8.json"))
		case strings.HasPrefix(r.URL.Path, "/api2/json/cluster/backup"):
			w.Write(loadFixture(t, "jobs-empty.json"))
		default:
			http.NotFound(w, r)
		}
	}))
	obs, err := c.ReadBackups(context.Background(), BackupsOptions{
		Sources: []BackupSource{{Node: "pve1", Storage: "local", Type: "local"}},
		Scope:   ReadScope{FullContent: false},
	})
	if err != nil {
		t.Fatalf("ReadBackups: %v", err)
	}
	if obs.Catalog.IsAvailable() {
		t.Fatal("catalog available with filtered scope, want unavailable")
	}
	if obs.Catalog.Reason != ReasonFiltered {
		t.Errorf("catalog reason = %q, want %q", obs.Catalog.Reason, ReasonFiltered)
	}
	if contentCalls.Load() != 0 {
		t.Errorf("content calls = %d, want 0 (filtered reads are not even attempted)", contentCalls.Load())
	}
	// Jobs are an independent dataset and still read.
	if !obs.Jobs.IsAvailable() {
		t.Errorf("jobs = %+v, want available", obs.Jobs)
	}
}

func TestReadBackupsAnyDeniedSourceMakesCatalogUnavailable(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/storage/local/"):
			w.Write(loadFixture(t, "content-vzdump-pve8.json"))
		case strings.Contains(r.URL.Path, "/storage/secret/"):
			http.Error(w, "no permission", http.StatusForbidden)
		case strings.HasPrefix(r.URL.Path, "/api2/json/cluster/backup"):
			w.Write(loadFixture(t, "jobs-empty.json"))
		default:
			http.NotFound(w, r)
		}
	}))
	obs, err := c.ReadBackups(context.Background(), BackupsOptions{
		Sources: []BackupSource{
			{Node: "pve1", Storage: "local", Type: "local"},
			{Node: "pve1", Storage: "secret", Type: "pbs"},
		},
		Scope: ReadScope{FullContent: true},
	})
	if err != nil {
		t.Fatalf("ReadBackups: %v", err)
	}
	if obs.Catalog.IsAvailable() {
		t.Fatal("partial catalog presented as available, want unavailable")
	}
	if obs.Catalog.Reason != ReasonDenied {
		t.Errorf("catalog reason = %q, want %q", obs.Catalog.Reason, ReasonDenied)
	}
}

func TestReadBackupsNotesContentNeverStored(t *testing.T) {
	const secretNotes = "NEVER-STORED-NOTES-XYZ"
	body := `{"data":[{"volid":"local:backup/vm-100-disk-0.vzdump","type":"backup","vmid":100,"ctime":1761621600,"size":10,"notes":"` + secretNotes + `"}]}`
	c, _ := newTestClient(t, jsonServer(t, map[string][]byte{
		"/api2/json/nodes/pve1/storage/local/content": []byte(body),
		"/api2/json/cluster/backup":                   loadFixture(t, "jobs-empty.json"),
	}))
	obs, err := c.ReadBackups(context.Background(), BackupsOptions{
		Sources: []BackupSource{{Node: "pve1", Storage: "local", Type: "local"}},
		Scope:   ReadScope{FullContent: true},
	})
	if err != nil {
		t.Fatalf("ReadBackups: %v", err)
	}
	if obs.Catalog.Value[0].NotesLength != len(secretNotes) {
		t.Errorf("notes length = %d, want %d", obs.Catalog.Value[0].NotesLength, len(secretNotes))
	}
	b, err := json.Marshal(obs)
	if err != nil {
		t.Fatalf("marshal observation: %v", err)
	}
	if strings.Contains(string(b), secretNotes) {
		t.Error("observation JSON contains the notes content")
	}
}

func TestReadBackupsRejectsMalformedEntries(t *testing.T) {
	valid := `{"volid":"local:backup/vm-100-disk-0.vzdump","type":"backup","vmid":100,"ctime":1761621600,"size":10}`
	cases := map[string]string{
		"missing vmid":     `{"volid":"local:backup/vm-100-disk-0.vzdump","type":"backup","ctime":1761621600,"size":10}`,
		"zero ctime":       `{"volid":"local:backup/vm-100-disk-0.vzdump","type":"backup","vmid":100,"ctime":0,"size":10}`,
		"ctime too large":  `{"volid":"local:backup/vm-100-disk-0.vzdump","type":"backup","vmid":100,"ctime":4294967296,"size":10}`,
		"negative size":    `{"volid":"local:backup/vm-100-disk-0.vzdump","type":"backup","vmid":100,"ctime":1761621600,"size":-1}`,
		"wrong content":    `{"volid":"local:backup/vm-100-disk-0.img","type":"disk","vmid":100,"ctime":1761621600,"size":10}`,
		"volid with space": `{"volid":"local:backup/vm 100.vzdump","type":"backup","vmid":100,"ctime":1761621600,"size":10}`,
		"oversized volid":  fmt.Sprintf(`{"volid":"%s","type":"backup","vmid":100,"ctime":1761621600,"size":10}`, strings.Repeat("a", maxVolidBytes+1)),
		"oversized notes":  fmt.Sprintf(`%s,"notes":"%s"}`, valid[:len(valid)-1], strings.Repeat("n", maxNotesBytes+1)),
	}
	for name, entry := range cases {
		t.Run(name, func(t *testing.T) {
			body := []byte(`{"data":[` + entry + `]}`)
			c, _ := newTestClient(t, jsonServer(t, map[string][]byte{
				"/api2/json/nodes/pve1/storage/local/content": body,
				"/api2/json/cluster/backup":                   loadFixture(t, "jobs-empty.json"),
			}))
			_, err := c.ReadBackups(context.Background(), BackupsOptions{
				Sources: []BackupSource{{Node: "pve1", Storage: "local", Type: "local"}},
				Scope:   ReadScope{FullContent: true},
			})
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if errors.Is(err, ErrDenied) {
				t.Error("malformed entry must not be ErrDenied")
			}
		})
	}
}

func TestReadBackupsRejectsTooManyEntries(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"data":[`)
	for i := 0; i < maxListings+1; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"volid":"local:backup/vm-100-disk-%d.vzdump","type":"backup","vmid":100,"ctime":1761621600,"size":10}`, i)
	}
	b.WriteString(`]}`)
	c, _ := newTestClient(t, jsonServer(t, map[string][]byte{
		"/api2/json/nodes/pve1/storage/local/content": []byte(b.String()),
		"/api2/json/cluster/backup":                   loadFixture(t, "jobs-empty.json"),
	}))
	_, err := c.ReadBackups(context.Background(), BackupsOptions{
		Sources: []BackupSource{{Node: "pve1", Storage: "local", Type: "local"}},
		Scope:   ReadScope{FullContent: true},
	})
	if err == nil || !strings.Contains(err.Error(), "entries") {
		t.Fatalf("error = %v, want entry-count limit error", err)
	}
}

// --- ReadBackups: jobs ------------------------------------------------------

func TestReadBackupsJobsParsed(t *testing.T) {
	c, _ := newTestClient(t, jsonServer(t, map[string][]byte{
		"/api2/json/nodes/pve1/storage/local/content": loadFixture(t, "content-empty.json"),
		"/api2/json/cluster/backup":                   loadFixture(t, "jobs-pve8.json"),
	}))
	obs, err := c.ReadBackups(context.Background(), BackupsOptions{
		Sources: []BackupSource{{Node: "pve1", Storage: "local", Type: "local"}},
		Scope:   ReadScope{FullContent: true},
	})
	if err != nil {
		t.Fatalf("ReadBackups: %v", err)
	}
	if !obs.Jobs.IsAvailable() {
		t.Fatalf("jobs = %+v, want available", obs.Jobs)
	}
	jobs := obs.Jobs.Value
	if len(jobs) != 2 {
		t.Fatalf("jobs = %d, want 2", len(jobs))
	}
	j0 := jobs[0]
	if j0.Schedule != "daily" || j0.Time != "02:00" || j0.Mode != "snapshot" || j0.Storage != "pbs1" {
		t.Errorf("job[0] = %+v, want daily 02:00 snapshot pbs1", j0)
	}
	if !j0.All {
		t.Error("job[0].all = false, want true (PVE renders 1)")
	}
	if j0.NotesLength != len("nightly PBS backup") {
		t.Errorf("job[0].notes length = %d, want %d", j0.NotesLength, len("nightly PBS backup"))
	}
	j1 := jobs[1]
	if j1.Schedule != "weekly" || j1.Day != "sunday" || j1.Pool != "webservers" {
		t.Errorf("job[1] = %+v, want weekly sunday pool webservers", j1)
	}
	if len(j1.Volumes) != 1 || j1.Volumes[0] != "local:backup/vm-200-disk-0.vzdump" {
		t.Errorf("job[1].volumes = %v", j1.Volumes)
	}
}

func TestReadBackupsJobsDeniedIsUnavailable(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/api2/json/nodes/"):
			w.Write(loadFixture(t, "content-empty.json"))
		case strings.HasPrefix(r.URL.Path, "/api2/json/cluster/backup"):
			http.Error(w, "no permission", http.StatusForbidden)
		default:
			http.NotFound(w, r)
		}
	}))
	obs, err := c.ReadBackups(context.Background(), BackupsOptions{
		Sources: []BackupSource{{Node: "pve1", Storage: "local", Type: "local"}},
		Scope:   ReadScope{FullContent: true},
	})
	if err != nil {
		t.Fatalf("ReadBackups: %v", err)
	}
	if obs.Jobs.IsAvailable() {
		t.Fatal("jobs available after denial, want unavailable")
	}
	if obs.Jobs.Reason != ReasonDenied {
		t.Errorf("jobs reason = %q, want %q", obs.Jobs.Reason, ReasonDenied)
	}
	if !obs.Catalog.IsAvailable() {
		t.Errorf("catalog = %+v, want available (independent dataset)", obs.Catalog)
	}
}

func TestReadBackupsJobsEmptyIsAvailableEmpty(t *testing.T) {
	c, _ := newTestClient(t, jsonServer(t, map[string][]byte{
		"/api2/json/nodes/pve1/storage/local/content": loadFixture(t, "content-empty.json"),
		"/api2/json/cluster/backup":                   loadFixture(t, "jobs-empty.json"),
	}))
	obs, err := c.ReadBackups(context.Background(), BackupsOptions{
		Sources: []BackupSource{{Node: "pve1", Storage: "local", Type: "local"}},
		Scope:   ReadScope{FullContent: true},
	})
	if err != nil {
		t.Fatalf("ReadBackups: %v", err)
	}
	if !obs.Jobs.IsAvailable() || len(obs.Jobs.Value) != 0 {
		t.Errorf("jobs = %+v, want available empty", obs.Jobs)
	}
}

// --- job selection coverage --------------------------------------------------

func TestJobCoversVMID(t *testing.T) {
	pools := map[string]map[uint64]bool{
		"webservers": {100: true, 200: true},
	}
	cases := []struct {
		job  BackupJob
		vmid uint64
		want bool
	}{
		{BackupJob{All: true}, 999, true},
		{BackupJob{Pool: "webservers"}, 100, true},
		{BackupJob{Pool: "webservers"}, 300, false},
		{BackupJob{Pool: "unknown-pool"}, 100, false},
		{BackupJob{Volumes: []string{"local:backup/vm-200-disk-0.vzdump"}}, 200, true},
		{BackupJob{Volumes: []string{"local:backup/vm-200-disk-0.vzdump"}}, 201, false},
		{BackupJob{Pool: "webservers", Volumes: []string{"local:backup/vm-300-disk-0.vzdump"}}, 300, true},
		{BackupJob{Storage: "local"}, 100, false},
	}
	for _, tc := range cases {
		if got := tc.job.CoversVMID(tc.vmid, pools); got != tc.want {
			t.Errorf("job %+v covers vmid %d = %v, want %v", tc.job, tc.vmid, got, tc.want)
		}
	}
}

// --- correlation --------------------------------------------------------------

func TestReadBackupsCorrelatesPerVMID(t *testing.T) {
	c, _ := newTestClient(t, jsonServer(t, map[string][]byte{
		"/api2/json/nodes/pve1/storage/local/content": loadFixture(t, "content-vzdump-pve8.json"),
		"/api2/json/cluster/backup":                   loadFixture(t, "jobs-pve8.json"),
	}))
	obs, err := c.ReadBackups(context.Background(), BackupsOptions{
		Sources: []BackupSource{{Node: "pve1", Storage: "local", Type: "local"}},
		Scope:   ReadScope{FullContent: true},
		Tasks: []TaskSummary{
			{Node: "pve1", Actor: "root@pam", Type: "backup", Target: "qemu/100", VMID: 100, StartedUnix: 1761621000, FinishedUnix: 1761621600, ExitStatus: TaskExitOK},
			{Node: "pve1", Actor: "root@pam", Type: "backup", Target: "qemu/200", VMID: 200, StartedUnix: 1761534000, FinishedUnix: 1761535200, ExitStatus: "CRITICAL: disk full"},
			// Not a backup task: must be ignored.
			{Node: "pve1", Actor: "root@pam", Type: "start", Target: "qemu/100", VMID: 100, StartedUnix: 1, FinishedUnix: 2, ExitStatus: TaskExitOK},
		},
		Pools: map[string]map[uint64]bool{"webservers": {300: true}},
	})
	if err != nil {
		t.Fatalf("ReadBackups: %v", err)
	}
	if len(obs.Guests) != 3 {
		t.Fatalf("guests = %+v, want 3 (100, 200, 300)", obs.Guests)
	}
	if obs.Guests[0].VMID != 100 || obs.Guests[1].VMID != 200 || obs.Guests[2].VMID != 300 {
		t.Fatalf("guest order = %d %d %d, want 100 200 300", obs.Guests[0].VMID, obs.Guests[1].VMID, obs.Guests[2].VMID)
	}
	g100, g200, g300 := obs.Guests[0], obs.Guests[1], obs.Guests[2]

	if len(g100.Tasks.Value) != 1 {
		t.Fatalf("guest 100 tasks = %+v, want 1", g100.Tasks.Value)
	}
	te := g100.Tasks.Value[0]
	if te.Kind != KindTask || te.Status != StatusSuccess || te.Source != SourceVZDump {
		t.Errorf("task evidence = %+v, want vzdump/task/success", te)
	}
	if te.Name != "qemu/100" || te.StartedUnix != 1761621000 || te.FinishedUnix != 1761621600 {
		t.Errorf("task evidence times/name = %+v", te)
	}
	if te.Verified != TriUnknown {
		t.Errorf("task evidence verified = %s, want unknown", te.Verified)
	}

	if len(g200.Tasks.Value) != 1 || g200.Tasks.Value[0].Status != StatusFailed {
		t.Fatalf("guest 200 tasks = %+v, want 1 failed", g200.Tasks.Value)
	}

	// The all=1 job covers every known guest; the pool job covers 300 and
	// (via volumes) 200.
	if len(g100.Jobs.Value) != 1 {
		t.Errorf("guest 100 jobs = %+v, want 1 (all=1)", g100.Jobs.Value)
	}
	if len(g200.Jobs.Value) != 2 {
		t.Errorf("guest 200 jobs = %+v, want 2 (all=1 + volumes)", g200.Jobs.Value)
	}
	if len(g300.Jobs.Value) != 2 {
		t.Errorf("guest 300 jobs = %+v, want 2 (all=1 + pool)", g300.Jobs.Value)
	}
	// Guest 300 is known only from pool membership: catalog and tasks are
	// available and empty.
	if !g300.Catalog.IsAvailable() || len(g300.Catalog.Value) != 0 {
		t.Errorf("guest 300 catalog = %+v, want available empty", g300.Catalog)
	}
	if !g300.Tasks.IsAvailable() || len(g300.Tasks.Value) != 0 {
		t.Errorf("guest 300 tasks = %+v, want available empty", g300.Tasks)
	}
}

func TestReadBackupsTaskWithoutVMIDIsSkipped(t *testing.T) {
	c, _ := newTestClient(t, jsonServer(t, map[string][]byte{
		"/api2/json/nodes/pve1/storage/local/content": loadFixture(t, "content-empty.json"),
		"/api2/json/cluster/backup":                   loadFixture(t, "jobs-empty.json"),
	}))
	obs, err := c.ReadBackups(context.Background(), BackupsOptions{
		Sources: []BackupSource{{Node: "pve1", Storage: "local", Type: "local"}},
		Scope:   ReadScope{FullContent: true},
		Tasks:   []TaskSummary{{Node: "pve1", Type: "backup", Target: "all", VMID: 0, StartedUnix: 1, FinishedUnix: 2, ExitStatus: TaskExitOK}},
	})
	if err != nil {
		t.Fatalf("ReadBackups: %v", err)
	}
	if len(obs.Guests) != 0 {
		t.Errorf("guests = %+v, want none (task has no vmid)", obs.Guests)
	}
}

func TestReadBackupsZeroSourcesIsAvailableEmpty(t *testing.T) {
	var contentCalls atomic.Int64
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api2/json/nodes/") {
			contentCalls.Add(1)
		}
		w.Write(loadFixture(t, "jobs-empty.json"))
	}))
	obs, err := c.ReadBackups(context.Background(), BackupsOptions{
		Scope: ReadScope{FullContent: true},
	})
	if err != nil {
		t.Fatalf("ReadBackups: %v", err)
	}
	if !obs.Catalog.IsAvailable() || len(obs.Catalog.Value) != 0 {
		t.Errorf("catalog = %+v, want available empty", obs.Catalog)
	}
	if contentCalls.Load() != 0 {
		t.Errorf("content calls = %d, want 0", contentCalls.Load())
	}
}

func TestReadBackupsRejectsInvalidOptions(t *testing.T) {
	var calls atomic.Int64
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) })
	cases := []struct {
		name string
		opts BackupsOptions
	}{
		{"bad node name", BackupsOptions{
			Sources: []BackupSource{{Node: "PVE 1", Storage: "local", Type: "local"}},
			Scope:   ReadScope{FullContent: true},
		}},
		{"bad storage name", BackupsOptions{
			Sources: []BackupSource{{Node: "pve1", Storage: "../etc", Type: "local"}},
			Scope:   ReadScope{FullContent: true},
		}},
		{"empty storage type", BackupsOptions{
			Sources: []BackupSource{{Node: "pve1", Storage: "local", Type: ""}},
			Scope:   ReadScope{FullContent: true},
		}},
		{"oversized task actor", BackupsOptions{
			Scope: ReadScope{FullContent: true},
			Tasks: []TaskSummary{{Node: "pve1", Actor: strings.Repeat("a", maxActorBytes+1), Type: "backup", Target: "qemu/1", VMID: 1, StartedUnix: 1, FinishedUnix: 2, ExitStatus: TaskExitOK}},
		}},
		{"task vmid out of range", BackupsOptions{
			Scope: ReadScope{FullContent: true},
			Tasks: []TaskSummary{{Node: "pve1", Type: "backup", Target: "qemu/1", VMID: 1 << 31, StartedUnix: 1, FinishedUnix: 2, ExitStatus: TaskExitOK}},
		}},
		{"task finished before start", BackupsOptions{
			Scope: ReadScope{FullContent: true},
			Tasks: []TaskSummary{{Node: "pve1", Type: "backup", Target: "qemu/1", VMID: 1, StartedUnix: 10, FinishedUnix: 5, ExitStatus: TaskExitOK}},
		}},
		{"bad pool key", BackupsOptions{
			Scope:   ReadScope{FullContent: true},
			Pools:   map[string]map[uint64]bool{"Bad Pool": {1: true}},
		}},
		{"oversized exit status", BackupsOptions{
			Scope: ReadScope{FullContent: true},
			Tasks: []TaskSummary{{Node: "pve1", Type: "backup", Target: "qemu/1", VMID: 1, StartedUnix: 1, FinishedUnix: 2, ExitStatus: strings.Repeat("e", maxExitStatusBytes+1)}},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := newTestClient(t, handler)
			if _, err := c.ReadBackups(context.Background(), tc.opts); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
	if calls.Load() != 0 {
		t.Errorf("server called %d times, want 0 (options validated before I/O)", calls.Load())
	}
}
