// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode"

	"github.com/nebula-operation-station/nebula-operation-station/internal/integrity"
	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// I1 self-check of nebula-server (ADR 0015 D4, IG-03). The server checks
// the installed NOS files at start and every integrityCheckInterval, logs
// each run and shows the latest result under integrityStatusPath. It
// does not react: findings, notifications and the unlock refusal are
// IG-04 and the executor's job.
const (
	// integrityCheckInterval is the period after the start check (ADR
	// 0015 D4 "When", Q2: every 60 minutes).
	integrityCheckInterval = integrity.DefaultInterval
	// integrityInstallRoot is the root of the installed NOS files the
	// server checks.
	integrityInstallRoot = "/"
	// integrityStatusPath serves the latest result as JSON behind the
	// session, like the other server pages.
	integrityStatusPath = "/integrity/status"
	// debPackageList exists when NOS was installed from the .deb.
	debPackageList = "var/lib/dpkg/info/nebula-operation-station.list"
)

// containerMarkers exist inside a Docker or Podman container.
var containerMarkers = []string{".dockerenv", "run/.containerenv"}

// newIntegrityMonitor returns the server's I1 monitor for the running
// version, checking the installed files under integrityInstallRoot.
func newIntegrityMonitor(log *slog.Logger, version string) *integrity.Monitor {
	return newIntegrityMonitorAt(log, version, integrityInstallRoot)
}

// newIntegrityMonitorAt is newIntegrityMonitor for the installation under
// root.
//
// Reference (ADR 0015 D4 "Reference"): checks run only against the
// installed-files list the executor admitted into its own storage, never
// against the copy in /usr/share. Nothing admits that list yet and the
// server cannot read executor storage (both IG-04), so a release build
// reports every run as incomplete (no-admitted-reference) at ERROR and
// hashes nothing; a development build stays not-checkable. The server
// does not react to either (IG-04). Previously the server re-admitted the
// /usr/share copy against its built-in anchors on every run; that
// deviation from D4 is removed.
//
// The install flavour is detected on every run (Monitor.Flavour), so a
// marker that could not be inspected once does not stick until restart.
func newIntegrityMonitorAt(log *slog.Logger, version, root string) *integrity.Monitor {
	v := strings.TrimPrefix(version, "v")
	return &integrity.Monitor{
		Load: func(context.Context) (integrity.Reference, error) {
			if !release.ValidReleaseVersion(v) {
				return integrity.Reference{}, integrity.ErrDevelopmentBuild
			}
			return integrity.Reference{}, fmt.Errorf("%w: the server cannot read it yet (IG-04)",
				integrity.ErrNoAdmittedReference)
		},
		ReferenceSource: integrity.SourceExecutorAdmitted,
		Options:         integrity.Options{Root: root},
		Flavour:         func(context.Context) (string, error) { return installFlavour(root) },
		Interval:        integrityCheckInterval,
		Log:             log,
	}
}

// installFlavour names the install flavour of the installation under
// root: container, deb or tarball, on this architecture. A marker that
// cannot be inspected is an error, never a guessed flavour.
func installFlavour(root string) (string, error) {
	exists := func(rel string) (bool, error) {
		_, err := os.Lstat(filepath.Join(root, rel))
		switch {
		case err == nil:
			return true, nil
		case errors.Is(err, fs.ErrNotExist):
			return false, nil
		default:
			return false, fmt.Errorf("inspect flavour marker %s: %w", rel, err)
		}
	}
	for _, m := range containerMarkers {
		found, err := exists(m)
		if err != nil {
			return "", err
		}
		if found {
			return "container:" + runtime.GOARCH, nil
		}
	}
	found, err := exists(debPackageList)
	switch {
	case err != nil:
		return "", err
	case found:
		return "deb:" + runtime.GOARCH, nil
	}
	return "tarball:" + runtime.GOARCH, nil
}

// Labels of the two sources on the status page. The server's own check
// and the executor's status are never presented as each other (decision
// (f) option 3, docs/implementation/integrity-wiring-decisions.md).
const (
	serverSourceLabel   = "server self-check"
	executorSourceLabel = "executor status"
	// integrityExecutorTimeout bounds one read of the executor's status per
	// page view. The page never waits longer for the executor.
	integrityExecutorTimeout = 2 * time.Second
	// integrityTextLimit bounds each text value taken from the executor, in
	// runes, after repairing it to valid UTF-8 and dropping control
	// characters. Executor values are untrusted input (AGENTS.md rule 6).
	integrityTextLimit = 256
	// integrityFindingsLimit bounds how many executor findings are shown.
	integrityFindingsLimit = 50
)

// integrityStatusReader reads the executor's I1 status (read-only).
// A nil reader means the executor is not reachable from this process.
type integrityStatusReader func(ctx context.Context, in *pb.GetIntegrityStatusRequest) (*pb.GetIntegrityStatusResponse, error)

// lazyIntegrityStatus reads the status through the lazily connected
// executor client. Before the connection exists the read fails with
// errNotConnected.
func lazyIntegrityStatus(l *lazyExecutor) integrityStatusReader {
	return func(ctx context.Context, in *pb.GetIntegrityStatusRequest) (*pb.GetIntegrityStatusResponse, error) {
		c := l.c.Load()
		if c == nil {
			return nil, errNotConnected
		}
		return c.GetIntegrityStatus(ctx, in)
	}
}

// integrityStatusPage renders /integrity/status: the server's own check
// and the executor's status in separate blocks.
type integrityStatusPage struct {
	monitor *integrity.Monitor
	read    integrityStatusReader
	now     func() time.Time
}

// integrityStatusJSON is the JSON form. The server's check keeps its
// fields at the top level (as before the executor status was added) and
// is labelled by Source; the executor's status sits under Executor.
type integrityStatusJSON struct {
	Source string `json:"source"`
	integrity.SelfCheck
	Executor executorView `json:"executor"`
}

// executorView is the executor's status as text, ready to render. Every
// value came from the executor and is clipped (integrityTextLimit).
// Available is false when the executor could not be asked; the other
// fields are then empty and Checked is the time of the failed attempt.
type executorView struct {
	Source          string        `json:"source"`
	Available       bool          `json:"available"`
	Checked         string        `json:"checked"`
	Configured      bool          `json:"configured"`
	Running         bool          `json:"running"`
	TotalRuns       uint64        `json:"total_runs"`
	Locked          bool          `json:"locked"`
	LockedSince     string        `json:"locked_since,omitempty"`
	LastRun         *runView      `json:"last_run,omitempty"`
	Findings        []findingView `json:"findings,omitempty"`
	FindingsOmitted int           `json:"findings_omitted,omitempty"`
	Note            string        `json:"note,omitempty"`
}

// runView is the executor's latest integrity run as text.
type runView struct {
	Started           string `json:"started,omitempty"`
	Finished          string `json:"finished,omitempty"`
	Complete          bool   `json:"complete"`
	Incomplete        string `json:"incomplete,omitempty"`
	ReleaseVersion    string `json:"release_version,omitempty"`
	Files             int32  `json:"files"`
	Different         int32  `json:"different"`
	Missing           int32  `json:"missing"`
	Extra             int32  `json:"extra"`
	Unreadable        int32  `json:"unreadable"`
	Locking           int32  `json:"locking"`
	DeviationsOmitted int32  `json:"deviations_omitted,omitempty"`
}

// findingView is one executor finding as text.
type findingView struct {
	ID        string `json:"id"`
	Cause     string `json:"cause,omitempty"`
	Path      string `json:"path,omitempty"`
	Class     string `json:"class,omitempty"`
	Status    string `json:"status,omitempty"`
	Reason    string `json:"reason,omitempty"`
	FirstSeen string `json:"first_seen,omitempty"`
	LastSeen  string `json:"last_seen,omitempty"`
	Count     int32  `json:"count"`
}

// mountIntegrityStatus serves the status page for the monitor m, reading
// the executor's status through read.
func mountIntegrityStatus(mux *http.ServeMux, m *integrity.Monitor, read integrityStatusReader) {
	p := integrityStatusPage{monitor: m, read: read, now: time.Now}
	mux.HandleFunc("GET "+integrityStatusPath, p.serve)
}

// serve answers with HTML for a browser (Accept: text/html) and JSON
// otherwise. Both carry the two sources separately.
func (p integrityStatusPage) serve(w http.ResponseWriter, r *http.Request) {
	server := p.monitor.Status()
	exec := p.executor(r.Context())
	w.Header().Set("Cache-Control", "no-store")
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		var buf bytes.Buffer
		data := integrityPageData{Server: server, ServerChecked: stampTime(server.Checked), Executor: exec}
		if err := integrityPageTmpl.Execute(&buf, data); err != nil {
			http.Error(w, "integrity status unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(buf.Bytes())
		return
	}
	b, err := json.Marshal(integrityStatusJSON{Source: serverSourceLabel, SelfCheck: server, Executor: exec})
	if err != nil {
		http.Error(w, "integrity status unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}

// executor reads the executor's status once, bounded by
// integrityExecutorTimeout. Any error, a missing reader or an empty reply
// gives the unavailable view; the last good value is never reused.
func (p integrityStatusPage) executor(ctx context.Context) executorView {
	checked := p.now().UTC()
	unavailable := executorView{Source: executorSourceLabel, Checked: stampTime(checked)}
	if p.read == nil {
		return unavailable
	}
	ctx, cancel := context.WithTimeout(ctx, integrityExecutorTimeout)
	defer cancel()
	resp, err := p.read(ctx, &pb.GetIntegrityStatusRequest{})
	if err != nil || resp == nil {
		return unavailable
	}
	return executorViewOf(resp, checked)
}

// executorViewOf turns the executor's reply into text, clipped and
// limited as described on executorView.
func executorViewOf(r *pb.GetIntegrityStatusResponse, checked time.Time) executorView {
	v := executorView{
		Source:      executorSourceLabel,
		Available:   true,
		Checked:     stampTime(checked),
		Configured:  r.GetConfigured(),
		Running:     r.GetRunning(),
		TotalRuns:   r.GetTotalRuns(),
		Locked:      r.GetLocked(),
		LockedSince: stampUnix(r.GetLockedSinceUnix()),
		Note:        clipText(r.GetNote()),
	}
	if lr := r.GetLastRun(); lr != nil {
		v.LastRun = &runView{
			Started:           stampUnix(lr.GetStartedUnix()),
			Finished:          stampUnix(lr.GetFinishedUnix()),
			Complete:          lr.GetComplete(),
			Incomplete:        clipText(lr.GetIncomplete()),
			ReleaseVersion:    clipText(lr.GetReleaseVersion()),
			Files:             lr.GetFiles(),
			Different:         lr.GetDifferent(),
			Missing:           lr.GetMissing(),
			Extra:             lr.GetExtra(),
			Unreadable:        lr.GetUnreadable(),
			Locking:           lr.GetLocking(),
			DeviationsOmitted: lr.GetDeviationsOmitted(),
		}
	}
	findings := r.GetFindings()
	for i, f := range findings {
		if i == integrityFindingsLimit {
			v.FindingsOmitted = len(findings) - i
			break
		}
		v.Findings = append(v.Findings, findingView{
			ID:        clipText(f.GetId()),
			Cause:     clipText(f.GetCause()),
			Path:      clipText(f.GetPath()),
			Class:     clipText(f.GetClass()),
			Status:    clipText(f.GetStatus()),
			Reason:    clipText(f.GetReason()),
			FirstSeen: stampUnix(f.GetFirstSeenUnix()),
			LastSeen:  stampUnix(f.GetLastSeenUnix()),
			Count:     f.GetCount(),
		})
	}
	return v
}

// clipText repairs s to valid UTF-8, replaces control characters by spaces
// and cuts it to integrityTextLimit runes, marking a cut with "…".
func clipText(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, strings.ToValidUTF8(s, "�"))
	n := 0
	for i := range s {
		if n == integrityTextLimit {
			return s[:i] + "…"
		}
		n++
	}
	return s
}

// stampTime formats t in UTC (RFC 3339); the zero time is empty.
func stampTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// stampUnix formats a Unix time in UTC; zero or negative is empty.
func stampUnix(sec int64) string {
	if sec <= 0 {
		return ""
	}
	return stampTime(time.Unix(sec, 0))
}

// integrityPageData is the data of integrityPageTmpl.
type integrityPageData struct {
	Server        integrity.SelfCheck
	ServerChecked string
	Executor      executorView
}

// integrityPageTmpl renders the page. html/template escapes every value,
// so executor text is shown as text.
var integrityPageTmpl = template.Must(template.New("integrity").Parse(`<!doctype html>
<html lang="de">
<head><meta charset="utf-8"><title>Integritätsstatus</title></head>
<body>
<h1>Integritätsstatus</h1>
<section id="server-self-check">
<h2>Server-Selbstprüfung</h2>
<p>Quelle: Selbstprüfung von nebula-server. Keine Aussage des Executors.</p>
<dl>
<dt>Zustand</dt><dd>{{.Server.State}}</dd>
{{- if .Server.Cause}}
<dt>Ursache</dt><dd>{{.Server.Cause}}</dd>
{{- end}}
{{- if .ServerChecked}}
<dt>Letzte Prüfung</dt><dd>{{.ServerChecked}}</dd>
{{- end}}
<dt>Prüfungen seit Start</dt><dd>{{.Server.Runs}}</dd>
</dl>
{{- if .Server.Note}}
<p>{{.Server.Note}}</p>
{{- end}}
</section>
<section id="executor-status">
<h2>Executor-Status</h2>
<p>Quelle: nebula-executor (GetIntegrityStatus). Keine Aussage des Servers.</p>
{{- if not .Executor.Available}}
<p><strong>nicht verfügbar</strong>, Abfrage am {{.Executor.Checked}}</p>
{{- else}}
<dl>
<dt>Stand der Abfrage</dt><dd>{{.Executor.Checked}}</dd>
<dt>Periodische Prüfung eingerichtet</dt><dd>{{.Executor.Configured}}</dd>
<dt>Periodische Prüfung läuft</dt><dd>{{.Executor.Running}}</dd>
<dt>Läufe gesamt</dt><dd>{{.Executor.TotalRuns}}</dd>
<dt>Sperre</dt><dd>{{if .Executor.Locked}}gesperrt seit {{.Executor.LockedSince}}{{else}}nicht gesperrt{{end}}</dd>
</dl>
{{- with .Executor.LastRun}}
<h3>Letzter Lauf</h3>
<dl>
<dt>Begonnen</dt><dd>{{.Started}}</dd>
<dt>Beendet</dt><dd>{{.Finished}}</dd>
<dt>Vollständig</dt><dd>{{.Complete}}</dd>
{{- if .Incomplete}}
<dt>Unvollständig</dt><dd>{{.Incomplete}}</dd>
{{- end}}
{{- if .ReleaseVersion}}
<dt>Release</dt><dd>{{.ReleaseVersion}}</dd>
{{- end}}
<dt>Dateien</dt><dd>{{.Files}}</dd>
<dt>Abweichend</dt><dd>{{.Different}}</dd>
<dt>Fehlend</dt><dd>{{.Missing}}</dd>
<dt>Zusätzlich</dt><dd>{{.Extra}}</dd>
<dt>Nicht lesbar</dt><dd>{{.Unreadable}}</dd>
<dt>Sperrend</dt><dd>{{.Locking}}</dd>
</dl>
{{- end}}
{{- if .Executor.Note}}
<p>{{.Executor.Note}}</p>
{{- end}}
{{- if .Executor.Findings}}
<h3>Befunde</h3>
<ul>
{{- range .Executor.Findings}}
<li>{{.ID}} {{.Class}} {{.Path}} {{.Status}} {{.Reason}} (seit {{.FirstSeen}}, {{.Count}}×)</li>
{{- end}}
</ul>
{{- end}}
{{- if .Executor.FindingsOmitted}}
<p>{{.Executor.FindingsOmitted}} weitere Befunde nicht angezeigt.</p>
{{- end}}
{{- end}}
</section>
</body>
</html>
`))
