// SPDX-License-Identifier: AGPL-3.0-or-later

// Package software serves the admin pages of the software catalog and
// its icons (ADR 0009 D5, D6; ticket TM17):
//
//   - GET /software: the catalog list (key, display name, state, icon,
//     host count), filterable by state;
//   - GET /software/unknown: the "Unknown software" queue with rename,
//     merge and ignore;
//   - GET /software/icon/{key}: the icon page of a catalog key (upload,
//     fetch from an allowlisted URL, crawler candidates, history with
//     rollback);
//   - GET /software/assets/icon?id=<asset>: the per-asset icon override
//     (upload, history with rollback).
//
// Icon changes are possible at any time and in any state of an entry
// (only a merged entry defers to its merge target); every change goes
// through internal/web/ui/icons, which sanitizes, stores and audits it,
// and every change can be rolled back from the history.
//
// The browser never loads an external image: every <img> this package
// renders points at /icons/<sha256>.png, built here from a validated
// hash. Source and candidate URLs never reach the page as a URL; the
// pages name the source host (and a candidate's file name) as text
// only. Candidates are picked by their ID; the server looks the URL up
// again and re-validates it before it queues a fetch.
//
// State changes are POST requests submitted with fetch (formpost.js for
// the url-encoded forms, software.js for the raw image upload), so the
// security middleware sees the real Origin. Pages use html/template only
// and carry no inline script or style (strict CSP).
package software

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/iconfetch"
	"github.com/nebula-operation-station/nebula-operation-station/internal/iconstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/softwarecat"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui/icons"
	"github.com/nebula-operation-station/nebula-operation-station/web/templates"
)

// Limits, next to the code that enforces them.
const (
	// MaxListRows bounds the rows of one catalog list page.
	MaxListRows = 2000
	// MaxCandidates bounds the crawler candidates shown for one key.
	MaxCandidates = 20
	// historyPage bounds the icon history rows shown on an icon page.
	historyPage = 50
	// queuePage bounds the unknown-queue rows shown. It is one less than
	// softwarecat.MaxQueuePage, the most the store returns, so the page
	// reads queuePage+1 rows and only claims a cut-off when that extra
	// row exists.
	queuePage = softwarecat.MaxQueuePage - 1
	// maxFormBytes bounds a url-encoded form body.
	maxFormBytes = 16 << 10
	// maxCandidateIDLen bounds a candidate ID.
	maxCandidateIDLen = 64
	// maxCandidateSourceLen bounds the crawler name shown for a
	// candidate.
	maxCandidateSourceLen = 64
	// maxFileNameLen bounds the candidate file name shown as text.
	maxFileNameLen = 80
	// callTimeout bounds the store and service calls of one request.
	callTimeout = 10 * time.Second
)

// Catalog is the part of the software catalog store the pages use.
// *softwarecat.Store satisfies it.
type Catalog interface {
	Entry(ctx context.Context, key softwarecat.Key) (softwarecat.Entry, error)
	UnknownQueue(ctx context.Context, limit int) ([]softwarecat.QueueEntry, error)
	Rename(ctx context.Context, actor string, key softwarecat.Key, display string) error
	Merge(ctx context.Context, actor string, from, into softwarecat.Key) error
	Ignore(ctx context.Context, actor string, key softwarecat.Key) error
	Icon(ctx context.Context, sha string) (softwarecat.Icon, error)
	IconHistory(ctx context.Context, subject softwarecat.IconSubject, limit int) ([]softwarecat.IconChange, error)
	AssetIcon(ctx context.Context, assetID string) (string, error)
}

// IconService changes icons. *icons.Service satisfies it.
type IconService interface {
	QueueFetch(ctx context.Context, actor, key, rawURL string) (string, error)
	Upload(ctx context.Context, actor string, subject softwarecat.IconSubject, data []byte) (string, error)
	Rollback(ctx context.Context, actor string, subject softwarecat.IconSubject, changeID int64) error
}

// Candidate is an icon source a crawler proposes for a catalog key. It
// is untrusted: the URL is re-validated against the icon URL policy
// before it is shown (as host and file name text only) or fetched.
type Candidate struct {
	// ID identifies the candidate within its key ([a-z0-9._-], at most
	// 64 bytes).
	ID string
	// URL is the proposed image URL. It is never rendered.
	URL string
	// Source names the crawler or index that proposed it.
	Source string
	// FoundAt is when the crawler found it.
	FoundAt time.Time
}

// Candidates lists crawler candidates for a catalog key. A crawler only
// proposes; an admin confirms on the icon page.
type Candidates interface {
	Candidates(ctx context.Context, key softwarecat.Key) ([]Candidate, error)
}

// Row is one row of the catalog list.
type Row struct {
	Key          softwarecat.Key
	Display      string
	State        softwarecat.State
	MergedInto   softwarecat.Key // "" unless merged
	IconSHA      string          // "" for the generic symbol
	Hosts        int             // distinct managed hosts, merged keys included
	Observations int             // observations, merged keys included
}

// ListFunc returns up to limit catalog rows ordered by key, and whether
// more rows exist.
type ListFunc func(ctx context.Context, limit int) ([]Row, bool, error)

// Chrome is the per-request data of the shared page layout.
type Chrome struct {
	// Theme is "system", "light" or "dark".
	Theme string
	// NavCollapsed, PVENav and DeployEnabled drive the navigation.
	NavCollapsed  bool
	PVENav        bool
	DeployEnabled bool
}

// Options configure a Handler.
type Options struct {
	// Catalog is the software catalog store. Required.
	Catalog Catalog
	// List lists the catalog. Required; SQLList(db) reads the server
	// database.
	List ListFunc
	// Icons changes icons. Nil leaves the icon pages read-only: no
	// forms, and the icon change routes answer 404.
	Icons IconService
	// Candidates lists crawler candidates. Nil shows "no crawler".
	Candidates Candidates
	// Allow is the icon host allowlist shown on the icon page; empty
	// means iconfetch.DefaultAllowlist(). Enforcement is the icon
	// service's; this list is for display and candidate filtering.
	Allow []string
	// Actor returns the signed-in admin; nil uses the web session.
	Actor func(r *http.Request) (string, bool)
	// Chrome returns the layout data; nil uses the defaults.
	Chrome func(r *http.Request) Chrome
	// Log receives errors and audit events; nil discards them.
	Log *slog.Logger
}

// Handler serves the software catalog pages.
type Handler struct {
	catalog    Catalog
	list       ListFunc
	icons      IconService
	candidates Candidates
	allow      []string
	actor      func(r *http.Request) (string, bool)
	chrome     func(r *http.Request) Chrome
	log        *slog.Logger
	pages      map[string]*template.Template
}

// pageFiles maps a page name to its template file (with layout.html).
var pageFiles = map[string]string{
	"catalog": "software.html",
	"unknown": "software_unknown.html",
	"icon":    "software_icon.html",
}

// New parses the templates and returns a Handler.
func New(o Options) (*Handler, error) {
	if o.Catalog == nil || o.List == nil {
		return nil, errors.New("software: catalog and list are required")
	}
	h := &Handler{catalog: o.Catalog, list: o.List, icons: o.Icons, candidates: o.Candidates,
		allow: append([]string(nil), o.Allow...), actor: o.Actor, chrome: o.Chrome, log: o.Log,
		pages: make(map[string]*template.Template, len(pageFiles))}
	if len(h.allow) == 0 {
		h.allow = iconfetch.DefaultAllowlist()
	}
	if h.actor == nil {
		h.actor = sessionActor
	}
	if h.chrome == nil {
		h.chrome = func(*http.Request) Chrome { return Chrome{Theme: "system"} }
	}
	if h.log == nil {
		h.log = slog.New(slog.DiscardHandler)
	}
	funcs := template.FuncMap{"when": formatTime, "iso": isoTime}
	for name, file := range pageFiles {
		t, err := template.New("").Funcs(funcs).ParseFS(templates.FS, "layout.html", file)
		if err != nil {
			return nil, fmt.Errorf("software: parse template %s: %w", file, err)
		}
		h.pages[name] = t
	}
	return h, nil
}

// sessionActor returns the user name of the web session.
func sessionActor(r *http.Request) (string, bool) {
	s, ok := auth.SessionFrom(r.Context())
	if !ok || s.UserName == "" {
		return "", false
	}
	return s.UserName, true
}

// Handler returns the routes. Authentication and the Origin check are
// the job of the surrounding chain (internal/web/auth, middleware).
func (h *Handler) Handler() http.Handler {
	mux := http.NewServeMux()
	h.Register(mux)
	return mux
}

// Register adds the routes to mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /software", h.handleCatalog)
	mux.HandleFunc("GET /software/unknown", h.handleUnknown)
	mux.HandleFunc("GET /software/icon/{key}", h.handleIconPage)
	mux.HandleFunc("GET /software/assets/icon", h.handleAssetIconPage)
	// Other methods on these paths answer 405 (the mux) or, under
	// /software/icon/, reach the GET icon page of that name.
	mux.HandleFunc("POST /software/rename", h.post(h.handleRename))
	mux.HandleFunc("POST /software/merge", h.post(h.handleMerge))
	mux.HandleFunc("POST /software/ignore", h.post(h.handleIgnore))
	mux.HandleFunc("POST /software/icon/fetch", h.post(h.handleFetch))
	mux.HandleFunc("POST /software/icon/candidate", h.post(h.handleCandidate))
	mux.HandleFunc("POST /software/icon/rollback", h.post(h.handleRollback))
	mux.HandleFunc("POST /software/icon/upload", h.handleUpload)
}

// --- views ---------------------------------------------------------------

// page is the data of the layout template (web/templates/layout.html)
// plus the data of this package's pages.
type page struct {
	Title         string
	Active        string
	Theme         string
	NavCollapsed  bool
	Bare          bool
	PVENav        bool
	DeployEnabled bool
	Search        any // the layout's search box state; none here
	BuiltinTrust  any // the layout's trust banner; none here
	Scripts       []string

	// Notice is a fixed confirmation text chosen by a ?done= code.
	Notice  string
	Catalog *catalogView
	Unknown *unknownView
	Icon    *iconView
}

type catalogView struct {
	Rows      []catalogRow
	Filter    string
	Filters   []filterLink
	Truncated bool
	// Unknown counts rows in state observed (unmerged), for the queue
	// link. When Truncated it only covers the rows read, so it is a
	// lower bound and the filtered view may miss matching entries.
	Unknown int
}

type filterLink struct {
	Label, Href string
	Active      bool
}

type catalogRow struct {
	Key          string
	Display      string
	State        string
	MergedInto   string
	IconSrc      string
	Hosts        int
	Observations int
}

type unknownView struct {
	Rows []unknownRow
	Full bool // more entries exist than the page shows
}

type unknownRow struct {
	Key          string
	Display      string
	IconSrc      string
	Hosts        int
	Observations int
	LastSeen     time.Time
	FirstHost    string
}

type iconView struct {
	Kind        string // "catalog" or "asset"
	ID          string
	Display     string
	State       string
	MergedInto  string
	Current     string // /icons/ path of the current icon, "" = generic
	CurrentFrom string // "upload" or "fetched from <host>", text only
	CurrentBy   string
	CurrentAt   time.Time
	Editable    bool
	UploadPath  string
	Allow       []string
	History     []historyRow
	HistoryErr  bool
	HistoryMore bool // older changes exist beyond the rows shown

	CandidatesOn  bool
	CandidatesErr bool
	Candidates    []candidateRow
}

type historyRow struct {
	ID           int64
	Src          string
	PrevSrc      string
	RollbackOf   int64
	AssetDeleted bool
	By           string
	At           time.Time
	CanRollback  bool
	Newest       bool
}

type candidateRow struct {
	ID     string
	Host   string
	File   string
	Source string
	Found  time.Time
}

// notices are the fixed confirmation texts of ?done= codes; any other
// value shows nothing (the query string is never reflected).
var notices = map[string]string{
	"renamed":    "Renamed. The entry is now known.",
	"merged":     "Merged.",
	"ignored":    "Ignored.",
	"uploaded":   "Icon uploaded and set.",
	"queued":     "Fetch queued. The icon is set once the icon fetcher has run.",
	"rolledback": "Icon rolled back.",
}

func (h *Handler) newPage(r *http.Request, title string, scripts ...string) *page {
	c := h.chrome(r)
	theme := c.Theme
	if theme != "light" && theme != "dark" {
		theme = "system"
	}
	return &page{Title: title, Active: "software", Theme: theme, NavCollapsed: c.NavCollapsed,
		PVENav: c.PVENav, DeployEnabled: c.DeployEnabled, Scripts: scripts,
		Notice: notices[r.URL.Query().Get("done")]}
}

func (h *Handler) render(w http.ResponseWriter, r *http.Request, name string, p *page) {
	var b strings.Builder
	if err := h.pages[name].ExecuteTemplate(&b, "layout", p); err != nil {
		h.log.ErrorContext(r.Context(), "render software page", "page", name, "error", err.Error())
		http.Error(w, "Internal error.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, b.String())
}

// iconSrc returns the /icons/ path of sha, or "" (generic symbol) when
// sha is not a lowercase hex SHA-256. It is the only way an image path
// is built in this package.
func iconSrc(sha string) string {
	if len(sha) != 64 {
		return ""
	}
	for i := 0; i < len(sha); i++ {
		if c := sha[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return ""
		}
	}
	return icons.PathPrefix + sha + ".png"
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.UTC().Format("2006-01-02 15:04 UTC")
}

// isoTime is the machine-readable form for a datetime attribute.
func isoTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// --- pages ---------------------------------------------------------------

// stateFilters are the catalog list filters.
var stateFilters = []struct{ value, label string }{
	{"", "All"},
	{string(softwarecat.StateKnown), "Known"},
	{string(softwarecat.StateObserved), "Observed"},
	{string(softwarecat.StateIgnored), "Ignored"},
	{"merged", "Merged"},
}

func (h *Handler) handleCatalog(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("state")
	valid := false
	for _, f := range stateFilters {
		valid = valid || f.value == filter
	}
	if !valid {
		http.Error(w, "Unknown state filter.", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), callTimeout)
	defer cancel()
	rows, truncated, err := h.list(ctx, MaxListRows)
	if err != nil {
		h.log.ErrorContext(ctx, "list software catalog", "error", err.Error())
		http.Error(w, "Catalog unavailable.", http.StatusInternalServerError)
		return
	}
	v := &catalogView{Filter: filter, Truncated: truncated}
	for _, f := range stateFilters {
		href := "/software"
		if f.value != "" {
			href += "?state=" + f.value
		}
		v.Filters = append(v.Filters, filterLink{Label: f.label, Href: href, Active: f.value == filter})
	}
	for _, row := range rows {
		if _, err := softwarecat.NewKey(string(row.Key)); err != nil {
			continue
		}
		if row.MergedInto == "" && row.State == softwarecat.StateObserved {
			v.Unknown++
		}
		if !matchesFilter(row, filter) {
			continue
		}
		v.Rows = append(v.Rows, catalogRow{Key: string(row.Key), Display: row.Display, State: string(row.State),
			MergedInto: string(row.MergedInto), IconSrc: iconSrc(row.IconSHA), Hosts: row.Hosts, Observations: row.Observations})
	}
	p := h.newPage(r, "Software catalog")
	p.Catalog = v
	h.render(w, r, "catalog", p)
}

func matchesFilter(row Row, filter string) bool {
	switch filter {
	case "":
		return true
	case "merged":
		return row.MergedInto != ""
	default:
		return row.MergedInto == "" && string(row.State) == filter
	}
}

func (h *Handler) handleUnknown(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), callTimeout)
	defer cancel()
	// Read one row more than shown to tell whether more entries exist.
	q, err := h.catalog.UnknownQueue(ctx, queuePage+1)
	if err != nil {
		h.log.ErrorContext(ctx, "read unknown software queue", "error", err.Error())
		http.Error(w, "Queue unavailable.", http.StatusInternalServerError)
		return
	}
	v := &unknownView{}
	if len(q) > queuePage {
		q, v.Full = q[:queuePage], true
	}
	for _, e := range q {
		v.Rows = append(v.Rows, unknownRow{Key: string(e.Key), Display: e.Display, IconSrc: iconSrc(e.IconSHA),
			Hosts: e.Hosts, Observations: e.Observations, LastSeen: e.LastSeen, FirstHost: e.FirstHost})
	}
	p := h.newPage(r, "Unknown software", "formpost.js", "software.js")
	p.Unknown = v
	h.render(w, r, "unknown", p)
}

func (h *Handler) handleIconPage(w http.ResponseWriter, r *http.Request) {
	key, err := softwarecat.NewKey(r.PathValue("key"))
	if err != nil {
		http.Error(w, "Invalid catalog key.", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), callTimeout)
	defer cancel()
	e, err := h.catalog.Entry(ctx, key)
	if err != nil {
		h.fail(w, r, "read catalog entry", err)
		return
	}
	v := &iconView{Kind: string(softwarecat.SubjectCatalog), ID: string(key), Display: e.Display,
		State: string(e.State), MergedInto: string(e.MergedInto), Allow: h.allow}
	v.Editable = h.icons != nil && e.MergedInto == ""
	h.fillIcon(ctx, v, e.IconSHA)
	if v.Editable {
		h.fillCandidates(ctx, v, key)
	}
	title := "Icon of " + string(key)
	p := h.newPage(r, title, "formpost.js", "software.js")
	p.Icon = v
	h.render(w, r, "icon", p)
}

func (h *Handler) handleAssetIconPage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	subject, ok := formSubject(string(softwarecat.SubjectAsset), q.Get("id"))
	if !ok || len(q["id"]) != 1 {
		http.Error(w, "Invalid asset ID.", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), callTimeout)
	defer cancel()
	sha, err := h.catalog.AssetIcon(ctx, subject.ID)
	if err != nil {
		h.fail(w, r, "read asset icon", err)
		return
	}
	v := &iconView{Kind: string(subject.Kind), ID: subject.ID, Editable: h.icons != nil}
	h.fillIcon(ctx, v, sha)
	p := h.newPage(r, "Icon override of asset "+subject.ID, "formpost.js", "software.js")
	p.Icon = v
	h.render(w, r, "icon", p)
}

// fillIcon fills the current icon, its source (as text) and the history.
func (h *Handler) fillIcon(ctx context.Context, v *iconView, sha string) {
	subject := softwarecat.IconSubject{Kind: softwarecat.SubjectKind(v.Kind), ID: v.ID}
	v.UploadPath = "/software/icon/upload?kind=" + v.Kind + "&id=" + url.QueryEscape(v.ID)
	v.Current = iconSrc(sha)
	if v.Current != "" {
		if ic, err := h.catalog.Icon(ctx, sha); err == nil {
			v.CurrentFrom = sourceText(ic)
			v.CurrentBy, v.CurrentAt = ic.AddedBy, ic.AddedAt
		}
	}
	// Read one row more than shown to tell whether older changes exist.
	hist, err := h.catalog.IconHistory(ctx, subject, historyPage+1)
	if err != nil {
		h.log.ErrorContext(ctx, "read icon history", "subject_kind", v.Kind, "subject", v.ID, "error", err.Error())
		v.HistoryErr = true
		return
	}
	if len(hist) > historyPage {
		hist, v.HistoryMore = hist[:historyPage], true
	}
	// Changes at or before an asset deletion belong to the deleted asset
	// and cannot be rolled back (history is newest first).
	deleted := false
	for i, c := range hist {
		deleted = deleted || c.AssetDeleted
		v.History = append(v.History, historyRow{ID: c.ID, Src: iconSrc(c.SHA), PrevSrc: iconSrc(c.PrevSHA),
			RollbackOf: c.RollbackOf, AssetDeleted: c.AssetDeleted, By: c.ChangedBy, At: c.ChangedAt,
			CanRollback: v.Editable && !deleted, Newest: i == 0})
	}
}

// sourceText describes where an icon came from without its URL: the
// source host is enough to judge it, and the URL must never be rendered.
func sourceText(ic softwarecat.Icon) string {
	switch ic.Kind {
	case softwarecat.IconUpload:
		return "uploaded"
	case softwarecat.IconURL:
		if u, err := url.Parse(ic.SourceURL); err == nil && u.Hostname() != "" {
			return "fetched from " + u.Hostname()
		}
		return "fetched"
	}
	return ""
}

// fillCandidates lists the crawler's candidates for key that pass the
// icon URL policy, as host and file name text.
func (h *Handler) fillCandidates(ctx context.Context, v *iconView, key softwarecat.Key) {
	if h.candidates == nil {
		return
	}
	v.CandidatesOn = true
	cs, err := h.candidates.Candidates(ctx, key)
	if err != nil {
		h.log.ErrorContext(ctx, "list icon candidates", "key", string(key), "error", err.Error())
		v.CandidatesErr = true
		return
	}
	for _, c := range cs {
		if len(v.Candidates) == MaxCandidates {
			break
		}
		u, ok := h.validCandidate(c)
		if !ok {
			continue
		}
		v.Candidates = append(v.Candidates, candidateRow{ID: c.ID, Host: u.Hostname(),
			File: clip(path.Base(u.Path), maxFileNameLen), Source: clip(c.Source, maxCandidateSourceLen), Found: c.FoundAt})
	}
}

// validCandidate checks a candidate's ID and URL (iconfetch policy).
func (h *Handler) validCandidate(c Candidate) (*url.URL, bool) {
	if !validCandidateID(c.ID) {
		return nil, false
	}
	u, err := iconfetch.ValidateURL(c.URL, h.allow)
	if err != nil {
		return nil, false
	}
	return u, true
}

func validCandidateID(id string) bool {
	if id == "" || len(id) > maxCandidateIDLen {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '.' && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

// clip returns printable text of at most limit bytes; anything else is
// replaced (the result is rendered as text, escaped by html/template).
func clip(s string, limit int) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r == '�' || (r >= 0x80 && r < 0xa0) {
			r = '?'
		}
		if b.Len()+len(string(r)) > limit {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// --- changes -------------------------------------------------------------

// post wraps a url-encoded form handler (POST routes): form content type,
// bounded body, single-valued fields, a signed-in actor.
func (h *Handler) post(fn func(w http.ResponseWriter, r *http.Request, actor string, form url.Values)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/x-www-form-urlencoded" {
			http.Error(w, "Content-Type must be application/x-www-form-urlencoded.", http.StatusUnsupportedMediaType)
			return
		}
		actor, ok := h.actor(r)
		if !ok {
			http.Error(w, "Not signed in.", http.StatusForbidden)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxFormBytes))
		if err != nil {
			var mbe *http.MaxBytesError
			if errors.As(err, &mbe) {
				http.Error(w, "Request too large.", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "Bad request.", http.StatusBadRequest)
			return
		}
		form, err := url.ParseQuery(string(body))
		if err != nil {
			http.Error(w, "Malformed form.", http.StatusBadRequest)
			return
		}
		for _, vs := range form {
			if len(vs) != 1 {
				http.Error(w, "Every field must appear once.", http.StatusBadRequest)
				return
			}
		}
		fn(w, r, actor, form)
	}
}

func formKey(form url.Values, field string) (softwarecat.Key, bool) {
	k, err := softwarecat.NewKey(form.Get(field))
	return k, err == nil
}

func (h *Handler) handleRename(w http.ResponseWriter, r *http.Request, actor string, form url.Values) {
	key, ok := formKey(form, "key")
	if !ok {
		http.Error(w, "Invalid catalog key.", http.StatusBadRequest)
		return
	}
	display := strings.TrimSpace(form.Get("display"))
	if display == "" {
		http.Error(w, "The display name must not be empty.", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), callTimeout)
	defer cancel()
	if err := h.catalog.Rename(ctx, actor, key, display); err != nil {
		h.fail(w, r, "rename catalog entry", err)
		return
	}
	h.audit(ctx, "software_renamed", actor, "key", string(key))
	http.Redirect(w, r, "/software/unknown?done=renamed", http.StatusSeeOther)
}

func (h *Handler) handleMerge(w http.ResponseWriter, r *http.Request, actor string, form url.Values) {
	from, ok1 := formKey(form, "key")
	into, ok2 := formKey(form, "into")
	if !ok1 || !ok2 {
		http.Error(w, "Invalid catalog key.", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), callTimeout)
	defer cancel()
	if err := h.catalog.Merge(ctx, actor, from, into); err != nil {
		h.fail(w, r, "merge catalog entry", err)
		return
	}
	h.audit(ctx, "software_merged", actor, "key", string(from), "into", string(into))
	http.Redirect(w, r, "/software/unknown?done=merged", http.StatusSeeOther)
}

func (h *Handler) handleIgnore(w http.ResponseWriter, r *http.Request, actor string, form url.Values) {
	key, ok := formKey(form, "key")
	if !ok {
		http.Error(w, "Invalid catalog key.", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), callTimeout)
	defer cancel()
	if err := h.catalog.Ignore(ctx, actor, key); err != nil {
		h.fail(w, r, "ignore catalog entry", err)
		return
	}
	h.audit(ctx, "software_ignored", actor, "key", string(key))
	http.Redirect(w, r, "/software/unknown?done=ignored", http.StatusSeeOther)
}

// editableKey checks that key names an existing, unmerged entry, so a
// change to a merged key is a conflict, not a silent no-op.
func (h *Handler) editableKey(ctx context.Context, key softwarecat.Key) error {
	e, err := h.catalog.Entry(ctx, key)
	if err != nil {
		return err
	}
	if e.MergedInto != "" {
		return fmt.Errorf("catalog entry %s: %w", key, softwarecat.ErrMerged)
	}
	return nil
}

func (h *Handler) handleFetch(w http.ResponseWriter, r *http.Request, actor string, form url.Values) {
	if h.icons == nil {
		http.NotFound(w, r)
		return
	}
	key, ok := formKey(form, "key")
	if !ok {
		http.Error(w, "Invalid catalog key.", http.StatusBadRequest)
		return
	}
	raw := strings.TrimSpace(form.Get("url"))
	if raw == "" {
		http.Error(w, "Enter an HTTPS image URL on an allowlisted host.", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), callTimeout)
	defer cancel()
	if err := h.editableKey(ctx, key); err != nil {
		h.fail(w, r, "queue icon fetch", err)
		return
	}
	if _, err := h.icons.QueueFetch(ctx, actor, string(key), raw); err != nil {
		h.fail(w, r, "queue icon fetch", err)
		return
	}
	http.Redirect(w, r, "/software/icon/"+string(key)+"?done=queued", http.StatusSeeOther)
}

func (h *Handler) handleCandidate(w http.ResponseWriter, r *http.Request, actor string, form url.Values) {
	if h.icons == nil || h.candidates == nil {
		http.NotFound(w, r)
		return
	}
	key, ok := formKey(form, "key")
	id := form.Get("candidate")
	if !ok || !validCandidateID(id) {
		http.Error(w, "Invalid catalog key or candidate.", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), callTimeout)
	defer cancel()
	if err := h.editableKey(ctx, key); err != nil {
		h.fail(w, r, "confirm icon candidate", err)
		return
	}
	cs, err := h.candidates.Candidates(ctx, key)
	if err != nil {
		h.log.ErrorContext(ctx, "list icon candidates", "key", string(key), "error", err.Error())
		http.Error(w, "Candidates unavailable.", http.StatusServiceUnavailable)
		return
	}
	for _, c := range cs {
		if c.ID != id {
			continue
		}
		u, ok := h.validCandidate(c)
		if !ok {
			h.audit(ctx, "icon_candidate_rejected", actor, "key", string(key), "candidate", id)
			http.Error(w, "The candidate does not meet the icon URL policy.", http.StatusBadRequest)
			return
		}
		job, err := h.icons.QueueFetch(ctx, actor, string(key), u.String())
		if err != nil {
			h.fail(w, r, "confirm icon candidate", err)
			return
		}
		h.audit(ctx, "icon_candidate_confirmed", actor, "key", string(key), "candidate", id, "job", job)
		http.Redirect(w, r, "/software/icon/"+string(key)+"?done=queued", http.StatusSeeOther)
		return
	}
	http.Error(w, "Not found.", http.StatusNotFound)
}

// formSubject reads the icon subject from kind and id.
func formSubject(kind, id string) (softwarecat.IconSubject, bool) {
	s := softwarecat.IconSubject{Kind: softwarecat.SubjectKind(kind), ID: id}
	switch s.Kind {
	case softwarecat.SubjectCatalog:
		_, err := softwarecat.NewKey(id)
		return s, err == nil
	case softwarecat.SubjectAsset:
		return s, validAssetID(id)
	}
	return s, false
}

// maxAssetIDLen bounds an asset ID (as in the assets table).
const maxAssetIDLen = 63

// validAssetID mirrors the asset ID check of softwarecat (letters,
// digits, '.', ':', '_', '/' and '-'), so a bad ID is refused before
// any image is processed.
func validAssetID(id string) bool {
	if id == "" || len(id) > maxAssetIDLen {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') &&
			c != '.' && c != ':' && c != '_' && c != '/' && c != '-' {
			return false
		}
	}
	return true
}

// subjectPage is the icon page of subject with the confirmation code
// done.
func subjectPage(s softwarecat.IconSubject, done string) string {
	if s.Kind == softwarecat.SubjectAsset {
		return "/software/assets/icon?id=" + url.QueryEscape(s.ID) + "&done=" + done
	}
	return "/software/icon/" + s.ID + "?done=" + done
}

func (h *Handler) handleRollback(w http.ResponseWriter, r *http.Request, actor string, form url.Values) {
	if h.icons == nil {
		http.NotFound(w, r)
		return
	}
	subject, ok := formSubject(form.Get("kind"), form.Get("id"))
	if !ok {
		http.Error(w, "Invalid icon subject.", http.StatusBadRequest)
		return
	}
	change, err := strconv.ParseInt(form.Get("change"), 10, 64)
	if err != nil || change <= 0 {
		http.Error(w, "Invalid change.", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), callTimeout)
	defer cancel()
	if subject.Kind == softwarecat.SubjectCatalog {
		if err := h.editableKey(ctx, softwarecat.Key(subject.ID)); err != nil {
			h.fail(w, r, "roll back icon", err)
			return
		}
	}
	if err := h.icons.Rollback(ctx, actor, subject, change); err != nil {
		h.fail(w, r, "roll back icon", err)
		return
	}
	http.Redirect(w, r, subjectPage(subject, "rolledback"), http.StatusSeeOther)
}

// uploadTypes are the accepted upload content types (ADR 0009 D6: PNG,
// JPEG or GIF; SVG and WebP are rejected). The sanitizer checks the
// bytes; the header check only refuses obvious mistakes early.
var uploadTypes = map[string]bool{"image/png": true, "image/jpeg": true, "image/gif": true}

// handleUpload takes the raw image as the request body (software.js
// posts the file with fetch), with kind and id in the query string.
func (h *Handler) handleUpload(w http.ResponseWriter, r *http.Request) {
	if h.icons == nil {
		http.NotFound(w, r)
		return
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || !uploadTypes[mt] {
		http.Error(w, "Upload a PNG, JPEG or GIF image (SVG and WebP are not supported).", http.StatusUnsupportedMediaType)
		return
	}
	actor, ok := h.actor(r)
	if !ok {
		http.Error(w, "Not signed in.", http.StatusForbidden)
		return
	}
	q := r.URL.Query()
	if len(q["kind"]) != 1 || len(q["id"]) != 1 {
		http.Error(w, "Invalid icon subject.", http.StatusBadRequest)
		return
	}
	subject, ok := formSubject(q.Get("kind"), q.Get("id"))
	if !ok {
		http.Error(w, "Invalid icon subject.", http.StatusBadRequest)
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, iconstore.MaxInputBytes))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			http.Error(w, "The image is larger than 256 KiB.", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "Bad request.", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), callTimeout)
	defer cancel()
	if subject.Kind == softwarecat.SubjectCatalog {
		if err := h.editableKey(ctx, softwarecat.Key(subject.ID)); err != nil {
			h.fail(w, r, "upload icon", err)
			return
		}
	}
	if _, err := h.icons.Upload(ctx, actor, subject, data); err != nil {
		h.fail(w, r, "upload icon", err)
		return
	}
	http.Redirect(w, r, subjectPage(subject, "uploaded"), http.StatusSeeOther)
}

// --- errors --------------------------------------------------------------

// fail answers err with a fixed text (never the error detail, which may
// carry a URL or path) and logs unexpected errors.
func (h *Handler) fail(w http.ResponseWriter, r *http.Request, op string, err error) {
	status, msg := classify(err)
	if status == http.StatusInternalServerError {
		h.log.ErrorContext(r.Context(), op, "error", err.Error())
	}
	http.Error(w, msg, status)
}

func classify(err error) (int, string) {
	switch {
	case errors.Is(err, icons.ErrUnavailable):
		return http.StatusServiceUnavailable, "The icon fetcher is not installed."
	case errors.Is(err, softwarecat.ErrNotFound):
		return http.StatusNotFound, "Not found."
	case errors.Is(err, softwarecat.ErrMerged):
		return http.StatusConflict, "This entry is merged into another one; change that entry instead."
	case errors.Is(err, softwarecat.ErrInvalidMerge):
		return http.StatusBadRequest, "Invalid merge: the target must be another entry that is not merged itself."
	case errors.Is(err, softwarecat.ErrInvalidKey):
		return http.StatusBadRequest, "Invalid catalog key."
	case errors.Is(err, iconstore.ErrTooLarge):
		return http.StatusRequestEntityTooLarge, "The image is larger than 256 KiB."
	case errors.Is(err, iconstore.ErrUnsupportedFormat):
		return http.StatusBadRequest, "Unsupported image: PNG, JPEG or GIF only (SVG and WebP are rejected)."
	case errors.Is(err, iconstore.ErrDimensions):
		return http.StatusBadRequest, "The image must be at most 1024×1024 pixels."
	case errors.Is(err, iconstore.ErrEmpty), errors.Is(err, iconstore.ErrMalformed):
		return http.StatusBadRequest, "The image could not be read."
	case errors.Is(err, iconfetch.ErrURL):
		return http.StatusBadRequest, "URL rejected: use an HTTPS URL on an allowlisted host (port 443, no user info, no IP address)."
	case errors.Is(err, softwarecat.ErrInvalidInput):
		return http.StatusBadRequest, "Invalid input."
	case errors.Is(err, icons.ErrRejected):
		return http.StatusBadRequest, "Rejected."
	}
	return http.StatusInternalServerError, "Internal error."
}

func (h *Handler) audit(ctx context.Context, kind, actor string, attrs ...any) {
	h.log.InfoContext(ctx, "audit", append([]any{"kind", kind, "user", actor}, attrs...)...)
}
