// SPDX-License-Identifier: AGPL-3.0-or-later

// Package jewels serves the crown-jewels admin page (ADR 0011 D10, Q7
// decided 2026-11-09; plan VU-23):
//
//   - GET /vuln/jewels: the marked crown jewels, the entry classes
//     (internet, NetBird) with their coverage, recent changes and a form to
//     pick a subject and a role. With ?node=&role= it shows the confirm
//     step: the role's suggested weight prefilled for the admin to confirm
//     or change.
//   - POST /vuln/jewels/mark: marks or changes a crown jewel with the
//     weight the admin submitted.
//   - POST /vuln/jewels/unmark: removes a crown jewel.
//
// Only admins may use the page: the handler needs an Authorize check and
// refuses (403) every request it does not approve, also when mounted
// outside the session chain. State-changing requests are refused unless
// their Origin header equals the configured public origin (CSRF; the
// middleware checks it too, the handler fails closed on its own), and the
// form body is bounded. The store audits every change.
//
// Suggested weights are never applied without the admin: the confirm step
// only prefills the form, and the POST needs an explicit weight. Subjects
// come from the server's own inventory (Directory); a role is chosen by the
// admin, never guessed from a name. Labels are untrusted text, rendered by
// html/template as text; pages carry no inline script or style.
package jewels

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
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/attackpath/jewels"
	"github.com/nebula-operation-station/nebula-operation-station/web/templates"
	jeweltpl "github.com/nebula-operation-station/nebula-operation-station/web/templates/jewels"
)

// Limits, next to the code that enforces them.
const (
	// MaxSubjects bounds the subjects offered in the form.
	MaxSubjects = 5000
	// MaxFormBytes bounds a POST body.
	MaxFormBytes = 8 << 10
	// MaxHistoryShown bounds the history rows on the page.
	MaxHistoryShown = 50
	// maxLabelRunes bounds a subject label as shown.
	maxLabelRunes = 120
	// callTimeout bounds the store and directory calls of one request.
	callTimeout = 10 * time.Second
)

// Subject is a markable attack-path node as the server's inventory knows it.
type Subject struct {
	// Node is the attack-path node ID (host:, pve:, guest:, ctr:, dev:).
	Node string
	// Label is the display name; untrusted text.
	Label string
}

// Directory lists the markable subjects from the server's own records.
type Directory interface {
	Subjects(ctx context.Context) ([]Subject, error)
}

// Store is the crown-jewel store; *jewels.Store implements it.
type Store interface {
	List(ctx context.Context) ([]jewels.Jewel, error)
	History(ctx context.Context, limit int) ([]jewels.Change, error)
	Mark(ctx context.Context, m jewels.Mark) (jewels.Change, error)
	Unmark(ctx context.Context, node, admin, reason string) (jewels.Change, error)
}

// Chrome is the per-request data of the shared page layout.
type Chrome struct {
	Theme         string
	NavCollapsed  bool
	PVENav        bool
	DeployEnabled bool
}

// Options configure a Handler.
type Options struct {
	// Store keeps the crown jewels. Required.
	Store Store
	// Directory lists the subjects. Required.
	Directory Directory
	// Entries returns the entry-class data sources; nil means none, so both
	// classes are unknown.
	Entries func(ctx context.Context) jewels.EntryInputs
	// Authorize approves admin requests. Required; the handler refuses
	// every request it does not approve.
	Authorize func(r *http.Request) bool
	// User returns the admin's user name for the audit trail. Required.
	User func(r *http.Request) string
	// PublicOrigin is the exact Origin a POST must carry. Required.
	PublicOrigin string
	// Chrome returns the layout data; nil uses the defaults.
	Chrome func(r *http.Request) Chrome
	// Log receives errors; nil discards them.
	Log *slog.Logger
}

// Handler serves the crown-jewels page.
type Handler struct {
	o    Options
	page *template.Template
}

// New parses the template and returns a Handler.
func New(o Options) (*Handler, error) {
	if o.Store == nil || o.Directory == nil {
		return nil, errors.New("jewels page: store and directory are required")
	}
	if o.Authorize == nil || o.User == nil {
		return nil, errors.New("jewels page: authorization and user are required")
	}
	if o.PublicOrigin == "" {
		return nil, errors.New("jewels page: public origin is required")
	}
	if o.Entries == nil {
		o.Entries = func(context.Context) jewels.EntryInputs { return jewels.EntryInputs{} }
	}
	if o.Chrome == nil {
		o.Chrome = func(*http.Request) Chrome { return Chrome{Theme: "system"} }
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	t, err := template.New("").ParseFS(templates.FS, "layout.html")
	if err != nil {
		return nil, fmt.Errorf("jewels page: parse layout: %w", err)
	}
	if t, err = t.ParseFS(jeweltpl.FS, "jewels.html"); err != nil {
		return nil, fmt.Errorf("jewels page: parse template: %w", err)
	}
	return &Handler{o: o, page: t}, nil
}

// Handler returns the routes.
func (h *Handler) Handler() http.Handler {
	mux := http.NewServeMux()
	h.Register(mux)
	return mux
}

// Register adds the routes to mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /vuln/jewels", h.guard(h.serveGet))
	mux.HandleFunc("POST /vuln/jewels/mark", h.guard(h.servePost(h.mark)))
	mux.HandleFunc("POST /vuln/jewels/unmark", h.guard(h.servePost(h.unmark)))
}

// guard refuses requests Authorize does not approve.
func (h *Handler) guard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.o.Authorize(r) {
			http.Error(w, "Forbidden.", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// errBadRequest marks an invalid request.
var errBadRequest = errors.New("invalid request")

// one returns the single value of key; a missing or repeated key is
// invalid unless optional and absent.
func one(v url.Values, key string, optional bool) (string, error) {
	vals, ok := v[key]
	if !ok && optional {
		return "", nil
	}
	if len(vals) != 1 {
		return "", fmt.Errorf("%w: %s", errBadRequest, key)
	}
	return vals[0], nil
}

// --- GET -----------------------------------------------------------------

type jewelRow struct {
	Node, Label, Role, MarkedBy, Updated, EditHref string
	Impact, Suggested                              int
	Missing                                        bool
}

type roleOption struct {
	Value, Label string
	Suggested    int
}

type confirmView struct {
	Node, Label, Role, RoleLabel string
	Suggested, Current, Prefill  int
}

type entryRow struct {
	Label, Coverage, Reason string
	Known, Truncated        bool
	Exposed, Dropped        int
}

type historyRow struct {
	At, Admin, Action, Node, Weight, Reason string
}

type view struct {
	Notice, Error string
	Max           int
	MaxReason     int
	MaxSubjects   int
	Rows          []jewelRow
	Subjects      []Subject
	SubjectsCut   bool
	Roles         []roleOption
	Confirm       *confirmView
	Entries       []entryRow
	History       []historyRow
}

type page struct {
	Title         string
	Active        string
	Theme         string
	NavCollapsed  bool
	Bare          bool
	PVENav        bool
	DeployEnabled bool
	Search        any
	BuiltinTrust  any
	Scripts       []string

	Jewels *view
}

// notices are the fixed messages a redirect can ask for.
var notices = map[string]string{
	"marked":   "Crown jewel saved.",
	"unmarked": "Crown jewel removed.",
	"none":     "Nothing changed.",
}

func (h *Handler) serveGet(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), callTimeout)
	defer cancel()
	q := r.URL.Query()
	done, err := one(q, "done", true)
	if err != nil {
		http.Error(w, "Invalid query.", http.StatusBadRequest)
		return
	}
	node, err := one(q, "node", true)
	if err != nil {
		http.Error(w, "Invalid query.", http.StatusBadRequest)
		return
	}
	role, err := one(q, "role", true)
	if err != nil {
		http.Error(w, "Invalid query.", http.StatusBadRequest)
		return
	}

	subjects, cut, err := h.subjects(ctx)
	if err != nil {
		h.fail(w, r, "directory", err)
		return
	}
	list, err := h.o.Store.List(ctx)
	if err != nil {
		h.fail(w, r, "list", err)
		return
	}
	hist, err := h.o.Store.History(ctx, MaxHistoryShown)
	if err != nil {
		h.fail(w, r, "history", err)
		return
	}
	labels := make(map[string]string, len(subjects))
	for _, s := range subjects {
		labels[s.Node] = s.Label
	}

	v := &view{Notice: notices[done], Max: jewels.MaxJewels, MaxReason: jewels.MaxReasonBytes, MaxSubjects: MaxSubjects,
		Subjects: subjects, SubjectsCut: cut}
	current := map[string]int{}
	for _, j := range list {
		label, ok := labels[j.Node]
		if !ok {
			label = j.Node
		}
		sug, _ := j.Role.SuggestedImpact()
		v.Rows = append(v.Rows, jewelRow{
			Node: j.Node, Label: label, Role: j.Role.Label(), MarkedBy: clip(j.MarkedBy),
			Updated: j.UpdatedAt.UTC().Format("2006-01-02 15:04 UTC"), Impact: j.Impact, Suggested: sug, Missing: !ok,
			EditHref: "/vuln/jewels?" + url.Values{"node": {j.Node}, "role": {string(j.Role)}}.Encode(),
		})
		current[j.Node] = j.Impact
	}
	for _, ro := range jewels.Roles() {
		sug, _ := ro.SuggestedImpact()
		v.Roles = append(v.Roles, roleOption{Value: string(ro), Label: ro.Label(), Suggested: sug})
	}

	if node != "" || role != "" {
		label, known := labels[node]
		ro := jewels.Role(role)
		switch {
		case !ro.Valid():
			v.Error = "Unknown role."
		case !known:
			v.Error = "Unknown subject; pick one from the inventory list."
		default:
			sug, _ := ro.SuggestedImpact()
			c := &confirmView{Node: node, Label: label, Role: role, RoleLabel: ro.Label(), Suggested: sug, Current: current[node]}
			// Prefill the form only; the admin still submits the weight.
			// An existing jewel keeps its weight in the form, so changing
			// the role or reason never moves it to the suggestion unseen.
			c.Prefill = c.Current
			if c.Prefill == 0 {
				c.Prefill = sug
			}
			v.Confirm = c
		}
	}

	for _, e := range jewels.EntryClasses(h.o.Entries(ctx)) {
		v.Entries = append(v.Entries, entryRow{
			Label: e.Label, Coverage: string(e.Coverage), Reason: e.Reason, Known: e.Coverage == jewels.CoverageKnown,
			Truncated: e.Truncated, Exposed: len(e.Exposed), Dropped: e.Dropped,
		})
	}
	for _, c := range hist {
		v.History = append(v.History, historyRow{
			At: c.At.UTC().Format("2006-01-02 15:04 UTC"), Admin: clip(c.Admin), Action: string(c.Action),
			Node: c.Node, Weight: weightChange(c), Reason: c.Reason,
		})
	}
	h.render(w, r, v)
}

// weightChange renders the role and weight change of c.
func weightChange(c jewels.Change) string {
	part := func(r jewels.Role, n int) string {
		if r == "" {
			return "—"
		}
		return r.Label() + " " + strconv.Itoa(n)
	}
	s := part(c.OldRole, c.OldImpact) + " → " + part(c.NewRole, c.NewImpact)
	if c.Suggested != 0 {
		s += " (suggested " + strconv.Itoa(c.Suggested) + ")"
	}
	return s
}

// subjects returns the valid subjects, at most MaxSubjects, and whether
// more were given. Invalid node IDs are dropped; labels are cleaned.
func (h *Handler) subjects(ctx context.Context) ([]Subject, bool, error) {
	in, err := h.o.Directory.Subjects(ctx)
	if err != nil {
		return nil, false, err
	}
	out := make([]Subject, 0, min(len(in), MaxSubjects))
	seen := make(map[string]bool, len(in))
	cut := false
	for _, s := range in {
		if _, err := jewels.NodeKind(s.Node); err != nil || seen[s.Node] {
			continue
		}
		if len(out) == MaxSubjects {
			cut = true
			break
		}
		seen[s.Node] = true
		label := clip(s.Label)
		if label == "" {
			label = s.Node
		}
		out = append(out, Subject{Node: s.Node, Label: label})
	}
	return out, cut, nil
}

// clip makes untrusted text valid, printable and bounded.
func clip(s string) string {
	s = strings.ToValidUTF8(s, "�")
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n == maxLabelRunes {
			b.WriteString("…")
			break
		}
		if !unicode.IsPrint(r) {
			r = '�'
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}

// --- POST ----------------------------------------------------------------

// servePost checks the Origin and the body, parses the form and runs f.
func (h *Handler) servePost(f func(ctx context.Context, r *http.Request, form url.Values) (string, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != h.o.PublicOrigin {
			http.Error(w, "Origin not allowed.", http.StatusForbidden)
			return
		}
		ct, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || ct != "application/x-www-form-urlencoded" {
			http.Error(w, "Unsupported content type.", http.StatusUnsupportedMediaType)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxFormBytes)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Request body too large.", http.StatusRequestEntityTooLarge)
			return
		}
		if !utf8.Valid(body) {
			http.Error(w, "Invalid form.", http.StatusBadRequest)
			return
		}
		form, err := url.ParseQuery(string(body))
		if err != nil {
			http.Error(w, "Invalid form.", http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), callTimeout)
		defer cancel()
		done, err := f(ctx, r, form)
		switch {
		case err == nil:
			http.Redirect(w, r, "/vuln/jewels?done="+done, http.StatusSeeOther)
		case errors.Is(err, jewels.ErrLimit):
			http.Error(w, fmt.Sprintf("At most %d crown jewels can be marked.", jewels.MaxJewels), http.StatusConflict)
		case errors.Is(err, jewels.ErrNotFound):
			http.Error(w, "Not a crown jewel.", http.StatusNotFound)
		case errors.Is(err, errBadRequest), errors.Is(err, jewels.ErrInvalidNode), errors.Is(err, jewels.ErrInvalidRole),
			errors.Is(err, jewels.ErrInvalidImpact), errors.Is(err, jewels.ErrInvalidText):
			http.Error(w, "Invalid form: "+userMessage(err), http.StatusBadRequest)
		default:
			h.fail(w, r, "save", err)
		}
	}
}

// userMessage names the invalid field without echoing input.
func userMessage(err error) string {
	switch {
	case errors.Is(err, jewels.ErrInvalidImpact):
		return "the impact weight must be a whole number from 1 to 10."
	case errors.Is(err, jewels.ErrInvalidRole):
		return "unknown role."
	case errors.Is(err, jewels.ErrInvalidNode):
		return "unknown subject."
	case errors.Is(err, jewels.ErrInvalidText):
		return "the reason is too long or has control characters."
	default:
		return "missing or repeated field."
	}
}

func (h *Handler) mark(ctx context.Context, r *http.Request, form url.Values) (string, error) {
	node, err := one(form, "node", false)
	if err != nil {
		return "", err
	}
	role, err := one(form, "role", false)
	if err != nil {
		return "", err
	}
	impactS, err := one(form, "impact", false)
	if err != nil {
		return "", err
	}
	reason, err := one(form, "reason", true)
	if err != nil {
		return "", err
	}
	// The weight is what the admin submitted; there is no fallback to the
	// role's suggestion.
	impact, err := strconv.Atoi(impactS)
	if err != nil || len(impactS) > 2 {
		return "", fmt.Errorf("impact: %w", jewels.ErrInvalidImpact)
	}
	known, err := h.knownSubject(ctx, node)
	if err != nil {
		return "", err
	}
	if !known {
		return "", fmt.Errorf("subject: %w", jewels.ErrInvalidNode)
	}
	c, err := h.o.Store.Mark(ctx, jewels.Mark{Node: node, Role: jewels.Role(role), Impact: impact, Admin: h.o.User(r), Reason: strings.TrimSpace(reason)})
	if err != nil {
		return "", err
	}
	if c.Action == "" {
		return "none", nil
	}
	return "marked", nil
}

func (h *Handler) unmark(ctx context.Context, r *http.Request, form url.Values) (string, error) {
	node, err := one(form, "node", false)
	if err != nil {
		return "", err
	}
	reason, err := one(form, "reason", true)
	if err != nil {
		return "", err
	}
	if _, err := h.o.Store.Unmark(ctx, node, h.o.User(r), strings.TrimSpace(reason)); err != nil {
		return "", err
	}
	return "unmarked", nil
}

// knownSubject reports whether node is a subject of the directory.
func (h *Handler) knownSubject(ctx context.Context, node string) (bool, error) {
	if _, err := jewels.NodeKind(node); err != nil {
		return false, nil
	}
	subjects, _, err := h.subjects(ctx)
	if err != nil {
		return false, err
	}
	for _, s := range subjects {
		if s.Node == node {
			return true, nil
		}
	}
	return false, nil
}

// --- render --------------------------------------------------------------

func (h *Handler) fail(w http.ResponseWriter, r *http.Request, what string, err error) {
	h.o.Log.ErrorContext(r.Context(), "jewels page", "step", what, "error", err.Error())
	http.Error(w, "Internal error.", http.StatusInternalServerError)
}

func (h *Handler) render(w http.ResponseWriter, r *http.Request, v *view) {
	c := h.o.Chrome(r)
	p := &page{
		Title: "Crown jewels", Active: "jewels", Theme: c.Theme, NavCollapsed: c.NavCollapsed,
		PVENav: c.PVENav, DeployEnabled: c.DeployEnabled, Jewels: v,
	}
	var b strings.Builder
	if err := h.page.ExecuteTemplate(&b, "layout", p); err != nil {
		h.fail(w, r, "render", err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, b.String())
}
