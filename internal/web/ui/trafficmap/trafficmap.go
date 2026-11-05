// SPDX-License-Identifier: AGPL-3.0-or-later

// Package trafficmap serves the traffic map page of ADR 0009 (D4, TM19):
//
//   - GET /traffic: the parent page. Its script (web/static/
//     trafficmap-bridge.js) fetches the bounded model from
//     /api/v1/trafficmap and the icons from /icons/<sha256>.png, decodes
//     the icons to ImageBitmaps and posts both to the renderer iframe. It
//     accepts only validated messages from that iframe and turns a node
//     id into a navigation to the host or asset page.
//   - GET /traffic/frame: the renderer document, loaded into an iframe with
//     sandbox="allow-scripts" and no allow-same-origin, so it runs in an
//     opaque origin without cookies or access to the parent DOM. Its own
//     CSP repeats the sandbox (also when opened top-level), forbids every
//     network use but the renderer modules and allows only this
//     deployment to frame it.
//   - GET /static/trafficmap/<module>.js: the renderer modules
//     (web/static/trafficmap). A module script of an opaque-origin
//     document is a CORS request with Origin: null and no cookies, so the
//     modules are served with Access-Control-Allow-Origin: * (without
//     credentials); they are public code, like everything under /static/.
//
// The time windows offered are those the map API allows
// (trafficmap.Builder.Windows, clamped to the flow retention). Pages use
// html/template only and carry no inline script; the frame's single
// inline style is allowed by its hash.
package trafficmap

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/web/static"
	"github.com/nebula-operation-station/nebula-operation-station/web/templates"
	tmtemplates "github.com/nebula-operation-station/nebula-operation-station/web/templates/trafficmap"
)

// Paths served by the handler.
const (
	// PagePath is the parent page.
	PagePath = "/traffic"
	// FramePath is the renderer document of the sandboxed iframe.
	FramePath = "/traffic/frame"
	// ModulePrefix is the URL prefix of the renderer modules.
	ModulePrefix = "/static/trafficmap/"
	// moduleDir is the directory of the renderer modules in static.FS.
	moduleDir = "trafficmap"
	// bridgeScript is the parent page's script under /static/.
	bridgeScript = "trafficmap-bridge.js"
)

// Limits, next to the code that enforces them.
const (
	// maxRawQuery bounds the page's query string.
	maxRawQuery = 512
	// maxIDBytes bounds a focus node id; it equals the map API's
	// MaxIDBytes and the renderer's LIMITS.idLength.
	maxIDBytes = 128
	// defaultWindow is used when the request names none and the API
	// allows it (trafficmap.DefaultWindow).
	defaultWindow = "24h"
)

// knownWindows are the window names of ADR 0009 D3, shortest first. A
// window from Options.Windows that is not listed here is ignored.
var knownWindows = []string{"1h", "24h", "7d", "21d"}

// idRE is the node id syntax shared by the map API and the renderer.
var idRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)

// moduleRE is the file name syntax of a renderer module.
var moduleRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*\.js$`)

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
	// PublicOrigin is the deployment's exact origin, e.g.
	// "https://nebula.example.org". Required: the renderer document's CSP
	// names it as the only allowed framing ancestor and script source,
	// because 'self' is ambiguous in an opaque-origin document.
	PublicOrigin string
	// Windows returns the windows the map API allows, shortest first
	// (trafficmap.Builder.Windows). Required.
	Windows func() []string
	// Chrome returns the layout data; nil uses the defaults.
	Chrome func(r *http.Request) Chrome
	// Log receives rendering errors; nil discards them.
	Log *slog.Logger
}

// Handler serves the traffic map page, the renderer document and the
// renderer modules.
type Handler struct {
	windows  func() []string
	chrome   func(r *http.Request) Chrome
	log      *slog.Logger
	page     *template.Template
	frame    []byte
	frameCSP string
	modules  fs.FS
}

// New parses the templates and returns a Handler.
func New(o Options) (*Handler, error) {
	origin, err := cleanOrigin(o.PublicOrigin)
	if err != nil {
		return nil, fmt.Errorf("trafficmap: public origin: %w", err)
	}
	if o.Windows == nil {
		return nil, errors.New("trafficmap: the API's window list is required")
	}
	h := &Handler{windows: o.Windows, chrome: o.Chrome, log: o.Log}
	if h.chrome == nil {
		h.chrome = func(*http.Request) Chrome { return Chrome{Theme: "system"} }
	}
	if h.log == nil {
		h.log = slog.New(slog.DiscardHandler)
	}
	page, err := template.ParseFS(templates.FS, "layout.html")
	if err != nil {
		return nil, fmt.Errorf("trafficmap: parse layout: %w", err)
	}
	if h.page, err = page.ParseFS(tmtemplates.FS, "page.html"); err != nil {
		return nil, fmt.Errorf("trafficmap: parse page: %w", err)
	}
	if h.frame, err = fs.ReadFile(tmtemplates.FS, "frame.html"); err != nil {
		return nil, fmt.Errorf("trafficmap: read frame: %w", err)
	}
	styleHash, err := inlineStyleHash(h.frame)
	if err != nil {
		return nil, fmt.Errorf("trafficmap: frame: %w", err)
	}
	h.frameCSP = frameCSP(origin, styleHash)
	if h.modules, err = fs.Sub(static.FS, moduleDir); err != nil {
		return nil, fmt.Errorf("trafficmap: renderer modules: %w", err)
	}
	return h, nil
}

// cleanOrigin accepts exactly scheme://host[:port] with an http or https
// scheme and returns it unchanged. Anything else could change the meaning
// of the CSP it is written into.
func cleanOrigin(s string) (string, error) {
	if s == "" {
		return "", errors.New("is required")
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", errors.New("is not a URL")
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil ||
		u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return "", errors.New("must be scheme://host[:port]")
	}
	if strings.ContainsAny(s, " ;,'\"\t\r\n") || (&url.URL{Scheme: u.Scheme, Host: u.Host}).String() != s {
		return "", errors.New("must be scheme://host[:port]")
	}
	return s, nil
}

// inlineStyleHash returns the CSP hash source of the document's single
// inline <style> element.
func inlineStyleHash(doc []byte) (string, error) {
	const open, end = "<style>", "</style>"
	i := bytes.Index(doc, []byte(open))
	j := bytes.Index(doc, []byte(end))
	if i < 0 || j < i || bytes.Count(doc, []byte("<style")) != 1 {
		return "", errors.New("want exactly one inline <style> element")
	}
	sum := sha256.Sum256(doc[i+len(open) : j])
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'", nil
}

// frameCSP is the renderer document's policy: nothing but the renderer
// modules and the hashed style, no network, no nested content, framed only
// by this deployment, and always sandboxed.
func frameCSP(origin, styleHash string) string {
	return strings.Join([]string{
		"default-src 'none'",
		"script-src " + origin + ModulePrefix,
		"style-src " + styleHash,
		"connect-src 'none'",
		"img-src 'none'",
		"font-src 'none'",
		"media-src 'none'",
		"object-src 'none'",
		"worker-src 'none'",
		"frame-src 'none'",
		"child-src 'none'",
		"manifest-src 'none'",
		"base-uri 'none'",
		"form-action 'none'",
		"frame-ancestors " + origin,
		"sandbox allow-scripts",
	}, "; ")
}

// Handler returns the routes. Authentication and the security headers are
// the job of the surrounding chain (internal/web/auth, middleware); the
// module route lies under /static/, which needs no session.
func (h *Handler) Handler() http.Handler {
	mux := http.NewServeMux()
	h.Register(mux)
	return mux
}

// Register adds the routes to mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET "+PagePath, h.handlePage)
	mux.HandleFunc("GET "+FramePath, h.handleFrame)
	mux.HandleFunc("GET "+ModulePrefix+"{file}", h.handleModule)
}

// page is the data of the layout template (web/templates/layout.html)
// plus the traffic map view.
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

	Traffic *view
}

// view is the traffic map part of the page.
type view struct {
	// Window is the selected window; Focus the focused node id or "".
	Window string
	Focus  string
	// Windows are the window links; OverviewHref leaves the focus.
	Windows      []windowLink
	OverviewHref string
}

type windowLink struct {
	Name, Href string
	Active     bool
}

// allowedWindows returns the provider's windows that are known window
// names, in the canonical order.
func (h *Handler) allowedWindows() []string {
	got := h.windows()
	out := make([]string, 0, len(knownWindows))
	for _, w := range knownWindows {
		if slices.Contains(got, w) {
			out = append(out, w)
		}
	}
	return out
}

// pageQuery is the parsed query of the page.
type pageQuery struct {
	window, focus string
}

// parseQuery accepts only window and focus, each at most once and valid.
func parseQuery(raw string, windows []string) (pageQuery, error) {
	if len(raw) > maxRawQuery {
		return pageQuery{}, errors.New("query too long")
	}
	v, err := url.ParseQuery(raw)
	if err != nil {
		return pageQuery{}, errors.New("malformed query")
	}
	var q pageQuery
	for k, vals := range v {
		if len(vals) != 1 {
			return pageQuery{}, errors.New("repeated parameter")
		}
		switch k {
		case "window":
			if !slices.Contains(windows, vals[0]) {
				return pageQuery{}, errors.New("window must be one of " + strings.Join(windows, ", "))
			}
			q.window = vals[0]
		case "focus":
			if len(vals[0]) > maxIDBytes || !idRE.MatchString(vals[0]) {
				return pageQuery{}, errors.New("focus is not a valid node id")
			}
			q.focus = vals[0]
		default:
			return pageQuery{}, errors.New("unknown parameter")
		}
	}
	if q.window == "" {
		q.window = windows[len(windows)-1]
		if slices.Contains(windows, defaultWindow) {
			q.window = defaultWindow
		}
	}
	return q, nil
}

func windowHref(w string) string {
	return PagePath + "?" + url.Values{"window": {w}}.Encode()
}

func (h *Handler) handlePage(w http.ResponseWriter, r *http.Request) {
	windows := h.allowedWindows()
	if len(windows) == 0 {
		http.Error(w, "traffic map unavailable: no time window is allowed", http.StatusServiceUnavailable)
		return
	}
	q, err := parseQuery(r.URL.RawQuery, windows)
	if err != nil {
		http.Error(w, "query: "+err.Error(), http.StatusBadRequest)
		return
	}
	v := &view{Window: q.window, Focus: q.focus, OverviewHref: windowHref(q.window)}
	for _, name := range windows {
		v.Windows = append(v.Windows, windowLink{Name: name, Href: windowHref(name), Active: name == q.window})
	}
	c := h.chrome(r)
	data := page{
		Title: "Traffic map", Active: "traffic", Theme: c.Theme, NavCollapsed: c.NavCollapsed,
		PVENav: c.PVENav, DeployEnabled: c.DeployEnabled, Scripts: []string{bridgeScript}, Traffic: v,
	}
	var buf bytes.Buffer
	if err := h.page.ExecuteTemplate(&buf, "layout", data); err != nil {
		h.log.Error("trafficmap page", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(buf.Bytes())
}

func (h *Handler) handleFrame(w http.ResponseWriter, _ *http.Request) {
	hd := w.Header()
	hd.Set("Content-Security-Policy", h.frameCSP)
	hd.Set("Content-Type", "text/html; charset=utf-8")
	hd.Set("Cache-Control", "no-store")
	hd.Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(h.frame)
}

func (h *Handler) handleModule(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("file")
	if !moduleRE.MatchString(name) {
		http.NotFound(w, r)
		return
	}
	b, err := fs.ReadFile(h.modules, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	hd := w.Header()
	hd.Set("Content-Type", "text/javascript; charset=utf-8")
	hd.Set("X-Content-Type-Options", "nosniff")
	hd.Set("Cache-Control", "no-cache")
	// Public code for an opaque-origin importer; never with credentials.
	hd.Set("Access-Control-Allow-Origin", "*")
	_, _ = w.Write(b)
}
