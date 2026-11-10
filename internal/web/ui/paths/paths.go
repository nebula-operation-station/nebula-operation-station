// SPDX-License-Identifier: AGPL-3.0-or-later

// Package paths serves the attack-path admin pages (ADR 0011 D10, plan
// VU-24):
//
//   - GET /vuln/paths: per crown jewel the top paths with likelihood L and
//     risk R, the coverage and every limit that was hit, and the choke
//     points (fixes ranked by risk removed) with their "fix with" links.
//   - GET /vuln/paths/p/{hash}: one path, step by step, with every input
//     of every number (KEV, EPSS, CVSS exploitability, the assumed-edge
//     factor, what the step grants, the target's impact) and a fix link or
//     the reason there is none per step.
//   - GET /vuln/paths/map: the traffic map with the attack-path overlay.
//     The page reuses the traffic map's parent bridge, which loads the
//     normal traffic model, but frames its own renderer document.
//   - GET /vuln/paths/map/frame: that renderer document. It carries the
//     overlay (mapped node IDs, ranks and flags only; no labels, findings
//     or fix links) in an attribute, so the overlay never travels through
//     the traffic map API or the normal renderer document: users who can
//     see the traffic map but not attack paths get nothing new.
//
// Every route is admin-only: the handler refuses (403) every request
// Authorize does not approve, also when mounted outside the session chain.
// Attack paths are not part of any API. Labels, vulnerability IDs and
// package names are untrusted text rendered by html/template as text; fix
// links are rendered only when they are NOS-relative paths. Pages carry no
// inline script or style; the frame's single inline style is allowed by its
// hash.
//
// "Unknown" is never shown as "safe": a target without paths reads
// "unknown" unless the coverage is complete and no limit was hit, and even
// then it says that no path was found within the limits, not that none
// exists.
package paths

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/attackpath"
	"github.com/nebula-operation-station/nebula-operation-station/internal/attackpath/sources"
	"github.com/nebula-operation-station/nebula-operation-station/web/templates"
	pathtpl "github.com/nebula-operation-station/nebula-operation-station/web/templates/paths"
)

// Routes served by the handler.
const (
	// ListPath is the list page.
	ListPath = "/vuln/paths"
	// DetailPrefix is the prefix of a path's detail page; the path hash
	// follows.
	DetailPrefix = "/vuln/paths/p/"
	// MapPath is the overlay page.
	MapPath = "/vuln/paths/map"
	// FramePath is the overlay renderer document.
	FramePath = "/vuln/paths/map/frame"
	// moduleScriptPrefix is where the renderer modules are served
	// (internal/web/ui/trafficmap.ModulePrefix).
	moduleScriptPrefix = "/static/trafficmap/"
	// bridgeScript is the traffic map's parent page script under /static/.
	bridgeScript = "trafficmap-bridge.js"
)

// Limits, next to the code that enforces them.
const (
	// MaxChokePointsShown bounds the choke-point rows on the list page.
	MaxChokePointsShown = 50
	// MaxBeams bounds the beams of one overlay; it equals LIMITS.beams in
	// web/static/trafficmap/paths.js.
	MaxBeams = 1000
	// MaxMarks bounds the marked nodes of one overlay; it equals
	// LIMITS.marks in paths.js.
	MaxMarks = 1000
	// MaxOverlayBytes bounds the encoded overlay; it equals
	// PATHS_LIMITS.bytes in paths.js, which rejects a larger overlay whole.
	// The overlay is ASCII JSON, so bytes equal the renderer's string length.
	MaxOverlayBytes = 262144
	// MaxFixHrefBytes bounds a fix link.
	MaxFixHrefBytes = 1024
	// maxRawQuery bounds a query string.
	maxRawQuery = 512
	// maxLabelRunes bounds untrusted text as shown.
	maxLabelRunes = 120
	// maxMapIDBytes bounds a traffic map node ID; it equals the
	// renderer's LIMITS.idLength.
	maxMapIDBytes = 128
	// callTimeout bounds the Source call of one request.
	callTimeout = 10 * time.Second
	// overlayVersion is the overlay schema version paths.js accepts.
	overlayVersion = 1
)

// The ap-v1 constants, repeated to explain the numbers (ADR 0011 D10).
// The explanation is shown only for a result of this formula version.
const (
	kevTerm        = 0.9
	cvssWeight     = 0.3
	exploitMax     = 3.9
	assumedFactor  = 0.5
	recomputeSlack = 1e-9
)

// knownWindows are the traffic map windows (ADR 0009 D3).
var knownWindows = []string{"1h", "24h", "7d", "21d"}

// FindingRef names one finding on one attack-path node.
type FindingRef struct {
	// Node is the attack-path node ID; Key the finding key.
	Node, Key string
}

// FixLink is a prefilled link into an existing NOS flow (ADR 0011 D8). It
// is never submitted by this page.
type FixLink struct {
	// Href is a NOS-relative path ("/..."); anything else is dropped.
	Href string
	// Text is the link text, e.g. "Update nginx on web01".
	Text string
	// Verified says whether the fix is verified (source version ≥ fixed);
	// otherwise the page says "fix not verified".
	Verified bool
	// Note is an extra remark such as "reboot required to take effect".
	Note string
}

// FindingInfo is what the page shows about a finding of a step.
type FindingInfo struct {
	// VulnID is the CVE or advisory ID; untrusted text.
	VulnID string
	// Package is the affected package, image or model; untrusted text.
	Package string
	// Fix is the "fix with" link; a zero Href means none.
	Fix FixLink
	// NoFix says why there is no fix link ("no fix in the configured
	// repositories", ...); empty uses a generic text.
	NoFix string
	// Stale is set when the finding rests on a stale run or feed.
	Stale bool
}

// Snapshot is the last attack-path computation and what explains it.
type Snapshot struct {
	// Result is the computation; nil means none has run yet.
	Result *attackpath.Result
	// Report is the data adapters' report; nil means coverage unknown.
	Report *sources.Report
	// ComputedAt is when Result was computed.
	ComputedAt time.Time
	// Labels maps node IDs to display names; untrusted text.
	Labels map[string]string
	// Findings describes the findings named by steps and choke points.
	Findings map[FindingRef]FindingInfo
}

// Source returns the current snapshot.
type Source interface {
	Snapshot(ctx context.Context) (Snapshot, error)
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
	// Source returns the snapshot. Required.
	Source Source
	// Authorize approves admin requests. Required; the handler refuses
	// every request it does not approve.
	Authorize func(r *http.Request) bool
	// PublicOrigin is the deployment's exact origin. Required: the overlay
	// frame's CSP names it as script source and only framing ancestor.
	PublicOrigin string
	// MapNode maps an attack-path node ID to the traffic map node ID; nil
	// maps nothing, so the overlay is empty and says so.
	MapNode func(id string) (string, bool)
	// Window is the traffic window the overlay page shows; "" means 24h.
	Window string
	// Chrome returns the layout data; nil uses the defaults.
	Chrome func(r *http.Request) Chrome
	// Log receives errors; nil discards them.
	Log *slog.Logger
}

// Handler serves the attack-path pages.
type Handler struct {
	o        Options
	list     *template.Template
	detail   *template.Template
	mapPage  *template.Template
	frame    *template.Template
	frameCSP string
}

// New parses the templates and returns a Handler.
func New(o Options) (*Handler, error) {
	if o.Source == nil || o.Authorize == nil {
		return nil, errors.New("paths pages: source and authorization are required")
	}
	origin, err := cleanOrigin(o.PublicOrigin)
	if err != nil {
		return nil, fmt.Errorf("paths pages: public origin: %w", err)
	}
	if o.Window == "" {
		o.Window = "24h"
	}
	if !contains(knownWindows, o.Window) {
		return nil, errors.New("paths pages: unknown traffic window")
	}
	if o.MapNode == nil {
		o.MapNode = func(string) (string, bool) { return "", false }
	}
	if o.Chrome == nil {
		o.Chrome = func(*http.Request) Chrome { return Chrome{Theme: "system"} }
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	h := &Handler{o: o}
	for _, p := range []struct {
		dst  **template.Template
		file string
	}{{&h.list, "list.html"}, {&h.detail, "detail.html"}, {&h.mapPage, "map.html"}} {
		t, err := template.New("").ParseFS(templates.FS, "layout.html")
		if err != nil {
			return nil, fmt.Errorf("paths pages: parse layout: %w", err)
		}
		if *p.dst, err = t.ParseFS(pathtpl.FS, p.file); err != nil {
			return nil, fmt.Errorf("paths pages: parse %s: %w", p.file, err)
		}
	}
	raw, err := fs.ReadFile(pathtpl.FS, "frame.html")
	if err != nil {
		return nil, fmt.Errorf("paths pages: read frame: %w", err)
	}
	styleHash, err := inlineStyleHash(raw)
	if err != nil {
		return nil, fmt.Errorf("paths pages: frame: %w", err)
	}
	if h.frame, err = template.New("frame").Parse(string(raw)); err != nil {
		return nil, fmt.Errorf("paths pages: parse frame: %w", err)
	}
	h.frameCSP = frameCSP(origin, styleHash)
	return h, nil
}

// Handler returns the routes.
func (h *Handler) Handler() http.Handler {
	mux := http.NewServeMux()
	h.Register(mux)
	return mux
}

// Register adds the routes to mux. mux must sit behind the session check
// and the security middleware; the handler checks Authorize on its own.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET "+ListPath, h.guard(h.serveList))
	mux.HandleFunc("GET "+DetailPrefix+"{hash}", h.guard(h.serveDetail))
	mux.HandleFunc("GET "+MapPath, h.guard(h.serveMap))
	mux.HandleFunc("GET "+FramePath, h.guard(h.serveFrame))
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

func (h *Handler) snapshot(r *http.Request) (Snapshot, error) {
	ctx, cancel := context.WithTimeout(r.Context(), callTimeout)
	defer cancel()
	s, err := h.o.Source.Snapshot(ctx)
	if err != nil {
		return Snapshot{}, fmt.Errorf("load attack-path snapshot: %w", err)
	}
	return s, nil
}

// --- validation helpers ----------------------------------------------------

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// validHash reports whether s is a path hash: 64 lowercase hex digits.
func validHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// validNodeID reports whether s has the attack-path node ID syntax.
func validNodeID(s string) bool {
	if s == "" || len(s) > attackpath.MaxIDBytes {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == '_', c == ':', c == '/', c == '@', c == '-':
		default:
			return false
		}
	}
	return true
}

// validMapID reports whether s has the traffic map's node ID syntax
// (^[A-Za-z0-9][A-Za-z0-9._:-]*$, at most maxMapIDBytes).
func validMapID(s string) bool {
	if s == "" || len(s) > maxMapIDBytes {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		alnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if !alnum && (i == 0 || (c != '.' && c != '_' && c != ':' && c != '-')) {
			return false
		}
	}
	return true
}

// safeFixHref returns href if it is a NOS-relative path, else "".
func safeFixHref(href string) string {
	if href == "" || len(href) > MaxFixHrefBytes || !utf8.ValidString(href) {
		return ""
	}
	if href[0] != '/' || strings.HasPrefix(href, "//") || strings.ContainsAny(href, "\\") {
		return ""
	}
	for _, r := range href {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return ""
		}
	}
	u, err := url.Parse(href)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.Opaque != "" {
		return ""
	}
	return href
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

// cleanOrigin accepts exactly scheme://host[:port] with an http or https
// scheme; anything else could change the meaning of the CSP.
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
	if i < 0 || j < i || bytes.Count(doc, []byte("<style")) != 1 || bytes.Contains(doc[i:j], []byte("{{")) {
		return "", errors.New("want exactly one static inline <style> element")
	}
	sum := sha256.Sum256(doc[i+len(open) : j])
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'", nil
}

// frameCSP is the overlay renderer document's policy: only the renderer
// modules and the hashed style, no network, framed only by this
// deployment, always sandboxed.
func frameCSP(origin, styleHash string) string {
	return strings.Join([]string{
		"default-src 'none'",
		"script-src " + origin + moduleScriptPrefix,
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

// --- number formatting -------------------------------------------------------

// f3 formats a value in 0..1 with three decimals; tiny values keep three
// significant digits so they never read as 0.
func f3(x float64) string {
	if x != 0 && math.Abs(x) < 0.001 {
		return strconv.FormatFloat(x, 'g', 3, 64)
	}
	return strconv.FormatFloat(x, 'f', 3, 64)
}

// fe formats a step value: exactly 1 as "1".
func fe(x float64) string {
	if x == 1 {
		return "1"
	}
	return f3(x)
}

// f2 formats a risk value (0..10).
func f2(x float64) string {
	if x != 0 && math.Abs(x) < 0.01 {
		return strconv.FormatFloat(x, 'g', 3, 64)
	}
	return strconv.FormatFloat(x, 'f', 2, 64)
}

// --- rendering -----------------------------------------------------------------

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

	Paths any
}

func (h *Handler) fail(w http.ResponseWriter, r *http.Request, what string, err error) {
	h.o.Log.ErrorContext(r.Context(), "attack-path pages", "step", what, "error", err.Error())
	http.Error(w, "Internal error.", http.StatusInternalServerError)
}

func (h *Handler) render(w http.ResponseWriter, r *http.Request, t *template.Template, title string, scripts []string, v any) {
	c := h.o.Chrome(r)
	p := &page{
		Title: title, Active: "vuln", Theme: c.Theme, NavCollapsed: c.NavCollapsed,
		PVENav: c.PVENav, DeployEnabled: c.DeployEnabled, Scripts: scripts, Paths: v,
	}
	var b bytes.Buffer
	if err := t.ExecuteTemplate(&b, "layout", p); err != nil {
		h.fail(w, r, "render", err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(b.Bytes())
}

// overlayJSON is the overlay data embedded into the frame document; o must
// come from fitOverlay.
func overlayJSON(o overlayData) (string, error) {
	b, err := json.Marshal(o)
	if err != nil {
		return "", fmt.Errorf("encode overlay: %w", err)
	}
	if len(b) > MaxOverlayBytes {
		return "", fmt.Errorf("encode overlay: %d bytes exceed the limit %d", len(b), MaxOverlayBytes)
	}
	return string(b), nil
}

// fitOverlay bounds the encoded overlay by MaxOverlayBytes: beams are
// dropped from the end first (the lowest ranked and last targets), then
// marks, and the overlay is flagged truncated. The renderer would reject a
// larger overlay as a whole.
func fitOverlay(o overlayData) (overlayData, error) {
	beamSize, err := itemSizes(o.Beams)
	if err != nil {
		return o, err
	}
	markSize, err := itemSizes(o.Marks)
	if err != nil {
		return o, err
	}
	// The envelope with empty lists and truncated:true, the longest form.
	env, err := json.Marshal(overlayData{Version: o.Version, Beams: []beam{}, Marks: []mark{}, Truncated: true})
	if err != nil {
		return o, fmt.Errorf("encode overlay: %w", err)
	}
	total := len(env) + listSize(beamSize) + listSize(markSize)
	nb, nm := len(beamSize), len(markSize)
	for total > MaxOverlayBytes && nb > 0 {
		nb--
		total -= beamSize[nb] + sep(nb)
	}
	for total > MaxOverlayBytes && nm > 0 {
		nm--
		total -= markSize[nm] + sep(nm)
	}
	if nb < len(o.Beams) || nm < len(o.Marks) {
		o.Beams, o.Marks, o.Truncated = o.Beams[:nb], o.Marks[:nm], true
	}
	return o, nil
}

// itemSizes returns the encoded size of every element.
func itemSizes[T any](items []T) ([]int, error) {
	out := make([]int, len(items))
	for i, it := range items {
		b, err := json.Marshal(it)
		if err != nil {
			return nil, fmt.Errorf("encode overlay: %w", err)
		}
		out[i] = len(b)
	}
	return out, nil
}

// listSize is the size of the elements of a JSON list with their commas.
func listSize(sizes []int) int {
	n := 0
	for i, s := range sizes {
		n += s + sep(i)
	}
	return n
}

// sep is the size of the comma before element i.
func sep(i int) int {
	if i == 0 {
		return 0
	}
	return 1
}
