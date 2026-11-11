// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/docsembed"
	"github.com/nebula-operation-station/nebula-operation-station/internal/docsembed/mdsafe"
	"github.com/nebula-operation-station/nebula-operation-station/web/templates"
)

// In-app help (/help): the operator handbook and FAQ, embedded at build
// time (internal/docsembed) and rendered once with the strict Markdown
// subset of internal/docsembed/mdsafe. The pages are static; nothing a
// request carries reaches the renderer. The search only matches the
// query against page and section titles and shows it back as text.

const (
	// maxHelpQueryBytes bounds the search text, like /search.
	maxHelpQueryBytes = 100
	// maxHelpResults bounds the shown search matches.
	maxHelpResults = 50
	// maxHelpSearchLevel is the deepest heading level the search covers.
	maxHelpSearchLevel = 3
)

// helpPage is one rendered handbook page.
type helpPage struct {
	slug     string
	url      string
	title    string
	body     template.HTML
	headings []mdsafe.Heading
}

// helpBook is the rendered handbook.
type helpBook struct {
	pages map[string]*helpPage
	// order is the chapter order: the overview, then the pages in the
	// order the overview first links them, then any others by slug.
	order []*helpPage
}

// helpURL is the in-app address of a handbook page.
func helpURL(slug string) string {
	if slug == docsembed.IndexSlug {
		return "/help"
	}
	return "/help/" + slug
}

// loadHelpBook renders every embedded handbook page once.
var loadHelpBook = sync.OnceValues(func() (*helpBook, error) {
	docs, err := docsembed.Pages()
	if err != nil {
		return nil, fmt.Errorf("load handbook: %w", err)
	}
	known := make(map[string]bool, len(docs))
	for _, d := range docs {
		known[d.Slug] = true
	}
	book := &helpBook{pages: make(map[string]*helpPage, len(docs))}
	var linked []string
	for _, d := range docs {
		resolve := func(p, frag string) (string, bool) {
			// Only sibling handbook pages ("hosts.md"); links into
			// the rest of docs/ are not served and stay text.
			slug, ok := strings.CutSuffix(p, ".md")
			slug = strings.ToLower(slug)
			if !ok || !docsembed.ValidSlug(slug) || !known[slug] {
				return "", false
			}
			if d.Slug == docsembed.IndexSlug {
				linked = append(linked, slug)
			}
			href := helpURL(slug)
			if frag != "" {
				href += "#" + frag
			}
			return href, true
		}
		res, err := mdsafe.Render(d.Source, mdsafe.Options{Relative: resolve})
		if err != nil {
			return nil, fmt.Errorf("render handbook %s: %w", d.File, err)
		}
		title := res.Title
		if title == "" {
			title = d.Slug
		}
		book.pages[d.Slug] = &helpPage{slug: d.Slug, url: helpURL(d.Slug), title: title, body: res.HTML, headings: res.Headings}
	}
	seen := map[string]bool{}
	add := func(slug string) {
		if p, ok := book.pages[slug]; ok && !seen[slug] {
			seen[slug] = true
			book.order = append(book.order, p)
		}
	}
	add(docsembed.IndexSlug)
	for _, s := range linked {
		add(s)
	}
	for _, d := range docs {
		add(d.Slug)
	}
	return book, nil
})

// helpTemplate is the layout plus the help page template.
var helpTemplate = sync.OnceValues(func() (*template.Template, error) {
	t, err := template.New("").Funcs(template.FuncMap{"timeTag": timeTag}).ParseFS(templates.FS, "layout.html", "help.html")
	if err != nil {
		return nil, fmt.Errorf("ui: parse template help: %w", err)
	}
	return t, nil
})

// helpPageData is the layout data plus the help page data.
type helpPageData struct {
	pageData
	// Help is the data of the help pages.
	Help *helpView
}

// helpView is what help.html shows.
type helpView struct {
	// Query is the search text as typed (shown escaped).
	Query string
	// Searched is true when a search was submitted.
	Searched bool
	// Invalid is true when the search text is too long or not UTF-8.
	Invalid bool
	// Results are the matching sections.
	Results []helpResult
	// Truncated is true when more than maxHelpResults matched.
	Truncated bool
	// Chapters is the handbook's table of contents.
	Chapters []helpChapter
	// Body is the rendered page (escaped HTML from mdsafe).
	Body template.HTML
}

// helpChapter is one table-of-contents entry.
type helpChapter struct {
	Title   string
	URL     string
	Current bool
}

// helpResult is one search match.
type helpResult struct {
	// Section is the heading text; Page the page title.
	Section string
	Page    string
	URL     string
}

// registerHelp adds the help routes. They take every method so that a
// non-GET request is answered 405 here instead of by the catch-all.
func (h *Handler) registerHelp(mux *http.ServeMux) {
	mux.HandleFunc("/help", h.handleHelpIndex)
	mux.HandleFunc("/help/{page}", h.handleHelpPage)
}

func helpMethodOK(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	return true
}

func (h *Handler) handleHelpIndex(w http.ResponseWriter, r *http.Request) {
	if !helpMethodOK(w, r) {
		return
	}
	book, err := loadHelpBook()
	if err != nil {
		h.log.Error("help: load handbook", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	v := &helpView{}
	if q, ok := r.URL.Query()["q"]; ok && len(q) > 0 {
		v.Searched = true
		v.Query = q[0]
		if len(v.Query) > maxHelpQueryBytes || !utf8.ValidString(v.Query) {
			v.Invalid = true
			v.Query = ""
		} else {
			v.Results, v.Truncated = book.search(v.Query)
		}
	}
	h.renderHelp(w, r, book, book.pages[docsembed.IndexSlug], v)
}

func (h *Handler) handleHelpPage(w http.ResponseWriter, r *http.Request) {
	if !helpMethodOK(w, r) {
		return
	}
	slug := r.PathValue("page")
	if slug == docsembed.IndexSlug {
		http.Redirect(w, r, "/help", http.StatusSeeOther)
		return
	}
	book, err := loadHelpBook()
	if err != nil {
		h.log.Error("help: load handbook", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	p, ok := book.pages[slug]
	if !ok || !docsembed.ValidSlug(slug) {
		http.NotFound(w, r)
		return
	}
	h.renderHelp(w, r, book, p, &helpView{})
}

// search matches every whitespace-separated term of q (case-folded)
// against page and section titles.
func (b *helpBook) search(q string) ([]helpResult, bool) {
	terms := strings.Fields(strings.ToLower(q))
	if len(terms) == 0 {
		return nil, false
	}
	match := func(s string) bool {
		s = strings.ToLower(s)
		for _, t := range terms {
			if !strings.Contains(s, t) {
				return false
			}
		}
		return true
	}
	var out []helpResult
	for _, p := range b.order {
		for _, hd := range p.headings {
			if hd.Level > maxHelpSearchLevel {
				continue
			}
			url := p.url + "#" + hd.ID
			if hd.Level == 1 {
				url = p.url
			}
			if !match(hd.Text) && !(hd.Level == 1 && match(p.slug)) {
				continue
			}
			if len(out) == maxHelpResults {
				return out, true
			}
			out = append(out, helpResult{Section: hd.Text, Page: p.title, URL: url})
		}
	}
	return out, false
}

func (h *Handler) renderHelp(w http.ResponseWriter, r *http.Request, book *helpBook, p *helpPage, v *helpView) {
	for _, c := range book.order {
		v.Chapters = append(v.Chapters, helpChapter{Title: c.title, URL: c.url, Current: c == p})
	}
	v.Body = p.body
	title := p.title
	if p.slug == docsembed.IndexSlug {
		title = "Help"
	}
	data := helpPageData{pageData: pageData{Title: title, Active: "help", Content: "help"}, Help: v}
	data.Theme = themeFromRequest(r)
	data.NavCollapsed = navStateFromRequest(r) == navCollapsed
	data.PVENav = h.pve != nil
	data.DeployEnabled = h.deploy != nil && h.pve != nil && h.pveRemotes != nil
	if h.builtinTrust != nil {
		data.BuiltinTrust = h.builtinTrust.get(r.Context())
	}
	set, err := helpTemplate()
	if err != nil {
		h.log.Error("help: template", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := set.ExecuteTemplate(&buf, "layout", data); err != nil {
		h.log.Error("render page", "page", "help", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if _, err := w.Write(buf.Bytes()); err != nil {
		h.log.Debug("write page", "page", "help", "error", err)
	}
}
