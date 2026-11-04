// SPDX-License-Identifier: AGPL-3.0-or-later

package icons

import (
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/nebula-operation-station/nebula-operation-station/internal/iconstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui/icons/iconjob"
)

// PathPrefix is the URL path icons are served under.
const PathPrefix = "/icons/"

// maxServeBytes bounds a served icon file; a sanitized 128 px PNG is far
// smaller.
const maxServeBytes = iconjob.MaxPNGBytes

// Response headers of every /icons/ response (ADR 0009 D6). The browser
// must treat the body as an inert PNG: no sniffing, no active content,
// never a download prompt or a document.
var iconHeaders = map[string]string{
	"Content-Security-Policy":      "default-src 'none'",
	"X-Content-Type-Options":       "nosniff",
	"Cross-Origin-Resource-Policy": "same-origin",
	"Referrer-Policy":              "no-referrer",
}

// cacheControl is used for a found icon: the URL is the content hash, so
// the response never changes. "private" keeps shared caches out because
// the route sits behind the web login.
const cacheControl = "private, max-age=31536000, immutable"

// ServeHTTP serves GET and HEAD /icons/<sha256>.png: the 128 px icon from
// the icon store with Content-Type image/png, nosniff, CSP default-src
// 'none', Content-Disposition inline and immutable caching. Any other path
// is 404, any other method 405. Authentication is the router's job.
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	for k, v := range iconHeaders {
		h.Set(k, v)
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		h.Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sha, ok := parseIconPath(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	p, err := s.store.Path(sha, iconstore.LargeSize)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	body, err := readIcon(p)
	if errors.Is(err, os.ErrNotExist) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.log.ErrorContext(r.Context(), "serve icon", "sha256", sha, "error", err.Error())
		http.Error(w, "icon unavailable", http.StatusInternalServerError)
		return
	}
	etag := `"` + sha + `"`
	h.Set("Content-Type", "image/png")
	h.Set("Content-Disposition", "inline")
	h.Set("Cache-Control", cacheControl)
	h.Set("ETag", etag)
	if inm := r.Header.Get("If-None-Match"); inm != "" && etagMatches(inm, etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(body)
	}
}

// parseIconPath returns the hash of "/icons/<64 lowercase hex>.png".
func parseIconPath(p string) (string, bool) {
	name, ok := strings.CutPrefix(p, PathPrefix)
	if !ok {
		return "", false
	}
	sha, ok := strings.CutSuffix(name, ".png")
	if !ok || len(sha) != 64 {
		return "", false
	}
	for i := 0; i < len(sha); i++ {
		if c := sha[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", false
		}
	}
	return sha, true
}

// etagMatches reports whether an If-None-Match header lists etag or "*".
func etagMatches(header, etag string) bool {
	for _, t := range strings.Split(header, ",") {
		t = strings.TrimSpace(t)
		if t == "*" || strings.TrimPrefix(t, "W/") == etag {
			return true
		}
	}
	return false
}

// readIcon reads a regular icon file (no symlink) of bounded size.
func readIcon(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > maxServeBytes {
		return nil, errors.New("icon file is not a bounded regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxServeBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxServeBytes {
		return nil, errors.New("icon file grew while reading")
	}
	return b, nil
}
