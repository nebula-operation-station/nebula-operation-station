// SPDX-License-Identifier: AGPL-3.0-or-later

package icons

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/iconstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/softwarecat"
)

func serve(f *fixture, method, path string, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://nebula.test"+path, nil)
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	f.svc.ServeHTTP(w, r)
	return w
}

func checkSafetyHeaders(t *testing.T, name string, w *httptest.ResponseRecorder) {
	t.Helper()
	for k, v := range map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"Content-Security-Policy": "default-src 'none'",
	} {
		if got := w.Header().Get(k); got != v {
			t.Errorf("%s: %s = %q, want %q", name, k, got, v)
		}
	}
}

func uploadIcon(t *testing.T, f *fixture) string {
	t.Helper()
	sha, err := f.svc.Upload(context.Background(), "alice",
		softwarecat.IconSubject{Kind: softwarecat.SubjectCatalog, ID: "widgetd"}, testPNG(t, red))
	if err != nil {
		t.Fatal(err)
	}
	return sha
}

func TestServeIconSetsHeaders(t *testing.T) {
	f := newFixture(t)
	sha := uploadIcon(t, f)
	p, _ := f.store.Path(sha, iconstore.LargeSize)
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	w := serve(f, http.MethodGet, "/icons/"+sha+".png", nil)
	if w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), want) {
		t.Fatalf("status %d, body %d bytes", w.Code, w.Body.Len())
	}
	checkSafetyHeaders(t, "get", w)
	for k, v := range map[string]string{
		"Content-Type":        "image/png",
		"Content-Disposition": "inline",
		"Cache-Control":       "private, max-age=31536000, immutable",
		"ETag":                `"` + sha + `"`,
	} {
		if got := w.Header().Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}

	head := serve(f, http.MethodHead, "/icons/"+sha+".png", nil)
	if head.Code != http.StatusOK || head.Body.Len() != 0 || head.Header().Get("Content-Type") != "image/png" {
		t.Fatalf("HEAD %d %d", head.Code, head.Body.Len())
	}
	nm := serve(f, http.MethodGet, "/icons/"+sha+".png", map[string]string{"If-None-Match": `"x", W/"` + sha + `"`})
	if nm.Code != http.StatusNotModified || nm.Body.Len() != 0 {
		t.Fatalf("conditional GET %d", nm.Code)
	}
	checkSafetyHeaders(t, "304", nm)
}

func TestServeIconRejectsOtherPathsAndMethods(t *testing.T) {
	f := newFixture(t)
	sha := uploadIcon(t, f)
	for _, p := range []string{
		"/icons/",
		"/icons/" + sha,
		"/icons/" + sha + ".svg",
		"/icons/" + strings.ToUpper(sha) + ".png",
		"/icons/" + sha + "-64.png",
		"/icons/" + sha + "-128.png",
		"/icons/../" + sha + ".png",
		"/icons/" + strings.Repeat("0", 64) + ".png", // well-formed, not stored
		"/other/" + sha + ".png",
	} {
		w := serve(f, http.MethodGet, p, nil)
		if w.Code != http.StatusNotFound {
			t.Errorf("%s: status %d", p, w.Code)
		}
		if ct := w.Header().Get("Content-Type"); ct == "image/png" {
			t.Errorf("%s: served as PNG", p)
		}
		checkSafetyHeaders(t, p, w)
	}
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		w := serve(f, m, "/icons/"+sha+".png", nil)
		if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET, HEAD" {
			t.Errorf("%s: status %d", m, w.Code)
		}
		checkSafetyHeaders(t, m, w)
	}
}

func TestServeIconRefusesSymlinkAndOversize(t *testing.T) {
	f := newFixture(t)
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("vault data"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := strings.Repeat("a", 64)
	if err := os.Symlink(secret, filepath.Join(f.dir, link+"-128.png")); err != nil {
		t.Fatal(err)
	}
	big := strings.Repeat("b", 64)
	if err := os.WriteFile(filepath.Join(f.dir, big+"-128.png"), make([]byte, maxServeBytes+1), 0o640); err != nil {
		t.Fatal(err)
	}
	for _, sha := range []string{link, big} {
		w := serve(f, http.MethodGet, "/icons/"+sha+".png", nil)
		if w.Code == http.StatusOK || bytes.Contains(w.Body.Bytes(), []byte("vault")) {
			t.Errorf("%s: status %d body %q", sha, w.Code, w.Body.String())
		}
		checkSafetyHeaders(t, sha, w)
	}
}

func TestEtagMatches(t *testing.T) {
	for h, want := range map[string]bool{`"a"`: true, `W/"a"`: true, `*`: true, `"b", "a"`: true, `"b"`: false, `a`: false} {
		if got := etagMatches(h, `"a"`); got != want {
			t.Errorf("%q: %v", h, got)
		}
	}
}
