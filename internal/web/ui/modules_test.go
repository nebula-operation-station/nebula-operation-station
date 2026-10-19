// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/modulelock"
	"github.com/nebula-operation-station/nebula-operation-station/internal/modules"
	"github.com/nebula-operation-station/nebula-operation-station/internal/prelude"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// hostileModule is an unsigned module whose texts try to inject HTML.
func hostileModule(t *testing.T) []byte {
	t.Helper()
	script := []byte("echo '</pre><script>alert(1)</script>'\nsudo -n reboot\n")
	s := sha256.Sum256(script)
	l := modulelock.Lock{Format: modulelock.Format, Name: "evil", Version: "1.0.0", Title: "<img src=x onerror=alert(2)>",
		Description: "<script>alert(3)</script>", Actions: map[string]modulelock.Action{"run": {Title: "<b>Run</b>", Script: "run.sh",
			SHA256: hex.EncodeToString(s[:]), Risk: "LOW", TimeoutS: 60, Params: []prelude.Param{{Name: "x", Label: "<i>X</i>", Type: "name"}},
			Secrets: []string{}, Declares: []string{"network_access"}}}}
	raw, _ := json.Marshal(l)
	lock, _, err := canonical.CanonicalParameters(raw)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for name, b := range map[string][]byte{"module.lock.json": lock, "run.sh": script} {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(b)), Typeflag: tar.TypeReg})
		_, _ = tw.Write(b)
	}
	_ = tw.Close()
	_ = zw.Close()
	return buf.Bytes()
}

func TestModulePages(t *testing.T) {
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org", Modules: modules.New(db, nil)}).Handler()
	if page := getBody(t, h, "/modules"); !strings.Contains(page, "No modules yet.") {
		t.Fatal(page)
	}
	post := func(ct string, body []byte) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/modules/import", bytes.NewReader(body))
		req.Header.Set("Content-Type", ct)
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if post("application/json", hostileModule(t)) != http.StatusUnsupportedMediaType {
		t.Fatal("JSON content type accepted for an archive")
	}
	if post("application/gzip", []byte("nope")) != http.StatusBadRequest {
		t.Fatal("garbage accepted")
	}
	if code := post("application/gzip", hostileModule(t)); code != http.StatusOK {
		t.Fatal(code)
	}
	list := getBody(t, h, "/modules")
	if !strings.Contains(list, `<a href="/modules/evil">evil</a>`) || !strings.Contains(list, "unverified") || strings.Contains(list, "<img src=x") {
		t.Fatal(list)
	}
	page := getBody(t, h, "/modules/evil")
	for _, want := range []string{"Unverified", "not signed", "&lt;img src=x onerror=alert(2)&gt;", "&lt;/pre&gt;&lt;script&gt;alert(1)", "reboot_or_power",
		`href="/operations/new?action=evil.run"`, "declares network_access"} {
		if !strings.Contains(page, want) {
			t.Errorf("page misses %q", want)
		}
	}
	if strings.Contains(page, "<script>alert") || strings.Contains(page, "<img src=x") || strings.Contains(page, "<b>Run</b>") {
		t.Fatal("unescaped module text")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/modules/nope", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatal(rec.Code)
	}
	if code, _ := postJSON(t, h, "/modules/verify", `{"name":"evil","version":"1.0.0"}`); code != http.StatusOK {
		t.Fatal(code)
	}
}
