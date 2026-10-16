// SPDX-License-Identifier: AGPL-3.0-or-later

package actions

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

var (
	digestA = "sha256:" + strings.Repeat("a", 64)
	digestB = "sha256:" + strings.Repeat("b", 64)
	digestC = "sha256:" + strings.Repeat("c", 64)
)

// TestDockerCheckUpdatesScript runs the script against a TLS test
// registry: anonymous token flow, an image that is current, one with an
// update, one whose token is refused, and a pinned one. It checks that
// only HEAD requests reach the manifests and no credentials are sent.
func TestDockerCheckUpdatesScript(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl missing")
	}
	var mu sync.Mutex
	var methods []string
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		methods = append(methods, r.Method+" "+r.URL.Path)
		mu.Unlock()
		switch {
		case r.URL.Path == "/token":
			if r.URL.Query().Get("scope") == "repository:private:pull" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"token":"eyJ.tok_DEF-123=","expires_in":300}`))
		case strings.HasPrefix(r.URL.Path, "/v2/"):
			if r.Header.Get("Authorization") != "Bearer eyJ.tok_DEF-123=" {
				w.Header().Set("WWW-Authenticate", `Bearer realm="`+srv.URL+`/token",service="test-registry"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if !strings.Contains(r.Header.Get("Accept"), "manifest.list.v2+json") {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			switch r.URL.Path {
			case "/v2/app/manifests/1":
				w.Header().Set("Docker-Content-Digest", digestA)
			case "/v2/team/old/manifests/2":
				w.Header().Set("Docker-Content-Digest", digestB)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	reg := u.Host
	f := newFakeHost(t, "1")
	ca := filepath.Join(f.dir, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	f.write(t, "docker", `case "$1" in
  version) echo 27 ;;
  ps) printf '%s\n' "`+reg+`/app:1" "`+reg+`/team/old:2" "`+reg+`/private:1" "busybox@`+digestC+`" ;;
  image) case "$5" in
      *app:1) echo "`+reg+`/app@`+digestA+` " ;;
      *old:2) echo "`+reg+`/team/old@`+digestC+` " ;;
      *) echo "" ;;
    esac ;;
esac`)
	a, ok := Lookup("docker.check_updates")
	if !ok || !a.ReadOnly || a.Risk.String() != "RISK_CLASS_LOW" {
		t.Fatalf("%+v", a)
	}
	p := filepath.Join(f.dir, "s.sh")
	if err := os.WriteFile(p, a.Script, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", p)
	cmd.Env = []string{"PATH=" + f.bin + ":/usr/bin:/bin", "CURL_CA_BUNDLE=" + ca, "HOME=" + f.dir}
	var stderr strings.Builder
	if os.Getenv("NEBULA_DEBUG_SCRIPT") != "" {
		cmd = exec.Command("/bin/sh", "-x", p)
		cmd.Env = []string{"PATH=" + f.bin + ":/usr/bin:/bin", "CURL_CA_BUNDLE=" + ca, "HOME=" + f.dir}
		cmd.Stderr = &stderr
		defer func() { t.Log(stderr.String()) }()
	}
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%v %s", err, out)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("%s: %v", out, err)
	}
	lines := b64(t, doc, "lines")
	for _, want := range []string{
		reg + "/app:1\tcurrent\t" + digestA + "\t\n",
		reg + "/team/old:2\tupdate\t" + digestB + "\tlocal " + digestC + "\n",
		reg + "/private:1\tunknown\t\tauthentication required\n",
		"busybox@" + digestC + "\tpinned\t\tthe image is pinned by digest\n",
	} {
		if !strings.Contains(lines, want) {
			t.Errorf("missing %q in %q", want, lines)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	for _, m := range methods {
		if strings.HasPrefix(m, "GET /v2/") || strings.HasPrefix(m, "POST") {
			t.Errorf("request %s: only HEAD may reach a manifest", m)
		}
	}
}
