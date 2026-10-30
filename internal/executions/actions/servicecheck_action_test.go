// SPDX-License-Identifier: AGPL-3.0-or-later

package actions

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestServiceCheckParamsAreStrict checks the service.check parameter
// rules: the four parameters with their patterns, plus the
// reserved-destination approval (SSRF refusal) from
// servicecheck.ValidateCheck.
func TestServiceCheckParamsAreStrict(t *testing.T) {
	a, ok := Lookup("service.check")
	if !ok {
		t.Fatal("service.check not found")
	}
	valid := func(destination, port, protocol, internal string) map[string]string {
		return map[string]string{"destination": destination, "port": port, "protocol": protocol, "internal": internal}
	}
	for _, tc := range []struct {
		name   string
		params map[string]string
		ok     bool
	}{
		{"hostname http", valid("web1.example.internal", "8080", "http", "no"), true},
		{"public ip tcp", valid("203.0.113.10", "9000", "tcp", "no"), true},
		{"reserved ip approved", valid("169.254.169.254", "80", "http", "yes"), true},
		{"missing destination", map[string]string{"port": "80", "protocol": "http", "internal": "no"}, false},
		{"extra parameter", func() map[string]string {
			p := valid("web1", "80", "http", "no")
			p["body"] = "x"
			return p
		}(), false},
		{"bad protocol", valid("web1", "80", "ftp", "no"), false},
		{"port zero", valid("web1", "0", "http", "no"), false},
		{"port above range", valid("web1", "65536", "http", "no"), false},
		{"destination with scheme", valid("http://web1", "80", "http", "no"), false},
		{"destination with path", valid("web1/x", "80", "http", "no"), false},
		{"destination with space", valid("web 1", "80", "http", "no"), false},
		{"metadata ip not approved", valid("169.254.169.254", "80", "http", "no"), false},
		{"loopback not approved", valid("127.0.0.1", "80", "tcp", "no"), false},
		{"private ip not approved", valid("10.0.0.5", "80", "tcp", "no"), false},
		{"cg nat ip not approved", valid("100.64.0.1", "80", "tcp", "no"), false},
		{"ipv6 loopback not approved", valid("::1", "80", "tcp", "no"), false},
		{"ipv6 link local not approved", valid("fe80::1", "80", "tcp", "no"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := a.ValidParams(tc.params)
			if tc.ok && err != nil {
				t.Errorf("rejected: %v", err)
			}
			if !tc.ok && err == nil {
				t.Error("accepted")
			}
		})
	}
}

// runServiceCheck runs the embedded service.check script with the given
// parameters document (real curl, loopback destinations only) and returns
// the exit code and the result document.
func runServiceCheck(t *testing.T, params string) (int, map[string]any) {
	t.Helper()
	a, ok := Lookup("service.check")
	if !ok {
		t.Fatal("service.check not found")
	}
	p := filepath.Join(t.TempDir(), "params")
	if err := os.WriteFile(p, []byte(params), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", "-c", string(a.Script))
	cmd.Env = []string{"PATH=/usr/bin:/bin", "NEBULA_PARAMS=" + p}
	out, err := cmd.Output()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("result %q: %v", out, err)
	}
	return code, doc
}

// TestServiceCheckScriptPrecheck checks the script's precheck refusals
// (missing or invalid parameters, unapproved reserved destinations).
func TestServiceCheckScriptPrecheck(t *testing.T) {
	for _, tc := range []struct {
		name   string
		params string
	}{
		{"missing parameter", `{"destination":"web1","port":"80","protocol":"http"}`},
		{"port zero", `{"destination":"web1","port":"0","protocol":"http","internal":"no"}`},
		{"port above range", `{"destination":"web1","port":"70000","protocol":"http","internal":"no"}`},
		{"metadata ip not approved", `{"destination":"169.254.169.254","port":"80","protocol":"http","internal":"no"}`},
		{"loopback not approved", `{"destination":"127.0.0.1","port":"80","protocol":"tcp","internal":"no"}`},
		{"private ip not approved", `{"destination":"10.0.0.5","port":"80","protocol":"tcp","internal":"no"}`},
		{"ipv6 not approved", `{"destination":"::1","port":"80","protocol":"tcp","internal":"no"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, doc := runServiceCheck(t, tc.params)
			if code != 10 {
				t.Errorf("exit = %d, want 10", code)
			}
			if doc["phase"] != "precheck" {
				t.Errorf("phase = %v, want precheck", doc["phase"])
			}
		})
	}
}

// TestServiceCheckScriptProbes runs the script against loopback targets:
// a TCP listener (ok), HTTP servers (ok, redirect, http-error), a
// never-answering listener (timeout) and a closed port (refused). The
// redirect must be reported, not followed.
func TestServiceCheckScriptProbes(t *testing.T) {
	// Plain TCP listener on loopback.
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpLn.Close()
	go func() {
		for {
			c, err := tcpLn.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	tcpPort := fmt.Sprint(tcpLn.Addr().(*net.TCPAddr).Port)

	// One HTTP server per behaviour; the script probes the fixed path /.
	httpPort := func(code int) string {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(code)
		}))
		t.Cleanup(srv.Close)
		return fmt.Sprint(srv.Listener.Addr().(*net.TCPAddr).Port)
	}
	okPort := httpPort(http.StatusOK)
	redirectPort := httpPort(http.StatusMovedPermanently)
	downPort := httpPort(http.StatusServiceUnavailable)

	// A listener that accepts but never answers: the probe must time out.
	stallLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer stallLn.Close()
	go func() {
		for {
			c, err := stallLn.Accept()
			if err != nil {
				return
			}
			// Hold the connection open without reading or writing.
			go func() { select {} }()
			_ = c
		}
	}()
	stallPort := fmt.Sprint(stallLn.Addr().(*net.TCPAddr).Port)

	// A closed port for the refused case.
	closedLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := fmt.Sprint(closedLn.Addr().(*net.TCPAddr).Port)
	closedLn.Close()

	for _, tc := range []struct {
		name   string
		params string
		status any
		http   float64
	}{
		{"tcp ok", fmt.Sprintf(`{"destination":"127.0.0.1","port":"%s","protocol":"tcp","internal":"yes"}`, tcpPort), "ok", 0},
		{"http ok", fmt.Sprintf(`{"destination":"127.0.0.1","port":"%s","protocol":"http","internal":"yes"}`, okPort), "ok", 200},
		{"redirect reported", fmt.Sprintf(`{"destination":"127.0.0.1","port":"%s","protocol":"http","internal":"yes"}`, redirectPort), "redirect", 301},
		{"http error", fmt.Sprintf(`{"destination":"127.0.0.1","port":"%s","protocol":"http","internal":"yes"}`, downPort), "http-error", 503},
		{"timeout", fmt.Sprintf(`{"destination":"127.0.0.1","port":"%s","protocol":"http","internal":"yes"}`, stallPort), "timeout", 0},
		{"refused", fmt.Sprintf(`{"destination":"127.0.0.1","port":"%s","protocol":"tcp","internal":"yes"}`, closedPort), "refused", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, doc := runServiceCheck(t, tc.params)
			if code != 0 {
				t.Fatalf("exit = %d, want 0 (doc %v)", code, doc)
			}
			if doc["phase"] != "done" {
				t.Errorf("phase = %v, want done", doc["phase"])
			}
			if doc["status"] != tc.status {
				t.Errorf("status = %v, want %v", doc["status"], tc.status)
			}
			if doc["http_status"] != tc.http {
				t.Errorf("http_status = %v, want %v", doc["http_status"], tc.http)
			}
		})
	}
}

// TestServiceCheckScriptRedirectNotFollowed checks that the redirect
// target (127.0.0.1:1, closed) is never probed: the result must be the
// 301 from the first hop, not the failure of the second.
func TestServiceCheckScriptRedirectNotFollowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/", http.StatusMovedPermanently)
	}))
	defer srv.Close()
	port := fmt.Sprint(srv.Listener.Addr().(*net.TCPAddr).Port)
	params := fmt.Sprintf(`{"destination":"127.0.0.1","port":"%s","protocol":"http","internal":"yes"}`, port)
	code, doc := runServiceCheck(t, params)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (doc %v)", code, doc)
	}
	if doc["status"] != "redirect" || doc["http_status"] != 301.0 {
		t.Errorf("status = %v, http_status = %v; want redirect 301 (the redirect target must not be probed)", doc["status"], doc["http_status"])
	}
	if strings.Contains(fmt.Sprint(doc), "127.0.0.1:1") {
		t.Error("the result must not contain the redirect target")
	}
}
