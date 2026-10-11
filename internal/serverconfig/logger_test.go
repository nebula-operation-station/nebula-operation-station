// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Tests for the structured logger: JSON output and the guarantee that a
// configured secret (the token) never appears in log output (acceptance
// criterion 4).

package serverconfig

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const tokenJSON = `{
	"public_origin": "https://nebula.example.org",
	"data_dir": "/var/lib/nebula",
	"executor_socket": "/run/nebula/executor.sock",
	"executor_user": "nebula-exec",
	"token": "super-secret-token-xyz-123"
}`

func TestTokenNeverInLogs(t *testing.T) {
	const token = "super-secret-token-xyz-123"
	cfg, err := Parse([]byte(tokenJSON))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Token != token {
		t.Fatalf("token not parsed: %q", cfg.Token)
	}

	var buf bytes.Buffer
	log := NewLogger(&buf, cfg)
	log.Info("server starting")
	log.Info("some event", "detail", "value")
	log.Warn("something happened", "code", 42)

	out := buf.String()
	if strings.Contains(out, token) {
		t.Errorf("token leaked into log output:\n%s", out)
	}
}

func TestLoggerIsJSON(t *testing.T) {
	var buf bytes.Buffer
	log := NewLogger(&buf, Config{Listen: DefaultListen})
	log.Info("hello")

	// Each line must be valid JSON with the bound config attributes.
	var first map[string]any
	if err := json.Unmarshal(buf.Bytes(), &first); err != nil {
		t.Fatalf("log output is not JSON: %v\n%s", err, buf.String())
	}
	if first["msg"] != "hello" {
		t.Errorf("msg = %v", first["msg"])
	}
	if first["listen"] != DefaultListen {
		t.Errorf("bound listen attr = %v, want %q", first["listen"], DefaultListen)
	}
	if _, ok := first["token"]; ok {
		t.Error("token attribute present in log output")
	}
}

func TestLogAttrsExcludesToken(t *testing.T) {
	cfg := Config{
		Listen:         "127.0.0.1:8080",
		PublicOrigin:   "https://n.example",
		DataDir:        "/d",
		ExecutorSocket: "/s",
		ExecutorUser:   "u",
		Token:          "secret-value",
	}
	var sb strings.Builder
	for _, a := range cfg.LogAttrs() {
		sb.WriteString(a.String())
	}
	if strings.Contains(sb.String(), "secret-value") {
		t.Errorf("LogAttrs includes the token: %s", sb.String())
	}
}
