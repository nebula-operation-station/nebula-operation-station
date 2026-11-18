// SPDX-License-Identifier: AGPL-3.0-or-later

package run

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// Synthetic probe token, never a real credential. It is deliberately
// distinctive so that any leak shows up in a test output.
const secretProbe = "nos-probe-ua03-7f3a9c-do-not-print"

// placeholder is what every printing path must show instead of the value.
const placeholder = "[REDACTED]"

// assertNoProbe fails if the output contains the token in plain text or in
// hex, and requires the placeholder to be present.
func assertNoProbe(t *testing.T, label, out string) {
	t.Helper()
	if strings.Contains(out, secretProbe) {
		t.Fatalf("%s: token leaked: %q", label, out)
	}
	if strings.Contains(out, hex.EncodeToString([]byte(secretProbe))) {
		t.Fatalf("%s: token leaked in hex: %q", label, out)
	}
	if !strings.Contains(out, placeholder) {
		t.Fatalf("%s: placeholder missing: %q", label, out)
	}
}

func TestSecretNeverFormatsItsValue(t *testing.T) {
	s := secret{v: secretProbe}
	cases := map[string]string{
		"%v":       fmt.Sprintf("%v", s),
		"%+v":      fmt.Sprintf("%+v", s),
		"%#v":      fmt.Sprintf("%#v", s),
		"%s":       fmt.Sprintf("%s", s),
		"%q":       fmt.Sprintf("%q", s),
		"%x":       fmt.Sprintf("%x", s),
		"%X":       fmt.Sprintf("%X", s),
		"%d":       fmt.Sprintf("%d", s),
		"Sprint":   fmt.Sprint(s),
		"Sprintln": fmt.Sprintln(s),
		"ptr %v":   fmt.Sprintf("%v", &s),
		"ptr %#v":  fmt.Sprintf("%#v", &s),
	}
	for label, out := range cases {
		assertNoProbe(t, label, out)
	}
}

func TestSecretNeverLeaksThroughSlog(t *testing.T) {
	s := secret{v: secretProbe}
	type holder struct {
		Token secret
		Note  string
	}
	h := holder{Token: s, Note: "x"}
	for _, mk := range map[string]func(*bytes.Buffer) slog.Handler{
		"text": func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) },
		"json": func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) },
	} {
		var buf bytes.Buffer
		log := slog.New(mk(&buf))
		log.Info("attr", "token", s)
		log.Info("ptr", "token", &s)
		log.Info("struct", "cfg", h)
		log.Info("group", slog.Group("g", slog.Any("token", s)))
		assertNoProbe(t, "slog", buf.String())
	}
}

func TestSecretNeverMarshalsItsValue(t *testing.T) {
	s := secret{v: secretProbe}
	type holder struct {
		Token secret `json:"token"`
	}
	for label, v := range map[string]any{
		"value":      s,
		"pointer":    &s,
		"struct":     holder{Token: s},
		"struct ptr": &holder{Token: s},
	} {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		assertNoProbe(t, "json "+label, string(b))
	}
}

func TestHTTPAgentConfigNeverFormatsItsToken(t *testing.T) {
	c := HTTPAgentConfig{
		endpoint: "https://nos.example.invalid" + AgentConfigPath,
		token:    secret{v: secretProbe},
	}
	for label, out := range map[string]string{
		"%+v value":   fmt.Sprintf("%+v", c),
		"%#v value":   fmt.Sprintf("%#v", c),
		"%+v pointer": fmt.Sprintf("%+v", &c),
		"%#v pointer": fmt.Sprintf("%#v", &c),
		"%v pointer":  fmt.Sprintf("%v", &c),
	} {
		if strings.Contains(out, secretProbe) {
			t.Fatalf("%s: token leaked: %q", label, out)
		}
	}
}

func TestRedactRemovesEveryTokenOccurrence(t *testing.T) {
	c := &HTTPAgentConfig{token: secret{v: secretProbe}}
	in := "Get https://nos.example.invalid/?x=" + secretProbe + ": boom " + secretProbe + " end " + secretProbe
	got := c.redact(in)
	if strings.Contains(got, secretProbe) {
		t.Fatalf("token survived redact: %q", got)
	}
	if n := strings.Count(got, placeholder); n != 3 {
		t.Fatalf("want 3 placeholders, got %d in %q", n, got)
	}
}

func TestRedactLeavesTextWithoutTokenUnchanged(t *testing.T) {
	c := &HTTPAgentConfig{token: secret{v: secretProbe}}
	for _, in := range []string{"", "dial tcp: connection refused", "HTTP 500", "nos-probe-ua03"} {
		if got := c.redact(in); got != in {
			t.Fatalf("text without token changed: %q -> %q", in, got)
		}
	}
}

func TestRedactWithEmptyTokenChangesNothing(t *testing.T) {
	c := &HTTPAgentConfig{token: secret{}}
	in := "some error text with no secret"
	if got := c.redact(in); got != in {
		t.Fatalf("empty token altered text: %q -> %q", in, got)
	}
}
