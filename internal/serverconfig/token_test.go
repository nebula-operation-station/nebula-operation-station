// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Tests for the Token type: every formatting, logging, and serialization
// path must print "[redacted]" instead of the secret.

package serverconfig

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

const tokenSecret = "super-secret-token-xyz-123"

func TestTokenRedactedInFormatting(t *testing.T) {
	cfg, err := Parse([]byte(tokenJSON))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Token != tokenSecret {
		t.Fatal("token not parsed")
	}
	out := []string{
		cfg.Token.String(),
		cfg.Token.GoString(),
		fmt.Sprintf("%v", cfg.Token),
		fmt.Sprintf("%s", cfg.Token),
		fmt.Sprintf("%q", cfg.Token),
		fmt.Sprintf("%#v", cfg.Token),
		fmt.Sprintf("%v", cfg),
		fmt.Sprintf("%+v", cfg),
		fmt.Sprintf("%#v", cfg),
	}
	for _, s := range out {
		if strings.Contains(s, tokenSecret) {
			t.Errorf("token leaked: %q", s)
		}
	}
	if got := fmt.Sprintf("%+v", cfg); !strings.Contains(got, "[redacted]") {
		t.Errorf("%%+v does not show the redaction marker: %q", got)
	}
}

func TestTokenRedactedInSlog(t *testing.T) {
	cfg, err := Parse([]byte(tokenJSON))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	log.Info("config", slog.Any("cfg", cfg))
	log.Info("token", "token", cfg.Token)
	if got := buf.String(); strings.Contains(got, tokenSecret) {
		t.Errorf("token leaked into slog output: %s", got)
	}
	if got := buf.String(); !strings.Contains(got, "[redacted]") {
		t.Errorf("redaction marker missing from slog output: %s", got)
	}
}

func TestTokenRedactedInJSON(t *testing.T) {
	cfg, err := Parse([]byte(tokenJSON))
	if err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), tokenSecret) {
		t.Errorf("token leaked into JSON: %s", out)
	}
}
