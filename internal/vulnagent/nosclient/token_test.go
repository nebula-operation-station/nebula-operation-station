// SPDX-License-Identifier: AGPL-3.0-or-later

package nosclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Synthetic test token, never a real credential.
const testToken = "nos_test-vuln-agent-token"

func writeToken(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadTokenReadsOwnerOnlyFile(t *testing.T) {
	for _, mode := range []os.FileMode{0o600, 0o400} {
		p := writeToken(t, testToken+"\n", mode)
		tok, err := LoadToken(p)
		if err != nil {
			t.Fatalf("mode %o: %v", mode, err)
		}
		if tok.value != testToken {
			t.Fatalf("mode %o: token not trimmed", mode)
		}
	}
}

func TestLoadTokenRefusesGroupOrWorldReadableFile(t *testing.T) {
	for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o660, 0o606, 0o620, 0o602, 0o610, 0o601} {
		p := writeToken(t, testToken, mode)
		_, err := LoadToken(p)
		if !errors.Is(err, ErrTokenFilePermissions) {
			t.Fatalf("mode %o: got %v", mode, err)
		}
		if strings.Contains(err.Error(), testToken) {
			t.Fatalf("mode %o: error quotes the token", mode)
		}
	}
}

func TestLoadTokenRefusesMalformedContent(t *testing.T) {
	cases := map[string]string{
		"empty":        "",
		"only newline": "\n",
		"inner space":  "nos_abc def",
		"two lines":    "nos_abc\nnos_def\n",
		"control":      "nos_abc\x00",
		"non-ascii":    "nos_äbc",
		"too long":     strings.Repeat("a", MaxTokenBytes+1),
	}
	for name, content := range cases {
		p := writeToken(t, content, 0o600)
		_, err := LoadToken(p)
		if !errors.Is(err, ErrTokenMalformed) {
			t.Fatalf("%s: got %v", name, err)
		}
		if c := strings.TrimSpace(content); c != "" && strings.Contains(err.Error(), c) {
			t.Fatalf("%s: error quotes the content", name)
		}
	}
}

func TestLoadTokenRefusesNonRegularFilesAndMissingFiles(t *testing.T) {
	if _, err := LoadToken(t.TempDir()); err == nil {
		t.Fatal("directory accepted")
	}
	if _, err := LoadToken(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing file accepted")
	}
	if _, err := LoadToken(""); err == nil {
		t.Fatal("empty path accepted")
	}
}

func TestTokenNeverFormatsItsValue(t *testing.T) {
	tok, err := LoadToken(writeToken(t, testToken, 0o600))
	if err != nil {
		t.Fatal(err)
	}
	var buf strings.Builder
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	log.Info("x", "token", tok, "ptr", &tok)
	js, err := json.Marshal(struct{ T Token }{tok})
	if err != nil {
		t.Fatal(err)
	}
	outs := []string{
		fmt.Sprint(tok), fmt.Sprintf("%v %+v %#v %s %q %x", tok, tok, tok, tok, tok, tok),
		fmt.Sprintf("%v", &tok), buf.String(), string(js),
	}
	for _, o := range outs {
		if strings.Contains(o, testToken) || strings.Contains(o, fmt.Sprintf("%x", testToken)) {
			t.Fatalf("token leaked: %s", o)
		}
	}
}

func TestRedactRemovesTheToken(t *testing.T) {
	tok := Token{value: testToken}
	got := tok.redact("Get https://nos/?x=" + testToken + ": boom " + testToken)
	if strings.Contains(got, testToken) || !strings.Contains(got, redacted) {
		t.Fatalf("%q", got)
	}
}
