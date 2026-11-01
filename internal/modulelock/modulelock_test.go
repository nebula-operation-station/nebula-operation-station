// SPDX-License-Identifier: AGPL-3.0-or-later

package modulelock

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/prelude"
)

var script = []byte("#!/bin/sh\nsystemctl restart telegraf\n")

func sum(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func valid() Lock {
	return Lock{Format: Format, Name: "telegraf", Version: "1.2.0", Title: "Telegraf", Description: "Metrics agent.",
		Actions: map[string]Action{"restart": {Title: "Restart", Description: "", Script: "actions/restart.sh", SHA256: sum(script),
			Risk: "LOW", TimeoutS: 60, Params: []prelude.Param{{Name: "unit", Label: "Unit", Type: prelude.TypeName}},
			Secrets: []string{}, Declares: []string{"requires_root"}}}}
}

func raw(t *testing.T, l Lock) []byte {
	t.Helper()
	b, err := json.Marshal(l)
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := canonical.CanonicalParameters(b)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Only the canonical bytes are a lock: the signed bytes and the recorded
// hash must be the same thing.
func TestParseRefusesNonCanonicalBytes(t *testing.T) {
	plain, err := json.Marshal(valid())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Parse(plain); !errors.Is(err, ErrInvalid) {
		t.Fatal("reordered members accepted")
	}
	c := raw(t, valid())
	if _, _, err := Parse(append(append([]byte{}, c...), '\n')); !errors.Is(err, ErrInvalid) {
		t.Fatal("trailing newline accepted")
	}
	if _, h, err := Parse(c); err != nil || h != sum(c) {
		t.Fatal("the hash is not the hash of the signed bytes", err)
	}
}

func TestParse(t *testing.T) {
	l, h, err := Parse(raw(t, valid()))
	if err != nil || len(h) != 64 || l.ActionID("restart") != "telegraf.restart" || l.Actions["restart"].TrustRisk() != "MEDIUM" {
		t.Fatalf("%v %s", err, h)
	}
	art, as, err := l.Artifact("restart", script)
	if err != nil || len(as) != 64 || !strings.Contains(string(art), "systemctl restart telegraf") || !strings.Contains(string(art), "module telegraf 1.2.0 action restart") {
		t.Fatalf("%v", err)
	}
	if _, _, err := l.Artifact("restart", append(script, '#')); !errors.Is(err, ErrInvalid) {
		t.Fatal("changed script accepted")
	}
	if _, _, err := l.Artifact("nope", script); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if _, _, err := l.Artifact("restart", []byte("a\u202eb")); !errors.Is(err, ErrInvalid) {
		t.Fatal("bidi script accepted")
	}
}

func TestParseRefuses(t *testing.T) {
	for name, mut := range map[string]func(*Lock){
		"format":   func(l *Lock) { l.Format = "x" },
		"reserved": func(l *Lock) { l.Name = "docker" },
		"name":     func(l *Lock) { l.Name = "Tele" },
		"version":  func(l *Lock) { l.Version = "1.2" },
		"title":    func(l *Lock) { l.Title = "" },
		"no actions": func(l *Lock) {
			l.Actions = map[string]Action{}
		},
		"action name": func(l *Lock) { l.Actions["Bad"] = l.Actions["restart"] },
		"script path": func(l *Lock) { a := l.Actions["restart"]; a.Script = "../etc/passwd"; l.Actions["restart"] = a },
		"abs path":    func(l *Lock) { a := l.Actions["restart"]; a.Script = "/bin/sh"; l.Actions["restart"] = a },
		"sha":         func(l *Lock) { a := l.Actions["restart"]; a.SHA256 = "x"; l.Actions["restart"] = a },
		"risk":        func(l *Lock) { a := l.Actions["restart"]; a.Risk = "low"; l.Actions["restart"] = a },
		"timeout":     func(l *Lock) { a := l.Actions["restart"]; a.TimeoutS = 3600; l.Actions["restart"] = a },
		"param": func(l *Lock) {
			a := l.Actions["restart"]
			a.Params = []prelude.Param{{Name: "x", Label: "X", Type: "string"}}
			l.Actions["restart"] = a
		},
		"declares":  func(l *Lock) { a := l.Actions["restart"]; a.Declares = []string{"sandboxed"}; l.Actions["restart"] = a },
		"nil lists": func(l *Lock) { a := l.Actions["restart"]; a.Secrets = nil; l.Actions["restart"] = a },
	} {
		l := valid()
		l.Actions = map[string]Action{"restart": l.Actions["restart"]}
		mut(&l)
		if _, _, err := Parse(raw(t, l)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Not the exact form: an unknown member, or a missing one.
	b := strings.Replace(string(raw(t, valid())), `"format"`, `"extra":1,"format"`, 1)
	if _, _, err := Parse([]byte(b)); !errors.Is(err, ErrInvalid) {
		t.Fatal("unknown member accepted")
	}
	b = strings.Replace(string(raw(t, valid())), `"description":"Metrics agent.",`, ``, 1)
	if _, _, err := Parse([]byte(b)); !errors.Is(err, ErrInvalid) {
		t.Fatal("missing member accepted")
	}
}

// The release-bundle profile admits first-party family names, including
// reserved built-in names and os-debian; the third-party profile still
// refuses them, and every other check applies to both.
func TestParseFirstPartyProfile(t *testing.T) {
	for _, name := range []string{"docker", "core", "os-debian", "package"} {
		l := valid()
		l.Name = name
		if _, _, err := Parse(raw(t, l)); !errors.Is(err, ErrInvalid) {
			t.Fatalf("third-party Parse accepted %q", name)
		}
		got, _, err := ParseFirstParty(raw(t, l))
		if err != nil || got.ActionID("restart") != name+".restart" {
			t.Fatalf("ParseFirstParty(%q): %v", name, err)
		}
	}
	for name, mut := range map[string]func(*Lock){
		"uppercase":     func(l *Lock) { l.Name = "Docker" },
		"leading digit": func(l *Lock) { l.Name = "1os" },
		"too long":      func(l *Lock) { l.Name = "a" + strings.Repeat("b", 64) },
		"dot":           func(l *Lock) { l.Name = "os.debian" },
		"version":       func(l *Lock) { l.Name = "docker"; l.Version = "1.2" },
		"risk":          func(l *Lock) { l.Name = "docker"; a := l.Actions["restart"]; a.Risk = "low"; l.Actions["restart"] = a },
	} {
		l := valid()
		mut(&l)
		if _, _, err := ParseFirstParty(raw(t, l)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: ParseFirstParty accepted it", name)
		}
	}
}
