// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
)

type fakeAgentAuditor struct {
	kinds []string
	attrs []map[string]string
	err   error
}

func (f *fakeAgentAuditor) Append(_ context.Context, kind string, attrs map[string]string) error {
	if f.err != nil {
		return f.err
	}
	f.kinds = append(f.kinds, kind)
	f.attrs = append(f.attrs, attrs)
	return nil
}

var agentNow = time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC)

func newAgentStore(t *testing.T) *AgentConfigStore {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	s, err := NewAgentConfigStore(db, func() time.Time { return agentNow })
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	return s
}

func validAgentSettings() AgentSettings {
	return AgentSettings{LLMEnabled: true, LLMBaseURL: "http://192.168.0.26:11434/v1", LLMModel: "qwen3.5-9b-64k", Language: "en",
		OperatorInstructions: "Prefer short answers.\nMention Debian backports."}
}

func TestAgentConfigDefaultsWhenNeverSaved(t *testing.T) {
	s := newAgentStore(t)
	c, err := s.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := AgentConfig{AgentSettings: AgentSettings{LLMEnabled: true, LLMModel: DefaultAgentLLMModel, Language: AgentLanguageDE}}
	if c != want {
		t.Fatalf("defaults %+v, want %+v", c, want)
	}
	if c.LLMBaseURL != "" {
		t.Fatal("the placeholder URL must never be served as a stored value")
	}
}

func TestAgentConfigChangeStoresAuditsAndBumpsVersion(t *testing.T) {
	s := newAgentStore(t)
	ctx := context.Background()
	au := &fakeAgentAuditor{}
	in := validAgentSettings()
	old, cur, err := s.Change(ctx, AgentChange{Settings: in, BaseVersion: 0, Actor: "admin"}, au)
	if err != nil {
		t.Fatal(err)
	}
	if old.Version != 0 || cur.Version != 1 || cur.AgentSettings != in || cur.UpdatedBy != "admin" || !cur.UpdatedAt.Equal(agentNow) {
		t.Fatalf("change returned old %+v new %+v", old, cur)
	}
	got, err := s.Get(ctx)
	if err != nil || got != cur {
		t.Fatalf("get %+v, %v; want %+v", got, err, cur)
	}
	if len(au.kinds) != 1 || au.kinds[0] != AuditAgentLLMChanged {
		t.Fatalf("audit kinds %v", au.kinds)
	}
	a := au.attrs[0]
	opSum := sha256.Sum256([]byte(in.OperatorInstructions))
	for k, v := range map[string]string{
		"actor": "admin", "old_llm_base_url": "", "new_llm_base_url": in.LLMBaseURL,
		"old_llm_model": DefaultAgentLLMModel, "new_llm_model": in.LLMModel,
		"old_llm_enabled": "true", "new_llm_enabled": "true",
		"old_language": "de", "new_language": "en", "llm_base_url_changed": "true",
		"old_version": "0", "new_version": "1",
		"old_operator_instructions_bytes":  "0",
		"new_operator_instructions_bytes":  strconv.Itoa(len(in.OperatorInstructions)),
		"new_operator_instructions_sha256": hex.EncodeToString(opSum[:]),
		"operator_instructions_changed":    "true",
	} {
		if a[k] != v {
			t.Errorf("audit %s = %q, want %q", k, a[k], v)
		}
	}
	// A second change from the same base version is a conflict.
	if _, _, err := s.Change(ctx, AgentChange{Settings: in, BaseVersion: 0, Actor: "admin"}, au); !errors.Is(err, ErrAgentConfigConflict) {
		t.Fatalf("stale base version: %v, want ErrAgentConfigConflict", err)
	}
	in.LLMModel = "llama3"
	_, cur, err = s.Change(ctx, AgentChange{Settings: in, BaseVersion: 1, Actor: "admin"}, au)
	if err != nil || cur.Version != 2 {
		t.Fatalf("second change: %+v %v", cur, err)
	}
	if au.attrs[1]["llm_base_url_changed"] != "false" || au.attrs[1]["old_llm_model"] != "qwen3.5-9b-64k" {
		t.Errorf("second audit %v", au.attrs[1])
	}
}

func TestAgentConfigAuditFailureLeavesSettingsUnchanged(t *testing.T) {
	s := newAgentStore(t)
	ctx := context.Background()
	_, _, err := s.Change(ctx, AgentChange{Settings: validAgentSettings(), Actor: "admin"}, &fakeAgentAuditor{err: errors.New("disk full")})
	if err == nil {
		t.Fatal("change without audit entry succeeded")
	}
	c, err := s.Get(ctx)
	if err != nil || c.Version != 0 {
		t.Fatalf("settings changed without audit: %+v %v", c, err)
	}
	if _, _, err := s.Change(ctx, AgentChange{Settings: validAgentSettings(), Actor: "admin"}, nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil auditor: %v", err)
	}
}

func TestAgentConfigRejectsInvalidInput(t *testing.T) {
	s := newAgentStore(t)
	mod := func(f func(*AgentSettings)) AgentSettings {
		v := validAgentSettings()
		f(&v)
		return v
	}
	for name, in := range map[string]AgentSettings{
		"javascript":       mod(func(v *AgentSettings) { v.LLMBaseURL = "javascript:alert(1)" }),
		"file":             mod(func(v *AgentSettings) { v.LLMBaseURL = "file:///etc/passwd" }),
		"ftp":              mod(func(v *AgentSettings) { v.LLMBaseURL = "ftp://llm.lab/v1" }),
		"userinfo":         mod(func(v *AgentSettings) { v.LLMBaseURL = "http://user:pw@llm.lab/v1" }),
		"user only":        mod(func(v *AgentSettings) { v.LLMBaseURL = "http://user@llm.lab/v1" }),
		"fragment":         mod(func(v *AgentSettings) { v.LLMBaseURL = "http://llm.lab/v1#x" }),
		"empty fragment":   mod(func(v *AgentSettings) { v.LLMBaseURL = "http://llm.lab/v1#" }),
		"query":            mod(func(v *AgentSettings) { v.LLMBaseURL = "http://llm.lab/v1?a=b" }),
		"empty query":      mod(func(v *AgentSettings) { v.LLMBaseURL = "http://llm.lab/v1?" }),
		"no host":          mod(func(v *AgentSettings) { v.LLMBaseURL = "http:///v1" }),
		"relative":         mod(func(v *AgentSettings) { v.LLMBaseURL = "/v1" }),
		"opaque":           mod(func(v *AgentSettings) { v.LLMBaseURL = "http:llm.lab" }),
		"space":            mod(func(v *AgentSettings) { v.LLMBaseURL = "http://llm.lab/v 1" }),
		"backslash":        mod(func(v *AgentSettings) { v.LLMBaseURL = `http://llm.lab\@evil/v1` }),
		"non-ascii":        mod(func(v *AgentSettings) { v.LLMBaseURL = "http://llm.läb/v1" }),
		"bad port":         mod(func(v *AgentSettings) { v.LLMBaseURL = "http://llm.lab:99999/v1" }),
		"overlong url":     mod(func(v *AgentSettings) { v.LLMBaseURL = "http://llm.lab/" + strings.Repeat("a", MaxAgentLLMURL) }),
		"overlong model":   mod(func(v *AgentSettings) { v.LLMModel = strings.Repeat("m", MaxAgentLLMModel+1) }),
		"model control":    mod(func(v *AgentSettings) { v.LLMModel = "qwen\n" }),
		"model non-ascii":  mod(func(v *AgentSettings) { v.LLMModel = "qwén" }),
		"model space":      mod(func(v *AgentSettings) { v.LLMModel = "a b" }),
		"language":         mod(func(v *AgentSettings) { v.Language = "fr" }),
		"no language":      mod(func(v *AgentSettings) { v.Language = "" }),
		"operator long":    mod(func(v *AgentSettings) { v.OperatorInstructions = strings.Repeat("x", MaxAgentOperatorText+1) }),
		"operator utf8":    mod(func(v *AgentSettings) { v.OperatorInstructions = "a\xffb" }),
		"operator control": mod(func(v *AgentSettings) { v.OperatorInstructions = "a\x1bb" }),
		"operator cr":      mod(func(v *AgentSettings) { v.OperatorInstructions = "a\r\nb" }),
		"operator bidi":    mod(func(v *AgentSettings) { v.OperatorInstructions = "a‮b" }),
		"operator c1":      mod(func(v *AgentSettings) { v.OperatorInstructions = "a\u0085b" }),
	} {
		t.Run(name, func(t *testing.T) {
			if err := in.Validate(); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("validate: %v, want ErrInvalidInput", err)
			}
			if _, _, err := s.Change(context.Background(), AgentChange{Settings: in, Actor: "admin"}, &fakeAgentAuditor{}); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("change: %v, want ErrInvalidInput", err)
			}
		})
	}
	if _, _, err := s.Change(context.Background(), AgentChange{Settings: validAgentSettings(), Actor: "bad actor"}, &fakeAgentAuditor{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("bad actor: %v", err)
	}
}

func TestAgentConfigAcceptsValidInput(t *testing.T) {
	for _, in := range []AgentSettings{
		validAgentSettings(),
		{LLMEnabled: false, Language: "de"},
		{LLMEnabled: true, LLMBaseURL: "https://llm.lab.example:8443/v1/", LLMModel: "a", Language: "de"},
		{LLMEnabled: true, LLMBaseURL: "http://[fd00::26]:11434/v1", Language: "en"},
		{LLMEnabled: true, LLMBaseURL: "HTTP://LLM.LAB/v1", Language: "en"},
		{LLMEnabled: true, LLMModel: strings.Repeat("m", MaxAgentLLMModel), Language: "de", OperatorInstructions: strings.Repeat("ä", MaxAgentOperatorText/2) + ""},
		{LLMEnabled: true, Language: "de", OperatorInstructions: "Tab\tand\nnewline and Ümlaut"},
	} {
		if err := in.Validate(); err != nil {
			t.Errorf("%+v: %v", in, err)
		}
	}
}

func TestAgentPromptVersionCoversCoreAndOperatorText(t *testing.T) {
	a := AgentPromptVersion("core", "op")
	if len(a) != 64 || a == AgentPromptVersion("core", "op2") || a == AgentPromptVersion("core2", "op") {
		t.Fatalf("prompt version does not cover both texts: %s", a)
	}
	// Moving text across the boundary changes the version.
	if AgentPromptVersion("ab", "c") == AgentPromptVersion("a", "bc") {
		t.Fatal("prompt version is ambiguous across the core/operator boundary")
	}
}
