// SPDX-License-Identifier: AGPL-3.0-or-later

package opsconfig

import (
	"errors"
	"strings"
	"testing"
)

// validSettings is an enabled, lab-class configuration that passes Validate.
func validSettings() Settings {
	return Settings{
		Enabled:        true,
		BaseURL:        "http://192.168.0.26:11434/v1",
		Model:          "qwen3.5-9b-64k",
		AllowPlainHTTP: true,
		DataClass:      DataClassLab,
		Instructions:   "Antworte knapp.",
		Language:       LanguageDE,
	}
}

func TestDefaultSettingsAreOffAndLab(t *testing.T) {
	d := Default()
	if d.Enabled {
		t.Fatal("default must be disabled")
	}
	if d.DataClass != DataClassLab {
		t.Fatalf("default data class = %q, want %q", d.DataClass, DataClassLab)
	}
	if d.Language != LanguageDE {
		t.Fatalf("default language = %q, want %q", d.Language, LanguageDE)
	}
	if d.BaseURL != "" || d.Model != "" || d.AllowPlainHTTP || d.Instructions != "" {
		t.Fatalf("default must carry no URL, model, plain http or instructions: %+v", d)
	}
	if err := d.Validate(); err != nil {
		t.Fatalf("default settings must validate: %v", err)
	}
}

func TestValidateAcceptsLabAndExternal(t *testing.T) {
	tests := []struct {
		name string
		mut  func(*Settings)
	}{
		{"lab private http with allow", func(s *Settings) {}},
		{"lab private https ipv4", func(s *Settings) { s.BaseURL = "https://10.1.2.3/v1"; s.AllowPlainHTTP = false }},
		{"lab ula ipv6 literal", func(s *Settings) { s.BaseURL = "https://[fd00::5]:8443/v1"; s.AllowPlainHTTP = false }},
		{"lab loopback", func(s *Settings) { s.BaseURL = "http://127.0.0.1:11434/v1" }},
		{"external name https", func(s *Settings) {
			s.DataClass = DataClassExternal
			s.BaseURL = "https://llm.example.com/v1"
			s.AllowPlainHTTP = false
		}},
		{"external public ip https", func(s *Settings) {
			s.DataClass = DataClassExternal
			s.BaseURL = "https://203.0.113.7/v1"
			s.AllowPlainHTTP = false
		}},
		{"disabled with empty url and model", func(s *Settings) {
			s.Enabled = false
			s.BaseURL = ""
			s.Model = ""
		}},
		{"english language", func(s *Settings) { s.Language = LanguageEN }},
		{"instructions with newline and tab", func(s *Settings) { s.Instructions = "Zeile 1\n\tZeile 2" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := validSettings()
			tc.mut(&s)
			if err := s.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
		})
	}
}

func TestValidateRejectsInvalidSettings(t *testing.T) {
	long := "http://10.0.0.1/" + strings.Repeat("a", MaxBaseURL)
	tests := []struct {
		name string
		mut  func(*Settings)
	}{
		{"userinfo", func(s *Settings) { s.BaseURL = "https://user:secret@10.0.0.5/v1"; s.AllowPlainHTTP = false }},
		{"at sign in path", func(s *Settings) { s.BaseURL = "https://10.0.0.5/v1@evil" }},
		{"query", func(s *Settings) { s.BaseURL = "http://10.0.0.5/v1?key=x" }},
		{"empty query marker", func(s *Settings) { s.BaseURL = "http://10.0.0.5/v1?" }},
		{"fragment", func(s *Settings) { s.BaseURL = "http://10.0.0.5/v1#x" }},
		{"ftp scheme", func(s *Settings) { s.BaseURL = "ftp://10.0.0.5/" }},
		{"no host", func(s *Settings) { s.BaseURL = "http:///v1" }},
		{"bad port", func(s *Settings) { s.BaseURL = "http://10.0.0.5:0/v1" }},
		{"space in url", func(s *Settings) { s.BaseURL = "http://10.0.0.5/v 1" }},
		{"backslash in url", func(s *Settings) { s.BaseURL = `http://10.0.0.5\v1` }},
		{"non ascii url", func(s *Settings) { s.BaseURL = "https://10.0.0.5/ü" }},
		{"url too long", func(s *Settings) { s.BaseURL = long }},
		{"plain http without allow", func(s *Settings) { s.AllowPlainHTTP = false }},
		{"lab with host name", func(s *Settings) { s.BaseURL = "https://llm.lab.example/v1"; s.AllowPlainHTTP = false }},
		{"lab with public ipv4", func(s *Settings) { s.BaseURL = "https://8.8.8.8/v1"; s.AllowPlainHTTP = false }},
		{"lab with public ipv6", func(s *Settings) { s.BaseURL = "https://[2001:db8::1]/v1"; s.AllowPlainHTTP = false }},
		{"lab with ipv6 zone", func(s *Settings) { s.BaseURL = "https://[fe80::1%25eth0]/v1"; s.AllowPlainHTTP = false }},
		{"lab with cgnat ipv4", func(s *Settings) { s.BaseURL = "https://100.64.0.9/v1"; s.AllowPlainHTTP = false }},
		{"unknown class", func(s *Settings) { s.DataClass = "public" }},
		{"empty class", func(s *Settings) { s.DataClass = "" }},
		{"model too long", func(s *Settings) { s.Model = strings.Repeat("m", MaxModel+1) }},
		{"model with space", func(s *Settings) { s.Model = "qwen 9b" }},
		{"model non ascii", func(s *Settings) { s.Model = "modell-ä" }},
		{"enabled without url", func(s *Settings) { s.BaseURL = "" }},
		{"enabled without model", func(s *Settings) { s.Model = "" }},
		{"instructions too long", func(s *Settings) { s.Instructions = strings.Repeat("a", MaxInstructions+1) }},
		{"instructions invalid utf8", func(s *Settings) { s.Instructions = "ok\xff" }},
		{"instructions nul", func(s *Settings) { s.Instructions = "a\x00b" }},
		{"instructions bidi override", func(s *Settings) { s.Instructions = "a‮b" }},
		{"instructions c1 control", func(s *Settings) { s.Instructions = "a\u0085b" }},
		{"instructions replacement char", func(s *Settings) { s.Instructions = "a�b" }},
		{"language fr", func(s *Settings) { s.Language = "fr" }},
		{"language empty", func(s *Settings) { s.Language = "" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := validSettings()
			tc.mut(&s)
			err := s.Validate()
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("Validate = %v, want ErrInvalidInput", err)
			}
		})
	}
}

func TestValidateErrorsDoNotQuoteValues(t *testing.T) {
	s := validSettings()
	s.BaseURL = "https://user:hunter2@10.0.0.5/v1"
	err := s.Validate()
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("error quotes the URL: %v", err)
	}
}
