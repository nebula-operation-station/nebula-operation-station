// SPDX-License-Identifier: AGPL-3.0-or-later

// Package opsconfig holds the settings of the ops agent (ADR 0016 D12, D5):
// one row with the enabled flag, the LLM base URL and model, the plain HTTP
// permission, the data class, the operator instructions and the language.
//
// Validate checks the data class together with the URL: the class `lab`
// requires a literal IP address inside the lab networks, so a lab
// configuration can never point at a public host by name. Names are not
// resolved here; the lab-only dialer checks them at run time. The store
// (Store.Save) writes the row only when the admin's base version is still
// current and writes the audit entry in the same transaction. The row holds
// no credential: the LLM credential, if any, stays on the agent host.
package opsconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Bounds of the settings. The migration 0046 CHECKs repeat the sizes.
const (
	// MaxBaseURL bounds the LLM base URL in bytes.
	MaxBaseURL = 512
	// MaxModel bounds the model name in bytes.
	MaxModel = 128
	// MaxInstructions bounds the operator instructions in bytes (ADR 0016 D6).
	MaxInstructions = 4096
)

// Data classes (ADR 0016 D5). Lab is the default.
const (
	// DataClassLab allows host labels and vulnerability IDs in the prompt;
	// the URL must be a literal address in the lab networks.
	DataClassLab = "lab"
	// DataClassExternal allows the URL outside the lab; the server then
	// serves only counts.
	DataClassExternal = "external"
)

// Languages of the assessment text. German is the default.
const (
	LanguageDE = "de"
	LanguageEN = "en"
)

// DigestDomain is the domain separator of the change digest (ADR 0016 D12;
// spec 05 v27-05-01 pattern).
const DigestDomain = "nebula-opsagent-settings-v1"

// AuditOpsAgentSettingsChanged is the audit kind of a settings change.
const AuditOpsAgentSettingsChanged = "opsagent.settings_changed"

// ErrInvalidInput marks a settings value that fails validation. Its
// messages never quote the value.
var ErrInvalidInput = errors.New("opsconfig: invalid input")

// ErrStale: the settings changed since the admin loaded them (the base
// version is no longer the stored version). The admin starts again.
var ErrStale = errors.New("opsconfig: settings changed meanwhile")

// labNetworks are the networks a `lab` URL may address: loopback, RFC 1918
// and IPv6 ULA, the same always-permitted set as the lab-only dialer of
// ADR 0011 A1.4 (internal/vulnagent/run). 100.64.0.0/10 is not included.
var labNetworks = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("fc00::/7"),
}

// Settings are the values the admin edits. The zero value is not a valid
// configuration; use Default.
type Settings struct {
	// Enabled turns the ops agent on. Off by default.
	Enabled bool
	// BaseURL is the OpenAI-compatible base URL. Empty only while disabled.
	BaseURL string
	// Model is the model name. Required while enabled.
	Model string
	// AllowPlainHTTP permits an http (not https) base URL.
	AllowPlainHTTP bool
	// DataClass is DataClassLab or DataClassExternal.
	DataClass string
	// Instructions are the operator instructions added to the core prompt.
	Instructions string
	// Language is LanguageDE or LanguageEN.
	Language string
}

// Row is the stored settings row.
type Row struct {
	Settings
	// Version counts saves; 0 means the defaults, never saved.
	Version int64
	// UpdatedBy is the admin of the last save; empty before the first save.
	UpdatedBy string
	// UpdatedAt is the time of the last save; zero before the first save.
	UpdatedAt time.Time
}

// Default returns the settings served before the first save: the agent is
// off, the data class is lab and the language is German.
func Default() Settings {
	return Settings{DataClass: DataClassLab, Language: LanguageDE}
}

// Validate checks every value. The URL and the data class are checked
// together: a lab URL must be a literal address in the lab networks.
func (s Settings) Validate() error {
	if s.DataClass != DataClassLab && s.DataClass != DataClassExternal {
		return fmt.Errorf("data class must be lab or external: %w", ErrInvalidInput)
	}
	if s.Language != LanguageDE && s.Language != LanguageEN {
		return fmt.Errorf("language must be de or en: %w", ErrInvalidInput)
	}
	if err := validateModel(s.Model); err != nil {
		return err
	}
	if err := validateInstructions(s.Instructions); err != nil {
		return err
	}
	if s.BaseURL == "" {
		if s.Enabled {
			return fmt.Errorf("base url is required while enabled: %w", ErrInvalidInput)
		}
		return nil
	}
	if s.Enabled && s.Model == "" {
		return fmt.Errorf("model is required while enabled: %w", ErrInvalidInput)
	}
	return s.validateURL()
}

// validateURL checks the base URL and its combination with the data class.
// Errors never quote the URL.
func (s Settings) validateURL() error {
	raw := s.BaseURL
	if len(raw) > MaxBaseURL {
		return fmt.Errorf("base url longer than %d bytes: %w", MaxBaseURL, ErrInvalidInput)
	}
	for i := 0; i < len(raw); i++ {
		if c := raw[i]; c <= 0x20 || c >= 0x7f || c == '\\' {
			return fmt.Errorf("base url: not printable ASCII: %w", ErrInvalidInput)
		}
	}
	if strings.ContainsAny(raw, "?#@") {
		return fmt.Errorf("base url: userinfo, query or fragment: %w", ErrInvalidInput)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("base url: does not parse: %w", ErrInvalidInput)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !s.AllowPlainHTTP {
			return fmt.Errorf("base url: plain http needs allow_plain_http: %w", ErrInvalidInput)
		}
	default:
		return fmt.Errorf("base url: scheme must be http or https: %w", ErrInvalidInput)
	}
	if u.Opaque != "" || u.User != nil || u.Host == "" || u.Hostname() == "" ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return fmt.Errorf("base url: needs a host and no userinfo, query or fragment: %w", ErrInvalidInput)
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("base url: bad port: %w", ErrInvalidInput)
		}
	}
	if s.DataClass == DataClassLab {
		addr, err := netip.ParseAddr(u.Hostname())
		if err != nil {
			return fmt.Errorf("base url: data class lab needs a literal IP address: %w", ErrInvalidInput)
		}
		if addr.Zone() != "" {
			return fmt.Errorf("base url: data class lab refuses an IPv6 zone: %w", ErrInvalidInput)
		}
		if !inLabNetworks(addr.Unmap()) {
			return fmt.Errorf("base url: data class lab needs an address in the lab networks: %w", ErrInvalidInput)
		}
	}
	return nil
}

// inLabNetworks reports whether a lies in one of labNetworks.
func inLabNetworks(a netip.Addr) bool {
	for _, p := range labNetworks {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// validateModel: empty, or at most MaxModel bytes of printable ASCII
// without space.
func validateModel(s string) error {
	if len(s) > MaxModel {
		return fmt.Errorf("model longer than %d bytes: %w", MaxModel, ErrInvalidInput)
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c <= 0x20 || c >= 0x7f {
			return fmt.Errorf("model: not printable ASCII: %w", ErrInvalidInput)
		}
	}
	return nil
}

// validateInstructions: at most MaxInstructions bytes of valid UTF-8.
// Newline and tab are the only control characters allowed; C1 controls,
// bidirectional overrides and isolates, direction marks and U+FFFD are
// refused.
func validateInstructions(s string) error {
	if len(s) > MaxInstructions {
		return fmt.Errorf("operator instructions longer than %d bytes: %w", MaxInstructions, ErrInvalidInput)
	}
	if !utf8.ValidString(s) {
		return fmt.Errorf("operator instructions: invalid UTF-8: %w", ErrInvalidInput)
	}
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
		case r < 0x20, r >= 0x7f && r <= 0x9f, r == utf8.RuneError,
			r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069,
			r == 0x200e, r == 0x200f, r == 0x061c:
			return fmt.Errorf("operator instructions: control character: %w", ErrInvalidInput)
		}
	}
	return nil
}

// digestPayload is the canonical JSON of a change: a struct, so the field
// order is fixed. It holds the complete new values and the base version.
type digestPayload struct {
	Enabled        bool   `json:"enabled"`
	BaseURL        string `json:"base_url"`
	Model          string `json:"model"`
	AllowPlainHTTP bool   `json:"allow_plain_http"`
	DataClass      string `json:"data_class"`
	Instructions   string `json:"operator_instructions"`
	Language       string `json:"language"`
	BaseVersion    int64  `json:"base_version"`
}

// ChangeDigest is the digest a fresh assertion of a settings change binds
// to: SHA-256 over DigestDomain, a zero byte and the canonical JSON of the
// complete new settings and the base version.
func ChangeDigest(s Settings, baseVersion int64) ([sha256.Size]byte, error) {
	var out [sha256.Size]byte
	payload, err := json.Marshal(digestPayload{
		Enabled:        s.Enabled,
		BaseURL:        s.BaseURL,
		Model:          s.Model,
		AllowPlainHTTP: s.AllowPlainHTTP,
		DataClass:      s.DataClass,
		Instructions:   s.Instructions,
		Language:       s.Language,
		BaseVersion:    baseVersion,
	})
	if err != nil {
		return out, fmt.Errorf("opsconfig: marshal change digest: %w", err)
	}
	h := sha256.New()
	h.Write([]byte(DigestDomain))
	h.Write([]byte{0})
	h.Write(payload)
	copy(out[:], h.Sum(nil))
	return out, nil
}

// Diff returns the audit fields of a change: the old and new values of
// enabled, base URL (in full), model, allow_plain_http, data class and
// language, a changed flag for each, and for the operator instructions only
// their length and SHA-256, never the text.
func Diff(old, next Settings) map[string]string {
	d := make(map[string]string, 24)
	b := strconv.FormatBool
	d["old_enabled"], d["new_enabled"] = b(old.Enabled), b(next.Enabled)
	d["old_base_url"], d["new_base_url"] = old.BaseURL, next.BaseURL
	d["old_model"], d["new_model"] = old.Model, next.Model
	d["old_allow_plain_http"], d["new_allow_plain_http"] = b(old.AllowPlainHTTP), b(next.AllowPlainHTTP)
	d["old_data_class"], d["new_data_class"] = old.DataClass, next.DataClass
	d["old_language"], d["new_language"] = old.Language, next.Language
	d["old_operator_instructions_bytes"] = strconv.Itoa(len(old.Instructions))
	d["new_operator_instructions_bytes"] = strconv.Itoa(len(next.Instructions))
	d["old_operator_instructions_sha256"] = sha256Hex(old.Instructions)
	d["new_operator_instructions_sha256"] = sha256Hex(next.Instructions)
	d["enabled_changed"] = b(old.Enabled != next.Enabled)
	d["base_url_changed"] = b(old.BaseURL != next.BaseURL)
	d["model_changed"] = b(old.Model != next.Model)
	d["allow_plain_http_changed"] = b(old.AllowPlainHTTP != next.AllowPlainHTTP)
	d["data_class_changed"] = b(old.DataClass != next.DataClass)
	d["language_changed"] = b(old.Language != next.Language)
	d["operator_instructions_changed"] = b(old.Instructions != next.Instructions)
	return d
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
