// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnagent/agent"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnagent/run"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfeed"
)

// Configuration limits.
const (
	// maxConfigBytes bounds the configuration file.
	maxConfigBytes = 1 << 20
	// maxKeyFileBytes bounds one pinned CSAF provider key file.
	maxKeyFileBytes = 1 << 20
	// maxKeyFiles bounds the key files of one CSAF provider.
	maxKeyFiles = 8
)

// errConfig marks a configuration or usage error (exit code 2).
var errConfig = run.ErrConfig

// fileConfig is the JSON configuration file. It holds paths, never a
// secret: the NOS token and the LLM API key live in their own files.
type fileConfig struct {
	DataDir        string              `json:"data_dir"`
	NOS            nosConfig           `json:"nos"`
	LLM            llmConfig           `json:"llm"`
	CSAF           map[string]csafKeys `json:"csaf"`
	AssessPhaseMax duration            `json:"assess_phase_max"`
	LogLevel       string              `json:"log_level"`
}

type nosConfig struct {
	URL       string `json:"url"`
	TokenFile string `json:"token_file"`
	CAFile    string `json:"ca_file"`
	// AgentConfig reads the LLM settings from NOS (default true).
	AgentConfig *bool `json:"agent_config"`
}

type llmConfig struct {
	Enabled              bool      `json:"enabled"`
	BaseURL              string    `json:"base_url"`
	Model                string    `json:"model"`
	APIKeyFile           string    `json:"api_key_file"`
	AllowPlainHTTP       bool      `json:"allow_plain_http"`
	ContextWindow        int       `json:"context_window"`
	Language             string    `json:"language"`
	OperatorInstructions string    `json:"operator_instructions"`
	Limits               llmLimits `json:"limits"`
	// AllowedNetworks are extra lab networks for the LLM endpoint
	// (subnets of loopback, RFC 1918, ULA or 100.64.0.0/10 only).
	AllowedNetworks []string `json:"allowed_networks"`
	// UnixSocket is an absolute path of a Unix socket on this host that
	// every LLM connection goes to.
	UnixSocket string `json:"unix_socket"`
}

// llmLimits are optional; zero keeps the default. Values above the hard
// maximum are refused at startup.
type llmLimits struct {
	MaxToolSteps       int      `json:"max_tool_steps"`
	MaxToolResultBytes int      `json:"max_tool_result_bytes"`
	MaxOutputTokens    int      `json:"max_output_tokens"`
	MaxPromptTokens    int      `json:"max_prompt_tokens"`
	MaxRunTokens       int64    `json:"max_run_tokens"`
	MaxRunCalls        int      `json:"max_run_calls"`
	LLMCallTimeout     duration `json:"llm_call_timeout"`
	FindingTimeout     duration `json:"finding_timeout"`
}

type csafKeys struct {
	KeyFiles []string `json:"key_files"`
}

// duration is a time.Duration written as a Go duration string.
type duration time.Duration

func (d *duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return errors.New("duration must be a string such as \"2h\"")
	}
	v, err := time.ParseDuration(s)
	if err != nil || v < 0 {
		return errors.New("duration must be a non-negative Go duration")
	}
	*d = duration(v)
	return nil
}

// loadConfig reads the configuration file. A missing file is an error
// only when it was named explicitly.
func loadConfig(path string, explicit bool) (fileConfig, error) {
	var c fileConfig
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) && !explicit {
		return c, nil
	}
	if err != nil {
		return c, fmt.Errorf("open config: %w: %w", errConfig, err)
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return c, fmt.Errorf("read config %s: %w", path, err)
	}
	if len(b) > maxConfigBytes {
		return c, fmt.Errorf("config %s larger than %d bytes: %w", path, maxConfigBytes, errConfig)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		// The decoder error names the field or offset, not a value.
		return c, fmt.Errorf("config %s: %w: %s", path, errConfig, cleanErr(err))
	}
	if dec.More() {
		return c, fmt.Errorf("config %s: trailing data: %w", path, errConfig)
	}
	return c, nil
}

// cleanErr shortens a decode error to printable text.
func cleanErr(err error) string {
	s := err.Error()
	if len(s) > 200 {
		s = s[:200]
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, s)
}

// validate checks the merged configuration for mode.
func (c fileConfig) validate(mode run.Mode) error {
	if c.DataDir == "" || !filepath.IsAbs(c.DataDir) {
		return fmt.Errorf("data_dir must be an absolute path: %w", errConfig)
	}
	if mode != run.ModeSyncOnly {
		u, err := url.Parse(c.NOS.URL)
		if c.NOS.URL == "" || err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil ||
			(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("nos.url must be https://host[:port]: %w", errConfig)
		}
		if c.NOS.TokenFile == "" || !filepath.IsAbs(c.NOS.TokenFile) {
			return fmt.Errorf("nos.token_file must be an absolute path: %w", errConfig)
		}
		if c.NOS.CAFile != "" && !filepath.IsAbs(c.NOS.CAFile) {
			return fmt.Errorf("nos.ca_file must be an absolute path: %w", errConfig)
		}
	}
	if c.LLM.APIKeyFile != "" && !filepath.IsAbs(c.LLM.APIKeyFile) {
		return fmt.Errorf("llm.api_key_file must be an absolute path: %w", errConfig)
	}
	switch c.LLM.Language {
	case "", string(agent.LanguageDE), string(agent.LanguageEN):
	default:
		return fmt.Errorf("llm.language must be de or en: %w", errConfig)
	}
	switch c.LogLevel {
	case "", "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log_level must be debug, info, warn or error: %w", errConfig)
	}
	names := make([]string, 0, len(c.CSAF))
	for n := range c.CSAF {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		if _, err := csafVendor(n); err != nil {
			return err
		}
		k := c.CSAF[n]
		if len(k.KeyFiles) == 0 || len(k.KeyFiles) > maxKeyFiles {
			return fmt.Errorf("csaf.%s: 1 to %d key files: %w", n, maxKeyFiles, errConfig)
		}
		for _, p := range k.KeyFiles {
			if !filepath.IsAbs(p) {
				return fmt.Errorf("csaf.%s: key files must be absolute paths: %w", n, errConfig)
			}
		}
	}
	return nil
}

// limits returns the assessor limits with defaults for unset values.
func (l llmLimits) limits() agent.Limits {
	d := agent.DefaultLimits()
	set := func(dst *int, v int) {
		if v != 0 {
			*dst = v
		}
	}
	set(&d.MaxToolSteps, l.MaxToolSteps)
	set(&d.MaxToolResultBytes, l.MaxToolResultBytes)
	set(&d.MaxOutputTokens, l.MaxOutputTokens)
	set(&d.MaxPromptTokens, l.MaxPromptTokens)
	set(&d.MaxRunCalls, l.MaxRunCalls)
	if l.MaxRunTokens != 0 {
		d.MaxRunTokens = l.MaxRunTokens
	}
	if l.LLMCallTimeout != 0 {
		d.LLMCallTimeout = time.Duration(l.LLMCallTimeout)
	}
	if l.FindingTimeout != 0 {
		d.FindingTimeout = time.Duration(l.FindingTimeout)
	}
	return d
}

// llm returns the local assessor configuration.
func (c fileConfig) llm() run.LLMConfig {
	lang := agent.Language(c.LLM.Language)
	if lang == "" {
		lang = agent.LanguageDE
	}
	return run.LLMConfig{Enabled: c.LLM.Enabled, BaseURL: c.LLM.BaseURL, Model: c.LLM.Model, APIKeyFile: c.LLM.APIKeyFile,
		AllowPlainHTTP: c.LLM.AllowPlainHTTP, ContextWindow: c.LLM.ContextWindow, Language: lang,
		OperatorInstructions: c.LLM.OperatorInstructions, Limits: c.LLM.Limits.limits(),
		AllowedNetworks: c.LLM.AllowedNetworks, UnixSocket: c.LLM.UnixSocket}
}

func csafVendor(feed string) (vulnfeed.CSAFVendor, error) {
	switch feed {
	case "cisco-csaf":
		return vulnfeed.CSAFVendorCisco, nil
	case "paloalto-csaf":
		return vulnfeed.CSAFVendorPaloAlto, nil
	}
	return "", fmt.Errorf("csaf: unknown provider feed: %w", errConfig)
}

// csafProviders loads the pinned keys of the configured providers.
func (c fileConfig) csafProviders() ([]run.CSAFProvider, error) {
	names := make([]string, 0, len(c.CSAF))
	for n := range c.CSAF {
		names = append(names, n)
	}
	slices.Sort(names)
	var out []run.CSAFProvider
	for _, n := range names {
		vendor, err := csafVendor(n)
		if err != nil {
			return nil, err
		}
		feed, ok := vulnfeed.FeedByName(n)
		if !ok {
			return nil, fmt.Errorf("csaf.%s: not in the feed table: %w", n, errConfig)
		}
		var armored [][]byte
		for _, p := range c.CSAF[n].KeyFiles {
			b, err := readBounded(p, maxKeyFileBytes)
			if err != nil {
				return nil, fmt.Errorf("csaf.%s: %w: %w", n, errConfig, err)
			}
			armored = append(armored, b)
		}
		kr, err := vulnfeed.ParseCSAFKeyring(armored...)
		if err != nil {
			return nil, fmt.Errorf("csaf.%s: pinned keys: %w: %w", n, errConfig, err)
		}
		out = append(out, run.CSAFProvider{Feed: feed, Vendor: vendor, Keys: kr})
	}
	return out, nil
}

func readBounded(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s larger than %d bytes", path, max)
	}
	return b, nil
}
