// SPDX-License-Identifier: AGPL-3.0-or-later

package run

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnagent/agent"
)

// LLM setting bounds (A1.8, as NOS stores them).
const (
	// MaxLLMURLBytes bounds an LLM base URL.
	MaxLLMURLBytes = 512
	// MaxLLMModelBytes bounds a model name.
	MaxLLMModelBytes = 128
)

// RemoteLLM are the LLM settings NOS serves (GET /api/v1/vuln/agent-config).
// They never hold a credential.
type RemoteLLM struct {
	Enabled              bool
	BaseURL              string
	Model                string
	OperatorInstructions string
	Language             string
	Version              int64
}

// ErrNoRemoteSettings: the server serves no agent settings (an older NOS
// without the endpoint); the local configuration applies.
var ErrNoRemoteSettings = errors.New("vulnagent/run: NOS serves no agent settings")

// AgentConfigSource reads the LLM settings from NOS.
type AgentConfigSource interface {
	AgentConfig(ctx context.Context) (RemoteLLM, error)
}

// ValidateLLMURL checks an LLM base URL: http or https with a host, no
// userinfo, query or fragment, printable ASCII within MaxLLMURLBytes.
// Plain http needs allowPlainHTTP. Values NOS serves are untrusted and
// pass through here before use.
func ValidateLLMURL(s string, allowPlainHTTP bool) error {
	if s == "" || len(s) > MaxLLMURLBytes || !printableASCII(s) {
		return errors.New("llm base url: empty, too long or not printable ASCII")
	}
	u, err := url.Parse(s)
	if err != nil {
		return errors.New("llm base url: does not parse")
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.ForceQuery || u.Hostname() == "" {
		return errors.New("llm base url: must be http(s) with a host, without userinfo, query or fragment")
	}
	if u.Scheme == "http" && !allowPlainHTTP {
		return errors.New("llm base url: plain http not allowed by the local configuration")
	}
	return nil
}

func validModel(s string) bool {
	return s != "" && len(s) <= MaxLLMModelBytes && printableASCII(s)
}

func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] >= 0x7f {
			return false
		}
	}
	return true
}

// minContextWindow is the context window the assessor needs (A1.4).
func minContextWindow(l agent.Limits) int {
	return l.MaxPromptTokens + l.MaxOutputTokens + TemplateMarginTokens
}

// checkLLM checks settings that would be used with the assessor enabled.
func checkLLM(c LLMConfig) error {
	if err := c.Limits.Validate(); err != nil {
		return fmt.Errorf("llm limits: %w", err)
	}
	if err := ValidateLLMURL(c.BaseURL, c.AllowPlainHTTP); err != nil {
		return err
	}
	if !validModel(c.Model) {
		return errors.New("llm model: empty, too long or not printable ASCII")
	}
	if c.Language != agent.LanguageDE && c.Language != agent.LanguageEN {
		return errors.New("llm language must be de or en")
	}
	if c.ContextWindow < minContextWindow(c.Limits) {
		return fmt.Errorf("llm context window %d below %d (prompt + output + template margin)", c.ContextWindow, minContextWindow(c.Limits))
	}
	if !utf8.ValidString(c.OperatorInstructions) || len(c.OperatorInstructions) > agent.MaxOperatorInstructionsBytes {
		return errors.New("llm operator instructions: invalid UTF-8 or too long")
	}
	return nil
}

// checkLocalLLM validates the local configuration at startup: an enabled
// assessor must be complete; the limits and the context window are
// checked whenever an LLM is configured, since NOS may enable it.
func checkLocalLLM(c LLMConfig) error {
	if c.Enabled {
		if err := checkLLM(c); err != nil {
			return fmt.Errorf("%w: %w", ErrConfig, err)
		}
		return nil
	}
	if err := c.Limits.Validate(); err != nil {
		return fmt.Errorf("%w: llm limits: %w", ErrConfig, err)
	}
	if c.BaseURL != "" {
		if err := ValidateLLMURL(c.BaseURL, c.AllowPlainHTTP); err != nil {
			return fmt.Errorf("%w: %w", ErrConfig, err)
		}
	}
	if c.Model != "" && !validModel(c.Model) {
		return fmt.Errorf("%w: llm model invalid", ErrConfig)
	}
	return nil
}

// resolveLLM merges the settings NOS serves over the local ones: NOS
// decides enabled, a non-empty URL, model, language and operator
// instructions; an empty value keeps the local one. The API key always
// comes from the local key file. Any setting that fails validation
// disables the assessor for this run (fail closed, never a fallback to a
// different endpoint).
func (r *Runner) resolveLLM(ctx context.Context) (LLMConfig, LLMEvidence) {
	eff := r.cfg.LLM
	ev := LLMEvidence{Origin: "local"}
	if r.cfg.AgentConfig != nil {
		rc, err := r.cfg.AgentConfig.AgentConfig(ctx)
		switch {
		case err == nil:
			ev.Origin, ev.SettingsVersion = "nos", rc.Version
			eff.Enabled = rc.Enabled
			if rc.BaseURL != "" {
				eff.BaseURL = rc.BaseURL
			}
			if rc.Model != "" {
				eff.Model = rc.Model
			}
			if rc.Language != "" {
				eff.Language = agent.Language(rc.Language)
			}
			if rc.OperatorInstructions != "" {
				eff.OperatorInstructions = rc.OperatorInstructions
			}
		case errors.Is(err, ErrNoRemoteSettings):
			ev.Reason = "NOS serves no agent settings; local configuration used"
		default:
			ev.Reason = "agent settings unavailable; local configuration used: " + cleanText(err.Error(), maxEvidenceText)
			r.log.Warn("agent settings read failed, local configuration used", "error", cleanText(err.Error(), maxEvidenceText))
		}
	}
	ev.Model = cleanText(eff.Model, MaxLLMModelBytes)
	if !eff.Enabled {
		if ev.Reason == "" {
			ev.Reason = "assessor disabled"
		}
		return eff, ev
	}
	if err := checkLLM(eff); err != nil {
		eff.Enabled = false
		ev.Reason = "assessor disabled for this run: " + cleanText(err.Error(), maxEvidenceText)
		r.log.Warn("llm settings refused, findings sent without text", "origin", ev.Origin, "error", cleanText(err.Error(), maxEvidenceText))
		return eff, ev
	}
	ev.Enabled = true
	if u, err := url.Parse(eff.BaseURL); err == nil {
		ev.Host = u.Host
	}
	return eff, ev
}
