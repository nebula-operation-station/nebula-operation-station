// SPDX-License-Identifier: AGPL-3.0-or-later

package api

// GET /api/v1/vuln/agent-config (ADR 0011 amendment 1, "LLM settings";
// autopilot va09): the vulnerability agent reads the LLM settings the
// admin saved in the web UI with its token (scope vuln.inventory.read,
// the token's source-address allowlist applies). The answer carries no
// secret: the LLM API key stays on the agent host, and the agent uses its
// local configuration for any empty value and re-validates the URL.

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
)

// AgentConfigPath is the path of the agent settings read.
const AgentConfigPath = VulnPrefix + "agent-config"

// Rate limit of the agent settings read per token: the agent reads it once
// per run, so 60 per hour leaves room for retries.
const (
	MaxAgentConfigRequests = 60
	AgentConfigWindow      = time.Hour
)

// AgentConfigSource reads the stored agent settings
// (vulnstore.AgentConfigStore).
type AgentConfigSource interface {
	AgentConfig(ctx context.Context) (vulnstore.AgentConfig, error)
}

// AgentConfigOptions configure the agent settings read.
type AgentConfigOptions struct {
	// Source reads the stored settings. Required.
	Source AgentConfigSource
	// CorePrompt is the agent's fixed core prompt; the answer's
	// prompt_version covers it and the operator instructions.
	CorePrompt string
}

// agentConfigHandler serves AgentConfigPath and hands every other request
// to the vuln handler.
type agentConfigHandler struct {
	vuln *VulnHandler
	src  AgentConfigSource
	core string

	mu    sync.Mutex
	limit rateWindow
}

// WithAgentConfig returns a handler that serves AgentConfigPath with the
// vuln token's authentication and source-address check and the scope
// vuln.inventory.read, and passes every other request to h.
func (h *VulnHandler) WithAgentConfig(o AgentConfigOptions) (http.Handler, error) {
	if h == nil || o.Source == nil {
		return nil, errors.New("vuln api: agent config: vuln handler and source are required")
	}
	return &agentConfigHandler{vuln: h, src: o.Source, core: o.CorePrompt,
		limit: rateWindow{span: AgentConfigWindow, max: MaxAgentConfigRequests}}, nil
}

// agentConfigResponse is the answer; no secret, no actor.
type agentConfigResponse struct {
	LLMEnabled           bool   `json:"llm_enabled"`
	LLMBaseURL           string `json:"llm_base_url"`
	LLMModel             string `json:"llm_model"`
	OperatorInstructions string `json:"operator_instructions"`
	Language             string `json:"language"`
	PromptVersion        string `json:"prompt_version"`
	Version              int64  `json:"version"`
}

// ServeHTTP serves AgentConfigPath; anything else goes to the vuln handler.
func (a *agentConfigHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != AgentConfigPath {
		a.vuln.ServeHTTP(w, r)
		return
	}
	h := a.vuln
	t := h.authenticate(r)
	if t == nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="nebula"`)
		h.log.Warn("audit", "kind", "api_unauthorized", "path", r.URL.Path, "remote", r.RemoteAddr)
		writeError(w, http.StatusUnauthorized, "a valid API token is required")
		return
	}
	if !h.sourceAllowed(r) {
		h.log.Warn("audit", "kind", "api_source_refused", "token", t.name, "path", r.URL.Path, "remote", r.RemoteAddr)
		writeError(w, http.StatusForbidden, "the token is not allowed from this address")
		return
	}
	if !t.has(serverconfig.ScopeVulnInventoryRead) {
		h.log.Warn("audit", "kind", "api_forbidden", "token", t.name, "path", r.URL.Path, "scope", serverconfig.ScopeVulnInventoryRead)
		writeError(w, http.StatusForbidden, "the token lacks the scope "+serverconfig.ScopeVulnInventoryRead)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeError(w, http.StatusMethodNotAllowed, "use GET")
		return
	}
	a.mu.Lock()
	ok, wait := a.limit.allow(h.now())
	a.mu.Unlock()
	if !ok {
		h.log.Warn("audit", "kind", "api_rate_limited", "token", t.name, "path", r.URL.Path)
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		writeError(w, http.StatusTooManyRequests, "rate limit reached")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), callTimeout)
	defer cancel()
	c, err := a.src.AgentConfig(ctx)
	if err != nil {
		h.log.Error("vuln api: read agent config", "error", err)
		writeError(w, http.StatusBadGateway, "agent settings unavailable")
		return
	}
	// The store validated the row when it was saved; a row that fails now
	// was written around it and is not served.
	if err := c.Validate(); err != nil {
		h.log.Error("vuln api: stored agent config invalid", "error", err)
		writeError(w, http.StatusInternalServerError, "stored agent settings are invalid")
		return
	}
	writeJSON(w, http.StatusOK, agentConfigResponse{
		LLMEnabled: c.LLMEnabled, LLMBaseURL: c.LLMBaseURL, LLMModel: c.LLMModel,
		OperatorInstructions: c.OperatorInstructions, Language: c.Language,
		PromptVersion: vulnstore.AgentPromptVersion(a.core, c.OperatorInstructions), Version: c.Version,
	})
}
