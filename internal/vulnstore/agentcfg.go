// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnstore

// LLM settings of the vulnerability agent (ADR 0011 amendment 1, "LLM
// settings"; autopilot va09): the one-row table vuln_agent_config (serverdb
// migration 0041) holds whether the agent's assessor is enabled, the LLM
// base URL and model, the operator instructions and the assessment
// language. The admin changes them on the settings page with a fresh
// WebAuthn assertion; the agent reads them with its token through
// GET /api/v1/vuln/agent-config. The LLM API key is never stored here: it
// stays on the agent host, and an empty URL or model means the agent's
// local configuration wins.
//
// AgentConfigStore validates every value before it stores it; the API
// re-validates every stored row before it serves it (a row that fails is
// not served), and the agent re-validates the URL on its side. The store
// writes the audit entry through the write transaction itself, so a
// change commits together with its audit entry or not at all.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Bounds and defaults of the agent LLM settings.
const (
	// MaxAgentLLMURL bounds the LLM base URL in bytes.
	MaxAgentLLMURL = 512
	// MaxAgentLLMModel bounds the model name in bytes (printable ASCII
	// without space).
	MaxAgentLLMModel = 128
	// MaxAgentOperatorText bounds the operator instructions in bytes.
	MaxAgentOperatorText = 4096
	// DefaultAgentLLMModel is the model served before the admin ever saved
	// the settings.
	DefaultAgentLLMModel = "qwen3.5-9b-64k"
	// AgentLLMURLPlaceholder is shown as the URL field's placeholder only;
	// it is never stored or served.
	AgentLLMURLPlaceholder = "http://192.168.0.26:11434/v1"
	// AgentLanguageDE and AgentLanguageEN are the assessment languages;
	// DE is the default.
	AgentLanguageDE = "de"
	AgentLanguageEN = "en"
	// AuditAgentLLMChanged is the audit kind of a settings change.
	AuditAgentLLMChanged = "vuln.agent_llm_changed"
)

// ErrAgentConfigConflict: the settings changed since the admin loaded
// them (the change's base version is not the stored version).
var ErrAgentConfigConflict = errors.New("agent settings changed meanwhile")

// AgentSettings are the values the admin edits.
type AgentSettings struct {
	// LLMEnabled turns the agent's assessor on or off.
	LLMEnabled bool
	// LLMBaseURL is the OpenAI-compatible base URL; empty means the
	// agent's local configuration wins.
	LLMBaseURL string
	// LLMModel is the model name; empty means the agent's local
	// configuration wins.
	LLMModel string
	// OperatorInstructions is added to the agent's fixed core prompt;
	// may be empty.
	OperatorInstructions string
	// Language is the assessment language, AgentLanguageDE or
	// AgentLanguageEN.
	Language string
}

// AgentConfig is the stored settings row.
type AgentConfig struct {
	AgentSettings
	// UpdatedBy is the admin who saved the row; empty before the first
	// save.
	UpdatedBy string
	// UpdatedAt is when the row was saved; zero before the first save.
	UpdatedAt time.Time
	// Version counts saves; 0 means never saved (defaults).
	Version int64
}

// DefaultAgentConfig is the configuration served before the first save.
func DefaultAgentConfig() AgentConfig {
	return AgentConfig{AgentSettings: AgentSettings{LLMEnabled: true, LLMModel: DefaultAgentLLMModel, Language: AgentLanguageDE}}
}

// AgentPromptVersion is the prompt version the agent reports: the hex
// SHA-256 over the core prompt and the operator instructions, each
// length-prefixed so that text cannot move across the boundary unnoticed.
func AgentPromptVersion(core, operator string) string {
	h := sha256.New()
	h.Write([]byte("nos-vuln-agent-prompt-v1\x00"))
	h.Write([]byte(strconv.Itoa(len(core)) + ":" + core))
	h.Write([]byte(strconv.Itoa(len(operator)) + ":" + operator))
	return hex.EncodeToString(h.Sum(nil))
}

// agentActorRe is the actor pattern of the human-state writes.
var agentActorRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@._:-]{0,127}$`)

// ValidateAgentLLMURL checks an LLM base URL: empty, or at most
// MaxAgentLLMURL bytes of printable ASCII without space or backslash, an
// absolute http or https URL with a host, an optional numeric port and no
// userinfo, query or fragment.
func ValidateAgentLLMURL(s string) error {
	if s == "" {
		return nil
	}
	if len(s) > MaxAgentLLMURL {
		return fmt.Errorf("llm base url longer than %d bytes: %w", MaxAgentLLMURL, ErrInvalidInput)
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c <= 0x20 || c >= 0x7f || c == '\\' {
			return fmt.Errorf("llm base url: not printable ASCII: %w", ErrInvalidInput)
		}
	}
	if strings.ContainsAny(s, "?#@") {
		return fmt.Errorf("llm base url: userinfo, query or fragment: %w", ErrInvalidInput)
	}
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("llm base url: does not parse: %w", ErrInvalidInput)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("llm base url: scheme must be http or https: %w", ErrInvalidInput)
	}
	if u.Opaque != "" || u.User != nil || u.Host == "" || u.Hostname() == "" ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return fmt.Errorf("llm base url: needs a host and no userinfo, query or fragment: %w", ErrInvalidInput)
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("llm base url: bad port: %w", ErrInvalidInput)
		}
	}
	return nil
}

// validateAgentModel: empty, or at most MaxAgentLLMModel bytes of
// printable ASCII without space.
func validateAgentModel(s string) error {
	if len(s) > MaxAgentLLMModel {
		return fmt.Errorf("llm model longer than %d bytes: %w", MaxAgentLLMModel, ErrInvalidInput)
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c <= 0x20 || c >= 0x7f {
			return fmt.Errorf("llm model: not printable ASCII: %w", ErrInvalidInput)
		}
	}
	return nil
}

// validateOperatorText: at most MaxAgentOperatorText bytes of valid UTF-8;
// newline and tab are the only control characters, and C1 controls,
// bidirectional overrides and isolates and U+FFFD are refused.
func validateOperatorText(s string) error {
	if len(s) > MaxAgentOperatorText {
		return fmt.Errorf("operator instructions longer than %d bytes: %w", MaxAgentOperatorText, ErrInvalidInput)
	}
	if !utf8.ValidString(s) {
		return fmt.Errorf("operator instructions: invalid UTF-8: %w", ErrInvalidInput)
	}
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
		case r < 0x20, r >= 0x7f && r <= 0x9f, r == utf8.RuneError,
			r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069, r == 0x200e, r == 0x200f, r == 0x061c:
			return fmt.Errorf("operator instructions: control character: %w", ErrInvalidInput)
		}
	}
	return nil
}

// Validate checks every field against its bound; errors wrap
// ErrInvalidInput and never quote the value.
func (a AgentSettings) Validate() error {
	if err := ValidateAgentLLMURL(a.LLMBaseURL); err != nil {
		return err
	}
	if err := validateAgentModel(a.LLMModel); err != nil {
		return err
	}
	if err := validateOperatorText(a.OperatorInstructions); err != nil {
		return err
	}
	if a.Language != AgentLanguageDE && a.Language != AgentLanguageEN {
		return fmt.Errorf("language must be de or en: %w", ErrInvalidInput)
	}
	return nil
}

// AgentAuditor runs a change in a write transaction that also carries
// its audit entries: fn writes the change through tx and the entry
// through appendLine, and the auditor commits both or neither. The server
// passes its audit log (auditlog.Store.WithTx), which runs the
// transaction on server.db, the database of the AgentConfigStore.
type AgentAuditor interface {
	WithTx(ctx context.Context, fn func(tx *sql.Tx, appendLine func(kind string, attrs map[string]string) error) error) error
}

// AgentChange is one admin change of the settings.
type AgentChange struct {
	// Settings are the new values.
	Settings AgentSettings
	// BaseVersion is the version the admin edited; a different stored
	// version fails with ErrAgentConfigConflict.
	BaseVersion int64
	// Actor is the admin; the caller has checked the role and the fresh
	// WebAuthn assertion.
	Actor string
}

// AgentConfigStore reads and changes the agent LLM settings.
type AgentConfigStore struct {
	db  *sql.DB
	now func() time.Time
}

// NewAgentConfigStore returns a store on db, which must carry the serverdb
// schema. now defaults to time.Now.
func NewAgentConfigStore(db *sql.DB, now func() time.Time) (*AgentConfigStore, error) {
	if db == nil {
		return nil, fmt.Errorf("vulnstore: new agent config store: db is required: %w", ErrInvalidInput)
	}
	if now == nil {
		now = time.Now
	}
	return &AgentConfigStore{db: db, now: now}, nil
}

type agentQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func readAgentConfig(ctx context.Context, q agentQuerier) (AgentConfig, error) {
	var (
		c       AgentConfig
		enabled int64
		at      int64
	)
	err := q.QueryRowContext(ctx, `SELECT llm_enabled, llm_base_url, llm_model, operator_instructions, language,
		updated_by, updated_at, version FROM vuln_agent_config WHERE id = 1`).
		Scan(&enabled, &c.LLMBaseURL, &c.LLMModel, &c.OperatorInstructions, &c.Language, &c.UpdatedBy, &at, &c.Version)
	if errors.Is(err, sql.ErrNoRows) {
		return DefaultAgentConfig(), nil
	}
	if err != nil {
		return AgentConfig{}, fmt.Errorf("read agent config: %w", err)
	}
	c.LLMEnabled = enabled == 1
	c.UpdatedAt = fromUnix(at)
	return c, nil
}

// Get returns the stored settings, or DefaultAgentConfig before the first
// save.
func (s *AgentConfigStore) Get(ctx context.Context) (AgentConfig, error) {
	return readAgentConfig(ctx, s.db)
}

// AgentConfig is Get; it lets the store serve the agent API directly.
func (s *AgentConfigStore) AgentConfig(ctx context.Context) (AgentConfig, error) {
	return s.Get(ctx)
}

// Change validates and stores ch, and writes the AuditAgentLLMChanged
// entry with the old and new values through the write transaction: when
// the audit write or the commit fails, neither the change nor the entry
// is stored. It returns the old and the new
// row. The operator instructions are audited as length and SHA-256 (the
// full text is on the settings page).
func (s *AgentConfigStore) Change(ctx context.Context, ch AgentChange, audit AgentAuditor) (old, cur AgentConfig, err error) {
	if audit == nil {
		return old, cur, fmt.Errorf("change agent config: auditor is required: %w", ErrInvalidInput)
	}
	if !agentActorRe.MatchString(ch.Actor) {
		return old, cur, fmt.Errorf("change agent config: actor: %w", ErrInvalidInput)
	}
	if err := ch.Settings.Validate(); err != nil {
		return old, cur, fmt.Errorf("change agent config: %w", err)
	}
	err = audit.WithTx(ctx, func(tx *sql.Tx, appendLine func(kind string, attrs map[string]string) error) error {
		old, cur, err = s.change(ctx, tx, ch)
		if err != nil {
			return err
		}
		if err := appendLine(AuditAgentLLMChanged, agentAuditAttrs(ch.Actor, old, cur)); err != nil {
			return fmt.Errorf("audit: %w", err)
		}
		return nil
	})
	if err != nil {
		return old, cur, fmt.Errorf("change agent config: %w", err)
	}
	return old, cur, nil
}

// change writes ch through tx and returns the old and the new row.
func (s *AgentConfigStore) change(ctx context.Context, tx *sql.Tx, ch AgentChange) (old, cur AgentConfig, err error) {
	// Take the write lock before reading, so two changes from the same
	// base version cannot both pass the version check.
	if _, err := tx.ExecContext(ctx, `UPDATE vuln_store_state SET lock_counter = lock_counter + 1 WHERE id = 1`); err != nil {
		return old, cur, fmt.Errorf("lock: %w", err)
	}
	if old, err = readAgentConfig(ctx, tx); err != nil {
		return old, cur, err
	}
	if old.Version != ch.BaseVersion {
		return old, cur, fmt.Errorf("base version %d, stored %d: %w", ch.BaseVersion, old.Version, ErrAgentConfigConflict)
	}
	cur = AgentConfig{AgentSettings: ch.Settings, UpdatedBy: ch.Actor, UpdatedAt: fromUnix(unix(s.now())), Version: old.Version + 1}
	enabled := 0
	if cur.LLMEnabled {
		enabled = 1
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO vuln_agent_config
		(id, llm_enabled, llm_base_url, llm_model, operator_instructions, language, updated_by, updated_at, version)
		VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET llm_enabled = excluded.llm_enabled, llm_base_url = excluded.llm_base_url,
		llm_model = excluded.llm_model, operator_instructions = excluded.operator_instructions,
		language = excluded.language, updated_by = excluded.updated_by, updated_at = excluded.updated_at,
		version = excluded.version`,
		enabled, cur.LLMBaseURL, cur.LLMModel, cur.OperatorInstructions, cur.Language, cur.UpdatedBy, unix(cur.UpdatedAt), cur.Version); err != nil {
		return old, cur, fmt.Errorf("write: %w", err)
	}
	return old, cur, nil
}

// agentAuditAttrs are the audit attributes of a change. A changed base URL
// is flagged: the agent sends finding context to it.
func agentAuditAttrs(actor string, old, cur AgentConfig) map[string]string {
	opHash := func(s string) string {
		sum := sha256.Sum256([]byte(s))
		return hex.EncodeToString(sum[:])
	}
	return map[string]string{
		"actor":                            actor,
		"user":                             actor,
		"old_version":                      strconv.FormatInt(old.Version, 10),
		"new_version":                      strconv.FormatInt(cur.Version, 10),
		"old_llm_enabled":                  strconv.FormatBool(old.LLMEnabled),
		"new_llm_enabled":                  strconv.FormatBool(cur.LLMEnabled),
		"old_llm_base_url":                 old.LLMBaseURL,
		"new_llm_base_url":                 cur.LLMBaseURL,
		"llm_base_url_changed":             strconv.FormatBool(old.LLMBaseURL != cur.LLMBaseURL),
		"old_llm_model":                    old.LLMModel,
		"new_llm_model":                    cur.LLMModel,
		"old_language":                     old.Language,
		"new_language":                     cur.Language,
		"old_operator_instructions_bytes":  strconv.Itoa(len(old.OperatorInstructions)),
		"new_operator_instructions_bytes":  strconv.Itoa(len(cur.OperatorInstructions)),
		"old_operator_instructions_sha256": opHash(old.OperatorInstructions),
		"new_operator_instructions_sha256": opHash(cur.OperatorInstructions),
		"operator_instructions_changed":    strconv.FormatBool(old.OperatorInstructions != cur.OperatorInstructions),
	}
}
