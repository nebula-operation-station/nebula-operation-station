// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"errors"
	"fmt"
	"time"
)

// Defaults and hard maxima of the configurable limits (ADR 0011 A1.4). The
// operator may set any value from 1 up to the hard maximum; zero never
// means "unlimited".
const (
	// DefaultMaxToolSteps is the default number of loop steps per finding:
	// every tool call the model returns counts, kept, invalid or discarded.
	DefaultMaxToolSteps = 8
	// HardMaxToolSteps caps MaxToolSteps.
	HardMaxToolSteps = 16

	// DefaultMaxToolResultBytes bounds one tool result as placed in the
	// prompt (after JSON encoding, cut marker included).
	DefaultMaxToolResultBytes = 4 << 10
	// HardMaxToolResultBytes caps MaxToolResultBytes.
	HardMaxToolResultBytes = 64 << 10
	// MinToolResultBytes is the smallest MaxToolResultBytes: room for the
	// cut envelope with its marker and record tag.
	MinToolResultBytes = 1 << 10

	// DefaultMaxOutputTokens is sent as max_tokens with every LLM call.
	DefaultMaxOutputTokens = 1024
	// HardMaxOutputTokens caps MaxOutputTokens.
	HardMaxOutputTokens = 4096

	// DefaultMaxPromptTokens bounds the estimated prompt of one LLM call.
	DefaultMaxPromptTokens = 49152
	// HardMaxPromptTokens caps MaxPromptTokens.
	HardMaxPromptTokens = 65536

	// DefaultMaxRunTokens is the token budget of all LLM calls of a run.
	DefaultMaxRunTokens int64 = 2_000_000
	// HardMaxRunTokens caps MaxRunTokens.
	HardMaxRunTokens int64 = 20_000_000

	// DefaultMaxRunCalls is the default number of LLM calls per run.
	DefaultMaxRunCalls = 5000
	// HardMaxRunCalls caps MaxRunCalls.
	HardMaxRunCalls = 50000

	// DefaultLLMCallTimeout bounds one LLM call.
	DefaultLLMCallTimeout = 60 * time.Second
	// HardMaxLLMCallTimeout caps LLMCallTimeout.
	HardMaxLLMCallTimeout = 300 * time.Second

	// DefaultFindingTimeout bounds all steps of one finding.
	DefaultFindingTimeout = 180 * time.Second
	// HardMaxFindingTimeout caps FindingTimeout.
	HardMaxFindingTimeout = 600 * time.Second
)

// Fixed sizes (not configurable).
const (
	// PromptBaseMaxBytes bounds the base prompt of a finding: system
	// prompt (core and operator block), tool definitions and finding
	// envelope, as sent. A finding whose base exceeds it is not assessed.
	PromptBaseMaxBytes = 8 << 10
	// MinEnvelopeRoomBytes is the room a prompt configuration must leave
	// for the finding envelope inside PromptBaseMaxBytes.
	MinEnvelopeRoomBytes = 2 << 10
	// ToolCallMaxBytes bounds one lookup tool call kept in the history,
	// measured on its encoded form.
	ToolCallMaxBytes = 512
	// MaxSubmitArgumentsBytes bounds the raw arguments of a
	// submit_assessment call (4 KiB text and 1 KiB rationale, escaped).
	MaxSubmitArgumentsBytes = 48 << 10
	// MessageOverheadTokens is the token estimate added per chat message.
	MessageOverheadTokens = 32
	// MaxTextBytes bounds the assessment text (equal to
	// vulnfinding.MaxAssessmentBytes, checked by a test).
	MaxTextBytes = 4 << 10
	// MaxRationaleBytes bounds the rationale kept in the local audit log.
	MaxRationaleBytes = 1 << 10
	// MaxOperatorInstructionsBytes bounds the operator instructions.
	MaxOperatorInstructionsBytes = 4 << 10
)

// ErrInvalidConfig reports a configuration the agent refuses.
var ErrInvalidConfig = errors.New("vulnagent/agent: invalid configuration")

// Limits are the per-run limits of the assessor.
type Limits struct {
	// MaxToolSteps is the number of loop steps per finding.
	MaxToolSteps int
	// MaxToolResultBytes bounds one encoded tool result.
	MaxToolResultBytes int
	// MaxOutputTokens is the max_tokens of every call.
	MaxOutputTokens int
	// MaxPromptTokens bounds the estimated prompt of one call.
	MaxPromptTokens int
	// MaxRunTokens is the token budget of a run.
	MaxRunTokens int64
	// MaxRunCalls is the number of LLM calls of a run.
	MaxRunCalls int
	// LLMCallTimeout bounds one call.
	LLMCallTimeout time.Duration
	// FindingTimeout bounds all calls of one finding.
	FindingTimeout time.Duration
}

// DefaultLimits returns the default limits.
func DefaultLimits() Limits {
	return Limits{
		MaxToolSteps:       DefaultMaxToolSteps,
		MaxToolResultBytes: DefaultMaxToolResultBytes,
		MaxOutputTokens:    DefaultMaxOutputTokens,
		MaxPromptTokens:    DefaultMaxPromptTokens,
		MaxRunTokens:       DefaultMaxRunTokens,
		MaxRunCalls:        DefaultMaxRunCalls,
		LLMCallTimeout:     DefaultLLMCallTimeout,
		FindingTimeout:     DefaultFindingTimeout,
	}
}

// Validate checks every limit against its range and that the prompt of a
// finding that uses all its steps fits MaxPromptTokens:
//
//	PromptBaseMaxBytes + MaxToolSteps × (ToolCallMaxBytes + MaxToolResultBytes)
//	  + (2 + 2 × MaxToolSteps) × MessageOverheadTokens ≤ MaxPromptTokens
func (l Limits) Validate() error {
	checks := []struct {
		name     string
		v, limit int64
	}{
		{"max_tool_steps", int64(l.MaxToolSteps), HardMaxToolSteps},
		{"max_tool_result_bytes", int64(l.MaxToolResultBytes), HardMaxToolResultBytes},
		{"max_output_tokens", int64(l.MaxOutputTokens), HardMaxOutputTokens},
		{"max_prompt_tokens", int64(l.MaxPromptTokens), HardMaxPromptTokens},
		{"max_run_tokens", l.MaxRunTokens, HardMaxRunTokens},
		{"max_run_calls", int64(l.MaxRunCalls), HardMaxRunCalls},
		{"llm_call_timeout", int64(l.LLMCallTimeout), int64(HardMaxLLMCallTimeout)},
		{"finding_timeout", int64(l.FindingTimeout), int64(HardMaxFindingTimeout)},
	}
	for _, c := range checks {
		if c.v < 1 || c.v > c.limit {
			return fmt.Errorf("%s %d outside 1..%d: %w", c.name, c.v, c.limit, ErrInvalidConfig)
		}
	}
	if l.MaxToolResultBytes < MinToolResultBytes {
		return fmt.Errorf("max_tool_result_bytes %d below %d: %w", l.MaxToolResultBytes, MinToolResultBytes, ErrInvalidConfig)
	}
	need := int64(PromptBaseMaxBytes) +
		int64(l.MaxToolSteps)*int64(ToolCallMaxBytes+l.MaxToolResultBytes) +
		int64(2+2*l.MaxToolSteps)*MessageOverheadTokens
	if need > int64(l.MaxPromptTokens) {
		return fmt.Errorf("prompt of %d steps needs %d tokens, max_prompt_tokens is %d: %w",
			l.MaxToolSteps, need, l.MaxPromptTokens, ErrInvalidConfig)
	}
	if first := int64(PromptBaseMaxBytes + 2*MessageOverheadTokens + l.MaxOutputTokens); l.MaxRunTokens < first {
		return fmt.Errorf("max_run_tokens %d below one first call (%d): %w", l.MaxRunTokens, first, ErrInvalidConfig)
	}
	return nil
}
