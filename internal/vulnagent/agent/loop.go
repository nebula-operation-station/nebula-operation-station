// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
)

// Outcome says how the assessment of one finding ended. Every outcome but
// OutcomeAssessed leaves the finding without new text; none holds it back.
type Outcome string

// Outcomes.
const (
	// OutcomeAssessed: a valid submit_assessment was received.
	OutcomeAssessed Outcome = "assessed"
	// OutcomeDisabled: the assessor is disabled; no call was made.
	OutcomeDisabled Outcome = "disabled"
	// OutcomeInvalidFinding: the finding facts failed validation.
	OutcomeInvalidFinding Outcome = "invalid_finding"
	// OutcomePromptBase: the base prompt exceeds PromptBaseMaxBytes.
	OutcomePromptBase Outcome = "prompt_base"
	// OutcomeStepLimit: MaxToolSteps reached without a valid result.
	OutcomeStepLimit Outcome = "step_limit"
	// OutcomePromptLimit: the next call would exceed MaxPromptTokens.
	OutcomePromptLimit Outcome = "prompt_limit"
	// OutcomeRunBudget: the run's token or call budget is used up.
	OutcomeRunBudget Outcome = "run_budget"
	// OutcomeTimeout: LLMCallTimeout or FindingTimeout reached.
	OutcomeTimeout Outcome = "timeout"
	// OutcomeLLMError: the endpoint failed or refused.
	OutcomeLLMError Outcome = "llm_error"
	// OutcomeCanceled: the run context ended.
	OutcomeCanceled Outcome = "canceled"
)

// Fixed notices sent to the model; they never echo model output.
const (
	noticeNoToolCall    = "No tool call received. Respond with exactly one tool call; free text is discarded."
	noticeUnknownTool   = "Unknown tool. Allowed tools: cve_details, advisory_text, package_history, backport_check, exposure, kev_epss, submit_assessment."
	noticeInvalidArgs   = "Tool call rejected: arguments do not match the tool's schema."
	noticeCallTooLarge  = "Tool call rejected: arguments too large."
	noticeInvalidSubmit = "submit_assessment rejected: payload does not match the schema (text <= 4096 bytes and rationale <= 1024 bytes of printable UTF-8, three booleans, no other fields)."
)

// FindingFacts are the bounded facts of one finding from the
// deterministic pipeline, given to the model as untrusted data.
type FindingFacts struct {
	// FindingKey is the lower-case hex finding_key.
	FindingKey string `json:"finding_key"`
	// VulnID is the primary vulnerability ID.
	VulnID string `json:"vuln_id"`
	// Aliases are further IDs.
	Aliases []string `json:"aliases,omitempty"`
	// SubjectKind is host, image or device.
	SubjectKind string `json:"subject_kind"`
	// Ecosystem is the component's ecosystem.
	Ecosystem string `json:"ecosystem"`
	// SourcePackage is the source package or device model.
	SourcePackage string `json:"source_package"`
	// SourceVersion is the installed source version.
	SourceVersion string `json:"source_version,omitempty"`
	// FixedVersion is the fixed version, if any.
	FixedVersion string `json:"fixed_version,omitempty"`
	// Fix is the fix keyword when there is no fixed version.
	Fix string `json:"fix,omitempty"`
	// KEV reports a KEV listing.
	KEV bool `json:"kev"`
	// CVSSMax is the highest CVSS base score, nil when unscored.
	CVSSMax *float64 `json:"cvss_max,omitempty"`
	// EPSS is the EPSS probability, nil when unscored.
	EPSS *float64 `json:"epss,omitempty"`
}

// FindingResult is the outcome for one finding.
type FindingResult struct {
	// FindingKey identifies the finding.
	FindingKey string
	// Outcome says how the loop ended.
	Outcome Outcome
	// Assessment is set only for OutcomeAssessed.
	Assessment *Assessment
	// Calls is the number of LLM calls sent for the finding.
	Calls int
	// LoopSteps counts every tool call the model returned (the budget unit).
	LoopSteps int
	// KeptSteps counts executed lookup calls placed in the history.
	KeptSteps int
	// DiscardedCalls counts parallel calls discarded unexecuted.
	DiscardedCalls int
	// InvalidCalls counts rejected calls and responses without a call.
	InvalidCalls int
}

// RunReport is the outcome of one assessment run.
type RunReport struct {
	// Results are in assessment order.
	Results []FindingResult
	// Calls is the number of LLM calls sent in the run.
	Calls int
	// TokensCharged is the token total charged to MaxRunTokens.
	TokensCharged int64
	// BudgetExhausted reports that the run made no further call.
	BudgetExhausted bool
}

// Config configures an Agent.
type Config struct {
	// Enabled switches the assessor on. When false no LLM call is made
	// and the other fields are ignored.
	Enabled bool
	// LLM is the endpoint.
	LLM LLM
	// Prompt is the validated system prompt.
	Prompt Prompt
	// Limits are the run limits.
	Limits Limits
	// Snapshot is the run's pinned feed snapshot.
	Snapshot Snapshot
	// View is the run's pipeline results and export.
	View RunView
	// Logger receives one entry per finding (counts only, never text);
	// nil discards.
	Logger *slog.Logger
}

// Agent assesses findings with an LLM.
type Agent struct {
	enabled   bool
	llm       LLM
	prompt    Prompt
	limits    Limits
	tools     tools
	toolDefs  []ToolDef
	toolBytes int
	log       *slog.Logger
}

// New validates cfg. A disabled configuration always succeeds.
func New(cfg Config) (*Agent, error) {
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if !cfg.Enabled {
		return &Agent{log: log}, nil
	}
	if cfg.LLM == nil || cfg.Snapshot == nil || cfg.View == nil {
		return nil, fmt.Errorf("enabled assessor needs llm, snapshot and view: %w", ErrInvalidConfig)
	}
	if cfg.Prompt.version == "" {
		return nil, fmt.Errorf("prompt not built with NewPrompt: %w", ErrInvalidConfig)
	}
	if err := cfg.Limits.Validate(); err != nil {
		return nil, err
	}
	defs := ToolDefinitions()
	tb, err := json.Marshal(encodeTools(defs))
	if err != nil {
		return nil, fmt.Errorf("encode tool definitions: %w", err)
	}
	if room := PromptBaseMaxBytes - len(cfg.Prompt.system) - len(tb); room < MinEnvelopeRoomBytes {
		return nil, fmt.Errorf("system prompt and tool definitions leave %d bytes for the finding, need %d: %w",
			room, MinEnvelopeRoomBytes, ErrInvalidConfig)
	}
	return &Agent{
		enabled: true, llm: cfg.LLM, prompt: cfg.Prompt, limits: cfg.Limits,
		tools: tools{snap: cfg.Snapshot, view: cfg.View}, toolDefs: defs, toolBytes: len(tb), log: log,
	}, nil
}

// SortFindings orders findings for assessment: KEV-listed first, then the
// highest CVSS score (unscored last), then finding_key ascending.
func SortFindings(fs []FindingFacts) {
	score := func(f FindingFacts) float64 {
		if f.CVSSMax == nil {
			return -1
		}
		return *f.CVSSMax
	}
	slices.SortStableFunc(fs, func(a, b FindingFacts) int {
		if a.KEV != b.KEV {
			if a.KEV {
				return -1
			}
			return 1
		}
		if c := cmp.Compare(score(b), score(a)); c != 0 {
			return c
		}
		return cmp.Compare(a.FindingKey, b.FindingKey)
	})
}

// runState is the budget shared by the findings of one run.
type runState struct {
	calls     int
	tokens    int64
	exhausted bool
}

// Run assesses the findings in priority order within the run budget. It
// never fails: every limit, endpoint error or invalid output leaves the
// affected finding without text. A disabled agent makes no call.
func (a *Agent) Run(ctx context.Context, findings []FindingFacts) RunReport {
	order := slices.Clone(findings)
	SortFindings(order)
	var st runState
	rep := RunReport{Results: make([]FindingResult, 0, len(order))}
	for _, f := range order {
		var r FindingResult
		switch {
		case !a.enabled:
			r = FindingResult{FindingKey: f.FindingKey, Outcome: OutcomeDisabled}
		case ctx.Err() != nil:
			r = FindingResult{FindingKey: f.FindingKey, Outcome: OutcomeCanceled}
		case st.exhausted:
			r = FindingResult{FindingKey: f.FindingKey, Outcome: OutcomeRunBudget}
		default:
			r = a.assess(ctx, f, &st)
		}
		if a.enabled {
			a.log.LogAttrs(ctx, slog.LevelInfo, "vuln assessment",
				slog.String("finding_key", r.FindingKey), slog.String("outcome", string(r.Outcome)),
				slog.Int("calls", r.Calls), slog.Int("loop_steps", r.LoopSteps), slog.Int("kept_steps", r.KeptSteps),
				slog.Int("discarded_calls", r.DiscardedCalls), slog.Int("invalid_calls", r.InvalidCalls))
		}
		rep.Results = append(rep.Results, r)
	}
	rep.Calls, rep.TokensCharged, rep.BudgetExhausted = st.calls, st.tokens, st.exhausted
	return rep
}

// estimate is the prompt token estimate of a call: bytes as sent plus
// MessageOverheadTokens per message.
func (a *Agent) estimate(msgs []Message) int64 {
	n := int64(a.toolBytes)
	for _, m := range msgs {
		n += int64(len(m.Content)) + MessageOverheadTokens
		for _, c := range m.ToolCalls {
			n += int64(encodedCallBytes(c))
		}
	}
	return n
}

// encodedCallBytes is the size of a tool call as placed in the prompt.
func encodedCallBytes(c ToolCall) int {
	b, err := json.Marshal(wireToolCall{ID: c.ID, Type: "function", Function: wireFunction{c.Name, c.Arguments}})
	if err != nil {
		return ToolCallMaxBytes + 1
	}
	return len(b)
}

// chargeUsage is the run-budget charge of one answered call. The reported
// usage is untrusted: each part is floored at what NOS measured itself
// (the prompt estimate, the bytes of the returned text and tool calls)
// and the charge is capped at maxRun, so a huge, negative or understated
// report can neither overflow the run total nor lower the charge below
// the measured size. Before the call st.tokens+reserve <= maxRun held, so
// the sum stays below 2 × HardMaxRunTokens.
func chargeUsage(est int64, u Usage, resp Response, maxRun int64) int64 {
	seen := int64(len(resp.Content))
	for _, c := range resp.ToolCalls {
		seen += int64(len(c.Name)) + int64(len(c.Arguments))
	}
	prompt := min(max(est, u.PromptTokens), maxRun)
	completion := min(max(seen, u.CompletionTokens), maxRun)
	return min(prompt+completion, maxRun)
}

// assess runs the loop for one finding.
func (a *Agent) assess(ctx context.Context, f FindingFacts, st *runState) FindingResult {
	res := FindingResult{FindingKey: f.FindingKey}
	if !findingKeyRe.MatchString(f.FindingKey) || !vulnIDRe.MatchString(f.VulnID) {
		res.Outcome = OutcomeInvalidFinding
		return res
	}
	facts, err := untrustedEnvelope("finding_facts", f)
	if err != nil {
		res.Outcome = OutcomeInvalidFinding
		return res
	}
	if len(a.prompt.system)+a.toolBytes+len(facts) > PromptBaseMaxBytes {
		res.Outcome = OutcomePromptBase
		return res
	}
	msgs := []Message{{Role: "system", Content: a.prompt.system}, {Role: "user", Content: facts}}
	fctx, cancel := context.WithTimeout(ctx, a.limits.FindingTimeout)
	defer cancel()
	l := a.limits
	for {
		if ctx.Err() != nil {
			res.Outcome = OutcomeCanceled
			return res
		}
		if fctx.Err() != nil {
			res.Outcome = OutcomeTimeout
			return res
		}
		if res.LoopSteps >= l.MaxToolSteps {
			res.Outcome = OutcomeStepLimit
			return res
		}
		est := a.estimate(msgs)
		if est > int64(l.MaxPromptTokens) {
			res.Outcome = OutcomePromptLimit
			return res
		}
		reserve := est + int64(l.MaxOutputTokens)
		if st.calls >= l.MaxRunCalls || st.tokens+reserve > l.MaxRunTokens {
			st.exhausted = true
			res.Outcome = OutcomeRunBudget
			return res
		}
		cctx, ccancel := context.WithTimeout(fctx, l.LLMCallTimeout)
		resp, err := a.llm.Complete(cctx, Request{Messages: slices.Clone(msgs), Tools: a.toolDefs, MaxTokens: l.MaxOutputTokens})
		callTimedOut := errors.Is(cctx.Err(), context.DeadlineExceeded)
		ccancel()
		st.calls++
		res.Calls++
		if err != nil || resp.Usage == nil {
			st.tokens += reserve
		} else {
			st.tokens += chargeUsage(est, *resp.Usage, resp, l.MaxRunTokens)
		}
		if err != nil {
			switch {
			case ctx.Err() != nil:
				res.Outcome = OutcomeCanceled
			case fctx.Err() != nil || callTimedOut:
				res.Outcome = OutcomeTimeout
			default:
				res.Outcome = OutcomeLLMError
			}
			return res
		}
		// resp.Content is free model text and is discarded unread.
		if len(resp.ToolCalls) == 0 {
			res.LoopSteps++
			res.InvalidCalls++
			msgs = append(msgs, Message{Role: "user", Content: noticeEnvelope(noticeNoToolCall)})
			continue
		}
		res.LoopSteps += len(resp.ToolCalls)
		res.DiscardedCalls += len(resp.ToolCalls) - 1
		call := resp.ToolCalls[0]
		if call.Name == ToolSubmitAssessment {
			as, err := parseSubmit(call.Arguments)
			if err != nil {
				res.InvalidCalls++
				msgs = append(msgs, Message{Role: "user", Content: noticeEnvelope(noticeInvalidSubmit)})
				continue
			}
			as.PromptVersion, as.Language = a.prompt.version, a.prompt.language
			res.Outcome, res.Assessment = OutcomeAssessed, &as
			return res
		}
		kept := ToolCall{ID: fmt.Sprintf("call_%d", res.KeptSteps+1), Name: call.Name, Arguments: call.Arguments}
		if encodedCallBytes(kept) > ToolCallMaxBytes {
			res.InvalidCalls++
			msgs = append(msgs, Message{Role: "user", Content: noticeEnvelope(noticeCallTooLarge)})
			continue
		}
		out, err := a.tools.execLookup(f.FindingKey, call.Name, call.Arguments)
		switch {
		case errors.Is(err, ErrNotFound):
			out = lookupResult{data: map[string]any{"found": false}}
		case errors.Is(err, ErrUnknownTool):
			res.InvalidCalls++
			msgs = append(msgs, Message{Role: "user", Content: noticeEnvelope(noticeUnknownTool)})
			continue
		case err != nil:
			res.InvalidCalls++
			msgs = append(msgs, Message{Role: "user", Content: noticeEnvelope(noticeInvalidArgs)})
			continue
		}
		content, err := toolResultContent(call.Name, out, l.MaxToolResultBytes)
		if err != nil {
			res.Outcome = OutcomeLLMError
			return res
		}
		res.KeptSteps++
		msgs = append(msgs,
			Message{Role: "assistant", ToolCalls: []ToolCall{kept}},
			Message{Role: "tool", ToolCallID: kept.ID, Content: content})
	}
}
