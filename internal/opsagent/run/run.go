// SPDX-License-Identifier: AGPL-3.0-or-later

// Package run is one oneshot run of the ops agent (ADR 0016 D2, D3, D5, D6).
// It reads the settings and the work list from NOS, checks both against its
// own rules, makes at most one LLM call per work item (one retry on invalid
// output), validates each answer, and posts the notes and the run status.
// It has no tool loop and no second data source.
package run

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/helpdocs"
	"github.com/nebula-operation-station/nebula-operation-station/internal/helpsearch"
	"github.com/nebula-operation-station/nebula-operation-station/internal/llmclient"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsagent/nosclient"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsagent/prompt"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsagent/state"
)

// Limits and timing of a run, named next to the code that enforces them.
const (
	// MaxLLMCallsPerRun bounds the LLM calls of one run, retries included.
	MaxLLMCallsPerRun = 20
	// MaxLLMCallsPerDay bounds the LLM calls of one UTC day.
	MaxLLMCallsPerDay = 200
	// MaxOutputTokens is the max_tokens of one call.
	MaxOutputTokens = 1024
	// CallTimeout bounds one call.
	CallTimeout = 90 * time.Second
	// StatusTimeout bounds the posting of the run status. It runs on a fresh
	// context, so a run that hit its deadline still reports why.
	StatusTimeout = 30 * time.Second
	// MaxAttemptsPerItem is one call and one retry on invalid output.
	MaxAttemptsPerItem = 2
	// MaxItemRefs bounds the length of a work item reference.
	MaxItemRefs = 128
	// maxConfigOperatorBytes is prompt.MaxOperatorBytes, repeated here so the
	// settings check does not depend on the prompt package.
	maxConfigOperatorBytes = prompt.MaxOperatorBytes
	// maxConfigURLBytes bounds the LLM base URL.
	maxConfigURLBytes = 512
	// maxConfigModelBytes bounds the model name.
	maxConfigModelBytes = 128
)

// Refusal reasons; they match the server's fixed list (internal/web/api).
const (
	RefusedLabRule     = "llm_refused_lab_rule"
	RefusedTimeout     = "llm_timeout"
	RefusedLLMError    = "llm_error"
	RefusedOutput      = "output_discarded"
	RefusedNote        = "note_refused"
	RefusedWork        = "work_unavailable"
	RefusedRateLimited = "rate_limited"
)

// NOS is the part of the NOS API the run uses. *nosclient.Client implements it.
type NOS interface {
	AgentConfig(ctx context.Context) (nosclient.AgentConfig, error)
	Work(ctx context.Context) ([]nosclient.WorkItem, error)
	PostNote(ctx context.Context, d nosclient.Draft) error
	PostStatus(ctx context.Context, s nosclient.Status) error
}

// Chatter is one chat call. *llmclient.Client implements it.
type Chatter interface {
	Chat(ctx context.Context, req llmclient.Request) (llmclient.Response, error)
}

// Searcher finds documentation. *helpsearch.Index implements it.
type Searcher interface {
	Search(q string) ([]helpsearch.Hit, error)
}

// LLMSettings is what the run needs to build its LLM client.
type LLMSettings struct {
	Class          prompt.Class
	BaseURL        string
	Model          string
	AllowPlainHTTP bool
	// CredentialFile is the agent's own credential file, empty for none.
	CredentialFile string
}

// Deps are the collaborators of a run. Nil Docs means no documentation.
type Deps struct {
	NOS   NOS
	State *state.Store
	Docs  Searcher
	// NewLLM builds the chat client for the settings. Production uses
	// BuildLLM; tests inject fakes.
	NewLLM func(ctx context.Context, s LLMSettings) (Chatter, error)
	// CredentialFile is the agent's LLM credential file (may be empty).
	CredentialFile string
	Now            func() time.Time
	Log            *slog.Logger
}

// Summary is what a run did. It holds counts and refusal reasons only.
type Summary struct {
	ItemsSeen int
	LLMCalls  int
	// Discarded counts model answers thrown away (one per invalid attempt),
	// work items refused, and steps dropped from answers that were used.
	Discarded    int
	NotesWritten int
	Refusals     []string
	// Disabled is true when the settings switch the agent off.
	Disabled bool
}

// BuildLLM returns the chat client for s. Class lab always gets the lab-only
// dialer, and it is checked before any connection; no flag or environment
// variable changes that (ADR 0016 D5). Class external gets the plain dialer.
func BuildLLM(ctx context.Context, s LLMSettings) (Chatter, error) {
	opts := llmclient.Options{
		BaseURL:        s.BaseURL,
		Model:          s.Model,
		CredentialFile: s.CredentialFile,
		AllowPlainHTTP: s.AllowPlainHTTP,
		Timeout:        CallTimeout,
	}
	switch s.Class {
	case prompt.ClassLab:
		opts.LabOnly = true
		if err := llmclient.CheckEndpoint(ctx, opts); err != nil {
			return nil, err
		}
	case prompt.ClassExternal:
		opts.UnrestrictedEgress = true
	default:
		return nil, fmt.Errorf("llm settings: unknown data class: %w", llmclient.ErrConfig)
	}
	c, err := llmclient.New(opts)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// validateSettings re-checks what the server served against the agent's
// rules. An error means the run does nothing.
func validateSettings(c nosclient.AgentConfig) error {
	if c.DataClass != string(prompt.ClassLab) && c.DataClass != string(prompt.ClassExternal) {
		return errors.New("settings: unknown data class")
	}
	if c.Language != string(prompt.LangDE) && c.Language != string(prompt.LangEN) {
		return errors.New("settings: unknown language")
	}
	if c.LLMBaseURL == "" || len(c.LLMBaseURL) > maxConfigURLBytes || !printableASCII(c.LLMBaseURL) {
		return errors.New("settings: llm base url")
	}
	if c.LLMModel == "" || len(c.LLMModel) > maxConfigModelBytes || !printableASCII(c.LLMModel) {
		return errors.New("settings: llm model")
	}
	if len(c.OperatorInstructions) > maxConfigOperatorBytes || !plainOperator(c.OperatorInstructions) {
		return errors.New("settings: operator instructions")
	}
	return nil
}

func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] > '~' {
			return false
		}
	}
	return true
}

// plainOperator accepts valid UTF-8 with newlines and tabs and no other
// control, bidi or zero-width characters.
func plainOperator(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r == '\n' || r == '\t' {
			continue
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == utf8.RuneError {
			return false
		}
	}
	return true
}

// validateItem checks one work item against the data class. A lab fix item
// must carry its group; class external gets summaries only.
func validateItem(class string, it nosclient.WorkItem) error {
	if it.Ref == "" || len(it.Ref) > MaxItemRefs || !printableASCII(it.Ref) {
		return errors.New("item ref")
	}
	if !isDigest(it.Digest) {
		return errors.New("item digest")
	}
	if it.Kind != "question" && (it.Question != "" || len(it.Facts) > 0) {
		return errors.New("item carries question data")
	}
	switch it.Kind {
	case "fix":
		if class != string(prompt.ClassLab) || it.Group == nil || it.Fleet != nil {
			return errors.New("fix item outside class lab")
		}
		g := it.Group
		if g.Host.ID == "" || !printableASCII(g.Host.ID) {
			return errors.New("fix item host")
		}
		keys := map[string]bool{}
		for _, c := range g.Candidates {
			if !prompt.ValidCandidateKey(c.Key) || keys[c.Key] || c.HostID != g.Host.ID ||
				c.Action == "" || !printableASCII(c.Action) {
				return errors.New("fix item candidate")
			}
			keys[c.Key] = true
		}
		return nil
	case "summary":
		if it.Fleet == nil || it.Group != nil {
			return errors.New("summary item shape")
		}
		return nil
	case "question":
		return validateQuestion(class, it)
	default:
		return errors.New("item kind")
	}
}

// validateQuestion checks a question item: its text and fleet counts, and,
// in class lab only, the facts of the hosts it names. Facts never carry
// findings or steps (ADR 0016 D11).
func validateQuestion(class string, it nosclient.WorkItem) error {
	if it.Question == "" || len(it.Question) > prompt.MaxQuestionBytes || it.Group != nil || it.Fleet == nil {
		return errors.New("question shape")
	}
	if class == string(prompt.ClassExternal) && len(it.Facts) > 0 {
		return errors.New("question facts outside class lab")
	}
	if len(it.Facts) > prompt.MaxFactHosts {
		return errors.New("question facts too many")
	}
	for _, f := range it.Facts {
		if f.Host.ID == "" || !printableASCII(f.Host.ID) || len(f.Findings) > 0 || len(f.Candidates) > 0 {
			return errors.New("question facts shape")
		}
	}
	return nil
}

func isDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if (s[i] < '0' || s[i] > '9') && (s[i] < 'a' || s[i] > 'f') {
			return false
		}
	}
	return true
}

// Run performs one oneshot run. It returns an error only when the run could
// not start or read its input; every other problem is a refusal in the
// Summary and the run goes on.
func Run(ctx context.Context, d Deps) (Summary, error) {
	log := d.Log
	if log == nil {
		log = slog.Default()
	}
	now := d.Now
	if now == nil {
		now = time.Now
	}
	cfg, err := d.NOS.AgentConfig(ctx)
	if err != nil {
		return Summary{}, fmt.Errorf("read settings: %w", err)
	}
	if !cfg.Enabled {
		log.Info("ops agent disabled by settings")
		return Summary{Disabled: true}, nil
	}
	if err := validateSettings(cfg); err != nil {
		return Summary{}, fmt.Errorf("settings refused: %w", err)
	}
	items, err := d.NOS.Work(ctx)
	if err != nil {
		return Summary{}, fmt.Errorf("read work list: %w", err)
	}
	var sum Summary
	if len(items) == 0 {
		log.Info("ops agent: no work")
		return sum, nil
	}
	used, err := d.State.Used()
	if err != nil {
		return Summary{}, fmt.Errorf("read call counter: %w", err)
	}
	budget := min(MaxLLMCallsPerRun, MaxLLMCallsPerDay-used)
	sum.ItemsSeen = len(items)
	r := &runner{d: d, log: log, cfg: cfg, sum: &sum, budget: budget, now: now}
	r.loop(ctx, items)
	sum.Refusals = uniqueSorted(sum.Refusals)
	status := nosclient.Status{
		RunAt:        now().UTC().Format(time.RFC3339),
		ItemsSeen:    sum.ItemsSeen,
		LLMCalls:     sum.LLMCalls,
		Discarded:    sum.Discarded,
		NotesWritten: sum.NotesWritten,
		Refusals:     sum.Refusals,
	}
	// The status is the place where a deadline shows up, so it is posted even
	// when ctx has expired; only the posting itself is bounded.
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), StatusTimeout)
	defer cancel()
	if err := d.NOS.PostStatus(sctx, status); err != nil {
		log.Warn("ops agent: post status failed", "error", err)
	}
	log.Info("ops agent run finished", "items_seen", sum.ItemsSeen, "llm_calls", sum.LLMCalls,
		"discarded", sum.Discarded, "notes_written", sum.NotesWritten, "refusals", len(sum.Refusals))
	return sum, nil
}

func uniqueSorted(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return slices.Compact(out)
}

// runner holds the state of one run's item loop.
type runner struct {
	d      Deps
	log    *slog.Logger
	cfg    nosclient.AgentConfig
	sum    *Summary
	budget int
	now    func() time.Time
	chat   Chatter
}

func (r *runner) refuse(reason string) {
	r.sum.Refusals = append(r.sum.Refusals, reason)
}

// loop works the items in order. A lab-rule refusal ends the run: there is
// no fallback to another class.
func (r *runner) loop(ctx context.Context, items []nosclient.WorkItem) {
	if r.budget <= 0 {
		r.refuse(RefusedRateLimited)
		return
	}
	// Admin questions run before fix items and share their budget (ADR 0016
	// D11); the order within each kind is the order of the work list.
	ordered := slices.Clone(items)
	slices.SortStableFunc(ordered, func(a, b nosclient.WorkItem) int {
		return kindRank(a.Kind) - kindRank(b.Kind)
	})
	for _, it := range ordered {
		if ctx.Err() != nil {
			r.refuse(RefusedTimeout)
			return
		}
		if err := validateItem(r.cfg.DataClass, it); err != nil {
			r.log.Warn("ops agent: work item refused", "kind", it.Kind)
			r.sum.Discarded++
			r.refuse(RefusedWork)
			continue
		}
		if r.budget <= 0 {
			r.refuse(RefusedRateLimited)
			return
		}
		if stop := r.item(ctx, it); stop {
			return
		}
	}
}

// kindRank orders work items: questions first, then the rest.
func kindRank(kind string) int {
	if kind == "question" {
		return 0
	}
	return 1
}

// item handles one work item with one call and at most one retry. It reports
// true when the run must stop.
func (r *runner) item(ctx context.Context, it nosclient.WorkItem) bool {
	if r.chat == nil {
		c, err := r.build(ctx)
		if err != nil {
			if errors.Is(err, llmclient.ErrNotLabAddress) {
				r.refuse(RefusedLabRule)
				r.log.Warn("ops agent: llm endpoint refused by the lab rule")
				return true
			}
			r.refuse(RefusedLLMError)
			r.log.Warn("ops agent: llm client not built")
			return true
		}
		r.chat = c
	}
	p, docs, err := r.prompt(it)
	if err != nil {
		r.sum.Discarded++
		r.refuse(RefusedWork)
		r.log.Warn("ops agent: prompt refused", "kind", it.Kind)
		return false
	}
	for attempt := 0; attempt < MaxAttemptsPerItem; attempt++ {
		if r.budget <= 0 {
			r.refuse(RefusedRateLimited)
			return true
		}
		if err := r.d.State.Add(1); err != nil {
			r.refuse(RefusedLLMError)
			r.log.Error("ops agent: call counter not written")
			return true
		}
		r.budget--
		r.sum.LLMCalls++
		content, stop := r.call(ctx, p.Text, it.Kind)
		if stop {
			return true
		}
		if content == nil {
			return false
		}
		draft, err := r.check(it, *content, docs)
		if err != nil {
			r.sum.Discarded++
			r.log.Warn("ops agent: model output discarded", "attempt", attempt+1)
			continue
		}
		if err := r.d.NOS.PostNote(ctx, draft); err != nil {
			if errors.Is(err, nosclient.ErrNoteRejected) {
				r.refuse(RefusedNote)
				r.log.Warn("ops agent: note refused by nos")
				return false
			}
			r.refuse(RefusedWork)
			r.log.Error("ops agent: post note failed")
			return true
		}
		r.sum.NotesWritten++
		return false
	}
	r.refuse(RefusedOutput)
	return false
}

// build makes the chat client for the settings of this run.
func (r *runner) build(ctx context.Context) (Chatter, error) {
	s := LLMSettings{
		Class:          prompt.Class(r.cfg.DataClass),
		BaseURL:        r.cfg.LLMBaseURL,
		Model:          r.cfg.LLMModel,
		AllowPlainHTTP: r.cfg.AllowPlainHTTP,
		CredentialFile: r.d.CredentialFile,
	}
	if r.d.NewLLM == nil {
		return BuildLLM(ctx, s)
	}
	return r.d.NewLLM(ctx, s)
}

// call makes one chat call. It returns the content, or stop=true when the
// run must end. A nil content without stop means the item is given up.
func (r *runner) call(ctx context.Context, text, kind string) (*string, bool) {
	cctx, cancel := context.WithTimeout(ctx, CallTimeout)
	defer cancel()
	resp, err := r.chat.Chat(cctx, llmclient.Request{
		Messages:  []llmclient.Message{{Role: "user", Content: text}},
		MaxTokens: MaxOutputTokens,
		JSONSchema: &llmclient.JSONSchema{
			Name:   "ops_" + kind,
			Schema: schemaFor(kind),
		},
	})
	switch {
	case errors.Is(err, llmclient.ErrNotLabAddress):
		r.refuse(RefusedLabRule)
		r.log.Warn("ops agent: connection refused by the lab rule")
		return nil, true
	case errors.Is(err, context.DeadlineExceeded):
		r.refuse(RefusedTimeout)
		r.log.Warn("ops agent: llm call timed out")
		return nil, false
	case err != nil:
		r.refuse(RefusedLLMError)
		r.log.Warn("ops agent: llm call failed")
		return nil, false
	}
	content := resp.Content
	return &content, false
}

// prompt builds the prompt and the documentation keys of one item.
func (r *runner) prompt(it nosclient.WorkItem) (prompt.Result, map[string]string, error) {
	in := prompt.Input{
		Class: prompt.Class(r.cfg.DataClass),
		Lang:  prompt.Lang(r.cfg.Language),
		Kind:  it.Kind,
		// The operator text is validated by validateSettings.
		Operator: r.cfg.OperatorInstructions,
	}
	var keys map[string]string
	switch it.Kind {
	case "summary":
		in.Fleet = countsOf(*it.Fleet)
	case "question":
		in.Fleet = countsOf(*it.Fleet)
		in.Question = it.Question
		for _, f := range it.Facts {
			in.Facts = append(in.Facts, prompt.Facts{
				Host: prompt.Host{
					Label:       f.Host.Label,
					Environment: f.Host.Environment,
					Criticality: f.Host.Criticality,
					Exposure:    f.Exposure,
					Ports:       portList(f.Ports),
				},
				Counts: *countsOf(f.Counts),
			})
		}
		in.Docs, keys = r.docs(it.Question)
	default:
		g := it.Group
		in.Group = countsOf(g.Counts)
		in.Host = &prompt.Host{
			Label:       g.Host.Label,
			Environment: g.Host.Environment,
			Criticality: g.Host.Criticality,
			Exposure:    g.Exposure,
			Ports:       portList(g.Ports),
		}
		for _, f := range g.Findings {
			in.Findings = append(in.Findings, prompt.Finding{VulnID: f.VulnID, Package: f.Package,
				Installed: f.Installed, Fixed: f.Fixed, Tier: f.Tier, Fix: f.Fix, Score: f.Score, KEV: f.KEV})
		}
		for _, c := range g.Candidates {
			in.Candidates = append(in.Candidates, prompt.Candidate{Key: c.Key, Label: c.Label})
		}
		query := ""
		if len(g.Findings) > 0 {
			query = g.Findings[0].Package
		}
		in.Docs, keys = r.docs(query)
	}
	res, err := prompt.Build(in)
	return res, keys, err
}

// docs picks up to MaxDocChunks documentation chunks for a query (a package
// name for a group, the question for an admin question) and gives them opaque
// keys d1, d2, …; keys maps each key back to the chunk ID.
func (r *runner) docs(query string) ([]prompt.Doc, map[string]string) {
	keys := map[string]string{}
	if r.d.Docs == nil || query == "" {
		return nil, keys
	}
	hits, err := r.d.Docs.Search(query)
	if err != nil {
		return nil, keys
	}
	var out []prompt.Doc
	for _, h := range hits {
		if len(out) == prompt.MaxDocChunks {
			break
		}
		if !validChunk(h.Chunk) {
			continue
		}
		k := "d" + strconv.Itoa(len(out)+1)
		out = append(out, prompt.Doc{Key: k, Text: h.Chunk.Text})
		keys[k] = h.Chunk.ID
	}
	return out, keys
}

func validChunk(c helpdocs.Chunk) bool {
	return c.ID != "" && len(c.Text) <= prompt.MaxDocTextBytes && len(c.ID) <= 128
}

// check parses an answer and builds the note for the item.
func (r *runner) check(it nosclient.WorkItem, content string, docs map[string]string) (nosclient.Draft, error) {
	if it.Kind == "summary" || it.Kind == "question" {
		text, cites, err := parseText(content, docs)
		if err != nil {
			return nosclient.Draft{}, err
		}
		kind := "summary"
		if it.Kind == "question" {
			kind = "answer"
		}
		return nosclient.Draft{Kind: kind, Ref: it.Ref, Digest: it.Digest, Text: text, Citations: cites}, nil
	}
	cands := map[string]nosclient.Candidate{}
	keys := map[string]bool{}
	for _, c := range it.Group.Candidates {
		cands[c.Key] = c
		keys[c.Key] = true
	}
	ans, err := parseFix(content, keys, docs)
	if err != nil {
		return nosclient.Draft{}, err
	}
	steps := make([]nosclient.Step, 0, len(ans.Steps))
	for _, s := range ans.Steps {
		c := cands[s.Candidate]
		steps = append(steps, nosclient.Step{ActionID: c.Action, HostID: c.HostID, Why: s.Why})
	}
	r.sum.Discarded += ans.Discarded
	return nosclient.Draft{
		Kind: "fix", Ref: it.Ref, Digest: it.Digest,
		Summary: ans.Summary, Urgency: ans.Urgency,
		Steps: steps, Mitigations: ans.Mitigations, Citations: ans.Citations,
	}, nil
}

func countsOf(c nosclient.Counts) *prompt.Counts {
	return &prompt.Counts{Critical: c.Critical, High: c.High, Medium: c.Medium, Low: c.Low, KEV: c.KEV}
}

func portList(ps []nosclient.Port) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, strconv.Itoa(p.Number)+"/"+p.Protocol)
	}
	return out
}

// schemaFor returns the JSON schema the endpoint is asked for.
func schemaFor(kind string) []byte {
	if kind == "summary" || kind == "question" {
		return []byte(textSchema)
	}
	return []byte(fixSchema)
}

const textSchema = `{"type":"object","additionalProperties":false,"required":["text"],` +
	`"properties":{"text":{"type":"string"},"citations":{"type":"array","maxItems":3,"items":{"type":"string"}}}}`

const fixSchema = `{"type":"object","additionalProperties":false,"required":["summary","steps"],` +
	`"properties":{"summary":{"type":"string"},"urgency":{"type":"string"},` +
	`"steps":{"type":"array","maxItems":6,"items":{"type":"object","additionalProperties":false,` +
	`"required":["candidate","why"],"properties":{"candidate":{"type":"string"},"why":{"type":"string"}}}},` +
	`"mitigations":{"type":"array","maxItems":3,"items":{"type":"object","additionalProperties":false,` +
	`"required":["text"],"properties":{"text":{"type":"string"}}}},` +
	`"citations":{"type":"array","maxItems":3,"items":{"type":"string"}}}}`
