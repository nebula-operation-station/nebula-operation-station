// SPDX-License-Identifier: AGPL-3.0-or-later

package api

// The ops agent API (ADR 0016 D2, D3, D5, D7): served under OpsPrefix only,
// and only to the one ops token (serverconfig.APIConfig.OpsToken). Every
// other token gets 401 here and never reaches the read-only API, the vuln
// API or the operations logs through this prefix (see MountOps).
//
// The server decides the data class: the work list is built from the
// stored settings, never from what the agent asks for. Nothing in this
// file creates a proposal, permit, lease or notification; a note is the
// only write, and it lives in the notes store.

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/opsconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsfacts"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsnotes"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
)

// OpsPrefix is the path prefix of the ops agent API (ADR 0016 D2).
const OpsPrefix = Prefix + "ops/"

// The ops agent endpoints.
const (
	OpsAgentConfigPath = OpsPrefix + "agent-config"
	OpsWorkPath        = OpsPrefix + "work"
	OpsNotesPath       = OpsPrefix + "notes"
	OpsStatusPath      = OpsPrefix + "status"
)

// Named bounds of the ops API (ADR 0016 D3, D4, D6).
const (
	// MaxOpsWorkItems bounds the items of one work list page.
	MaxOpsWorkItems = 20
	// MaxOpsItemBytes bounds one work item as JSON; a larger one is left
	// out and logged.
	MaxOpsItemBytes = 32 << 10
	// MaxOpsReadRequests is the read budget of the ops token per window
	// (agent config and work list).
	MaxOpsReadRequests = 60
	// MaxOpsWriteRequests is the write budget of the ops token per window
	// (notes and status). The store's own daily limit applies on top.
	MaxOpsWriteRequests = 120
	// OpsWindow is the span of both budgets.
	OpsWindow = time.Hour
	// MaxOpsStatusBytes bounds one status request before it is parsed.
	MaxOpsStatusBytes = 4 << 10
	// MaxOpsRefusals bounds the refusal reasons of one status.
	MaxOpsRefusals = 8
	// MaxOpsRunCount bounds each counter of a status.
	MaxOpsRunCount = 1_000_000
)

// opsRefusalReasons is the fixed list of refusal reasons a status may name
// (ADR 0016 D14). Any other text is refused, so no model output reaches the
// status or the audit log.
var opsRefusalReasons = map[string]bool{
	"llm_refused_lab_rule": true,
	"llm_timeout":          true,
	"llm_error":            true,
	"output_discarded":     true,
	"note_refused":         true,
	"work_unavailable":     true,
	"rate_limited":         true,
}

// OpsSettings reads the stored ops agent settings (opsconfig.Store).
type OpsSettings interface {
	Get(ctx context.Context) (opsconfig.Row, error)
}

// OpsFacts is the server's view of the ops projection (opsfacts.Projector
// and the inventory). Every call reads the sources again.
type OpsFacts interface {
	// EligibleGroups returns the eligible finding groups in class lab with
	// their input digests.
	EligibleGroups(ctx context.Context) ([]opsfacts.Group, error)
	// External returns the fleet counters, the only data of class external.
	External(ctx context.Context) (opsfacts.ExternalProjection, error)
	// Hosts returns the IDs of the managed hosts.
	Hosts(ctx context.Context) ([]string, error)
}

// OpsNotes is the notes store (opsnotes.Store).
type OpsNotes interface {
	Put(ctx context.Context, r opsnotes.Resolver, d opsnotes.Draft, snapshot string) (opsnotes.Note, bool, error)
	List(ctx context.Context) ([]opsnotes.Note, error)
}

// OpsOptions configure the ops API. Tokens is the validated API
// configuration; Settings, Facts and Notes are required.
type OpsOptions struct {
	Tokens   []serverconfig.APIToken
	Settings OpsSettings
	Facts    OpsFacts
	Notes    OpsNotes
	// CorePrompt is the agent's fixed core prompt; prompt_version covers it
	// and the operator instructions.
	CorePrompt string
	// DocChunk reports whether a documentation chunk ID is in the index.
	// Nil means no chunk exists, so no note may cite one.
	DocChunk func(chunkID string) bool
	// OnNoteAccepted runs after a note was stored for the first time (not
	// for an idempotent repeat). Nil does nothing. The caller may use it to
	// attach a message; it must not change the note.
	OnNoteAccepted func(n opsnotes.Note)
	Log            *slog.Logger
	Now            func() time.Time
}

// OpsRunStatus is the last status the agent reported (ADR 0016 D14).
type OpsRunStatus struct {
	RunAt        time.Time
	ReceivedAt   time.Time
	ItemsSeen    int
	LLMCalls     int
	Discarded    int
	NotesWritten int
	Refusals     []string
}

// OpsHandler serves OpsPrefix.
type OpsHandler struct {
	tok      token
	prefixes []netip.Prefix
	opts     OpsOptions
	log      *slog.Logger
	now      func() time.Time

	mu     sync.Mutex
	reads  rateWindow
	writes rateWindow
	last   *OpsRunStatus
}

// NewOps returns the ops agent API handler. It refuses a configuration in
// which the ops scopes are not exclusive to one token (ADR 0016 D2).
func NewOps(o OpsOptions) (*OpsHandler, error) {
	if o.Settings == nil || o.Facts == nil || o.Notes == nil {
		return nil, errors.New("ops api: settings, facts and notes are required")
	}
	if p := (serverconfig.APIConfig{Enabled: true, Tokens: o.Tokens}).Problems(); len(p) > 0 {
		return nil, errors.New("ops api: invalid token configuration: " + strings.Join(p, "; "))
	}
	cfg, ok := serverconfig.APIConfig{Tokens: o.Tokens}.OpsToken()
	if !ok {
		return nil, errors.New("ops api: no token holds an ops scope")
	}
	raw, err := hex.DecodeString(cfg.SHA256)
	if err != nil || len(raw) != sha256.Size {
		return nil, errors.New("ops api: token " + cfg.Name + ": bad hash")
	}
	pfx, err := cfg.SourcePrefixes()
	if err != nil {
		return nil, fmt.Errorf("ops api: token %s: %w", cfg.Name, err)
	}
	h := &OpsHandler{opts: o, prefixes: pfx,
		reads:  rateWindow{span: OpsWindow, max: MaxOpsReadRequests},
		writes: rateWindow{span: OpsWindow, max: MaxOpsWriteRequests},
		log:    o.Log, now: o.Now}
	h.tok.name, h.tok.scopes = cfg.Name, slices.Clone(cfg.Scopes)
	copy(h.tok.hash[:], raw)
	if h.log == nil {
		h.log = slog.Default()
	}
	if h.now == nil {
		h.now = time.Now
	}
	return h, nil
}

// MountOps returns a handler that sends every path under OpsPrefix to ops
// and everything else to next. It is the only way ops paths are routed:
// no other handler sees them. A nil ops answers 404 under the prefix.
func MountOps(next, ops http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, OpsPrefix) || r.URL.Path == strings.TrimSuffix(OpsPrefix, "/") {
			if ops == nil {
				writeError(w, http.StatusNotFound, "no such endpoint")
				return
			}
			ops.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// authenticate returns the ops token if the request carries it.
func (h *OpsHandler) authenticate(r *http.Request) *token {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || tok == "" || len(tok) > 256 {
		return nil
	}
	sum := sha256.Sum256([]byte(tok))
	if subtle.ConstantTimeCompare(sum[:], h.tok.hash[:]) == 1 {
		return &h.tok
	}
	return nil
}

// sourceAllowed checks the client address against the token's allowlist;
// only the connection's address counts.
func (h *OpsHandler) sourceAllowed(r *http.Request) bool {
	if len(h.prefixes) == 0 {
		return true
	}
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	addr := ap.Addr().Unmap().WithZone("")
	return slices.ContainsFunc(h.prefixes, func(p netip.Prefix) bool { return p.Contains(addr) })
}

// ServeHTTP authenticates, checks the source address, the endpoint, scope,
// method, content type and the rate budget, then serves the endpoint.
func (h *OpsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
	var (
		scope, method string
		limiter       *rateWindow
		serve         func(ctx context.Context)
	)
	switch r.URL.Path {
	case OpsAgentConfigPath:
		scope, method, limiter = serverconfig.ScopeOpsRead, http.MethodGet, &h.reads
		serve = func(ctx context.Context) { h.serveAgentConfig(ctx, w, t) }
	case OpsWorkPath:
		scope, method, limiter = serverconfig.ScopeOpsRead, http.MethodGet, &h.reads
		serve = func(ctx context.Context) { h.serveWork(ctx, w, t) }
	case OpsNotesPath:
		scope, method, limiter = serverconfig.ScopeOpsNotesWrite, http.MethodPost, &h.writes
		serve = func(ctx context.Context) { h.postNote(ctx, w, r, t) }
	case OpsStatusPath:
		scope, method, limiter = serverconfig.ScopeOpsNotesWrite, http.MethodPost, &h.writes
		serve = func(ctx context.Context) { h.postStatus(w, r, t) }
	default:
		writeError(w, http.StatusNotFound, "no such endpoint")
		return
	}
	if !t.has(scope) {
		h.log.Warn("audit", "kind", "api_forbidden", "token", t.name, "path", r.URL.Path, "scope", scope)
		writeError(w, http.StatusForbidden, "the token lacks the scope "+scope)
		return
	}
	if r.Method != method {
		w.Header().Set("Allow", method)
		writeError(w, http.StatusMethodNotAllowed, "use "+method)
		return
	}
	if method == http.MethodPost && !jsonContent(r) {
		writeError(w, http.StatusUnsupportedMediaType, "the body must be application/json")
		return
	}
	h.mu.Lock()
	ok, wait := limiter.allow(h.now())
	h.mu.Unlock()
	if !ok {
		h.log.Warn("audit", "kind", "api_rate_limited", "token", t.name, "path", r.URL.Path)
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		writeError(w, http.StatusTooManyRequests, "rate limit reached")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), callTimeout)
	defer cancel()
	serve(ctx)
}

// opsAgentConfigResponse is the agent's settings. The LLM base URL is the
// admin's setting the agent needs to call its model; it is the only address
// in any ops answer, and the API key is never stored here.
type opsAgentConfigResponse struct {
	Enabled              bool   `json:"enabled"`
	LLMBaseURL           string `json:"llm_base_url"`
	LLMModel             string `json:"llm_model"`
	AllowPlainHTTP       bool   `json:"allow_plain_http"`
	DataClass            string `json:"data_class"`
	Language             string `json:"language"`
	OperatorInstructions string `json:"operator_instructions"`
	PromptVersion        string `json:"prompt_version"`
	Version              int64  `json:"version"`
}

// serveAgentConfig answers GET OpsAgentConfigPath.
func (h *OpsHandler) serveAgentConfig(ctx context.Context, w http.ResponseWriter, t *token) {
	row, err := h.opts.Settings.Get(ctx)
	if err != nil {
		h.log.Error("ops api: read settings", "error", err)
		writeError(w, http.StatusBadGateway, "ops agent settings unavailable")
		return
	}
	h.log.Info("audit", "kind", "api_read", "token", t.name, "path", OpsAgentConfigPath)
	writeJSON(w, http.StatusOK, opsAgentConfigResponse{
		Enabled: row.Enabled, LLMBaseURL: row.BaseURL, LLMModel: row.Model, AllowPlainHTTP: row.AllowPlainHTTP,
		DataClass: row.DataClass, Language: row.Language, OperatorInstructions: row.Instructions,
		PromptVersion: opsPromptVersion(h.opts.CorePrompt, row.Instructions), Version: row.Version,
	})
}

// opsWorkResponse is the work list: at most MaxOpsWorkItems items.
type opsWorkResponse struct {
	Items []opsWorkItem `json:"items"`
}

// opsWorkItem is one due item. Kind "fix" carries the group projection
// (class lab only); kind "summary" carries the fleet counters.
type opsWorkItem struct {
	Kind   string                  `json:"kind"`
	Ref    string                  `json:"ref"`
	Digest string                  `json:"digest"`
	Group  *opsfacts.LabProjection `json:"group,omitempty"`
	Fleet  *opsfacts.Counts        `json:"fleet,omitempty"`
}

// serveWork answers GET OpsWorkPath. The class comes from the stored
// settings: disabled gives an empty list; external gives the summary only;
// lab gives the due groups in order of tier, KEV and score.
func (h *OpsHandler) serveWork(ctx context.Context, w http.ResponseWriter, t *token) {
	row, err := h.opts.Settings.Get(ctx)
	if err != nil {
		h.log.Error("ops api: read settings", "error", err)
		writeError(w, http.StatusBadGateway, "ops agent settings unavailable")
		return
	}
	items := make([]opsWorkItem, 0, MaxOpsWorkItems)
	if row.Enabled {
		items, err = h.dueItems(ctx, row.DataClass)
		if err != nil {
			h.log.Error("ops api: build work list", "error", err)
			writeError(w, http.StatusBadGateway, "ops work list unavailable")
			return
		}
	}
	h.log.Info("audit", "kind", "api_read", "token", t.name, "path", OpsWorkPath, "items", len(items))
	writeJSON(w, http.StatusOK, opsWorkResponse{Items: items})
}

// dueItems builds the work list for one data class.
func (h *OpsHandler) dueItems(ctx context.Context, class string) ([]opsWorkItem, error) {
	answered, err := h.answeredSet(ctx)
	if err != nil {
		return nil, err
	}
	fleet, err := h.opts.Facts.External(ctx)
	if err != nil {
		return nil, fmt.Errorf("fleet counters: %w", err)
	}
	items := make([]opsWorkItem, 0, MaxOpsWorkItems)
	day := h.now().UTC().Format(time.DateOnly)
	if sd := fleetDigest(fleet.Fleet); !answered[answerKey(opsnotes.KindSummary, day, sd)] {
		c := fleet.Fleet
		items = append(items, opsWorkItem{Kind: string(opsnotes.KindSummary), Ref: day, Digest: sd, Fleet: &c})
	}
	if class != opsconfig.DataClassLab {
		return items, nil
	}
	groups, err := h.opts.Facts.EligibleGroups(ctx)
	if err != nil {
		return nil, fmt.Errorf("eligible groups: %w", err)
	}
	sortGroups(groups)
	for _, g := range groups {
		if len(items) >= MaxOpsWorkItems {
			break
		}
		if answered[answerKey(opsnotes.KindFix, g.Key, g.Digest)] {
			continue
		}
		p := g.Projection
		it := opsWorkItem{Kind: string(opsnotes.KindFix), Ref: g.Key, Digest: g.Digest, Group: &p}
		if size, err := json.Marshal(it); err != nil || len(size) > MaxOpsItemBytes {
			h.log.Warn("ops api: work item left out", "kind", "item_over_limit", "ref", g.Key)
			continue
		}
		items = append(items, it)
	}
	return items, nil
}

// answeredSet returns the (kind, ref, digest) keys of every stored note. A
// note with the current digest makes its item not due (ADR 0016 D3).
func (h *OpsHandler) answeredSet(ctx context.Context) (map[string]bool, error) {
	notes, err := h.opts.Notes.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list notes: %w", err)
	}
	set := make(map[string]bool, len(notes))
	for _, n := range notes {
		set[answerKey(n.Kind, n.Ref, n.Digest)] = true
	}
	return set, nil
}

// answerKey joins the parts of a note key with a byte that cannot occur in
// an ID (the note validator rejects control characters).
func answerKey(kind opsnotes.Kind, ref, digest string) string {
	return string(kind) + "\x00" + ref + "\x00" + digest
}

// sortGroups orders groups: highest tier first, then KEV, then the highest
// score, then the key. The order is the agent's priority.
func sortGroups(gs []opsfacts.Group) {
	sort.SliceStable(gs, func(i, j int) bool {
		a, b := groupRank(gs[i]), groupRank(gs[j])
		if a.tier != b.tier {
			return a.tier > b.tier
		}
		if a.kev != b.kev {
			return a.kev
		}
		if a.score != b.score {
			return a.score > b.score
		}
		return gs[i].Key < gs[j].Key
	})
}

// groupPriority is the sort key of one group.
type groupPriority struct {
	tier  int
	kev   bool
	score int
}

// groupRank returns the highest tier, whether any finding is KEV, and the
// highest score of the group's listed findings.
func groupRank(g opsfacts.Group) groupPriority {
	var p groupPriority
	for _, f := range g.Projection.Findings {
		p.tier = max(p.tier, tierRank(f.Tier))
		p.kev = p.kev || f.KEV
		p.score = max(p.score, f.Score)
	}
	return p
}

// tierRank orders tiers: low = 1 … critical = 4; 0 is not a tier.
func tierRank(t opsfacts.Tier) int {
	switch t {
	case opsfacts.TierLow:
		return 1
	case opsfacts.TierMedium:
		return 2
	case opsfacts.TierHigh:
		return 3
	case opsfacts.TierCritical:
		return 4
	}
	return 0
}

// fleetDigest is the input digest of the fleet summary of a day.
func fleetDigest(c opsfacts.Counts) string {
	b, _ := json.Marshal(c) // a struct of integers never fails
	sum := sha256.Sum256(append([]byte("nebula-ops-summary-v1\x00"), b...))
	return hex.EncodeToString(sum[:])
}

// opsPromptVersion covers the core prompt and the operator instructions,
// each length-prefixed so the two cannot trade bytes.
func opsPromptVersion(core, operator string) string {
	h := sha256.New()
	h.Write([]byte("nebula-ops-agent-prompt-v1\x00"))
	h.Write([]byte(strconv.Itoa(len(core)) + ":" + core))
	h.Write([]byte(strconv.Itoa(len(operator)) + ":" + operator))
	return hex.EncodeToString(h.Sum(nil))
}
