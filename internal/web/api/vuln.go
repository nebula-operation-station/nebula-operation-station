// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
)

// VulnPrefix is the path prefix of the vulnerability agent API (ADR 0011
// D3, D5). It is served by VulnHandler, not by the read-only Handler.
const VulnPrefix = Prefix + "vuln/"

// Rate limits per token (ADR 0011 D3, D5).
const (
	// MaxExportRequests per ExportWindow: 60 per hour.
	MaxExportRequests = 60
	ExportWindow      = time.Hour
	// MaxWriteRequests per WriteWindow: 60 per minute.
	MaxWriteRequests = 60
	WriteWindow      = time.Minute
)

// Body limits.
const (
	// MaxBatchBytes bounds a findings batch body (D5: 1 MiB).
	MaxBatchBytes = 1 << 20
	// maxStartBytes bounds a run start body; the source list is short.
	maxStartBytes = 64 << 10
	// maxCompleteBytes bounds a complete body (empty or {}).
	maxCompleteBytes = 64
	// maxJSONDepth bounds nesting of every request body.
	maxVulnJSONDepth = 10
	// maxRunStates bounds the run states the handler keeps.
	maxRunStates = 32
	// maxListedSubjects bounds subject refs listed in an error response.
	maxListedSubjects = 16
	// completeTimeout bounds one run complete. The store plans a complete
	// on a read snapshot and applies it in short, paced write
	// transactions with a durable completing state, so a complete that
	// runs out of time either applied nothing (the run stays open) or is
	// resumed by the retry, or by the store's own sweep
	// (vulnstore.ResumeCompleting) if the client does not come back. The
	// apply phase is paced by rows: MaxFindingsPerRun superseded holds
	// took about 90 s in vulnstore's
	// TestCompleteDropsSupersededHoldsInRowBoundedTransactions, most of it
	// the pauses that let other server.db writers in, so the largest runs
	// fit with headroom for slow disks. The complete is not cancelled when
	// the client goes away (the server write timeout is shorter), so a
	// retry finds it saved.
	completeTimeout = 5 * time.Minute
)

// VulnStore is the findings store (internal/vulnstore).
type VulnStore interface {
	StartRun(ctx context.Context, req vulnstore.StartRequest) (vulnstore.Run, error)
	SubmitBatch(ctx context.Context, runID string, b vulnstore.Batch) (vulnstore.BatchResult, error)
	RejectBatch(ctx context.Context, runID string, seq int64, bodySHA256 [32]byte) error
	Complete(ctx context.Context, runID string) (vulnstore.Completion, error)
	CompletionOf(ctx context.Context, runID, tokenID string) (vulnstore.Completion, error)
	ResumeComplete(ctx context.Context, runID, tokenID string) (vulnstore.Completion, error)
}

// VulnOptions configure the vulnerability agent API.
type VulnOptions struct {
	// Tokens is the validated API configuration; only the token holding
	// the vuln scopes is used.
	Tokens    []serverconfig.APIToken
	Inventory VulnInventory
	Store     VulnStore
	// Sources is NOS's fixed feed source list (the one the store uses);
	// the run start reports listed sources a run omits.
	Sources []vulnstore.Source
	Log     *slog.Logger
	// Now returns the current time. Defaults to time.Now.
	Now func() time.Time
}

// VulnHandler serves /api/v1/vuln/: the inventory export (scope
// vuln.inventory.read) and the run protocol (scope vuln.findings.write).
type VulnHandler struct {
	tok      token
	prefixes []netip.Prefix
	inv      VulnInventory
	store    VulnStore
	sources  []string
	log      *slog.Logger
	now      func() time.Time

	mu      sync.Mutex
	cache   *prepared
	runs    map[string]*runState
	export  rateWindow
	write   rateWindow
	batchMu sync.Mutex
}

// NewVuln returns the vulnerability agent API handler. It refuses a
// configuration in which the vuln scopes are not exclusive to one token
// (ADR 0011 D3, D5), even if the caller skipped the configuration check.
func NewVuln(o VulnOptions) (*VulnHandler, error) {
	if o.Inventory == nil || o.Store == nil || len(o.Sources) == 0 {
		return nil, errors.New("vuln api: inventory, store and sources are required")
	}
	if p := (serverconfig.APIConfig{Enabled: true, Tokens: o.Tokens}).Problems(); len(p) > 0 {
		return nil, errors.New("vuln api: invalid token configuration: " + strings.Join(p, "; "))
	}
	cfg, ok := serverconfig.APIConfig{Tokens: o.Tokens}.VulnToken()
	if !ok {
		return nil, errors.New("vuln api: no token holds a vuln scope")
	}
	raw, err := hex.DecodeString(cfg.SHA256)
	if err != nil || len(raw) != sha256.Size {
		return nil, errors.New("vuln api: token " + cfg.Name + ": bad hash")
	}
	pfx, err := cfg.SourcePrefixes()
	if err != nil {
		return nil, fmt.Errorf("vuln api: token %s: %w", cfg.Name, err)
	}
	h := &VulnHandler{inv: o.Inventory, store: o.Store, log: o.Log, now: o.Now, prefixes: pfx, runs: map[string]*runState{},
		export: rateWindow{span: ExportWindow, max: MaxExportRequests}, write: rateWindow{span: WriteWindow, max: MaxWriteRequests}}
	h.tok.name, h.tok.scopes = cfg.Name, slices.Clone(cfg.Scopes)
	copy(h.tok.hash[:], raw)
	for _, s := range o.Sources {
		h.sources = append(h.sources, s.ID)
	}
	if h.log == nil {
		h.log = slog.Default()
	}
	if h.now == nil {
		h.now = time.Now
	}
	return h, nil
}

// Mount returns a handler that sends VulnPrefix to vuln and everything else
// to api. vuln may be nil (the vuln API is not configured).
func Mount(api, vuln http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if vuln != nil && (strings.HasPrefix(r.URL.Path, VulnPrefix) || r.URL.Path == strings.TrimSuffix(VulnPrefix, "/")) {
			vuln.ServeHTTP(w, r)
			return
		}
		api.ServeHTTP(w, r)
	})
}

// authenticate returns the vuln token if the request carries it. Like the
// read-only API, the hash is compared in constant time.
func (h *VulnHandler) authenticate(r *http.Request) *token {
	auth := r.Header.Get("Authorization")
	tok, ok := strings.CutPrefix(auth, "Bearer ")
	if !ok || tok == "" || len(tok) > 256 {
		return nil
	}
	sum := sha256.Sum256([]byte(tok))
	if subtle.ConstantTimeCompare(sum[:], h.tok.hash[:]) == 1 {
		return &h.tok
	}
	return nil
}

// sourceAllowed checks the client address against the token's allowlist.
// Only the connection's address counts; forwarding headers are ignored.
func (h *VulnHandler) sourceAllowed(r *http.Request) bool {
	if len(h.prefixes) == 0 {
		return true
	}
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	addr := ap.Addr().Unmap().WithZone("")
	for _, p := range h.prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

var runIDRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

// ServeHTTP authenticates, checks source address, scope and rate limit,
// and serves one endpoint.
func (h *VulnHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
	path := strings.TrimPrefix(r.URL.Path, VulnPrefix)
	parts := strings.Split(path, "/")
	ctx, cancel := context.WithTimeout(r.Context(), callTimeout)
	defer cancel()
	var (
		scope, method string
		limiter       *rateWindow
		serve         func()
	)
	switch {
	case path == "inventory":
		scope, method, limiter = serverconfig.ScopeVulnInventoryRead, http.MethodGet, &h.export
		serve = func() { h.serveInventory(ctx, w, r, t) }
	case path == "runs":
		scope, method, limiter = serverconfig.ScopeVulnFindingsWrite, http.MethodPost, &h.write
		serve = func() { h.startRun(ctx, w, r, t) }
	case len(parts) == 3 && parts[0] == "runs" && runIDRe.MatchString(parts[1]) && parts[2] == "findings":
		scope, method, limiter = serverconfig.ScopeVulnFindingsWrite, http.MethodPost, &h.write
		serve = func() { h.submitBatch(ctx, w, r, t, parts[1]) }
	case len(parts) == 3 && parts[0] == "runs" && runIDRe.MatchString(parts[1]) && parts[2] == "complete":
		scope, method, limiter = serverconfig.ScopeVulnFindingsWrite, http.MethodPost, &h.write
		// complete runs under its own budget, not callTimeout.
		serve = func() { h.completeRun(r, w, t, parts[1]) }
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
	serve()
}

func jsonContent(r *http.Request) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mt == "application/json"
}

// rateWindow is a sliding-window limit: at most max requests per span.
type rateWindow struct {
	span  time.Duration
	max   int
	times []time.Time
}

func (rw *rateWindow) allow(now time.Time) (bool, time.Duration) {
	cut := now.Add(-rw.span)
	i := 0
	for i < len(rw.times) && !rw.times[i].After(cut) {
		i++
	}
	rw.times = rw.times[i:]
	if len(rw.times) >= rw.max {
		return false, rw.times[0].Sub(cut)
	}
	rw.times = append(rw.times, now)
	return true, 0
}

// errBodyTooLarge reports a body above its limit.
var errBodyTooLarge = errors.New("body too large")

// readBody reads at most limit bytes; a longer body returns what was read
// and errBodyTooLarge.
func readBody(r *http.Request, limit int) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r.Body, int64(limit)+1))
	if err != nil {
		return b, fmt.Errorf("read body: %w", err)
	}
	if len(b) > limit {
		return b, errBodyTooLarge
	}
	return b, nil
}

var jsonKeyRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// errMalformedJSON is every strict-JSON failure; it never quotes input.
var errMalformedJSON = errors.New("malformed JSON")

// errUnknownJSONField is an unknown field.
var errUnknownJSONField = errors.New("unknown field")

// decodeStrict decodes one JSON object into v: strict UTF-8, bounded
// depth, keys only in their lower-case canonical spelling and unique per
// object (encoding/json would match keys case-insensitively and keep the
// last duplicate), no escaped lone surrogates, no trailing data and no
// unknown fields.
func decodeStrict(data []byte, v any) error {
	if !utf8.Valid(data) {
		return fmt.Errorf("invalid UTF-8: %w", errMalformedJSON)
	}
	if err := checkShape(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		if strings.HasPrefix(err.Error(), "json: unknown field ") {
			return errUnknownJSONField
		}
		return fmt.Errorf("decode: %w", errMalformedJSON)
	}
	return nil
}

func checkShape(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	type frame struct {
		object, expectKey bool
		keys              map[string]struct{}
	}
	var stack []*frame
	first := true
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			if first || len(stack) != 0 {
				return fmt.Errorf("unexpected end: %w", errMalformedJSON)
			}
			return nil
		}
		if err != nil {
			return fmt.Errorf("syntax: %w", errMalformedJSON)
		}
		if !first && len(stack) == 0 {
			return fmt.Errorf("trailing data: %w", errMalformedJSON)
		}
		if first {
			if d, ok := tok.(json.Delim); !ok || d != '{' {
				return fmt.Errorf("not an object: %w", errMalformedJSON)
			}
		}
		first = false
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if top != nil && top.object && top.expectKey {
			if d, ok := tok.(json.Delim); ok && d == '}' {
				stack = stack[:len(stack)-1]
				if len(stack) > 0 && stack[len(stack)-1].object {
					stack[len(stack)-1].expectKey = true
				}
				continue
			}
			k, ok := tok.(string)
			if !ok || !jsonKeyRe.MatchString(k) {
				return fmt.Errorf("key: %w", errMalformedJSON)
			}
			if _, dup := top.keys[k]; dup {
				return fmt.Errorf("duplicate key: %w", errMalformedJSON)
			}
			top.keys[k] = struct{}{}
			top.expectKey = false
			continue
		}
		switch x := tok.(type) {
		case json.Delim:
			switch x {
			case '{', '[':
				if len(stack) >= maxVulnJSONDepth {
					return fmt.Errorf("too deep: %w", errMalformedJSON)
				}
				stack = append(stack, &frame{object: x == '{', expectKey: x == '{', keys: map[string]struct{}{}})
				continue
			case ']':
				stack = stack[:len(stack)-1]
			}
		case string:
			if strings.ContainsRune(x, utf8.RuneError) {
				return fmt.Errorf("replacement character: %w", errMalformedJSON)
			}
		}
		if len(stack) > 0 && stack[len(stack)-1].object {
			stack[len(stack)-1].expectKey = true
		}
	}
}
