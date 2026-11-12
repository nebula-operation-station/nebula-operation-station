// SPDX-License-Identifier: AGPL-3.0-or-later

// Package enroll serves the unauthenticated enrollment script download
// GET /enroll/<offer-id> (ADR 0013 D7, EN-09).
//
// The route lives outside the UI's session check. Every refusal (unknown,
// expired, consumed, revoked or malformed offer, rate limit, trusted proxy
// without a usable X-Forwarded-For, executor failure) is the same 404 with
// the same body and headers as the 200, so the endpoint is no oracle. The
// request path carries the offer ID, a capability, and is never logged.
package enroll

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/clientaddr"
)

// PathPrefix is the route prefix; the offer ID follows it.
const PathPrefix = "/enroll/"

// Limits of the download route.
const (
	// OfferIDLen is the length of an offer ID: 160 bits as lowercase RFC
	// 4648 base32 without padding (ADR 0013 D2).
	OfferIDLen = 32
	// MaxScriptBytes is the largest script the route passes on.
	MaxScriptBytes = 64 << 10
	// fetchTimeout bounds the executor call.
	fetchTimeout = 15 * time.Second
	// scriptFilename is the fixed download name; it is never derived from
	// the request.
	scriptFilename = "nebula-enroll.sh"
)

// notFoundBody is the body of every refusal.
const notFoundBody = "not found\n"

// AuditKind is the audit record of a released script.
const AuditKind = "enroll_script_downloaded"

// Executor is the part of the executor client the route uses.
type Executor interface {
	FetchEnrollScript(ctx context.Context, in *executorv1.FetchEnrollScriptRequest, opts ...grpc.CallOption) (*executorv1.FetchEnrollScriptResponse, error)
}

// Options configure the download route.
type Options struct {
	// Executor releases the script (FetchEnrollScript, server role).
	Executor Executor
	// ClientAddr determines the client address. Its trusted-proxy
	// configuration and forwarded-header limits are fixed at construction.
	ClientAddr *clientaddr.Resolver
	// Limiter is the per-client rate-limit table.
	Limiter *Limiter
	// Log receives operational lines and the audit record (message
	// "audit"). Nil discards.
	Log *slog.Logger
}

// Handler serves GET /enroll/<offer-id>.
type Handler struct {
	exec     Executor
	addr     *clientaddr.Resolver
	limiter  *Limiter
	log      *slog.Logger
	refusals atomic.Uint64
}

// Errors of New.
var errMissingOption = errors.New("enroll download: executor, client address resolver and limiter are required")

// New builds the handler.
func New(o Options) (*Handler, error) {
	if o.Executor == nil || o.ClientAddr == nil || o.Limiter == nil {
		return nil, errMissingOption
	}
	log := o.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Handler{exec: o.Executor, addr: o.ClientAddr, limiter: o.Limiter, log: log}, nil
}

// ForwardedRefusals returns the number of requests refused because a
// trusted proxy sent no usable X-Forwarded-For header (metric).
func (h *Handler) ForwardedRefusals() uint64 { return h.refusals.Load() }

// setHeaders sets the headers shared by the 200 and every 404.
func setHeaders(w http.ResponseWriter) {
	hd := w.Header()
	hd.Set("Content-Type", "text/plain; charset=utf-8")
	hd.Set("Content-Disposition", `attachment; filename="`+scriptFilename+`"`)
	hd.Set("Cache-Control", "no-store")
	hd.Set("X-Content-Type-Options", "nosniff")
	hd.Set("Content-Security-Policy", "default-src 'none'; sandbox")
	hd.Set("X-Accel-Buffering", "no")
}

// notFound writes the uniform refusal.
func notFound(w http.ResponseWriter) {
	setHeaders(w)
	w.Header().Set("Content-Length", strconv.Itoa(len(notFoundBody)))
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(notFoundBody))
}

// validOfferID checks the offer ID's syntax.
func validOfferID(id string) bool {
	if len(id) != OfferIDLen {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if (c < 'a' || c > 'z') && (c < '2' || c > '7') {
			return false
		}
	}
	return true
}

// ServeHTTP implements http.Handler. Order: method, client address (a
// refused forwarded header charges nothing and calls nothing), the single
// rate-limit charge, ID syntax, executor.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		// HEAD (and anything else) must never consume an offer.
		notFound(w)
		return
	}
	res, err := h.addr.Resolve(r)
	if err != nil {
		h.refusals.Add(1)
		h.log.Warn("enroll download refused: no usable client address", "reason", err.Error(), "peer", addrString(res.Peer))
		notFound(w)
		return
	}
	if !h.limiter.Charge(res.Client) {
		h.log.Info("enroll download refused: rate limit", "client", res.Client.String(), "peer", res.Peer.String())
		notFound(w)
		return
	}
	id, ok := strings.CutPrefix(r.URL.Path, PathPrefix)
	if !ok || !validOfferID(id) {
		notFound(w)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), fetchTimeout)
	defer cancel()
	resp, err := h.exec.FetchEnrollScript(ctx, &executorv1.FetchEnrollScriptRequest{
		OfferId:    id,
		ClientAddr: res.Client.String(),
		PeerAddr:   res.Peer.String(),
	})
	if err != nil {
		if status.Code(err) != codes.NotFound {
			h.log.Warn("enroll download: executor call failed", "code", status.Code(err).String())
		}
		notFound(w)
		return
	}
	script := resp.GetScript()
	defer clear(script)
	if len(script) == 0 || len(script) > MaxScriptBytes {
		h.log.Error("enroll download: executor returned a script of invalid size", "bytes", len(script))
		notFound(w)
		return
	}
	sum := sha256.Sum256(script)
	if hex.EncodeToString(sum[:]) != resp.GetScriptSha256() {
		h.log.Error("enroll download: executor returned a script that does not match its hash")
		notFound(w)
		return
	}
	h.log.Info("audit", "kind", AuditKind,
		"client", res.Client.String(),
		"peer", res.Peer.String(),
		"forwarded", res.Forwarded,
		"script_sha256", resp.GetScriptSha256())
	setHeaders(w)
	w.Header().Set("Content-Length", strconv.Itoa(len(script)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(script)
}

// addrString renders a possibly invalid address for logs.
func addrString(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}
