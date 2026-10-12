// SPDX-License-Identifier: AGPL-3.0-or-later

// Package middleware provides the HTTP security middleware for the Nebula
// web UI: strict response headers, a request body limit, and an origin
// check for state-changing methods.
//
// The chain is applied by Handler: security headers first (so they are
// present on every response, including rejections), then the origin check,
// then the body limit.
package middleware

import (
	"net/http"
	"time"
)

// DefaultMaxBodyBytes is the request body limit when Options.MaxBodyBytes
// is zero.
const DefaultMaxBodyBytes = 1 << 20 // 1 MiB

// The security headers, exactly as specified in docs/spec/09 and
// docs/spec/14 (strict CSP, no inline scripts).
const (
	headerCSP      = "Content-Security-Policy"
	headerNosniff  = "X-Content-Type-Options"
	headerReferrer = "Referrer-Policy"
	headerCOOP     = "Cross-Origin-Opener-Policy"
	valueCSP       = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
	valueNosniff   = "nosniff"
	valueReferrer  = "no-referrer"
	valueCOOP      = "same-origin"
)

// Options configure the security middleware chain and the server timeouts.
type Options struct {
	// PublicOrigin is the exact Origin header value the browser sends for
	// this deployment, e.g. "https://nebula.example.org". State-changing
	// requests with any other (or no) Origin are rejected with 403.
	PublicOrigin string
	// MaxBodyBytes limits request bodies. Zero means DefaultMaxBodyBytes.
	MaxBodyBytes int64
	// ReadTimeout bounds reading the request, including the body. Zero
	// means DefaultReadTimeout.
	ReadTimeout time.Duration
	// WriteTimeout bounds writing the response. Zero means
	// DefaultWriteTimeout.
	WriteTimeout time.Duration
	// IdleTimeout bounds idle keep-alive connections. Zero means
	// DefaultIdleTimeout.
	IdleTimeout time.Duration
}

// Handler wraps next with the security chain: response headers, the origin
// check for state-changing methods, and the body limit.
//
// If opts.PublicOrigin is empty, every state-changing request is rejected:
// a missing origin configuration must fail closed, not open.
//
// The body limit is enforced twice: a request whose declared
// Content-Length already exceeds the limit is rejected with 413 before the
// handler runs, and the body is additionally wrapped with
// http.MaxBytesReader as a backstop for chunked or lying clients. Handlers
// that read the body should check for *http.MaxBytesError and answer 413.
func Handler(opts Options, next http.Handler) http.Handler {
	max := opts.MaxBodyBytes
	if max <= 0 {
		max = DefaultMaxBodyBytes
	}
	return securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// An empty PublicOrigin must fail closed: reject every
		// state-changing request, including ones with no Origin header
		// ("" == "" must not pass).
		if stateChanging(r.Method) && (opts.PublicOrigin == "" || r.Header.Get("Origin") != opts.PublicOrigin) {
			http.Error(w, "origin not allowed", http.StatusForbidden)
			return
		}
		// Reject up front when the declared size already exceeds the limit.
		// ContentLength is -1 for unknown (chunked) bodies; those fall
		// through to the MaxBytesReader backstop below.
		if r.ContentLength > max {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, max)
		next.ServeHTTP(w, r)
	}))
}

// stateChanging reports whether the method can change server state and
// therefore needs the origin check. GET, HEAD and OPTIONS are safe;
// everything else (POST, PUT, PATCH, DELETE, TRACE, CONNECT, custom
// methods) is treated as state-changing.
func stateChanging(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}

// securityHeaders sets the security headers before the handler runs, so
// they are present on every response the connection produces, including
// 403 and 413 rejections and handler panics.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set(headerCSP, valueCSP)
		h.Set(headerNosniff, valueNosniff)
		h.Set(headerReferrer, valueReferrer)
		h.Set(headerCOOP, valueCOOP)
		next.ServeHTTP(w, r)
	})
}
