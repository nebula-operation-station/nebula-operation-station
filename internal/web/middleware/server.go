// SPDX-License-Identifier: AGPL-3.0-or-later

package middleware

import (
	"errors"
	"net/http"
	"time"
)

// Default server timeouts. The read timeout also bounds how long a client
// may take to send a request body; the write timeout covers slow log
// streaming to the UI.
const (
	// DefaultReadTimeout bounds reading the request, including the body.
	DefaultReadTimeout = 10 * time.Second
	// DefaultWriteTimeout bounds writing the response.
	DefaultWriteTimeout = 30 * time.Second
	// DefaultIdleTimeout bounds idle keep-alive connections.
	DefaultIdleTimeout = 120 * time.Second
)

// NewServer builds an http.Server with the security middleware applied to
// handler and the read/write/idle timeouts set. It fails fast on a missing
// PublicOrigin: a misconfigured origin must not silently reject (or accept)
// every state-changing request.
func NewServer(o Options, handler http.Handler) (*http.Server, error) {
	if o.PublicOrigin == "" {
		return nil, errors.New("middleware: PublicOrigin is required")
	}
	if o.ReadTimeout <= 0 {
		o.ReadTimeout = DefaultReadTimeout
	}
	if o.WriteTimeout <= 0 {
		o.WriteTimeout = DefaultWriteTimeout
	}
	if o.IdleTimeout <= 0 {
		o.IdleTimeout = DefaultIdleTimeout
	}
	return &http.Server{
		Handler:      Handler(o, handler),
		ReadTimeout:  o.ReadTimeout,
		WriteTimeout: o.WriteTimeout,
		IdleTimeout:  o.IdleTimeout,
	}, nil
}
