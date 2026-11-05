// SPDX-License-Identifier: AGPL-3.0-or-later

package trafficmap

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Path is the endpoint below the API prefix /api/v1/.
const Path = "trafficmap"

// Request bounds.
const (
	// maxRawQuery bounds the query string.
	maxRawQuery = 512
	// callTimeout bounds building one model.
	callTimeout = 10 * time.Second
)

// Options configure the handler.
type Options struct {
	// Inventory and Flows feed the Builder; both are required.
	Inventory func(ctx context.Context) (Inventory, error)
	Flows     Flows
	// Authorize decides whether the request may read the map. It is
	// required: the API's existing token and scope check (inventory.read)
	// is passed in here; the handler has no authentication of its own and
	// fails closed without it.
	Authorize func(r *http.Request) bool
	Now       func() time.Time
	Limits    Limits
	Log       *slog.Logger
}

// Handler serves GET /api/v1/trafficmap?window=1h|24h|7d|21d&focus=<node>.
type Handler struct {
	builder   *Builder
	authorize func(r *http.Request) bool
	log       *slog.Logger
}

// New returns the handler.
func New(o Options) (*Handler, error) {
	if o.Authorize == nil {
		return nil, errors.New("trafficmap: an authorization check is required")
	}
	b, err := NewBuilder(o.Inventory, o.Flows, o.Now, o.Limits)
	if err != nil {
		return nil, err
	}
	h := &Handler{builder: b, authorize: o.Authorize, log: o.Log}
	if h.log == nil {
		h.log = slog.Default()
	}
	return h, nil
}

func setHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

func writeError(w http.ResponseWriter, status int, msg string) {
	setHeaders(w)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// parseQuery accepts only window and focus, each at most once.
func parseQuery(raw string) (Query, error) {
	if len(raw) > maxRawQuery {
		return Query{}, errors.New("query too long")
	}
	v, err := url.ParseQuery(raw)
	if err != nil {
		return Query{}, errors.New("malformed query")
	}
	var q Query
	for k, vals := range v {
		if len(vals) != 1 {
			return Query{}, errors.New("repeated parameter")
		}
		switch k {
		case "window":
			q.Window = vals[0]
			if q.Window == "" {
				return Query{}, errors.New("empty window")
			}
		case "focus":
			q.Focus = vals[0]
			if q.Focus == "" {
				return Query{}, errors.New("empty focus")
			}
		default:
			return Query{}, errors.New("unknown parameter")
		}
	}
	return q, nil
}

// ServeHTTP serves the model. Only GET and HEAD are allowed.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeError(w, http.StatusMethodNotAllowed, "the API is read-only")
		return
	}
	if !h.authorize(r) {
		writeError(w, http.StatusForbidden, "not allowed to read the traffic map")
		return
	}
	q, err := parseQuery(r.URL.RawQuery)
	if err != nil {
		writeError(w, http.StatusBadRequest, "query: "+err.Error()+"; use window="+strings.Join(h.builder.Windows(), "|")+" and focus=<node id>")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), callTimeout)
	defer cancel()
	data, err := h.builder.Build(ctx, q)
	switch {
	case errors.Is(err, ErrBadWindow):
		writeError(w, http.StatusBadRequest, "window must be one of "+strings.Join(h.builder.Windows(), ", "))
		return
	case errors.Is(err, ErrBadFocus):
		writeError(w, http.StatusBadRequest, "focus is not a valid node id")
		return
	case errors.Is(err, ErrUnknownFocus):
		writeError(w, http.StatusNotFound, "no such node")
		return
	case err != nil:
		h.log.Error("trafficmap", "error", err)
		writeError(w, http.StatusServiceUnavailable, "traffic map unavailable")
		return
	}
	setHeaders(w)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(data)
}
