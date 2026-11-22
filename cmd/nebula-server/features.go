// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/auditlog"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/ipam"
	"github.com/nebula-operation-station/nebula-operation-station/internal/notify"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsnotes"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/api"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/enroll"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// Feature registry (ticket uf01). Each server feature wires itself in its
// own file: it registers a serverFeature from init() and its hooks receive
// the values runServer has already built (serverDeps). main.go calls the
// two phases below (options, pages) at fixed places; it does not name the
// features.
//
// Features run in name order, so the start is the same on every build.
// A duplicate or empty name, a failing hook and a route the mux refuses
// (a conflict is a panic in http.ServeMux, caught at startup) all stop the
// start with an error that names the feature.

// errDuplicateFeature marks two features registered under one name.
var errDuplicateFeature = errors.New("duplicate server feature name")

// errBadFeature marks a feature without a name.
var errBadFeature = errors.New("server feature without a name")

// serverDeps holds the values runServer has built before the features are
// wired. Hooks read them; they do not replace them.
type serverDeps struct {
	cfg       serverconfig.Config
	db        *sql.DB
	log       *slog.Logger
	audit     *auditlog.Store
	exec      *lazyExecutor
	inventory *inventory.Store
	ipamStore *ipam.Store
	pveStore  *pveinventory.Store
	vuln      *vulnService
	opsNotes  *opsnotes.Store
	notifier  *notify.Notifier
	isAdmin   func(ctx context.Context) bool
	retention time.Duration
	// opsTouch is the ops agent trigger's Touch, nil without the ops token.
	opsTouch func() bool
	// run starts a background loop under the server's connection context;
	// the server waits for it at shutdown. It fails with errServerStopping
	// once shutdown has begun, and the loop does not start.
	run func(func(context.Context)) error
}

// errServerStopping is returned by serverDeps.run after shutdown has begun.
var errServerStopping = errors.New("server is shutting down")

// backgroundRuns starts the server's background loops in one wait group.
// Close refuses every later start, so no goroutine is added once the server
// waits for the group at shutdown.
type backgroundRuns struct {
	mu     sync.Mutex
	wg     *sync.WaitGroup
	closed bool
}

// newBackgroundRuns returns a gate that starts loops in wg.
func newBackgroundRuns(wg *sync.WaitGroup) *backgroundRuns {
	return &backgroundRuns{wg: wg}
}

// Go starts f in the wait group. It returns errServerStopping after Close.
func (b *backgroundRuns) Go(f func()) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return errServerStopping
	}
	b.wg.Go(f)
	return nil
}

// Close refuses every later Go. The server calls it before it waits for the
// wait group.
func (b *backgroundRuns) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
}

// serverFeature is one feature's wiring. Each hook is optional (nil skips it):
//   - options edits the ui.Options before ui.New receives them;
//   - pages adds routes behind the session check (webServer's pages mux);
//   - public adds routes outside the session check (ADR 0013 D7). Only the
//     exact prefixes in publicRoutePrefixes are accepted; see publicRoutes.
type serverFeature struct {
	name    string
	options func(serverDeps, *ui.Options) error
	pages   func(serverDeps, *http.ServeMux) error
	public  func(serverDeps, *publicRoutes) error
}

// errPublicRouteRefused marks a public route the registry does not accept.
var errPublicRouteRefused = errors.New("public route refused")

// errBadPublicRoute marks a public route registered without a handler.
var errBadPublicRoute = errors.New("public route without a handler")

// publicRoutePrefixes are the only prefixes a public route may use. Each
// names a subtree of its own; the handler behind it refuses every method
// but GET. Adding a prefix changes the security surface and needs a review.
var publicRoutePrefixes = []string{enroll.PathPrefix}

// reservedRoutePaths are paths no public route may overlap: the root, the
// login and setup pages, and the two API prefixes.
var reservedRoutePaths = []string{"/", "/login", "/setup", api.Prefix, trafficMapAPIPath}

// publicRoute is one accepted public route.
type publicRoute struct {
	prefix  string
	handler http.Handler
}

// publicRoutes collects the routes that run outside the session check.
// Handle accepts a route only when its prefix is exactly one of
// publicRoutePrefixes, and refuses any prefix that overlaps a reserved path
// or an earlier route. Everything else stays behind login.Wrap.
type publicRoutes struct {
	routes []publicRoute
}

// newPublicRoutes returns an empty registry.
func newPublicRoutes() *publicRoutes {
	return &publicRoutes{}
}

// Handle registers h under prefix. A refused prefix is not mounted.
func (p *publicRoutes) Handle(prefix string, h http.Handler) error {
	if h == nil {
		return errBadPublicRoute
	}
	if !slices.Contains(publicRoutePrefixes, prefix) {
		return fmt.Errorf("%w: %q is not an allowed public prefix", errPublicRouteRefused, prefix)
	}
	for _, r := range reservedRoutePaths {
		// The root is refused only as itself: every path is under "/", and a
		// public subtree under it is a more specific route, not a conflict.
		if r == "/" && prefix == r || r != "/" && overlapsPath(prefix, r) {
			return fmt.Errorf("%w: %q overlaps %q", errPublicRouteRefused, prefix, r)
		}
	}
	for _, r := range p.routes {
		if overlapsPath(prefix, r.prefix) {
			return fmt.Errorf("%w: %q is already registered", errPublicRouteRefused, prefix)
		}
	}
	p.routes = append(p.routes, publicRoute{prefix: prefix, handler: h})
	return nil
}

// overlapsPath reports whether a route under a could match a path under b or
// the reverse: one is a prefix of the other.
func overlapsPath(a, b string) bool {
	return strings.HasPrefix(a, b) || strings.HasPrefix(b, a)
}

// serverFeatures is the registry, filled by the init functions of the
// feature files. Tests replace it for one test (withServerFeatures).
var serverFeatures []serverFeature

// registerServerFeature adds f to the registry. Call it from init; the
// name is checked when the features run, so the error reaches the start.
func registerServerFeature(f serverFeature) {
	serverFeatures = append(serverFeatures, f)
}

// orderServerFeatures returns a copy of fs sorted by name. It fails on an
// empty name and on a duplicate name.
func orderServerFeatures(fs []serverFeature) ([]serverFeature, error) {
	out := slices.Clone(fs)
	slices.SortStableFunc(out, func(a, b serverFeature) int { return strings.Compare(a.name, b.name) })
	for i, f := range out {
		if f.name == "" {
			return nil, errBadFeature
		}
		if i > 0 && out[i-1].name == f.name {
			return nil, fmt.Errorf("%w: %q", errDuplicateFeature, f.name)
		}
	}
	return out, nil
}

// muxRefusalMarkers are the texts of the panics http.ServeMux raises when it
// refuses a route: a pattern that is already registered, a pattern that
// conflicts with one, or a pattern it cannot parse.
var muxRefusalMarkers = []string{"multiple registrations", "conflicts with pattern", "invalid pattern", "parsing"}

// muxRefusal returns the text of a ServeMux refusal panic, and false for any
// other panic value.
func muxRefusal(r any) (string, bool) {
	var text string
	switch v := r.(type) {
	case error:
		text = v.Error()
	case string:
		text = v
	default:
		return "", false
	}
	for _, m := range muxRefusalMarkers {
		if strings.Contains(text, m) {
			return text, true
		}
	}
	return "", false
}

// featureHook calls one hook. A ServeMux refusal (a route that is already
// registered, conflicts with one, or does not parse) becomes an error here,
// so the start fails with the feature name instead of crashing. Any other
// panic is a bug in the hook and propagates unchanged.
func featureHook(f serverFeature, phase string, call func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			text, ok := muxRefusal(r)
			if !ok {
				panic(r)
			}
			err = fmt.Errorf("feature %s: %s: %s", f.name, phase, text)
		}
	}()
	if err := call(); err != nil {
		return fmt.Errorf("feature %s: %s: %w", f.name, phase, err)
	}
	return nil
}

// applyServerFeatureOptions runs the options hooks on o, in name order.
// main.go calls it with the ui.Options that ui.New receives.
func applyServerFeatureOptions(deps serverDeps, o *ui.Options) error {
	fs, err := orderServerFeatures(serverFeatures)
	if err != nil {
		return err
	}
	for _, f := range fs {
		if f.options == nil {
			continue
		}
		if err := featureHook(f, "options", func() error { return f.options(deps, o) }); err != nil {
			return err
		}
	}
	return nil
}

// mountServerPublicRoutes runs the public hooks on p, in name order. The
// routes are mounted by webServerPublic, outside the session check.
func mountServerPublicRoutes(deps serverDeps, p *publicRoutes) error {
	fs, err := orderServerFeatures(serverFeatures)
	if err != nil {
		return err
	}
	for _, f := range fs {
		if f.public == nil {
			continue
		}
		if err := featureHook(f, "public", func() error { return f.public(deps, p) }); err != nil {
			return err
		}
	}
	return nil
}

// mountServerFeaturePages runs the pages hooks on mux, in name order. mux is
// the pages mux the session check guards.
func mountServerFeaturePages(deps serverDeps, mux *http.ServeMux) error {
	fs, err := orderServerFeatures(serverFeatures)
	if err != nil {
		return err
	}
	for _, f := range fs {
		if f.pages == nil {
			continue
		}
		if err := featureHook(f, "pages", func() error { return f.pages(deps, mux) }); err != nil {
			return err
		}
	}
	return nil
}
