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
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/auditlog"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/ipam"
	"github.com/nebula-operation-station/nebula-operation-station/internal/notify"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsnotes"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
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
	// the server waits for it at shutdown.
	run func(func(context.Context))
}

// serverFeature is one feature's wiring. Each hook is optional (nil skips it):
//   - options edits the ui.Options before ui.New receives them;
//   - pages adds routes behind the session check (webServer's pages mux).
//
// There is no hook for routes without a session: a feature that needs one
// changes the security surface and comes with its own review.
type serverFeature struct {
	name    string
	options func(serverDeps, *ui.Options) error
	pages   func(serverDeps, *http.ServeMux) error
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

// featureHook calls one hook. A panic (http.ServeMux panics on a route that
// is already registered) becomes an error here, so the start fails with the
// feature name instead of crashing; the panic can only come from the hook's
// own setup at startup.
func featureHook(f serverFeature, phase string, call func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("feature %s: %s: panic: %v", f.name, phase, r)
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
