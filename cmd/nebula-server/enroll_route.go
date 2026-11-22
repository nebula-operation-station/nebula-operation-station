// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"log/slog"

	"github.com/nebula-operation-station/nebula-operation-station/internal/web/clientaddr"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/enroll"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// enrollFeatureName is the registry name of the one-step enrollment
// download wiring (ADR 0013 D7, EN-09).
const enrollFeatureName = "enroll-download"

func init() {
	registerServerFeature(enrollFeature())
}

// enrollFeature returns the download route's feature. Its options hook sets
// the dialog's client-address resolver, so the dialog and the download see
// the same address (ADR 0013 D7). Its public hook mounts the download route
// outside the session check (EN-09), the only public route.
func enrollFeature() serverFeature {
	return serverFeature{name: enrollFeatureName, options: enrollOptions, public: enrollPublic}
}

// enrollPublic mounts GET /enroll/<offer-id> with its rate limit. The
// resolver is built from the same configuration as the dialog's (no trusted
// proxies), so both see the same client address. The startup warning is
// logged once, by enrollOptions.
func enrollPublic(deps serverDeps, p *publicRoutes) error {
	addr, err := enrollClientAddr(deps.log)
	if err != nil {
		return err
	}
	h, err := enroll.New(enroll.Options{
		Executor:   deps.exec,
		ClientAddr: addr,
		Limiter:    enroll.NewLimiter(enroll.DefaultTableSize, nil),
		Log:        deps.log,
	})
	if err != nil {
		return fmt.Errorf("enrollment download route: %w", err)
	}
	return p.Handle(enroll.PathPrefix, h)
}

// enrollOptions sets ui.Options.EnrollClientAddr and runs the startup
// warning of WarnListener. No trusted proxy is configured (this release has
// no setting for one, docs/admin/guide.md), so the TCP peer is the client.
func enrollOptions(deps serverDeps, o *ui.Options) error {
	r, err := enrollClientAddr(deps.log)
	if err != nil {
		return err
	}
	r.WarnListener(deps.log, deps.cfg.Listen, true)
	o.EnrollClientAddr = r
	return nil
}

// enrollClientAddr builds the resolver without trusted proxies, the
// configuration the download route and the dialog share.
func enrollClientAddr(log *slog.Logger) (*clientaddr.Resolver, error) {
	r, err := clientaddr.New(clientaddr.Config{}, log)
	if err != nil {
		return nil, fmt.Errorf("enrollment client address: %w", err)
	}
	return r, nil
}
