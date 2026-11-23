// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"log/slog"

	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
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
// resolver is built from the same configuration as the dialog's
// (enrollClientAddr on deps.cfg), so both see the same client address. The
// startup warning and the trusted-proxy-network lines are logged once, by
// enrollOptions.
func enrollPublic(deps serverDeps, p *publicRoutes) error {
	addr, err := enrollClientAddr(deps.cfg, nil)
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
// warning of WarnListener. The trusted proxies come from server.json
// (trusted_proxies, trusted_proxy_networks); without them the TCP peer is
// the client.
func enrollOptions(deps serverDeps, o *ui.Options) error {
	r, err := enrollClientAddr(deps.cfg, deps.log)
	if err != nil {
		return err
	}
	r.WarnListener(deps.log, deps.cfg.Listen, true)
	o.EnrollClientAddr = r
	return nil
}

// enrollClientAddr builds the resolver of the download route and the dialog
// from the trusted-proxy settings of cfg (ADR 0013 D7). Both hooks call it
// on the same deps.cfg, so the two resolvers are equal. log receives the
// trusted proxy networks; nil logs nothing. An invalid setting fails the
// start (the loader has refused it already).
func enrollClientAddr(cfg serverconfig.Config, log *slog.Logger) (*clientaddr.Resolver, error) {
	r, err := clientaddr.New(cfg.ClientAddrConfig(), log)
	if err != nil {
		return nil, fmt.Errorf("enrollment client address: %w", err)
	}
	return r, nil
}
