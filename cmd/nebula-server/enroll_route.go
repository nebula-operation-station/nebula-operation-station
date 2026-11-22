// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"log/slog"

	"github.com/nebula-operation-station/nebula-operation-station/internal/web/clientaddr"
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
// the same address (ADR 0013 D7). The route itself is not mounted here: it
// needs a route outside the session check, which the registry does not
// offer yet.
func enrollFeature() serverFeature {
	return serverFeature{name: enrollFeatureName, options: enrollOptions}
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
