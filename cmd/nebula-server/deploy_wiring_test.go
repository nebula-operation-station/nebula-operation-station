// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// TestLazyExecutorServesDeployments checks that the server's executor
// connection serves the deployment pages (ADR 0008 section 6, PV-08):
// provisioning with its approval, and the guest join the run page drives
// through pveinventory.GuestJoinFlow.
func TestLazyExecutorServesDeployments(t *testing.T) {
	var exec any = new(lazyExecutor)
	if _, ok := exec.(ui.DeployProvisioner); !ok {
		t.Error("lazyExecutor does not serve the deployment wizard")
	}
	if _, ok := exec.(pveinventory.GuestJoinExecutor); !ok {
		t.Error("lazyExecutor does not serve the guest join")
	}
}
