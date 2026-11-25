// SPDX-License-Identifier: AGPL-3.0-or-later

package netdevinventory_test

import (
	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevinventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// The device pages read the store through ui.NetDevStore. This fails to
// compile when a read method of the store drifts from the interface.
var _ ui.NetDevStore = (*netdevinventory.Store)(nil)
