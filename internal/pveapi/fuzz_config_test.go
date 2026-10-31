// SPDX-License-Identifier: AGPL-3.0-or-later
package pveapi

import (
	"context"
	"testing"
)

// FuzzGetQemuConfig feeds hostile bodies to GetQemuConfig (parseGuestConfig via
// the do path). The do path sanitizes (does not reject) invalid UTF-8, so the
// asserted rejection is the size limit; per-field limits are enforced inside
// the parser and surface as errors.
func FuzzGetQemuConfig(f *testing.F) {
	f.Add(wrapData(readFuzzFixture(f, "pve8/qemu_config_100.json")))
	_, c, body := newSingleBodyFuzzServer(f)
	ctx := context.Background()
	f.Fuzz(func(t *testing.T, data []byte) {
		body.Store(data)
		_, err := c.GetQemuConfig(ctx, "pve1", 100)
		assertFuzzInvariants(t, data, MaxResponseBytes, false, err, nil)
	})
}

// FuzzGetLxcConfig is the LXC twin of FuzzGetQemuConfig.
func FuzzGetLxcConfig(f *testing.F) {
	f.Add(wrapData(readFuzzFixture(f, "pve8/lxc_config_200.json")))
	_, c, body := newSingleBodyFuzzServer(f)
	ctx := context.Background()
	f.Fuzz(func(t *testing.T, data []byte) {
		body.Store(data)
		_, err := c.GetLxcConfig(ctx, "pve1", 200)
		assertFuzzInvariants(t, data, MaxResponseBytes, false, err, nil)
	})
}
