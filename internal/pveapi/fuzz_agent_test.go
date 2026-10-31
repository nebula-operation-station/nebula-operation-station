// SPDX-License-Identifier: AGPL-3.0-or-later
package pveapi

import (
	"context"
	"testing"
)

// FuzzAgentOSInfo feeds hostile bodies to AgentOSInfo (the get-osinfo parser).
// The do path sanitizes (does not reject) invalid UTF-8; field-length limits
// are enforced inside the parser.
func FuzzAgentOSInfo(f *testing.F) {
	f.Add(wrapData(readFuzzFixture(f, "pve8/agent_osinfo_100.json")))
	_, c, body := newSingleBodyFuzzServer(f)
	ctx := context.Background()
	f.Fuzz(func(t *testing.T, data []byte) {
		body.Store(data)
		_, err := c.AgentOSInfo(ctx, "pve1", 100)
		assertFuzzInvariants(t, data, MaxResponseBytes, false, err, nil)
	})
}

// FuzzAgentNetworkInterfaces feeds hostile bodies to AgentNetworkInterfaces and
// asserts the interface count limit holds on success.
func FuzzAgentNetworkInterfaces(f *testing.F) {
	f.Add(wrapData(readFuzzFixture(f, "pve8/agent_net_100.json")))
	_, c, body := newSingleBodyFuzzServer(f)
	ctx := context.Background()
	f.Fuzz(func(t *testing.T, data []byte) {
		body.Store(data)
		ifs, err := c.AgentNetworkInterfaces(ctx, "pve1", 100)
		assertFuzzInvariants(t, data, MaxResponseBytes, false, err, func() {
			if len(ifs.Interfaces) > MaxAgentInterfaces {
				t.Fatalf("interfaces %d exceeds MaxAgentInterfaces %d", len(ifs.Interfaces), MaxAgentInterfaces)
			}
		})
	})
}

// FuzzAgentFSInfo feeds hostile bodies to AgentFSInfo and asserts the
// filesystem count limit holds on success.
func FuzzAgentFSInfo(f *testing.F) {
	f.Add(wrapData(readFuzzFixture(f, "pve8/agent_fsinfo_100.json")))
	_, c, body := newSingleBodyFuzzServer(f)
	ctx := context.Background()
	f.Fuzz(func(t *testing.T, data []byte) {
		body.Store(data)
		fs, err := c.AgentFSInfo(ctx, "pve1", 100)
		assertFuzzInvariants(t, data, MaxResponseBytes, false, err, func() {
			if len(fs.Filesystems) > MaxAgentFilesystems {
				t.Fatalf("filesystems %d exceeds MaxAgentFilesystems %d", len(fs.Filesystems), MaxAgentFilesystems)
			}
		})
	})
}
