// SPDX-License-Identifier: AGPL-3.0-or-later

// Package version carries build metadata set with -ldflags -X.
package version

// Set at build time, e.g.
//
//	-ldflags "-X github.com/nebula-operation-station/nebula-operation-station/internal/version.Version=v0.0.1"
var (
	Version = "dev"
	Commit  = "unknown"
)

// String returns "version (commit)".
func String() string { return Version + " (" + Commit + ")" }
