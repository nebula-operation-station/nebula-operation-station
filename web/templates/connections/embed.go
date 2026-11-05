// SPDX-License-Identifier: AGPL-3.0-or-later

// Package connections holds the html/template file of the connections
// tab on the host and asset pages (ADR 0009 D3, ticket TM20), embedded
// into the binary. It is rendered inside web/templates/layout.html by
// internal/web/ui/connections; it carries no inline script or style.
package connections

import "embed"

// FS contains the connections page template.
//
//go:embed *.html
var FS embed.FS
