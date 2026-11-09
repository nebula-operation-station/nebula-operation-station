// SPDX-License-Identifier: AGPL-3.0-or-later

// Package jewels holds the html/template file of the crown-jewels admin page
// (ADR 0011 D10, plan VU-23), embedded into the binary. It is rendered
// inside web/templates/layout.html by internal/web/ui/jewels; it carries no
// inline script or style.
package jewels

import "embed"

// FS contains the crown-jewels page template.
//
//go:embed *.html
var FS embed.FS
