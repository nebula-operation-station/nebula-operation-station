// SPDX-License-Identifier: AGPL-3.0-or-later

// Package paths holds the html/template files of the attack-path pages
// (ADR 0011 D10, plan VU-24), embedded into the binary:
//
//   - list.html, detail.html and map.html define the "content" block of a
//     page rendered inside web/templates/layout.html by
//     internal/web/ui/paths; they carry no inline script or style;
//   - frame.html is the renderer document of the sandboxed overlay iframe.
//     Its single inline <style> element is static, so the hash its CSP
//     allows is fixed at build time; the only dynamic value is the overlay
//     data in an attribute.
package paths

import "embed"

// FS contains the attack-path page templates.
//
//go:embed list.html detail.html map.html frame.html
var FS embed.FS
