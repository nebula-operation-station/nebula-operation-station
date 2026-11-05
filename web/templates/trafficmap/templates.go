// SPDX-License-Identifier: AGPL-3.0-or-later

// Package trafficmap holds the templates of the traffic map page (ADR 0009
// D4, TM19), embedded into the binary:
//
//   - page.html defines the "content" block of the parent page, rendered
//     inside web/templates/layout.html;
//   - frame.html is the renderer document loaded into the sandboxed
//     iframe. It is served verbatim (not executed as a template) so the
//     hash of its single inline <style> element, which its CSP allows, is
//     fixed at build time.
package trafficmap

import "embed"

// FS contains the traffic map templates.
//
//go:embed page.html frame.html
var FS embed.FS
