// SPDX-License-Identifier: AGPL-3.0-or-later

// Package templates holds the web UI's html/template files, embedded
// into the binary. Rendering uses html/template only; there is no other
// templating engine and no inline JavaScript or CSS (docs/spec/14).
package templates

import "embed"

// FS contains the page templates.
//
//go:embed *.html
var FS embed.FS
