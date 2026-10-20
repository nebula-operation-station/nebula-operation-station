// SPDX-License-Identifier: AGPL-3.0-or-later

// Package static holds the web UI's static assets, embedded into the
// binary. Vendored third-party files are pinned and recorded in
// VENDORED.md; the test in internal/web/ui verifies the recorded hash
// against the embedded bytes.
package static

import "embed"

// FS contains the static assets served under /static/.
//
//go:embed htmx.min.js app.css webauthn.js login.js setup.js nav.js dashboard.js inventory.js operations.js inventory-import.js repin.js inventory-enroll.js schedules.js runbooks.js modules.js network.js discovery.js
var FS embed.FS
