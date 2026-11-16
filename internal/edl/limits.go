// SPDX-License-Identifier: AGPL-3.0-or-later

// Package edl holds the pure rules for External Dynamic Lists (ADR 0012 D7):
// entry refusals and deterministic list rendering. It performs no I/O and
// holds no credentials, and it does not know about routes, migrations or the
// firewall. Serving, authentication, audit and the WebAuthn add flow belong
// to later tickets (NS-15, NS-17 part 2, NS-18).
package edl

// MaxEntries is the largest number of entries one published list may hold
// (ADR 0012 D7, default 10,000). A list over this cap is never truncated and
// never published; the previous version stays in place.
const MaxEntries = 10000
