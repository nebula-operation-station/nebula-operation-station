// SPDX-License-Identifier: AGPL-3.0-or-later

// Package panapi is the read-only PAN-OS XML API client of the executor
// (ADR 0010 D1–D3, implementation plan ND-08).
//
// Trust and transport:
//
//   - TLS trust is pinned with pvetransport.Trust (leaf SHA-256 or an
//     admin-imported issuing CA, validity, serverAuth EKU, SAN), reused, not
//     copied; the system root store is never consulted. TLS 1.2 minimum.
//   - The endpoint is an IP literal; no dial ever resolves DNS. Before every
//     dial the address is re-checked and public, loopback, link-local,
//     multicast and unspecified addresses are refused.
//   - Redirects are refused, environment proxies are ignored, compression
//     and HTTP/2 are off. 10 s connect, 60 s per request, one request in
//     flight per Client (one Client per device).
//
// Credentials: the API key travels only in the X-PAN-KEY header, never in
// the URL or the body, and is written to the connection only after the
// handshake has verified the pin. It never appears in errors or logs.
//
// Requests: every call is a POST of a form body to /api/. A Request can
// only be built by this package's constructors, from fixed operational
// commands and fixed xpath templates; rule and object names are validated
// (ValidateName) and quoted. There are no write, commit, import, export or
// keygen operations.
//
// Responses: bodies are capped before parsing (8 MiB configuration, 1 MiB
// other), must be valid UTF-8 XML within the ND-04 depth, element and text
// limits, with a <response status="success"> root. Error bodies are never
// returned, logged or put into errors; only a numeric API code is kept.
// Parsing the result is ND-09.
package panapi
