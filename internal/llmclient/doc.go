// SPDX-License-Identifier: AGPL-3.0-or-later

// Package llmclient is the shared OpenAI-compatible chat-completions client
// of the NOS agents (ADR 0016 D6, ADR 0011 A1.4): one non-streaming call per
// request, an optional JSON schema for the answer, and the lab-only dialer.
//
// The lab-only dialer checks every connected address against the lab
// networks (loopback, RFC 1918, IPv6 ULA, plus the networks the caller
// names), after DNS resolution and on every connection. The client follows
// no redirect, ignores proxy variables and sends an API key only over TLS.
// Errors never carry the API key, the request or the response body.
package llmclient
