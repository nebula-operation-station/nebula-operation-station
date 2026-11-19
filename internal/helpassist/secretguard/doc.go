// SPDX-License-Identifier: AGPL-3.0-or-later

// Package secretguard refuses help-assistant questions that look like
// secrets, before any LLM call (ADR 0014 D5, threat T9 in D6, AS-09 part 2).
//
// Check rejects a question that
//   - contains a private-key block: the text "-----BEGIN" in any case,
//     anywhere in the question (so also after spaces and on any line);
//   - contains "AGE-SECRET-KEY-" in any case;
//   - contains "otpauth://" in any case;
//   - contains an API token of NOS's own format.
//
// Token format: cmd/nebula-server/apitoken.go (newAPIToken) issues every
// API token as "nos_" followed by base64.RawURLEncoding of 32 random bytes,
// that is 43 characters of [A-Za-z0-9_-]. The guard refuses "nos_" followed
// by at least 43 such characters. The prefix is case-sensitive, as issued.
//
// The guard is not a guarantee. It sees only the question text, not
// pasted material in other forms (for example base64 of a key, or a secret
// without one of the fixed markers). The UI hint "never paste secrets"
// stays in place.
//
// A rejection names no finding and no position. Its error text is fixed;
// the class of the finding is available through ClassOf for callers that
// branch on it.
//
// Open points: none for the NOS token. Other token kinds (for example
// enrollment material) are not covered unless they use the same issued
// format.
package secretguard
