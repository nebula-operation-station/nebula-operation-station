// SPDX-License-Identifier: AGPL-3.0-or-later

// Package agent is the optional LLM assessor of the vulnerability agent
// (ADR 0011 Amendment 1, A1.4): a minimal tool-calling loop with a fixed,
// compiled-in tool registry and hard limits.
//
// The model sees a fixed core system prompt, optional operator notes in a
// separate lower-priority block, the facts of one finding and the results
// of the read-only lookup tools, all feed and export text JSON-encoded
// inside an envelope that the prompt declares as untrusted data. The only
// output path is the submit_assessment tool, whose payload is validated
// against a strict schema; every other model text is discarded. The lookup
// tools read only in-memory views of the run's pinned snapshot and export
// (Snapshot, RunView) and perform no network or filesystem I/O.
//
// A disabled assessor makes no LLM call and produces no text and no error.
package agent
