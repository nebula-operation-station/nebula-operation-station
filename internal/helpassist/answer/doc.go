// SPDX-License-Identifier: AGPL-3.0-or-later

// Package answer decodes and checks the structured answer of the in-app help
// assistant. ADR 0014 (docs/adr/0014-help-assistant.md) decides the answer
// format in D4 ("Structured response" and "Rendering") and the citation rule
// in D2 ("Citations are mandatory").
//
// This package implements the first part of ticket AS-09
// (docs/implementation/help-assistant.md):
//
//   - Decode: the model answer is one JSON object with the fields of D4. Any
//     deviation from the schema discards the whole answer with the fixed
//     error ErrInvalidAnswer. Nothing is repaired, and the error never
//     contains part of the answer.
//   - MapCitations: only citation IDs that were in the prompt count (D2).
//   - CleanText: the rendering rule of D4 for text fields. Control characters,
//     bidi overrides and zero-width characters become U+FFFD.
//
// Not part of this package: the LLM call, the prompt, the command validator
// (internal/helpcmd), the HTTP handlers and the UI, settings, and the audit
// log. The package imports the standard library only, and the test
// TestAnswerImportsOnlyStdlib enforces it.
//
// Line breaks in text fields: ADR 0014 D4 replaces control characters in text
// fields and names no exception for line breaks. CleanText therefore also
// replaces line feeds, carriage returns, tabs and the Unicode line and
// paragraph separators (categories Cc, Zl and Zp). Each step text is one
// line in the rendered page; the command field is never changed here, and
// its one-line rule is checked in Decode and again by helpcmd.CheckASCII.
package answer
