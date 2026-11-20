// SPDX-License-Identifier: AGPL-3.0-or-later

// Package turns keeps the follow-up turns of one help-assistant panel session
// in server memory (ADR 0014 D5 "Conversation storage", ticket AS-09 part 5).
//
// A follow-up question may carry the previous turns of the same panel session.
// Those turns live only here:
//
//   - at most MaxTurns turns per session; the oldest turn is dropped first;
//   - a turn expires MaxAge after it was appended and is never returned after
//     that; expired turns are removed on the next access;
//   - Clear ends one session, ClearUser ends every session of one user (logout);
//   - nothing is written to disk or to the database; a restart empties the store;
//   - a turn holds the question and the rendered answer as text only. Facts sent
//     with a turn and chunk texts are not stored: the Turn type has no field for
//     them;
//   - Turn never renders its text in String, GoString or LogValue (ADR 0014 D5
//     "Audit": no question or answer text in logs).
//
// Sessions are keyed by an identifier that the caller supplies. The key must be
// unguessable and must belong to exactly one logged-in user; the store binds each
// session to the user of its first turn and refuses turns from any other user.
//
// Limits are named constants in this package and are enforced on every write.
// The package uses the standard library only.
package turns
