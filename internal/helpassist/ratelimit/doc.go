// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ratelimit limits how many help-assistant questions a user and the
// whole installation may ask (ADR 0014 D5, Q9; AS-09 part 3).
//
// The limits are:
//
//   - per user: PerUserPerHour questions in a sliding one-hour window, and
//     PerUserInFlight question running at a time;
//   - globally: GlobalPerDay questions in a sliding 24-hour window.
//
// Counting. A question is counted when Acquire succeeds. A question that
// fails or is cancelled after Acquire still counts, because it may already
// have triggered an LLM call. A refused Acquire (ErrUserBusy, ErrUserLimit,
// ErrGlobalLimit, ErrEmptyUser, ErrUserTableFull) counts nothing. Calling the
// release function frees the in-flight slot but never refunds the count.
// The caller must call release on every path, for example with defer.
//
// Clock. Time comes from the function given to New; the package never reads
// the wall clock itself. A window only expires when the clock reaches the
// time at which the question stamped by Acquire is one window old. If the
// clock goes backwards, questions stamped later than the clock still count,
// so a backwards jump can never allow more than the limit.
//
// Memory. Question times outside their window are dropped. The number of
// tracked users is capped at MaxTrackedUsers. When that cap is reached and no
// idle entry can be removed, a new user is refused (fail closed); a known
// user is never forgotten to make room.
//
// Scope. All state is in memory. A restart of the process resets every
// counter, including the global day count. ADR 0014 does not require
// persistent counters. The package has no HTTP handling, no sessions and no
// LLM calls; those belong to the callers.
package ratelimit
