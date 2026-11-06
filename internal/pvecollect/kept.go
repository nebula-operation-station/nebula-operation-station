// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecollect

import (
	"slices"
	"time"
)

const (
	// maxKeptPerRemote is how many files a remote with a failure on record
	// keeps. Older ones are superseded: the store refuses a generation below
	// its watermark, so they could only ever apply if no newer file does.
	maxKeptPerRemote = 3
	// keptRetryBase is the delay after the second store failure in a row. The
	// first is retried on the next pass, because most are transient.
	keptRetryBase = time.Minute
	// keptRetryMax caps the delay. It is also how long a dataset that keeps
	// failing can hold back the other datasets of its remote.
	keptRetryMax = 5 * time.Minute
)

// keptRemote is the retry state of one remote with a failure on record.
type keptRemote struct {
	// notBefore is when the store may be tried again.
	notBefore time.Time
	// delay is the wait after the next store failure.
	delay time.Duration
}

// keptRemotes tracks, in memory, the remotes whose latest attempt failed. It
// is what keeps files that stay in the spool cheap: without it every pass
// would retry all of them, and because the watermark of a failing remote may
// not move, superseded would never remove any.
//
// A remote listed here keeps only its newest files, and the importer tries
// those newest first, so one success supersedes the rest. Its store attempts
// back off; failed reads do not, because they never reach the store and
// the cap already bounds them. After a restart the state is empty and the first
// failure of each remote rebuilds it, at the cost of one more attempt.
type keptRemotes map[string]keptRemote

// plan forgets remotes without listed files and returns the listing in
// processing order, with every remote's run of names still contiguous, plus
// the names above the cap. names must be sorted, which orders a remote's
// generations; healthy remotes stay oldest first, so a backlog applies in
// order.
func (k keptRemotes) plan(names []string) (order []string, excess map[string]struct{}) {
	listed := make(map[string]struct{}, len(k))
	order = make([]string, 0, len(names))
	excess = map[string]struct{}{}
	for start := 0; start < len(names); {
		remote := spoolRemote(names[start])
		end := start + 1
		for end < len(names) && spoolRemote(names[end]) == remote {
			end++
		}
		run := names[start:end]
		start = end
		listed[remote] = struct{}{}
		if _, failing := k[remote]; !failing {
			order = append(order, run...)
			continue
		}
		over := max(len(run)-maxKeptPerRemote, 0)
		for _, name := range run[:over] {
			excess[name] = struct{}{}
			order = append(order, name)
		}
		newestFirst := slices.Clone(run[over:])
		slices.Reverse(newestFirst)
		order = append(order, newestFirst...)
	}
	for remote := range k {
		if _, ok := listed[remote]; !ok {
			delete(k, remote)
		}
	}
	return order, excess
}

// spoolRemote returns the remote of a spool name, or "" for a malformed one.
func spoolRemote(name string) string {
	remote, _, err := parseSpoolName(name)
	if err != nil {
		return ""
	}
	return remote
}

// due reports whether the remote's store back-off has run out at now.
func (k keptRemotes) due(remote string, now time.Time) bool {
	return !now.Before(k[remote].notBefore)
}

// readFailed records a file of remote that could not be read.
func (k keptRemotes) readFailed(remote string) {
	if _, ok := k[remote]; !ok {
		k[remote] = keptRemote{}
	}
}

// storeFailed records a store failure on remote and schedules the next try.
func (k keptRemotes) storeFailed(remote string, now time.Time) {
	r := k[remote]
	r.notBefore = now.Add(r.delay)
	r.delay = min(max(2*r.delay, keptRetryBase), keptRetryMax)
	k[remote] = r
}

// succeeded ends the remote's failure episode.
func (k keptRemotes) succeeded(remote string) {
	delete(k, remote)
}
