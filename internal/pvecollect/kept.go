// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecollect

import (
	"slices"
	"time"
)

const (
	// maxKeptPerRemote is how many files a remote with a failure on record
	// keeps, and how many failed reads a pass spends on its files. Older ones
	// are superseded once a newer file is judged valid: the store refuses a
	// generation below its watermark, so they could only ever apply if no
	// newer file does. Until then they may be the remote's last valid
	// observation and stay.
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
	// valid is the newest generation judged valid whose file still waits in
	// the spool, or 0 when there is none. Reaching the store's dataset writes
	// is what judges a file: validation comes first there.
	valid uint64
}

// keptRemotes tracks, in memory, the remotes whose latest attempt failed. It
// is what keeps files that stay in the spool cheap: without it every pass
// would retry all of them, and because the watermark of a failing remote may
// not move, superseded would never remove any.
//
// A remote listed here is tried newest first, so one success supersedes the
// rest, and it keeps only its newest files plus whatever no valid file covers
// yet: a file above the cap goes only when it is older than a file still in
// the spool that was judged valid. Its store attempts back off; failed reads
// do not, because they never reach the store and a pass stops reading the
// remote after maxKeptPerRemote of them. After a restart the state is empty and
// the first failure of each remote rebuilds it, at the cost of one more attempt.
type keptRemotes map[string]keptRemote

// plan forgets remotes without listed files and judged files that left the
// spool, and returns the listing in processing order, with every remote's run
// of names still contiguous, plus the names above the cap. Those come last in
// their run, so the newer files can be judged first. names must be sorted,
// which orders a remote's generations; healthy remotes stay oldest first, so a
// backlog applies in order.
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
		k.confirmValid(remote, run)
		for _, name := range run[:max(len(run)-maxKeptPerRemote, 0)] {
			excess[name] = struct{}{}
		}
		newestFirst := slices.Clone(run)
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

// confirmValid forgets the remote's judged file unless run still lists it.
func (k keptRemotes) confirmValid(remote string, run []string) {
	r := k[remote]
	for _, name := range run {
		if _, generation, err := parseSpoolName(name); err == nil && generation == r.valid {
			return
		}
	}
	r.valid = 0
	k[remote] = r
}

// judgedValid records that the file of generation passed validation and stays.
func (k keptRemotes) judgedValid(remote string, generation uint64) {
	r := k[remote]
	r.valid = max(r.valid, generation)
	k[remote] = r
}

// rejected forgets a judged file that a later look found invalid.
func (k keptRemotes) rejected(remote string, generation uint64) {
	if r, ok := k[remote]; ok && r.valid == generation {
		r.valid = 0
		k[remote] = r
	}
}

// covered reports whether a file judged valid and newer than generation waits
// in the spool, which is what allows the cap to remove that generation.
func (k keptRemotes) covered(remote string, generation uint64) bool {
	return generation < k[remote].valid
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
