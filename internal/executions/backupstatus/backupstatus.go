// SPDX-License-Identifier: AGPL-3.0-or-later
// Package backupstatus reads the result of the built-in backup.status
// action (ADR 0006 P1-28, spec 10 v2.3). The action collects bounded,
// allowlisted Veeam Agent for Linux session evidence from the host.
// Everything in the result is host data and untrusted: fields are
// checked, truncated or dropped, never interpreted.
package backupstatus

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// ErrFormat means the result is not a backup.status result.
var ErrFormat = errors.New("backupstatus: not a backup.status result")

const (
	maxDocumentSize = 2 << 20                  // 2 MiB JSON, checked before unmarshalling
	maxRawSize      = 1 << 20                  // 1 MiB of decoded session text
	maxEncodedSize  = (maxRawSize + 2) / 3 * 4 // base64 of maxRawSize, checked before decoding
	maxSessions     = 64                       // session blocks per document
	maxJobs         = 64                       // jobs per host
	maxBlockLines   = 64                       // lines per session block
	maxNameLen      = 256                      // job name
	maxReasonLen    = 300                      // precheck reason
	minYear         = 2000                     // session times outside the bound are rejected
	maxYear         = 2099
)

// stateClass groups the allowlisted Veeam session states.
type stateClass int

const (
	stateRunning stateClass = iota // in progress
	stateSuccess                   // completed successfully
	stateFailed                    // completed without success
)

// stateClasses is the allowlist of veeamconfig session states. Anything
// else is hostile or unknown and drops the session.
var stateClasses = map[string]stateClass{
	"Running":     stateRunning,
	"In Progress": stateRunning,
	"Paused":      stateRunning,
	"Success":     stateSuccess,
	"Warning":     stateFailed,
	"Failed":      stateFailed,
	"Canceled":    stateFailed,
	"Cancelled":   stateFailed,
}

// Job is the latest evidenced session of one Veeam backup job.
type Job struct {
	Name      string     // job name
	State     string     // allowlisted state of the latest session
	StartedAt time.Time  // start time; UTC location, wall clock as reported
	EndedAt   *time.Time // nil while the session is still running
	UTC       bool       // start time explicitly said UTC (not a guess)
	EndUTC    bool       // end time explicitly said UTC (not a guess)
	Sessions  int        // sessions observed for this job
}

// Report is a parsed backup.status result.
type Report struct {
	Phase     string // done or precheck
	Reason    string // precheck reason, fixed strings from the script
	Present   bool   // false: no veeamconfig on the host
	Truncated bool   // the evidence is incomplete
	Jobs      []Job
}

// Classification is the phase-1 evidence class (ADR 0006).
type Classification string

const (
	// ClassUnknown: Veeam not detected, denied, unsupported or no
	// sessions. It never means "no backups" or "backups safe".
	ClassUnknown Classification = "unknown"
	// ClassOK: every job's latest session is a completed Success within
	// the maximum age.
	ClassOK Classification = "ok"
	// ClassWarning: stale, failed, overdue or in-progress evidence.
	ClassWarning Classification = "warning"
)

// Classify returns the phase-1 evidence class of the report as of now,
// comparing the last evidenced successful backup against maxAge.
func (r Report) Classify(now time.Time, maxAge time.Duration) Classification {
	if r.Phase == "precheck" || !r.Present || r.Truncated || len(r.Jobs) == 0 {
		return ClassUnknown
	}
	for _, j := range r.Jobs {
		if j.State == "Success" && (!j.UTC || !j.EndUTC || (j.EndedAt != nil && j.EndedAt.Before(j.StartedAt))) {
			return ClassUnknown
		}
	}
	for _, j := range r.Jobs {
		if j.State != "Success" || j.EndedAt == nil || now.Before(*j.EndedAt) || now.Sub(*j.EndedAt) > maxAge {
			return ClassWarning
		}
	}
	return ClassOK
}

var (
	// sessionIDRe is a veeamconfig session ID: {8-4-4-4-12 hex}.
	sessionIDRe = regexp.MustCompile(`^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$`)
	// blockHeaderRe is one session block header: [N] {id}.
	blockHeaderRe = regexp.MustCompile(`^\[(\d+)\] \{([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\}$`)
	// timeRe is a veeamconfig time: YYYY-MM-DD HH:MM:SS with an
	// optional explicit UTC marker.
	timeRe = regexp.MustCompile(`^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})(?: (UTC|GMT|Z))?$`)
)

// Parse reads a backup.status result.
func Parse(result []byte) (Report, error) {
	if len(result) > maxDocumentSize {
		return Report{}, ErrFormat
	}
	var doc struct {
		Format    string `json:"format"`
		Phase     string `json:"phase"`
		Reason    string `json:"reason"`
		Present   bool   `json:"present"`
		Truncated bool   `json:"truncated"`
		Sessions  string `json:"sessions"`
	}
	if json.Unmarshal(result, &doc) != nil || doc.Format != "backup-status-v1" || len(doc.Sessions) > maxEncodedSize || (doc.Phase != "done" && doc.Phase != "precheck") {
		return Report{}, ErrFormat
	}
	rep := Report{Phase: doc.Phase, Present: doc.Present, Truncated: doc.Truncated}
	if doc.Phase == "precheck" {
		if printable(doc.Reason, maxReasonLen) {
			rep.Reason = doc.Reason
		}
		return rep, nil
	}
	if !doc.Present {
		return rep, nil
	}
	text, ok := decode(doc.Sessions)
	if !ok {
		return Report{}, ErrFormat
	}
	var incomplete bool
	rep.Jobs, incomplete = parseSessions(text)
	rep.Truncated = rep.Truncated || incomplete
	return rep, nil
}

// session is one parsed session block before per-job aggregation.
type session struct {
	name     string
	state    string
	start    time.Time
	startUTC bool
	end      time.Time
	endUTC   bool
	ended    bool
}

// parseSessions reads the session document: one "[N] {id}" block per
// session, each block the key/value lines of
// `veeamconfig session info --id {id}`. A block that violates the
// strict schema is dropped and marks the evidence incomplete. Per job,
// the session with the latest start time wins. A broken header sequence
// makes the whole document hostile: no evidence is taken from it.
func parseSessions(text string) ([]Job, bool) {
	var (
		jobs       = map[string]*Job{}
		order      []string
		seq        int
		curID      string
		cur        []string
		overflow   bool
		incomplete bool
	)
	flush := func() {
		if curID != "" {
			if s, ok := parseSessionBlock(curID, cur); ok && !overflow {
				addSession(jobs, &order, s)
			} else {
				incomplete = true
			}
		}
		curID, cur, overflow = "", nil, false
	}
	for _, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		line = strings.TrimRight(line, "\r")
		if m := blockHeaderRe.FindStringSubmatch(line); m != nil {
			flush()
			seq++
			n, _ := strconv.Atoi(m[1])
			if n != seq || seq > maxSessions {
				return nil, true // corrupted or hostile document
			}
			curID = "{" + m[2] + "}"
			continue
		}
		if curID != "" {
			if len(cur) < maxBlockLines {
				cur = append(cur, line)
			} else {
				overflow = true
			}
		}
	}
	flush()
	if len(jobs) > maxJobs {
		return nil, true
	}
	out := make([]Job, 0, len(order))
	for _, name := range order {
		out = append(out, *jobs[name])
	}
	return out, incomplete
}

// parseSessionBlock reads one session block against the strict schema.
// The ID line must equal the header ID (identity limit). Unknown keys
// (Job ID, progress, log paths, ...) are dropped.
func parseSessionBlock(headerID string, lines []string) (session, bool) {
	var (
		s         session
		haveID    bool
		haveName  bool
		haveState bool
		haveStart bool
	)
	for _, line := range lines {
		if line == "" {
			continue
		}
		key, value, found := strings.Cut(line, ": ")
		if !found {
			continue // not a key/value line: dropped
		}
		value = strings.TrimSpace(value)
		switch key {
		case "ID":
			if haveID || !sessionIDRe.MatchString(value) || value != headerID {
				return session{}, false
			}
			haveID = true
		case "Job name":
			if haveName || value == "" || !printable(value, maxNameLen) {
				return session{}, false
			}
			s.name, haveName = value, true
		case "State":
			if haveState {
				return session{}, false
			}
			if _, ok := stateClasses[value]; !ok {
				return session{}, false
			}
			s.state, haveState = value, true
		case "Start time":
			if haveStart {
				return session{}, false
			}
			tt, u, ok := parseTime(value)
			if !ok {
				return session{}, false
			}
			s.start, s.startUTC, haveStart = tt, u, true
		case "End time":
			if value == "" {
				continue // running session: no end time yet
			}
			if s.ended {
				return session{}, false
			}
			tt, u, ok := parseTime(value)
			if !ok {
				return session{}, false
			}
			s.end, s.endUTC, s.ended = tt, u, true
		default:
			// Unknown key: dropped.
		}
	}
	if !haveID || !haveName || !haveState || !haveStart || (s.ended && s.end.Before(s.start)) {
		return session{}, false
	}
	return s, true
}

// addSession aggregates a session into the per-job report: the session
// with the latest start time wins, ties keep the first seen.
func addSession(jobs map[string]*Job, order *[]string, s session) {
	j, ok := jobs[s.name]
	if !ok {
		j = &Job{Name: s.name}
		jobs[s.name] = j
		*order = append(*order, s.name)
	}
	j.Sessions++
	if !s.start.After(j.StartedAt) {
		return
	}
	j.State = s.state
	j.StartedAt = s.start
	j.UTC = s.startUTC
	j.EndUTC = s.endUTC
	if s.ended {
		e := s.end
		j.EndedAt = &e
	} else {
		j.EndedAt = nil
	}
}

// parseTime parses a veeamconfig time. The wall clock is stored as UTC;
// the bool reports whether the source explicitly said UTC, GMT or Z.
// Impossible calendar dates and times outside the year bound are
// rejected.
func parseTime(in string) (time.Time, bool, bool) {
	m := timeRe.FindStringSubmatch(strings.TrimSpace(in))
	if m == nil {
		return time.Time{}, false, false
	}
	vals := make([]int, 6)
	for i := 1; i <= 6; i++ {
		v, err := strconv.Atoi(m[i])
		if err != nil {
			return time.Time{}, false, false
		}
		vals[i-1] = v
	}
	y, mo, d, h, mi, se := vals[0], vals[1], vals[2], vals[3], vals[4], vals[5]
	if y < minYear || y > maxYear {
		return time.Time{}, false, false
	}
	t := time.Date(y, time.Month(mo), d, h, mi, se, 0, time.UTC)
	if t.Format("2006-01-02 15:04:05") != m[1]+"-"+m[2]+"-"+m[3]+" "+m[4]+":"+m[5]+":"+m[6] {
		return time.Time{}, false, false // not a real calendar time
	}
	return t, m[7] != "", true
}

// decode base64-decodes the session text within the size limits.
func decode(in string) (string, bool) {
	raw, err := base64.StdEncoding.DecodeString(in)
	if err != nil || len(raw) > maxRawSize {
		return "", false
	}
	return string(raw), true
}

// printable reports whether s is printable text within maxLen.
func printable(s string, maxLen int) bool {
	if len(s) > maxLen || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
