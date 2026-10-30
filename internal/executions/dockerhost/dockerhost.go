// SPDX-License-Identifier: AGPL-3.0-or-later

// Package dockerhost reads the results of the built-in Docker actions
// (spec 11). Everything in a result comes from the host and is untrusted:
// fields are checked, cut and dropped, never interpreted.
package dockerhost

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// ErrFormat means the result is not a docker.list result.
var ErrFormat = errors.New("dockerhost: not a docker.list result")

const (
	maxRawSize    = 4 << 20
	maxContainers = 2000
)

// Container is one line of `docker ps -a`.
type Container struct {
	ID      string // first 12 hex digits
	FullID  string // full 64 hex digits
	Name    string
	Image   string
	State   string // created, running, paused, restarting, removing, exited, dead
	Status  string // docker's text, e.g. "Up 3 hours (healthy)"
	Health  string // healthy, unhealthy, starting or ""
	Ports   string
	Created string // creation time, RFC 3339 UTC, "" if not parseable
	Project string // Compose project, "" for a standalone container
	Service string // Compose service
	Dir     string // Compose working directory
}

// Running reports whether the container runs.
func (c Container) Running() bool { return c.State == "running" }

// List is a parsed docker.list result.
type List struct {
	Phase      string // done or precheck
	Reason     string
	Present    bool
	Version    string
	Containers []Container
}

// Summary counts a list.
type Summary struct {
	Total, Running, Unhealthy, Stopped int
	Projects                           []string
}

// Summary counts the containers by state and lists the Compose projects.
func (l List) Summary() Summary {
	var s Summary
	seen := map[string]bool{}
	for _, c := range l.Containers {
		s.Total++
		switch {
		case c.Running():
			s.Running++
		case c.State == "exited" || c.State == "dead" || c.State == "created":
			s.Stopped++
		}
		if c.Health == "unhealthy" {
			s.Unhealthy++
		}
		if c.Project != "" && !seen[c.Project] {
			seen[c.Project] = true
			s.Projects = append(s.Projects, c.Project)
		}
	}
	sort.Strings(s.Projects)
	return s
}

var (
	idRe      = regexp.MustCompile(`^[0-9a-f]{12,64}$`)
	fullIDRe  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	nameRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.,/-]{0,254}$`)
	projectRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,99}$`)
	states    = map[string]bool{"created": true, "running": true, "paused": true, "restarting": true, "removing": true, "exited": true, "dead": true}
)

// unsafeRune reports control characters (C0, DEL, C1), line and
// paragraph separators, bidirectional marks, embeddings, overrides and
// isolates, and the byte order mark: characters that can make a value
// look different from what it is.
func unsafeRune(r rune) bool {
	switch {
	case r < 0x20, r >= 0x7f && r <= 0x9f:
		return true
	case r == 0x061c, r == 0x200e, r == 0x200f, r == 0x2028, r == 0x2029, r == 0xfeff:
		return true
	case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x206f:
		return true
	}
	return false
}

// printable is one line of at most limit bytes without unsafe characters.
func printable(s string, limit int) bool {
	if len(s) > limit || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unsafeRune(r) {
			return false
		}
	}
	return true
}

func decode(s string) (string, bool) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) > maxRawSize || !utf8.Valid(b) {
		return "", false
	}
	return string(b), true
}

func health(status string) string {
	switch {
	case strings.Contains(status, "(unhealthy)"):
		return "unhealthy"
	case strings.Contains(status, "(healthy)"):
		return "healthy"
	case strings.Contains(status, "(health: starting)"):
		return "starting"
	}
	return ""
}

// ParseList reads a docker.list result. Lines that do not fit are left
// out; the containers are sorted by Compose project, then name.
func ParseList(result []byte) (List, error) {
	var doc struct {
		Format     string `json:"format"`
		Phase      string `json:"phase"`
		Reason     string `json:"reason"`
		Present    bool   `json:"present"`
		Version    string `json:"version"`
		Containers string `json:"containers"`
	}
	if json.Unmarshal(result, &doc) != nil || doc.Format != "docker-ps-v1" || (doc.Phase != "done" && doc.Phase != "precheck") {
		return List{}, ErrFormat
	}
	l := List{Phase: doc.Phase, Present: doc.Present}
	if doc.Phase == "precheck" {
		if printable(doc.Reason, 300) {
			l.Reason = doc.Reason
		}
		return l, nil
	}
	if !doc.Present {
		return l, nil
	}
	if v, ok := decode(doc.Version); ok && printable(strings.TrimSpace(v), 100) {
		l.Version = strings.TrimSpace(v)
	}
	text, ok := decode(doc.Containers)
	if !ok {
		return List{}, ErrFormat
	}
	for _, line := range strings.Split(text, "\n") {
		if len(l.Containers) >= maxContainers {
			break
		}
		f := strings.Split(line, "	")
		if (len(f) != 9 && len(f) != 10) || !idRe.MatchString(f[0]) || !nameRe.MatchString(f[1]) || !states[f[3]] {
			continue
		}
		c := Container{ID: f[0][:12], Name: f[1], State: f[3]}
		if fullIDRe.MatchString(f[0]) {
			c.FullID = f[0]
		}
		if !printable(f[2], 300) || !printable(f[4], 200) || !printable(f[5], 1000) {
			continue
		}
		c.Image, c.Status, c.Ports, c.Health = f[2], f[4], f[5], health(f[4])
		if len(f) == 10 {
			c.Created = createdFromList(f[9])
		}
		if projectRe.MatchString(f[6]) {
			c.Project = f[6]
			if printable(f[7], 100) {
				c.Service = f[7]
			}
			if printable(f[8], 500) {
				c.Dir = f[8]
			}
		}
		l.Containers = append(l.Containers, c)
	}
	sort.SliceStable(l.Containers, func(i, j int) bool {
		a, b := l.Containers[i], l.Containers[j]
		if a.Project != b.Project {
			return a.Project < b.Project
		}
		return a.Name < b.Name
	})
	return l, nil
}

// Logs is a parsed docker.logs result.
type Logs struct {
	Phase     string // done or precheck
	Reason    string
	Container string
	State     string
	Lines     []string
}

const (
	maxLogLines   = 100
	maxLogLineLen = 1000
)

// containerRe is the docker.logs parameter pattern.
var containerRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

// logLine makes one log line safe to show: at most maxLogLineLen bytes,
// valid UTF-8, unsafe characters (see unsafeRune) but tab replaced.
func logLine(s string) string {
	if len(s) > maxLogLineLen {
		s = s[:maxLogLineLen]
	}
	s = strings.ToValidUTF8(s, "\uFFFD")
	return strings.Map(func(r rune) rune {
		if r != '\t' && unsafeRune(r) {
			return '\uFFFD'
		}
		return r
	}, s)
}

// ParseLogs reads a docker.logs result.
func ParseLogs(result []byte) (Logs, error) {
	var doc struct {
		Format    string `json:"format"`
		Phase     string `json:"phase"`
		Reason    string `json:"reason"`
		Container string `json:"container"`
		State     string `json:"state"`
		Logs      string `json:"logs"`
	}
	if json.Unmarshal(result, &doc) != nil || doc.Format != "docker-logs-v1" || (doc.Phase != "done" && doc.Phase != "precheck") {
		return Logs{}, errors.New("dockerhost: not a docker.logs result")
	}
	l := Logs{Phase: doc.Phase}
	if doc.Phase == "precheck" {
		if printable(doc.Reason, 300) {
			l.Reason = doc.Reason
		}
		return l, nil
	}
	if containerRe.MatchString(doc.Container) {
		l.Container = doc.Container
	}
	if st, ok := decode(doc.State); ok && states[strings.TrimSpace(st)] {
		l.State = strings.TrimSpace(st)
	}
	// Logs are any bytes (cut by the script at 256 KiB, maybe inside a
	// UTF-8 sequence): invalid UTF-8 is replaced, not refused.
	raw, err := base64.StdEncoding.DecodeString(doc.Logs)
	if err != nil || len(raw) > maxRawSize {
		return Logs{}, errors.New("dockerhost: not a docker.logs result")
	}
	text := string(raw)
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	if len(lines) > maxLogLines {
		lines = lines[len(lines)-maxLogLines:]
	}
	for _, s := range lines {
		if text != "" {
			l.Lines = append(l.Lines, logLine(strings.TrimSuffix(s, "\r")))
		}
	}
	return l, nil
}
