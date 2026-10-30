// SPDX-License-Identifier: AGPL-3.0-or-later

package dockerhost

import (
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ContainerStats is one running container of a docker.stats snapshot.
// Metrics docker did not report, or that do not fit, are nil, never zero:
// a stopped or removed container is absent, not a row of zeros.
type ContainerStats struct {
	FullID        string // full 64 hex digits; the key a container is matched by
	Name          string
	CPUPercent    *float64 // nil if not reported or not parseable
	MemUsedBytes  *int64   // nil if not reported or not parseable
	MemLimitBytes *int64
	MemPercent    *float64 // nil if not reported or not parseable
}

// Stats is a parsed docker.stats result.
type Stats struct {
	Phase      string // done or precheck
	Reason     string
	Present    bool
	Version    string
	Containers []ContainerStats
}

// ErrStatsFormat means the result is not a docker.stats result.
var ErrStatsFormat = errors.New("dockerhost: not a docker.stats result")

const (
	// maxStatsContainers bounds the snapshot; the script keeps at most this
	// many lines and the parser drops the rest.
	maxStatsContainers = 2000
	// maxMemBytes bounds one memory figure (4 EiB), so the byte conversion
	// cannot overflow an int64.
	maxMemBytes = 1 << 62
	// maxCPUPercent bounds a CPU reading; docker reports it per core, so it
	// may exceed 100 on multi-core hosts, but not by orders of magnitude.
	maxCPUPercent = 100000
	maxMemPercent = 100
)

// humanSizeRe matches one docker human size, e.g. "5B", "524kB", "1.25MB".
var humanSizeRe = regexp.MustCompile(`^(\d{1,15}(?:\.\d{1,6})?)(B|kB|MB|GB|TB|PB|EB|KiB|MiB|GiB|TiB|PiB|EiB)$`)

// memUsageRe matches docker's "used / limit" memory string.
var memUsageRe = regexp.MustCompile(`^(\S+) / (\S+)$`)

// humanSizeBytes converts one docker human size to bytes (base 1024).
func humanSizeBytes(s string) (int64, bool) {
	m := humanSizeRe.FindStringSubmatch(s)
	if m == nil {
		return 0, false
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil || v < 0 {
		return 0, false
	}
	var mult int64
	switch m[2] {
	case "B":
		mult = 1
	case "kB", "KiB":
		mult = 1 << 10
	case "MB", "MiB":
		mult = 1 << 20
	case "GB", "GiB":
		mult = 1 << 30
	case "TB", "TiB":
		mult = 1 << 40
	case "PB", "PiB":
		mult = 1 << 50
	case "EB", "EiB":
		mult = 1 << 60
	default:
		return 0, false
	}
	if v > float64(maxMemBytes)/float64(mult) {
		return 0, false
	}
	return int64(v * float64(mult)), true
}

// memUsage splits docker's "used / limit" string into byte counts.
func memUsage(s string) (used, limit int64, ok bool) {
	m := memUsageRe.FindStringSubmatch(s)
	if m == nil {
		return 0, 0, false
	}
	u, okU := humanSizeBytes(m[1])
	l, okL := humanSizeBytes(m[2])
	if !okU || !okL {
		return 0, 0, false
	}
	return u, l, true
}

// percent parses a docker percentage string like "41.90%" into a value in
// [0, max], or reports false.
func percent(s string, max float64) (float64, bool) {
	s = strings.TrimSpace(s)
	if !strings.HasSuffix(s, "%") {
		return 0, false
	}
	v, err := strconv.ParseFloat(strings.TrimSuffix(s, "%"), 64)
	if err != nil || v < 0 || v > max {
		return 0, false
	}
	return v, true
}

// ParseStats reads a docker.stats result. Only running containers appear,
// keyed by full ID and ordered by it; lines that do not fit are left out.
func ParseStats(result []byte) (Stats, error) {
	var doc struct {
		Format  string `json:"format"`
		Phase   string `json:"phase"`
		Reason  string `json:"reason"`
		Present bool   `json:"present"`
		Version string `json:"version"`
		Stats   string `json:"stats"`
	}
	if json.Unmarshal(result, &doc) != nil || doc.Format != "docker-stats-v1" || (doc.Phase != "done" && doc.Phase != "precheck") {
		return Stats{}, ErrStatsFormat
	}
	s := Stats{Phase: doc.Phase, Present: doc.Present}
	if doc.Phase == "precheck" {
		if printable(doc.Reason, 300) {
			s.Reason = doc.Reason
		}
		return s, nil
	}
	if !doc.Present {
		return s, nil
	}
	if v, ok := decode(doc.Version); ok && printable(strings.TrimSpace(v), 100) {
		s.Version = strings.TrimSpace(v)
	}
	text, ok := decode(doc.Stats)
	if !ok {
		return Stats{}, ErrStatsFormat
	}
	for _, line := range strings.Split(text, "\n") {
		if len(s.Containers) >= maxStatsContainers {
			break
		}
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			continue
		}
		var row struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			CPU  string `json:"cpu"`
			Mem  string `json:"mem"`
			MemP string `json:"memp"`
		}
		if json.Unmarshal([]byte(line), &row) != nil {
			continue
		}
		// The full ID is the matching key: a recreated container has a new
		// ID even when it keeps its name, so a short ID is not enough.
		if !fullIDRe.MatchString(row.ID) {
			continue
		}
		c := ContainerStats{FullID: row.ID}
		if name := strings.TrimPrefix(row.Name, "/"); nameRe.MatchString(name) {
			c.Name = name
		}
		if v, ok := percent(row.CPU, maxCPUPercent); ok {
			c.CPUPercent = &v
		}
		if u, l, ok := memUsage(row.Mem); ok {
			c.MemUsedBytes = &u
			c.MemLimitBytes = &l
		}
		if v, ok := percent(row.MemP, maxMemPercent); ok {
			c.MemPercent = &v
		}
		s.Containers = append(s.Containers, c)
	}
	sort.Slice(s.Containers, func(i, j int) bool { return s.Containers[i].FullID < s.Containers[j].FullID })
	return s, nil
}
