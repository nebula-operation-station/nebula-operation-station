// SPDX-License-Identifier: AGPL-3.0-or-later

package dockerhost

import (
	"math"
	"os"
	"testing"
)

// fuzzSeedFiles returns the golden result documents named by the caller,
// used to seed the fuzz corpora with realistic host output. A missing
// committed fixture is a test setup failure, so it panics.
func fuzzSeedFiles(names ...string) [][]byte {
	var seeds [][]byte
	for _, n := range names {
		b, err := os.ReadFile("testdata/" + n)
		if err != nil {
			panic("missing golden fuzz seed " + n + ": " + err.Error())
		}
		seeds = append(seeds, b)
	}
	return seeds
}

// FuzzParseStats feeds arbitrary bytes to the docker.stats parser. The
// parser must never panic, must keep the snapshot within its bounds, and
// must keep every reported metric inside its range: a metric that does not
// parse is nil (unavailable), never a guessed zero.
func FuzzParseStats(f *testing.F) {
	for _, s := range fuzzSeedFiles("docker29-stats.json") {
		f.Add(s)
	}
	f.Add([]byte(`{"format":"docker-stats-v1","phase":"precheck","reason":"no docker"}`))
	f.Add([]byte(`{"format":"docker-stats-v1","phase":"done","present":false}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`"text"`))
	f.Fuzz(func(t *testing.T, b []byte) {
		s, _ := ParseStats(b)
		if len(s.Containers) > maxStatsContainers {
			t.Fatalf("stats snapshot has %d containers, bound is %d", len(s.Containers), maxStatsContainers)
		}
		for _, c := range s.Containers {
			if !fullIDRe.MatchString(c.FullID) {
				t.Fatalf("container full ID %q is not 64 hex digits", c.FullID)
			}
			if len(c.Name) > 255 {
				t.Fatalf("container name exceeds 255 bytes: %d", len(c.Name))
			}
			if c.CPUPercent != nil && fuzzFloatOutsideRange(*c.CPUPercent, maxCPUPercent) {
				t.Fatalf("cpu percent %v outside [0, %d]", *c.CPUPercent, maxCPUPercent)
			}
			for _, m := range []*int64{c.MemUsedBytes, c.MemLimitBytes} {
				if m != nil && (*m < 0 || *m > maxMemBytes) {
					t.Fatalf("memory bytes %d outside [0, %d]", *m, maxMemBytes)
				}
			}
			if c.MemPercent != nil && fuzzFloatOutsideRange(*c.MemPercent, maxMemPercent) {
				t.Fatalf("memory percent %v outside [0, %d]", *c.MemPercent, maxMemPercent)
			}
		}
	})
}

// FuzzParseImageVulns feeds arbitrary bytes to the image.vulnerabilities
// (Trivy) parser. The parser must never panic, must keep every count and
// list within its bounds, and must keep unknown states distinct from zero:
// a status that is not ok can never carry CVE numbers.
func FuzzParseImageVulns(f *testing.F) {
	for _, s := range fuzzSeedFiles("trivy052-vulns.json") {
		f.Add(s)
	}
	f.Add([]byte(`{"format":"image-vulns-v1","phase":"precheck","reason":"no trivy"}`))
	f.Add([]byte(`{"format":"image-vulns-v1","phase":"done","present":false,"status":"absent"}`))
	f.Add([]byte(`{"format":"image-vulns-v1","phase":"done","present":true,"status":"stale"}`))
	f.Add([]byte(`{"format":"image-vulns-v1","phase":"done","present":true,"status":"failed"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, b []byte) {
		v, _ := ParseImageVulns(b)
		if v.DBAgeH != nil && (*v.DBAgeH < 0 || *v.DBAgeH > maxVulnsDBAgeH) {
			t.Fatalf("database age %d outside [0, %d]", *v.DBAgeH, maxVulnsDBAgeH)
		}
		if v.Status != VulnsOK {
			// Unknown states are "unknown", never zero findings.
			if len(v.Severity) != 0 || v.Total != 0 || v.Targets != 0 || len(v.Top) != 0 {
				t.Fatalf("status %q carries findings: %+v", v.Status, v)
			}
			return
		}
		if len(v.Severity) != len(vulnSeverityOrder) {
			t.Fatalf("completed scan has %d severity entries, want %d", len(v.Severity), len(vulnSeverityOrder))
		}
		total := 0
		for _, n := range v.Severity {
			if n < 0 || n > maxVulnsCount {
				t.Fatalf("severity count %d outside [0, %d]", n, maxVulnsCount)
			}
			total += n
		}
		if v.Total != total || v.Total > maxVulnsCount {
			t.Fatalf("total %d is not the severity sum %d within [0, %d]", v.Total, total, maxVulnsCount)
		}
		if v.Targets < 0 || v.Targets > maxVulnsTargets {
			t.Fatalf("targets %d outside [0, %d]", v.Targets, maxVulnsTargets)
		}
		if len(v.Top) > maxVulnsTop || len(v.Top) > v.Total {
			t.Fatalf("top list has %d entries, bounds are %d and total %d", len(v.Top), maxVulnsTop, v.Total)
		}
		for _, x := range v.Top {
			if !vulnIDRe.MatchString(x.ID) || !vulnSeveritySet[x.Severity] {
				t.Fatalf("top entry has bad id or severity: %+v", x)
			}
			if len(x.Fixed) > maxVulnsFixed {
				t.Fatalf("fixed version exceeds %d bytes: %d", maxVulnsFixed, len(x.Fixed))
			}
		}
	})
}

func fuzzFloatOutsideRange(v, max float64) bool {
	return math.IsNaN(v) || v < 0 || v > max
}

func TestFuzzFloatRangeRejectsNonfinite(t *testing.T) {
	for _, max := range []float64{maxCPUPercent, maxMemPercent} {
		for _, tc := range []struct {
			name    string
			value   float64
			outside bool
		}{
			{"NaN", math.NaN(), true},
			{"positive infinity", math.Inf(1), true},
			{"negative infinity", math.Inf(-1), true},
			{"negative", -1, true},
			{"above maximum", max + 1, true},
			{"zero", 0, false},
			{"maximum", max, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if got := fuzzFloatOutsideRange(tc.value, max); got != tc.outside {
					t.Errorf("range [0, %v], value %v: outside = %v, want %v", max, tc.value, got, tc.outside)
				}
			})
		}
	}
}
