// SPDX-License-Identifier: AGPL-3.0-or-later

package dockerhost

import (
	"os"
	"strings"
	"testing"
)

func statsResult(version, lines string) []byte {
	return []byte(`{"format":"docker-stats-v1","phase":"done","present":true,"version":"` + enc(version) + `","stats":"` + enc(lines) + `"}`)
}

func statsByID(t *testing.T, s Stats, id string) ContainerStats {
	t.Helper()
	for _, c := range s.Containers {
		if c.FullID == id {
			return c
		}
	}
	t.Fatalf("no container with full ID %s in %+v", id, s.Containers)
	return ContainerStats{}
}

func mustFloat(t *testing.T, name string, v *float64) float64 {
	t.Helper()
	if v == nil {
		t.Fatalf("%s is nil, want a value", name)
	}
	return *v
}

func mustInt(t *testing.T, name string, v *int64) int64 {
	t.Helper()
	if v == nil {
		t.Fatalf("%s is nil, want a value", name)
	}
	return *v
}

// testdata/docker29-stats.json is docker.stats on Docker 29.8.2 with two
// running containers: web and worker, both on an 8 GiB host.
func TestParseStatsRealOutput(t *testing.T) {
	b, err := os.ReadFile("testdata/docker29-stats.json")
	if err != nil {
		t.Fatal(err)
	}
	s, err := ParseStats(b)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Present || s.Version != "29.8.2" || len(s.Containers) != 2 {
		t.Fatalf("%+v", s)
	}
	// Deterministic order: by full container ID.
	if s.Containers[0].Name != "worker" || s.Containers[1].Name != "web" {
		t.Fatalf("order %+v", s.Containers)
	}
	web := s.Containers[1]
	if web.FullID != "c1bfa1cc4a9a2109aa190e758a09c75ffa9cc9caf9fb653a143fb27e9e299cf2" {
		t.Fatalf("web ID %+v", web)
	}
	if mustFloat(t, "web cpu", web.CPUPercent) != 12.34 {
		t.Fatalf("web cpu %+v", web)
	}
	if mustInt(t, "web mem used", web.MemUsedBytes) != 512<<20 {
		t.Fatalf("web mem used %+v", web)
	}
	if mustInt(t, "web mem limit", web.MemLimitBytes) != 8<<30 {
		t.Fatalf("web mem limit %+v", web)
	}
	if mustFloat(t, "web mem %", web.MemPercent) != 6.25 {
		t.Fatalf("web mem%% %+v", web)
	}
	worker := s.Containers[0]
	if mustFloat(t, "worker cpu", worker.CPUPercent) != 0.5 {
		t.Fatalf("worker cpu %+v", worker)
	}
	if mustInt(t, "worker mem used", worker.MemUsedBytes) != 1<<30 {
		t.Fatalf("worker mem used %+v", worker)
	}
	if mustInt(t, "worker mem limit", worker.MemLimitBytes) != 8<<30 {
		t.Fatalf("worker mem limit %+v", worker)
	}
	if mustFloat(t, "worker mem %", worker.MemPercent) != 12.5 {
		t.Fatalf("worker mem%% %+v", worker)
	}
}

// Lines that do not fit are left out: a full ID is required to key a row,
// but a bad name or metric leaves the container with that field empty.
func TestParseStatsDropsWhatDoesNotFit(t *testing.T) {
	ok, badName, badCPU, overCPU, badMem, badMemP :=
		strings.Repeat("01", 32), strings.Repeat("02", 32), strings.Repeat("03", 32),
		strings.Repeat("04", 32), strings.Repeat("05", 32), strings.Repeat("06", 32)
	lines := strings.Join([]string{
		`{"id":"` + ok + `","name":"ok","cpu":"1.00%","mem":"1MB / 2GB","memp":"5.00%"}`,
		`{"id":"` + strings.Repeat("ab", 6) + `","name":"short","cpu":"1%","mem":"1MB / 2GB","memp":"5%"}`, // 12-hex ID
		`{"id":"XYZ","name":"badid","cpu":"1%","mem":"1MB / 2GB","memp":"5%"}`,                             // not an ID
		`{"id":"` + badName + `","name":"-lead","cpu":"1%","mem":"1MB / 2GB","memp":"5%"}`,                 // bad name
		`{"id":"` + badCPU + `","name":"noper","cpu":"high","mem":"1MB / 2GB","memp":"5%"}`,                // bad CPU
		`{"id":"` + overCPU + `","name":"over","cpu":"100001%","mem":"1MB / 2GB","memp":"5%"}`,             // CPU out of range
		`{"id":"` + badMem + `","name":"badmem","cpu":"1%","mem":"lots / much","memp":"5%"}`,               // bad memory
		`{"id":"` + badMemP + `","name":"badmemp","cpu":"1%","mem":"1MB / 2GB","memp":"n/a"}`,              // bad memory %
		"garbage", // not JSON
	}, "\n")
	s, err := ParseStats(statsResult("27.0", lines))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Containers) != 6 {
		t.Fatalf("kept %d rows: %+v", len(s.Containers), s.Containers)
	}
	c := statsByID(t, s, ok)
	if c.Name != "ok" || mustFloat(t, "cpu", c.CPUPercent) != 1 || mustInt(t, "mem", c.MemUsedBytes) != 1<<20 ||
		mustInt(t, "limit", c.MemLimitBytes) != 2<<30 || mustFloat(t, "memp", c.MemPercent) != 5 {
		t.Fatalf("ok %+v", c)
	}
	if c := statsByID(t, s, badName); c.Name != "" {
		t.Fatalf("bad name kept: %+v", c)
	}
	for _, id := range []string{badCPU, overCPU} {
		if c := statsByID(t, s, id); c.CPUPercent != nil {
			t.Fatalf("cpu kept for %s: %+v", id, c)
		}
	}
	if c := statsByID(t, s, badMem); c.MemUsedBytes != nil || c.MemLimitBytes != nil {
		t.Fatalf("memory kept: %+v", c)
	}
	if c := statsByID(t, s, badMemP); c.MemPercent != nil {
		t.Fatalf("memory %% kept: %+v", c)
	}
}

func TestParseStatsOtherResults(t *testing.T) {
	s, err := ParseStats([]byte(`{"format":"docker-stats-v1","phase":"done","present":false}`))
	if err != nil || s.Present || len(s.Containers) != 0 {
		t.Fatalf("%+v %v", s, err)
	}
	s, err = ParseStats([]byte(`{"format":"docker-stats-v1","phase":"precheck","reason":"the Docker daemon is not reachable"}`))
	if err != nil || s.Phase != "precheck" || s.Reason == "" {
		t.Fatalf("%+v %v", s, err)
	}
	s, _ = ParseStats([]byte(`{"format":"docker-stats-v1","phase":"precheck","reason":"a\nb"}`))
	if s.Reason != "" {
		t.Fatalf("reason with a newline kept: %q", s.Reason)
	}
	for _, bad := range []string{`{}`, `{"format":"docker-ps-v1","phase":"done"}`, `{"format":"docker-stats-v1","phase":"later"}`,
		`{"format":"docker-stats-v1","phase":"done","present":true,"stats":"%%%"}`, `not json`} {
		if _, err := ParseStats([]byte(bad)); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

// A stopped or removed container is absent, never a row of zeros: an empty
// snapshot has no rows, and a metric docker did not report stays nil.
func TestParseStatsAbsentNeverZero(t *testing.T) {
	s, err := ParseStats(statsResult("27.0", ""))
	if err != nil || !s.Present || len(s.Containers) != 0 {
		t.Fatalf("%+v %v", s, err)
	}
	full := strings.Repeat("07", 32)
	s, err = ParseStats(statsResult("27.0", `{"id":"`+full+`","name":"bare","cpu":"","mem":"","memp":""}`))
	if err != nil || len(s.Containers) != 1 {
		t.Fatalf("%+v %v", s, err)
	}
	c := s.Containers[0]
	if c.CPUPercent != nil || c.MemUsedBytes != nil || c.MemLimitBytes != nil || c.MemPercent != nil {
		t.Fatalf("metrics fabricated for a bare container: %+v", c)
	}
}

// A recreated container keeps its name but has a new full ID: the two are
// distinct rows, keyed by full ID, so a replacement is not mixed up.
func TestParseStatsFullIDReplacement(t *testing.T) {
	a, b := strings.Repeat("aa", 32), strings.Repeat("bb", 32)
	lines := `{"id":"` + a + `","name":"web","cpu":"1.00%","mem":"1MB / 2GB","memp":"5.00%"}` + "\n" +
		`{"id":"` + b + `","name":"web","cpu":"2.00%","mem":"2MB / 2GB","memp":"10.00%"}`
	s, err := ParseStats(statsResult("27.0", lines))
	if err != nil || len(s.Containers) != 2 {
		t.Fatalf("%+v %v", s, err)
	}
	ca, cb := statsByID(t, s, a), statsByID(t, s, b)
	if ca.Name != "web" || cb.Name != "web" {
		t.Fatalf("names %+v %+v", ca, cb)
	}
	if mustFloat(t, "old cpu", ca.CPUPercent) != 1 || mustFloat(t, "new cpu", cb.CPUPercent) != 2 {
		t.Fatalf("cpu mixed up: %+v %+v", ca, cb)
	}
	if mustInt(t, "old mem", ca.MemUsedBytes) != 1<<20 || mustInt(t, "new mem", cb.MemUsedBytes) != 2<<20 {
		t.Fatalf("memory mixed up: %+v %+v", ca, cb)
	}
}

// Docker reports memory as a human size ("used / limit"); the parser
// converts it back to bytes (base 1024) and rejects what does not fit.
func TestParseStatsHumanSizes(t *testing.T) {
	for _, tc := range []struct {
		in          string
		used, limit int64
	}{
		{"5B / 10B", 5, 10},
		{"524kB / 1MB", 524 << 10, 1 << 20},
		{"1.25MB / 8GB", 1310720, 8 << 30},
		{"1GiB / 2TiB", 1 << 30, 2 << 40},
		{"999999999999999999EB / 1B", 0, 0}, // overflows, unavailable
		{"1MB", 0, 0},                       // no separator
		{"-1MB / 1B", 0, 0},                 // negative
	} {
		t.Run(tc.in, func(t *testing.T) {
			u, l, ok := memUsage(tc.in)
			if tc.used == 0 && tc.limit == 0 {
				if ok {
					t.Fatalf("%q parsed as %d / %d, want unavailable", tc.in, u, l)
				}
				return
			}
			if !ok || u != tc.used || l != tc.limit {
				t.Fatalf("%q = %d / %d (ok=%v), want %d / %d", tc.in, u, l, ok, tc.used, tc.limit)
			}
		})
	}
}

func TestParseStatsPercentBounds(t *testing.T) {
	for _, tc := range []struct {
		in  string
		max float64
		ok  bool
		v   float64
	}{
		{"0%", 100, true, 0},
		{"100%", 100, true, 100},
		{"12.34%", 100, true, 12.34},
		{"101%", 100, false, 0},        // memory % cannot exceed 100
		{"200.00%", 100000, true, 200}, // CPU % may exceed 100 on multi-core
		{"100001%", 100000, false, 0},  // CPU % sanity bound
		{"high", 100, false, 0},
		{"-1%", 100, false, 0},
		{"1e300%", 100000, false, 0},
	} {
		t.Run(tc.in, func(t *testing.T) {
			got, ok := percent(tc.in, tc.max)
			if ok != tc.ok || (ok && got != tc.v) {
				t.Fatalf("percent(%q, %v) = %v, %v; want %v, %v", tc.in, tc.max, got, ok, tc.v, tc.ok)
			}
		})
	}
}

func TestParseStatsCapsTheList(t *testing.T) {
	full := strings.Repeat("0", 64)
	var b strings.Builder
	for i := 0; i < maxStatsContainers+10; i++ {
		b.WriteString(`{"id":"` + full + `","name":"c","cpu":"1%","mem":"1B / 1B","memp":"1%"}` + "\n")
	}
	s, err := ParseStats(statsResult("27.0", b.String()))
	if err != nil || len(s.Containers) != maxStatsContainers {
		t.Fatalf("%d %v", len(s.Containers), err)
	}
}
