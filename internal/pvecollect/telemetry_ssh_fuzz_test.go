// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecollect

import (
	"encoding/base64"
	"math"
	"os"
	"slices"
	"strings"
	"testing"
)

// fuzzSSHErrMax bounds the length of an error from sshTelemetrySamples. The
// host ID and the parser's own short messages fit well inside it; anything
// longer means the host's bytes were quoted back without a limit.
const fuzzSSHErrMax = 512

// fuzzSSHLongPhase is a phase several KiB long. Parsers that quote the host's
// phase into an error without a limit produce an error far above
// fuzzSSHErrMax, so this seed exercises the error bound for real.
var fuzzSSHLongPhase = strings.Repeat("P", 4096)

// fuzzSSHActions maps the fuzzed selector byte to an action ID. The third
// entry is not a telemetry action: it must yield no samples and no error.
var fuzzSSHActions = [...]string{"host.metrics", "filesystem.list", "gpu.status"}

// fuzzSSHMetrics lists the metric kinds each telemetry action may yield.
// filesystem.list only describes mounts, so it may yield disk and nothing else.
var fuzzSSHMetrics = map[string][]string{
	"host.metrics":    {TelemetryMetricCPU, TelemetryMetricRAM, TelemetryMetricDisk},
	"filesystem.list": {TelemetryMetricDisk},
}

// fuzzSSHHostID is the host ID every fuzz target carries; errors must name it.
const fuzzSSHHostID = "host-fuzz"

// fuzzSSHMetricsDoc builds a host.metrics document with base64-encoded
// fields, the way a managed host sends it.
func fuzzSSHMetricsDoc(phase, cpu, mem, disk string) []byte {
	enc := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	return []byte(`{"format":"host-metrics-v1","phase":"` + phase + `","cpu":"` + enc(cpu) +
		`","mem":"` + enc(mem) + `","disk":"` + enc(disk) + `"}`)
}

// fuzzSSHFSDoc builds a filesystem.list document with a base64 mounts field.
func fuzzSSHFSDoc(phase, mounts string) []byte {
	return []byte(`{"format":"fs-list-v1","phase":"` + phase + `","mounts":"` +
		base64.StdEncoding.EncodeToString([]byte(mounts)) + `"}`)
}

// fuzzSSHSeeds lists the seed inputs: the valid example documents from
// telemetry_ssh_test.go and the edge cases the review asks for.
func fuzzSSHSeeds(f *testing.F) {
	fsRaw, err := os.ReadFile("../executions/hostmetrics/testdata/proxmox-fs.json")
	if err != nil {
		f.Fatal(err)
	}
	metricsRaw, err := os.ReadFile("../executions/hostmetrics/testdata/proxmox-metrics.json")
	if err != nil {
		f.Fatal(err)
	}
	seeds := []struct {
		sel byte
		in  []byte
	}{
		// Valid examples, both actions.
		{0, fuzzSSHMetricsDoc("done", "25.0", "1024 4096", "/\t30\t100")},
		{0, metricsRaw},
		{1, fsRaw},
		{1, fuzzSSHFSDoc("done", "ext4\t/\t100\t30\nproc\t/proc\t0\t0\n")},
		// Used > Total, Total == 0, and zero-sized mounts.
		{0, fuzzSSHMetricsDoc("done", "50", "5 4", "/\t5\t4")},
		{0, fuzzSSHMetricsDoc("done", "50", "0 0", "/\t0\t0")},
		{1, fuzzSSHFSDoc("done", "ext4\t/\t0\t0\next4\t/x\t10\t20\n")},
		// Phase other than done.
		{0, fuzzSSHMetricsDoc("precheck", "25", "1 2", "/\t1\t2")},
		{1, fuzzSSHFSDoc("precheck", "ext4\t/\t10\t5\n")},
		{0, fuzzSSHMetricsDoc("bogus", "25", "1 2", "/\t1\t2")},
		// Negative and very large numbers, NaN and Inf.
		{0, fuzzSSHMetricsDoc("done", "-5", "-1 10", "/\t-1\t10")},
		{0, fuzzSSHMetricsDoc("done", "150", "18446744073709551615 18446744073709551615", "/\t18446744073709551615\t18446744073709551615")},
		{0, fuzzSSHMetricsDoc("done", "NaN", "9999999999999999999999 1", "/\t1e300\t1")},
		{0, fuzzSSHMetricsDoc("done", "Inf", "1 2", "/\t1\t2")},
		{1, fuzzSSHFSDoc("done", "ext4\t/\t18446744073709551615\t1\n")},
		// Truncated JSON, empty input, wrong format.
		{0, []byte(`{"format":"host-metrics-v1","phase":"do`)},
		{1, []byte(`{"format":"fs-list-v1","phase":"done","mounts":"`)},
		{0, []byte{}},
		{1, []byte{}},
		{0, []byte(`{"format":"other","phase":"done"}`)},
		// A several-KiB invalid phase: the error may name the phase but must
		// stay within fuzzSSHErrMax.
		{0, []byte(`{"format":"host-metrics-v1","phase":"` + fuzzSSHLongPhase + `"}`)},
		{1, []byte(`{"format":"fs-list-v1","phase":"` + fuzzSSHLongPhase + `"}`)},
		// Unknown action selector.
		{2, fuzzSSHMetricsDoc("done", "25", "1 2", "/\t1\t2")},
	}
	for _, s := range seeds {
		f.Add(s.sel, s.in)
	}
}

// fuzzSSHChecks asserts the properties every result of sshTelemetrySamples
// must hold, whatever the host sent.
func fuzzSSHChecks(t *testing.T, action string, target TelemetryTarget, samples []TelemetrySample, err error) {
	t.Helper()
	// The non-telemetry action must yield neither samples nor an error.
	if action == "gpu.status" {
		if err != nil || len(samples) != 0 {
			t.Fatalf("non-telemetry action %s: err=%v samples=%+v, want none", action, err, samples)
		}
		return
	}
	if err != nil {
		if samples != nil {
			t.Fatalf("error %v with samples %+v", err, samples)
		}
		if !strings.Contains(err.Error(), fuzzSSHHostID) {
			t.Fatalf("error does not name the host: %q", err.Error())
		}
		if len(err.Error()) > fuzzSSHErrMax {
			t.Fatalf("error exceeds %d bytes (%d): host input quoted without bound", fuzzSSHErrMax, len(err.Error()))
		}
		return
	}
	allowed, ok := fuzzSSHMetrics[action]
	if !ok {
		t.Fatalf("no metric kinds declared for action %q", action)
	}
	if len(samples) > len(allowed) {
		t.Fatalf("%s: %d samples, at most %d allowed", action, len(samples), len(allowed))
	}
	seen := map[string]bool{}
	for _, s := range samples {
		if s.Target != target {
			t.Fatalf("sample target = %+v, want %+v", s.Target, target)
		}
		if !slices.Contains(allowed, s.Metric) {
			t.Fatalf("%s yielded metric %q, allowed %v", action, s.Metric, allowed)
		}
		if seen[s.Metric] {
			t.Fatalf("duplicate metric %q in %+v", s.Metric, samples)
		}
		seen[s.Metric] = true
		if math.IsNaN(s.Value) || math.IsInf(s.Value, 0) || s.Value < 0 || s.Value > 1 {
			t.Fatalf("%s value %v outside [0,1]", s.Metric, s.Value)
		}
	}
}

// FuzzSSHTelemetrySamples fuzzes the mapping from an untrusted SSH telemetry
// result to box metric fractions. The host output is the only input that
// varies; the target is fixed.
func FuzzSSHTelemetrySamples(f *testing.F) {
	fuzzSSHSeeds(f)
	f.Fuzz(func(t *testing.T, sel byte, result []byte) {
		action := fuzzSSHActions[int(sel)%len(fuzzSSHActions)]
		target := TelemetryTarget{Source: TelemetrySSH, HostID: fuzzSSHHostID, HostKey: telKeyFuzz, ActionID: action}
		samples, err := sshTelemetrySamples(target, result)
		fuzzSSHChecks(t, action, target, samples, err)
	})
}

// telKeyFuzz is a well-formed host key fingerprint for fuzz targets.
var telKeyFuzz = "SHA256:" + strings.Repeat("f", 43)
