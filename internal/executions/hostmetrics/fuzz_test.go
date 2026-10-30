// SPDX-License-Identifier: AGPL-3.0-or-later
package hostmetrics

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

// FuzzParseMetrics feeds arbitrary bytes to the host.metrics parser. The
// parser must never panic and must reject unknown formats and malformed
// values rather than guess.
func FuzzParseMetrics(f *testing.F) {
	f.Add([]byte(`{"format":"host-metrics-v1","phase":"done"}`))
	f.Add([]byte(`{"format":"host-metrics-v1","phase":"done","cpu":"` + b64("12.5") + `"}`))
	f.Add([]byte(`{"format":"host-metrics-v1","phase":"precheck","reason":"` + b64("no /proc/stat") + `"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseMetrics(data)
	})
}

// FuzzParseFilesystems feeds arbitrary bytes to the filesystem.list parser.
func FuzzParseFilesystems(f *testing.F) {
	f.Add([]byte(`{"format":"fs-list-v1","phase":"done"}`))
	f.Add([]byte(`{"format":"fs-list-v1","phase":"done","mounts":"` + b64("ext4\t/\t1000\t10") + `"}`))
	f.Add([]byte(`{"format":"fs-list-v1","phase":"done","mounts":"` + b64("tmpfs\t/run\t1000\t10\nproc\t/proc\t0\t0") + `"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseFilesystems(data)
	})
}

// FuzzParseMetricsRoundTrip seeds the fuzz corpus with well-formed documents
// built from arbitrary field values, so the parser is exercised against both
// valid and adversarial encodings.
func FuzzParseMetricsRoundTrip(f *testing.F) {
	f.Add("12.5", "0.1 0.2 0.3", "100 200", "/\t100\t200")
	f.Fuzz(func(t *testing.T, cpu, load, mem, disk string) {
		doc := map[string]string{
			"format": "host-metrics-v1",
			"phase":  "done",
			"cpu":    base64.StdEncoding.EncodeToString([]byte(cpu)),
			"load":   base64.StdEncoding.EncodeToString([]byte(load)),
			"mem":    base64.StdEncoding.EncodeToString([]byte(mem)),
			"disk":   base64.StdEncoding.EncodeToString([]byte(disk)),
		}
		raw, err := json.Marshal(doc)
		if err != nil {
			t.Skip()
		}
		_, _ = ParseMetrics(raw)
	})
}
