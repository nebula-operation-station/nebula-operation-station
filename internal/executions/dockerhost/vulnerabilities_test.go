// SPDX-License-Identifier: AGPL-3.0-or-later
package dockerhost

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestParseImageVulnsRealOutput(t *testing.T) {
	b, err := os.ReadFile("testdata/trivy052-vulns.json")
	if err != nil {
		t.Fatal(err)
	}
	v, err := ParseImageVulns(b)
	if err != nil {
		t.Fatalf("ParseImageVulns: %v", err)
	}
	if v.Phase != "done" || v.Status != VulnsOK || !v.Present || v.Cached {
		t.Fatalf("phase/status/present = %q/%q/%v", v.Phase, v.Status, v.Present)
	}
	if v.Trivy != "0.52.0" || v.DBVersion != "2" || v.DBAgeH == nil || *v.DBAgeH != 1 {
		t.Fatalf("trivy/db = %q/%q/%v", v.Trivy, v.DBVersion, v.DBAgeH)
	}
	if v.Image != "nginx@sha256:a3f9c1d2e4b5a6978867564534231201fedcba98765432100123456789abcdef" {
		t.Fatalf("image = %q", v.Image)
	}
	if v.Platform != "linux/amd64" {
		t.Fatalf("platform = %q", v.Platform)
	}
	if v.Total != 5 || v.Targets != 2 {
		t.Fatalf("total/targets = %d/%d", v.Total, v.Targets)
	}
	want := map[string]int{"CRITICAL": 2, "HIGH": 1, "MEDIUM": 1, "LOW": 1, "UNKNOWN": 0}
	for sev, n := range want {
		if v.Severity[sev] != n {
			t.Fatalf("severity[%s] = %d, want %d", sev, v.Severity[sev], n)
		}
	}
	wantTop := []ImageVuln{
		{ID: "CVE-2023-45290", Severity: "CRITICAL", Fixed: "v0.23.0"},
		{ID: "CVE-2024-28085", Severity: "CRITICAL", Fixed: "3.1.4-3~deb12u5"},
		{ID: "CVE-2023-38408", Severity: "HIGH", Fixed: "2.9.14+dfsg-1.3~deb12u5"},
		{ID: "CVE-2023-52425", Severity: "MEDIUM", Fixed: "2.12.6-0+deb12u4"},
		{ID: "CVE-2022-37434", Severity: "LOW", Fixed: ""},
	}
	if len(v.Top) != len(wantTop) {
		t.Fatalf("top len = %d, want %d", len(v.Top), len(wantTop))
	}
	for i, tv := range wantTop {
		if v.Top[i] != tv {
			t.Fatalf("top[%d] = %+v, want %+v", i, v.Top[i], tv)
		}
	}
}

func mkVulnsDoc(status string, extra map[string]any) []byte {
	doc := map[string]any{"format": "image-vulns-v1", "phase": "done", "status": status}
	for k, v := range extra {
		doc[k] = v
	}
	b, _ := json.Marshal(doc)
	return b
}

func TestParseImageVulnsUnknownStatusesCarryNoFindings(t *testing.T) {
	for _, status := range []string{VulnsAbsent, VulnsStale, VulnsNotLocal, VulnsBusy, VulnsFailed, VulnsTruncated, VulnsUnsupported} {
		v, err := ParseImageVulns(mkVulnsDoc(status, map[string]any{
			"present": true,
			// A hostile host may attach findings to an unknown state; the
			// parser must drop them.
			"summary": base64.StdEncoding.EncodeToString([]byte(`{"severity":{"CRITICAL":9,"HIGH":0,"MEDIUM":0,"LOW":0,"UNKNOWN":0},"total":9,"targets":1,"top":[{"id":"CVE-1999-0001","severity":"CRITICAL","fixed":"1"}]}`)),
		}))
		if err != nil {
			t.Fatalf("%s: %v", status, err)
		}
		if v.Status != status || v.Total != 0 || len(v.Top) != 0 || len(v.Severity) != 0 {
			t.Fatalf("%s: status=%q total=%d top=%d sev=%d", status, v.Status, v.Total, len(v.Top), len(v.Severity))
		}
	}
}

func TestParseImageVulnsAbsent(t *testing.T) {
	v, err := ParseImageVulns(mkVulnsDoc(VulnsAbsent, map[string]any{"present": false}))
	if err != nil {
		t.Fatal(err)
	}
	if v.Present || v.Status != VulnsAbsent {
		t.Fatalf("present=%v status=%q", v.Present, v.Status)
	}
}

func TestParseImageVulnsPrecheck(t *testing.T) {
	v, err := ParseImageVulns([]byte(`{"format":"image-vulns-v1","phase":"precheck","reason":"the Docker daemon is not reachable (no root and no passwordless sudo)"}`))
	if err != nil {
		t.Fatal(err)
	}
	if v.Phase != "precheck" || v.Reason == "" {
		t.Fatalf("phase=%q reason=%q", v.Phase, v.Reason)
	}
	// Newlines in the reason are dropped, not forwarded.
	v, err = ParseImageVulns([]byte(`{"format":"image-vulns-v1","phase":"precheck","reason":"a\nb"}`))
	if err != nil || v.Reason != "ab" {
		t.Fatalf("reason = %q err=%v", v.Reason, err)
	}
}

func TestParseImageVulnsHostile(t *testing.T) {
	okSummary := base64.StdEncoding.EncodeToString([]byte(`{"severity":{"CRITICAL":1,"HIGH":0,"MEDIUM":0,"LOW":0,"UNKNOWN":0},"total":1,"targets":1,"top":[{"id":"CVE-2024-28085","severity":"CRITICAL","fixed":"3.1.4"}]}`))
	cases := []struct {
		name string
		doc  []byte
	}{
		{"wrong format", []byte(`{"format":"docker29-stats","phase":"done","status":"ok"}`)},
		{"no format", []byte(`{"phase":"done","status":"ok"}`)},
		{"bad phase", []byte(`{"format":"image-vulns-v1","phase":"maybe","status":"ok"}`)},
		{"bad status", mkVulnsDoc("exploited", nil)},
		{"no status", []byte(`{"format":"image-vulns-v1","phase":"done"}`)},
		{"ok without summary", mkVulnsDoc(VulnsOK, nil)},
		{"summary not base64", mkVulnsDoc(VulnsOK, map[string]any{"summary": "!!!"})},
		{"summary not json", mkVulnsDoc(VulnsOK, map[string]any{"summary": base64.StdEncoding.EncodeToString([]byte(`[1,2`))})},
		{"summary missing severity key", mkVulnsDoc(VulnsOK, map[string]any{"summary": base64.StdEncoding.EncodeToString([]byte(`{"severity":{"CRITICAL":1,"HIGH":0,"MEDIUM":0,"LOW":0},"total":1,"targets":1,"top":[]}`))})},
		{"total mismatch", mkVulnsDoc(VulnsOK, map[string]any{"summary": base64.StdEncoding.EncodeToString([]byte(`{"severity":{"CRITICAL":2,"HIGH":0,"MEDIUM":0,"LOW":0,"UNKNOWN":0},"total":1,"targets":1,"top":[]}`))})},
		{"negative count", mkVulnsDoc(VulnsOK, map[string]any{"summary": base64.StdEncoding.EncodeToString([]byte(`{"severity":{"CRITICAL":-1,"HIGH":0,"MEDIUM":0,"LOW":0,"UNKNOWN":0},"total":-1,"targets":1,"top":[]}`))})},
		{"count overflow", mkVulnsDoc(VulnsOK, map[string]any{"summary": base64.StdEncoding.EncodeToString([]byte(`{"severity":{"CRITICAL":1000001,"HIGH":0,"MEDIUM":0,"LOW":0,"UNKNOWN":0},"total":1000001,"targets":1,"top":[]}`))})},
		{"targets overflow", mkVulnsDoc(VulnsOK, map[string]any{"summary": base64.StdEncoding.EncodeToString([]byte(`{"severity":{"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"UNKNOWN":0},"total":0,"targets":1001,"top":[]}`))})},
		{"top larger than total", mkVulnsDoc(VulnsOK, map[string]any{"summary": base64.StdEncoding.EncodeToString([]byte(`{"severity":{"CRITICAL":1,"HIGH":0,"MEDIUM":0,"LOW":0,"UNKNOWN":0},"total":1,"targets":1,"top":[{"id":"CVE-1","severity":"CRITICAL","fixed":""},{"id":"CVE-2","severity":"CRITICAL","fixed":""}]}`))})},
		{"top too long", mkVulnsDoc(VulnsOK, map[string]any{"summary": base64.StdEncoding.EncodeToString([]byte(topTooLongSummary(30)))})},
		{"bad vuln id (control char)", mkVulnsDoc(VulnsOK, map[string]any{"summary": base64.StdEncoding.EncodeToString([]byte(`{"severity":{"CRITICAL":1,"HIGH":0,"MEDIUM":0,"LOW":0,"UNKNOWN":0},"total":1,"targets":1,"top":[{"id":"CVE-1\x00x","severity":"CRITICAL","fixed":""}]}`))})},
		{"bad vuln id (too long)", mkVulnsDoc(VulnsOK, map[string]any{"summary": base64.StdEncoding.EncodeToString([]byte(`{"severity":{"CRITICAL":1,"HIGH":0,"MEDIUM":0,"LOW":0,"UNKNOWN":0},"total":1,"targets":1,"top":[{"id":"` + strings.Repeat("A", 70) + `","severity":"CRITICAL","fixed":""}]}`))})},
		{"bad severity in top", mkVulnsDoc(VulnsOK, map[string]any{"summary": base64.StdEncoding.EncodeToString([]byte(`{"severity":{"CRITICAL":1,"HIGH":0,"MEDIUM":0,"LOW":0,"UNKNOWN":0},"total":1,"targets":1,"top":[{"id":"CVE-1","severity":"FATAL","fixed":""}]}`))})},
		{"duplicate top id kept once", nil}, // handled below, not an error
		{"bad trivy field", mkVulnsDoc(VulnsOK, map[string]any{"trivy": "@@@", "summary": okSummary})},
		{"bad dbver", mkVulnsDoc(VulnsOK, map[string]any{"dbver": base64.StdEncoding.EncodeToString([]byte("2.0-beta")), "summary": okSummary})},
		{"negative dbage", mkVulnsDoc(VulnsOK, map[string]any{"dbage": -1, "summary": okSummary})},
		{"dbage not integer", mkVulnsDoc(VulnsOK, map[string]any{"dbage": 1.5, "summary": okSummary})},
		{"dbage overflow", mkVulnsDoc(VulnsOK, map[string]any{"dbage": maxVulnsDBAgeH + 1, "summary": okSummary})},
		{"bad image (tag only)", mkVulnsDoc(VulnsOK, map[string]any{"image": "nginx:1.27", "summary": okSummary})},
		{"bad image (short digest)", mkVulnsDoc(VulnsOK, map[string]any{"image": "nginx@sha256:abc", "summary": okSummary})},
		{"bad platform", mkVulnsDoc(VulnsOK, map[string]any{"platform": base64.StdEncoding.EncodeToString([]byte("linux amd64")), "summary": okSummary})},
		{"non-utf8 reason", []byte(`{"format":"image-vulns-v1","phase":"precheck","reason":"\xff\xfe"}`)},
		{"not json", []byte(`{"format":"image-vulns-v1",`)},
		{"summary oversized", mkVulnsDoc(VulnsOK, map[string]any{"summary": base64.StdEncoding.EncodeToString(make([]byte, maxVulnsSummary+1))})},
	}
	for _, tc := range cases {
		if tc.name == "duplicate top id kept once" {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseImageVulns(tc.doc); !errors.Is(err, ErrImageVulnsFormat) {
				t.Fatalf("err = %v, want ErrImageVulnsFormat", err)
			}
		})
	}
}

func topTooLongSummary(n int) string {
	top := ""
	for i := 0; i < n; i++ {
		if i > 0 {
			top += ","
		}
		top += `{"id":"CVE-2024-000` + itoa(i) + `","severity":"CRITICAL","fixed":""}`
	}
	return `{"severity":{"CRITICAL":` + itoa(n) + `,"HIGH":0,"MEDIUM":0,"LOW":0,"UNKNOWN":0},"total":` + itoa(n) + `,"targets":1,"top":[` + top + `]}`
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}

func TestParseImageVulnsDuplicateTopIDKeptOnce(t *testing.T) {
	doc := mkVulnsDoc(VulnsOK, map[string]any{
		"summary": base64.StdEncoding.EncodeToString([]byte(`{"severity":{"CRITICAL":2,"HIGH":0,"MEDIUM":0,"LOW":0,"UNKNOWN":0},"total":2,"targets":1,"top":[{"id":"CVE-2024-28085","severity":"CRITICAL","fixed":"a"},{"id":"CVE-2024-28085","severity":"CRITICAL","fixed":"b"},{"id":"CVE-2023-45290","severity":"CRITICAL","fixed":"c"}]}`)),
	})
	v, err := ParseImageVulns(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Top) != 2 || v.Top[0].ID != "CVE-2024-28085" || v.Top[0].Fixed != "a" || v.Top[1].ID != "CVE-2023-45290" {
		t.Fatalf("top = %+v", v.Top)
	}
}

func TestParseImageVulnsCachedFlag(t *testing.T) {
	doc := mkVulnsDoc(VulnsOK, map[string]any{
		"cached":  true,
		"summary": base64.StdEncoding.EncodeToString([]byte(`{"severity":{"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"UNKNOWN":0},"total":0,"targets":1,"top":[]}`)),
	})
	v, err := ParseImageVulns(doc)
	if err != nil {
		t.Fatal(err)
	}
	if !v.Cached || v.Total != 0 || len(v.Top) != 0 {
		t.Fatalf("cached=%v total=%d top=%d", v.Cached, v.Total, len(v.Top))
	}
}
