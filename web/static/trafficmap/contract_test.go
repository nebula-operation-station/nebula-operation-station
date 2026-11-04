// SPDX-License-Identifier: AGPL-3.0-or-later

// Package trafficmap_test checks the traffic map renderer's JSON contract and
// the security properties of its JavaScript sources (ADR 0009 D4, TM18). The
// behavioural tests of the modules themselves are *.test.mjs files for the
// node test runner; TestJavaScriptBehaviour runs them as part of go test.
package trafficmap_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Contract limits; they must equal LIMITS in model.js.
const (
	maxZones       = 256
	maxNodes       = 4000
	maxLinks       = 20000
	maxIDLength    = 128
	maxLabelLength = 128
	maxSoftware    = 32
)

type zone struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Color string `json:"color"`
}

type resources struct {
	VCPU   *int64 `json:"vcpu,omitempty"`
	RAMMiB *int64 `json:"ramMiB,omitempty"`
	GPUs   *int64 `json:"gpus,omitempty"`
}

type health struct {
	Patches         *string `json:"patches,omitempty"`
	General         *string `json:"general,omitempty"`
	Disk            *string `json:"disk,omitempty"`
	Load            *string `json:"load,omitempty"`
	Unreachable     *bool   `json:"unreachable,omitempty"`
	HostKeyMismatch *bool   `json:"hostKeyMismatch,omitempty"`
}

type software struct {
	Key      string     `json:"key"`
	Count    int64      `json:"count"`
	Children []software `json:"children,omitempty"`
}

type node struct {
	ID        string     `json:"id"`
	Label     string     `json:"label"`
	Kind      string     `json:"kind"`
	Zone      *string    `json:"zone"`
	Resources *resources `json:"resources,omitempty"`
	OS        *string    `json:"os,omitempty"`
	Host      *string    `json:"host,omitempty"`
	Health    *health    `json:"health,omitempty"`
	Software  []software `json:"software,omitempty"`
}

type link struct {
	A       string  `json:"a"`
	B       string  `json:"b"`
	BytesAB int64   `json:"bytesAB"`
	BytesBA int64   `json:"bytesBA"`
	Proto   *string `json:"proto,omitempty"`
	Port    *int    `json:"port,omitempty"`
	Count   *int64  `json:"count,omitempty"`
	Via     *string `json:"via,omitempty"`
}

type model struct {
	Type      string `json:"type"`
	Version   int    `json:"version"`
	Window    string `json:"window"`
	Truncated bool   `json:"truncated"`
	Zones     []zone `json:"zones"`
	Nodes     []node `json:"nodes"`
	Links     []link `json:"links"`
}

var (
	idRE    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)
	keyRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	colorRE = regexp.MustCompile(`^#[0-9a-f]{6}$`)
)

func readFile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return b
}

func TestModelFixtureMatchesContract(t *testing.T) {
	dec := json.NewDecoder(bytes.NewReader(readFile(t, "testdata/model-valid.json")))
	dec.DisallowUnknownFields()
	var m model
	if err := dec.Decode(&m); err != nil {
		t.Fatalf("strict decode of fixture: %v", err)
	}
	if m.Type != "nos.trafficmap.model" || m.Version != 1 {
		t.Fatalf("type/version = %q/%d", m.Type, m.Version)
	}
	if len(m.Zones) > maxZones || len(m.Nodes) > maxNodes || len(m.Links) > maxLinks {
		t.Fatal("fixture exceeds limits")
	}
	zones := map[string]bool{}
	for _, z := range m.Zones {
		if !idRE.MatchString(z.ID) || len(z.ID) > maxIDLength || zones[z.ID] {
			t.Errorf("zone id %q invalid or duplicate", z.ID)
		}
		if !colorRE.MatchString(z.Color) {
			t.Errorf("zone %s color %q", z.ID, z.Color)
		}
		zones[z.ID] = true
	}
	nodes := map[string]bool{}
	routers := 0
	for _, n := range m.Nodes {
		if !idRE.MatchString(n.ID) || nodes[n.ID] {
			t.Errorf("node id %q invalid or duplicate", n.ID)
		}
		nodes[n.ID] = true
		if n.Label == "" || len(n.Label) > maxLabelLength {
			t.Errorf("node %s label length", n.ID)
		}
		if n.Kind == "router" {
			routers++
			if n.Zone != nil {
				t.Errorf("router %s has a zone", n.ID)
			}
		} else if n.Zone == nil || !zones[*n.Zone] {
			t.Errorf("node %s references no known zone", n.ID)
		}
		if n.OS != nil && !keyRE.MatchString(*n.OS) {
			t.Errorf("node %s os key %q", n.ID, *n.OS)
		}
		if len(n.Software) > maxSoftware {
			t.Errorf("node %s has too many software entries", n.ID)
		}
	}
	if routers > 1 {
		t.Errorf("fixture has %d routers", routers)
	}
	for i, l := range m.Links {
		if !nodes[l.A] || !nodes[l.B] || l.A == l.B {
			t.Errorf("link %d endpoints invalid", i)
		}
		if l.Via != nil && !nodes[*l.Via] {
			t.Errorf("link %d via unknown node", i)
		}
	}
}

// TestGoLimitsMatchJavaScript keeps the documented contract and LIMITS in
// model.js in sync, so the map API (TM15) can rely on these constants.
func TestGoLimitsMatchJavaScript(t *testing.T) {
	src := string(readFile(t, "model.js"))
	block := regexp.MustCompile(`(?s)export const LIMITS = Object\.freeze\(\{(.*?)\}\);`).FindStringSubmatch(src)
	if block == nil {
		t.Fatal("LIMITS block not found in model.js")
	}
	want := map[string]int{
		"zones":           maxZones,
		"nodes":           maxNodes,
		"links":           maxLinks,
		"idLength":        maxIDLength,
		"labelLength":     maxLabelLength,
		"softwarePerNode": maxSoftware,
	}
	for k, v := range want {
		m := regexp.MustCompile(`\b` + k + `: (\d+),`).FindStringSubmatch(block[1])
		if m == nil {
			t.Errorf("LIMITS.%s not found", k)
			continue
		}
		got, err := strconv.Atoi(m[1])
		if err != nil || got != v {
			t.Errorf("LIMITS.%s = %s, Go contract says %d", k, m[1], v)
		}
	}
}

func sources(t *testing.T) map[string]string {
	t.Helper()
	files, err := filepath.Glob("*.js")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no renderer sources found")
	}
	out := map[string]string{}
	for _, f := range files {
		out[f] = string(readFile(t, f))
	}
	return out
}

// stripComments removes // and /* */ comments so the forbidden-API scan
// looks at code only. String literals containing "//" are not used in the
// renderer sources; the scan errs on the side of reporting.
func stripComments(src string) string {
	src = regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(src, "")
	return regexp.MustCompile(`(?m)(^|[^:"'])//.*$`).ReplaceAllString(src, "$1")
}

func TestRendererSourcesUseNoNetworkOrHTMLSinks(t *testing.T) {
	forbidden := []string{
		`\bfetch\s*\(`, `XMLHttpRequest`, `WebSocket`, `EventSource`, `sendBeacon`,
		`importScripts`, `\bimport\s*\(`, `new\s+Worker`, `SharedWorker`, `RTCPeerConnection`,
		`innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document\.write`, `createContextualFragment`,
		`DOMParser`, `\beval\s*\(`, `new\s+Function`, `setTimeout\s*\(\s*["'\x60]`,
		`\.src\s*=`, `\.href\s*=`, `setAttribute\s*\(\s*["'](src|href|on)`, `https?://`,
		`localStorage`, `sessionStorage`, `indexedDB`, `document\.cookie`,
		`postMessage\([^)]*["']\*["']`,
	}
	for name, src := range sources(t) {
		code := stripComments(src)
		for _, pat := range forbidden {
			if loc := regexp.MustCompile(pat).FindStringIndex(code); loc != nil {
				t.Errorf("%s uses forbidden API %q", name, code[loc[0]:loc[1]])
			}
		}
	}
}

func TestRendererSourcesImportOnlySiblingModules(t *testing.T) {
	importRE := regexp.MustCompile(`(?m)^\s*import\b[^;]*?from\s+["']([^"']+)["']`)
	for name, src := range sources(t) {
		for _, m := range importRE.FindAllStringSubmatch(src, -1) {
			if !regexp.MustCompile(`^\./[a-z0-9-]+\.js$`).MatchString(m[1]) {
				t.Errorf("%s imports %q; only sibling modules are allowed", name, m[1])
			}
		}
	}
}

func TestRendererSourcesHaveLicenseHeader(t *testing.T) {
	for name, src := range sources(t) {
		if !strings.HasPrefix(src, "// SPDX-License-Identifier: AGPL-3.0-or-later\n") {
			t.Errorf("%s lacks the SPDX header on its first line", name)
		}
	}
}
