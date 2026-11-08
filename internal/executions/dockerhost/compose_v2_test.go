// SPDX-License-Identifier: AGPL-3.0-or-later

package dockerhost

import (
	"encoding/json"
	"strings"
	"testing"
)

func v2Entry(id, svc, replica, health string, ports ...string) map[string]any {
	if ports == nil {
		ports = []string{}
	}
	return map[string]any{
		"id": strings.Repeat(id, 64), "name": "site-" + svc + "-" + replica, "service": svc, "replica": replica,
		"state": "running", "started_at": "2026-11-08T01:00:00Z", "health": health, "ports": ports,
		"mounts":   []any{map[string]any{"type": "volume", "source": "/var/lib/docker/volumes/d", "destination": "/data", "mode": "z", "rw": true}},
		"networks": []string{"site_default"}, "image_id": "sha256:" + strings.Repeat("a", 64),
		"running_reference": "nginx:1.27", "configuration_digest": strings.Repeat("c", 64),
	}
}

func v2Result(t *testing.T, doc map[string]any) []byte {
	t.Helper()
	doc["format"] = "compose-update-v2"
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestComposeUpdateV2StopShownAsPrecheck(t *testing.T) {
	for _, phase := range []string{"precheck", "resolve", "pull", "retain"} {
		c, err := ParseComposeUpdate(v2Result(t, map[string]any{"phase": phase, "reason": "pull_failed", "service": "web", "project": "site"}))
		if err != nil || c.Format != "compose-update-v2" || c.Phase != "precheck" || c.Verdict != "FAILED" ||
			c.Reason != phase+": pull_failed (service web)" || c.Project != "site" {
			t.Errorf("%s: %+v %v", phase, c, err)
		}
	}
	// A reason that is not a typed reason is never shown as is.
	c, err := ParseComposeUpdate(v2Result(t, map[string]any{"phase": "pull", "reason": "SECRET=hunter2 <b>"}))
	if err != nil || strings.Contains(c.Reason, "hunter2") || c.Verdict != "FAILED" {
		t.Fatalf("%+v %v", c, err)
	}
}

func TestComposeUpdateV2Verdicts(t *testing.T) {
	web := func() map[string]any { return v2Entry("1", "web", "1", "healthy", "80/tcp->0.0.0.0:8080") }
	webNew := func() map[string]any { return v2Entry("2", "web", "1", "healthy", "80/tcp->0.0.0.0:8080") }
	db := func() map[string]any { return v2Entry("3", "db", "1", "none") }
	done := func(up int, before, after []any) map[string]any {
		d := map[string]any{"phase": "after_snapshot", "reason": "", "project": "site", "up_exit": up, "baseline": before}
		if after != nil {
			d["after"] = after
		}
		return d
	}
	with := func(e map[string]any, k string, v any) map[string]any { e[k] = v; return e }
	cases := []struct {
		name, verdict, finding string
		doc                    map[string]any
	}{
		{"clean, replica matched by number after its ID changed", "OK", "", done(0, []any{web(), db()}, []any{webNew(), db()})},
		{"up failed", "FAILED", "exited with 1", done(1, []any{web(), db()}, []any{webNew(), db()})},
		{"after-snapshot missing", "FAILED", "uncertain", done(0, []any{web(), db()}, nil)},
		{"baseline missing", "FAILED", "no baseline", done(0, []any{}, []any{webNew()})},
		{"replica fewer", "FAILED", "web replica 1 is missing", done(0, []any{web(), db()}, []any{db()})},
		{"stopped", "FAILED", "ran before", done(0, []any{web(), db()}, []any{with(webNew(), "state", "exited"), db()})},
		{"health regression", "FAILED", "was healthy before", done(0, []any{web(), db()}, []any{with(webNew(), "health", "unhealthy"), db()})},
		{"starting past the wait", "FAILED", "is starting now", done(0, []any{web(), db()}, []any{with(webNew(), "health", "starting"), db()})},
		{"lost port", "FAILED", "published ports", done(0, []any{web(), db()}, []any{with(webNew(), "ports", []string{}), db()})},
		{"changed host port", "FAILED", "published ports", done(0, []any{web(), db()}, []any{with(webNew(), "ports", []string{"80/tcp->0.0.0.0:8081"}), db()})},
		{"lost mount", "FAILED", "mounts", done(0, []any{web(), db()}, []any{with(webNew(), "mounts", []any{}), db()})},
		{"changed network", "FAILED", "networks", done(0, []any{web(), db()}, []any{with(webNew(), "networks", []string{"other"}), db()})},
		{"extra container", "FAILED", "2 containers before, 3 after", done(0, []any{web(), db()}, []any{webNew(), db(), v2Entry("4", "web", "2", "healthy")})},
		{"oversize after entry", "FAILED", "too large", done(0, []any{web(), db()}, []any{map[string]any{"id": strings.Repeat("2", 64), "oversize": true}, db()})},
		{"up timeout reason", "FAILED", "up_timeout", with(done(124, []any{web()}, []any{webNew()}), "reason", "up_timeout")},
	}
	for _, tc := range cases {
		c, err := ParseComposeUpdate(v2Result(t, tc.doc))
		if err != nil || c.Verdict != tc.verdict || c.Project != "site" ||
			(tc.finding != "" && !strings.Contains(strings.Join(c.Findings, "|"), tc.finding)) {
			t.Errorf("%s: %+v %v", tc.name, c, err)
		}
		if !strings.Contains(strings.Join(c.Findings, "|"), "executor's own verdict") {
			t.Errorf("%s: the display does not defer to the executor's verdict: %v", tc.name, c.Findings)
		}
	}
	c, err := ParseComposeUpdate(v2Result(t, done(0, []any{web(), db()}, []any{webNew(), db()})))
	if err != nil || len(c.Before) != 2 || len(c.After) != 2 || c.After[0].Ports != "80/tcp->0.0.0.0:8080" ||
		c.After[0].Image != "nginx:1.27" || c.After[1].Health != "" || c.After[0].Health != "healthy" {
		t.Fatalf("%+v %v", c, err)
	}
}

func TestComposeUpdateV2RejectsMalformed(t *testing.T) {
	many := make([]any, maxComposeV2Containers+1)
	for i := range many {
		many[i] = v2Entry("1", "web", "1", "none")
	}
	for name, raw := range map[string][]byte{
		"unknown phase":   v2Result(t, map[string]any{"phase": "rm"}),
		"too many":        v2Result(t, map[string]any{"phase": "after_snapshot", "up_exit": 0, "baseline": many, "after": []any{}}),
		"trailing data":   append(v2Result(t, map[string]any{"phase": "precheck"}), []byte(`{"x":1}`)...),
		"invalid utf-8":   []byte("{\"format\":\"compose-update-v2\",\"phase\":\"precheck\",\"reason\":\"\xff\"}"),
		"oversize result": append([]byte(`{"format":"compose-update-v2","phase":"precheck","reason":"`), []byte(strings.Repeat("a", maxComposeV2Bytes))...),
	} {
		if c, err := ParseComposeUpdate(raw); err == nil {
			t.Errorf("%s: accepted: %+v", name, c)
		}
	}
	// Unsafe display values are dropped, never shown.
	e := v2Entry("1", "web", "1", "none", "80/tcp‮->x")
	e["running_reference"] = "nginx\x1b[31m"
	c, err := ParseComposeUpdate(v2Result(t, map[string]any{"phase": "after_snapshot", "up_exit": 0, "baseline": []any{e}, "after": []any{e}}))
	if err != nil || len(c.After) != 1 || c.After[0].Ports != "" || c.After[0].Image != "" {
		t.Fatalf("%+v %v", c, err)
	}
}

func TestComposeUpdateV1StillParses(t *testing.T) {
	c, err := ParseComposeUpdate([]byte(`{"format":"compose-update-v1","phase":"precheck","reason":"no compose"}`))
	if err != nil || c.Format != "compose-update-v1" || c.Verdict != "FAILED" {
		t.Fatalf("%+v %v", c, err)
	}
}
