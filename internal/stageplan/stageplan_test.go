// SPDX-License-Identifier: AGPL-3.0-or-later

package stageplan

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
)

func stage(name string, hosts ...string) Stage {
	return Stage{Name: name, Hosts: hosts, Continue: ContinueManual, TimeoutS: 3600}
}

func encode(t *testing.T, stages ...Stage) []byte {
	t.Helper()
	b, err := Encode(stages)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseAcceptsAPlanCoveringEveryTargetOnce(t *testing.T) {
	raw := encode(t, stage("canary", "web-01"), Stage{Name: "rest", Hosts: []string{"web-02", "web-03"}, MaxFailed: 1, MaxUnreachable: 2, Continue: ContinueAuto, TimeoutS: 600})
	p, err := Parse(raw, []string{"web-03", "web-01", "web-02"})
	if err != nil {
		t.Fatal(err)
	}
	want, _ := canonical.HashParameters(raw)
	if p.Hash != want || len(p.Stages) != 2 || p.Duration() != 4200 || p.AutoContinue() {
		t.Fatalf("%+v", p)
	}
	// auto on a stage that is followed by another one
	p, err = Parse(encode(t, Stage{Name: "a", Hosts: []string{"x"}, Continue: ContinueAuto, TimeoutS: 60}, stage("b", "y")), []string{"x", "y"})
	if err != nil || !p.AutoContinue() {
		t.Fatalf("%+v %v", p, err)
	}
}

func TestParseRefusesPlansThatDoNotFitTheRequest(t *testing.T) {
	targets := []string{"a", "b"}
	many := make([]Stage, MaxStages+1)
	for i := range many {
		many[i] = stage("s"+strings.Repeat("x", i), "a")
	}
	cases := map[string][]byte{
		"host in two stages":   encode(t, stage("one", "a", "b"), stage("two", "b")),
		"host in no stage":     encode(t, stage("one", "a")),
		"host not a target":    encode(t, stage("one", "a", "b", "c")),
		"empty stage":          encode(t, stage("one", "a", "b"), Stage{Name: "two", Hosts: []string{}, Continue: "manual", TimeoutS: 60}),
		"duplicate name":       encode(t, stage("one", "a"), stage("one", "b")),
		"bad name":             encode(t, stage("One", "a", "b")),
		"negative max_failed":  encode(t, Stage{Name: "s", Hosts: targets, MaxFailed: -1, Continue: "manual", TimeoutS: 60}),
		"max_failed too high":  encode(t, Stage{Name: "s", Hosts: targets, MaxFailed: 3, Continue: "manual", TimeoutS: 60}),
		"max_unreachable high": encode(t, Stage{Name: "s", Hosts: targets, MaxUnreachable: 3, Continue: "manual", TimeoutS: 60}),
		"continue":             encode(t, Stage{Name: "s", Hosts: targets, Continue: "later", TimeoutS: 60}),
		"timeout short":        encode(t, Stage{Name: "s", Hosts: targets, Continue: "manual", TimeoutS: 59}),
		"timeout long":         encode(t, Stage{Name: "s", Hosts: targets, Continue: "manual", TimeoutS: MaxTimeout + 1}),
		"no stages":            []byte(`{"plan":"stages-v1","stages":[]}`),
		"too many stages":      encode(t, many...),
		"other format":         []byte(`{"plan":"single-stage-v1"}`),
		"unknown member":       []byte(`{"plan":"stages-v1","stages":[{"name":"s","hosts":["a","b"],"max_failed":0,"max_unreachable":0,"continue":"manual","timeout_s":60,"extra":1}]}`),
		"member left out":      []byte(`{"plan":"stages-v1","stages":[{"name":"s","hosts":["a","b"],"max_unreachable":0,"continue":"manual","timeout_s":60}]}`),
		"member in upper case": []byte(`{"plan":"stages-v1","stages":[{"name":"s","hosts":["a","b"],"max_failed":0,"MAX_FAILED":2,"max_unreachable":0,"continue":"manual","timeout_s":60}]}`),
		"duplicate member":     []byte(`{"plan":"stages-v1","stages":[{"name":"s","hosts":["a","b"],"max_failed":0,"max_failed":2,"max_unreachable":0,"continue":"manual","timeout_s":60}]}`),
		"not a number":         []byte(`{"plan":"stages-v1","stages":[{"name":"s","hosts":["a","b"],"max_failed":1.0,"max_unreachable":0,"continue":"manual","timeout_s":60}]}`),
		"array":                []byte(`[]`),
	}
	for name, raw := range cases {
		if _, err := Parse(raw, targets); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestAutoContinueOnEmptyPlanIsFalse(t *testing.T) {
	cases := map[string]Plan{
		"zero value":        {},
		"one auto stage":    {Stages: []Stage{{Name: "only", Hosts: []string{"a"}, Continue: ContinueAuto, TimeoutS: 60}}},
		"one manual stage":  {Stages: []Stage{{Name: "only", Hosts: []string{"a"}, Continue: ContinueManual, TimeoutS: 60}}},
		"empty non-nil set": {Stages: []Stage{}},
	}
	for name, p := range cases {
		if got := p.AutoContinue(); got {
			t.Errorf("%s: AutoContinue() = true, want false", name)
		}
	}
}

func TestDurationOfEmptyPlanIsZero(t *testing.T) {
	if got := (Plan{}).Duration(); got != 0 {
		t.Fatalf("Duration() of zero Plan = %d, want 0", got)
	}
}

func TestParseBoundariesAreInclusiveAndTrailingBytesRefused(t *testing.T) {
	name := func(n int) string { return strings.Repeat("a", n) }
	atMaxStages := make([]Stage, MaxStages)
	var targets []string
	for i := range atMaxStages {
		host := fmt.Sprintf("h%02d", i)
		atMaxStages[i] = stage(fmt.Sprintf("s%02d", i), host)
		targets = append(targets, host)
	}
	validStage := func(n string, timeout int) Stage {
		return Stage{Name: n, Hosts: []string{"a"}, Continue: ContinueManual, TimeoutS: timeout}
	}
	cases := []struct {
		name    string
		raw     []byte
		targets []string
		ok      bool
	}{
		{"exactly MaxStages stages accepted", encode(t, atMaxStages...), targets, true},
		{"timeout_s equal MinTimeout accepted", encode(t, validStage("s", MinTimeout)), []string{"a"}, true},
		{"timeout_s equal MaxTimeout accepted", encode(t, validStage("s", MaxTimeout)), []string{"a"}, true},
		{"name of 32 characters accepted", encode(t, validStage(name(32), 60)), []string{"a"}, true},
		{"name of 33 characters refused", encode(t, validStage(name(33), 60)), []string{"a"}, false},
		{"trailing bytes after the document refused", append(encode(t, validStage("s", 60)), []byte(" x")...), []string{"a"}, false},
		{"second document after the first refused", append(encode(t, validStage("s", 60)), encode(t, validStage("s", 60))...), []string{"a"}, false},
	}
	for _, c := range cases {
		_, err := Parse(c.raw, c.targets)
		if c.ok && err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
		if !c.ok && !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", c.name, err)
		}
	}
}

func TestSingleStageHashIsTheLegacyPlan(t *testing.T) {
	want, _ := canonical.HashParameters([]byte(`{"plan":"single-stage-v1"}`))
	if SingleStageHash != want || len(SingleStageHash) != 64 {
		t.Fatal(SingleStageHash)
	}
}
