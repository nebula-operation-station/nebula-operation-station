// SPDX-License-Identifier: AGPL-3.0-or-later

package dockerhost

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// ComposeContainer is one container of a Compose project as listed
// before or after an update.
type ComposeContainer struct {
	Service, Name, State, Status, Ports, Image string
	Health                                     string
}

// ComposeUpdate is a parsed docker.compose_update result with the
// server's postflight verdict (spec 11: running containers, health,
// published ports and container count before and after).
type ComposeUpdate struct {
	Phase, Reason, Project string
	PullExit, UpExit       int
	Before, After          []ComposeContainer
	// Verdict is OK, WARNING or FAILED.
	Verdict  string
	Findings []string
}

// ErrComposeFormat means the result is not a docker.compose_update result.
var ErrComposeFormat = errors.New("dockerhost: not a docker.compose_update result")

var composeServiceRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$`)

func parseComposeList(s string) []ComposeContainer {
	t, ok := decode(s)
	if !ok {
		return nil
	}
	var out []ComposeContainer
	for _, line := range strings.Split(t, "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 6 || len(out) >= 200 || !nameRe.MatchString(f[1]) || !states[f[2]] {
			continue
		}
		c := ComposeContainer{Name: f[1], State: f[2], Status: text(f[3], 200), Ports: text(f[4], 1000), Image: text(f[5], 300)}
		if composeServiceRe.MatchString(f[0]) {
			c.Service = f[0]
		}
		c.Health = health(c.Status)
		out = append(out, c)
	}
	return out
}

// ParseComposeUpdate reads a docker.compose_update result and judges it.
func ParseComposeUpdate(result []byte) (ComposeUpdate, error) {
	var doc struct {
		Format   string `json:"format"`
		Phase    string `json:"phase"`
		Reason   string `json:"reason"`
		Project  string `json:"project"`
		PullExit int    `json:"pull_exit"`
		UpExit   int    `json:"up_exit"`
		Before   string `json:"before"`
		After    string `json:"after"`
	}
	if json.Unmarshal(result, &doc) != nil || doc.Format != "compose-update-v1" || (doc.Phase != "done" && doc.Phase != "precheck") {
		return ComposeUpdate{}, ErrComposeFormat
	}
	c := ComposeUpdate{Phase: doc.Phase}
	if doc.Phase == "precheck" {
		c.Reason, c.Verdict = text(doc.Reason, 300), "FAILED"
		return c, nil
	}
	if projectRe.MatchString(doc.Project) {
		c.Project = doc.Project
	}
	c.PullExit, c.UpExit = doc.PullExit, doc.UpExit
	c.Before, c.After = parseComposeList(doc.Before), parseComposeList(doc.After)
	c.judge()
	return c, nil
}

func running(cs []ComposeContainer) int {
	n := 0
	for _, x := range cs {
		if x.State == "running" {
			n++
		}
	}
	return n
}

// judge sets the verdict: FAILED if pull or up failed, fewer containers
// run, or a container that was healthy is not; WARNING if a container is
// unhealthy, a published port is gone, or the number of containers
// changed.
func (c *ComposeUpdate) judge() {
	failed := func(f string, a ...any) { c.Findings = append(c.Findings, "FAILED: "+fmt.Sprintf(f, a...)) }
	warn := func(f string, a ...any) { c.Findings = append(c.Findings, "WARNING: "+fmt.Sprintf(f, a...)) }
	if c.PullExit != 0 {
		failed("docker compose pull exited with %d; nothing was restarted", c.PullExit)
	} else if c.UpExit != 0 {
		failed("docker compose up -d exited with %d", c.UpExit)
	}
	if rb, ra := running(c.Before), running(c.After); ra < rb {
		failed("%d containers ran before, %d after", rb, ra)
	}
	healthyBefore := map[string]bool{}
	portsBefore := map[string]string{}
	for _, x := range c.Before {
		key := x.Service
		if key == "" {
			key = x.Name
		}
		if x.Health == "healthy" {
			healthyBefore[key] = true
		}
		if x.State == "running" && x.Ports != "" {
			portsBefore[key] = x.Ports
		}
	}
	portsAfter := map[string]string{}
	var unhealthy []string
	for _, x := range c.After {
		key := x.Service
		if key == "" {
			key = x.Name
		}
		if x.State == "running" {
			portsAfter[key] = x.Ports
		}
		if x.Health == "unhealthy" || x.Health == "starting" {
			if healthyBefore[key] {
				failed("%s was healthy before and is %s now", x.Name, x.Health)
			} else {
				unhealthy = append(unhealthy, x.Name+" ("+x.Health+")")
			}
		}
	}
	if len(unhealthy) > 0 {
		sort.Strings(unhealthy)
		warn("not healthy after the update: %s", strings.Join(unhealthy, ", "))
	}
	var lost []string
	for k, p := range portsBefore {
		if portsAfter[k] != p {
			lost = append(lost, k)
		}
	}
	if len(lost) > 0 {
		sort.Strings(lost)
		warn("published ports changed or gone: %s", strings.Join(lost, ", "))
	}
	if len(c.Before) != len(c.After) {
		warn("%d containers before, %d after", len(c.Before), len(c.After))
	}
	c.Verdict = "OK"
	for _, f := range c.Findings {
		if strings.HasPrefix(f, "FAILED") {
			c.Verdict = "FAILED"
			return
		}
		c.Verdict = "WARNING"
	}
}
