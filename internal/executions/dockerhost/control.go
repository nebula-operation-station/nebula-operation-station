// SPDX-License-Identifier: AGPL-3.0-or-later

package dockerhost

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// Control is a parsed docker.start/stop/restart result.
type Control struct {
	Phase string // done or precheck
	// Code is the fixed code of a precheck refusal that the server acts on:
	// CodeContainerChanged when the bound container or image no longer
	// matches the approved binding (G5b). Empty for other refusals.
	Code      string
	Reason    string
	Verb      string
	Container string
	Exit      int
	// Before and After are the container's state around the command.
	Before, After string
	// Output is docker's own output (cut, unsafe characters replaced).
	Output []string
}

// ErrControlFormat means the result is not a docker control result.
var ErrControlFormat = errors.New("dockerhost: not a docker.start/stop/restart result")

// CodeContainerChanged is the precheck code of a bound control (G5b) that
// stopped because the container ID or image ID differs from the approved
// binding, or the container is gone. The bound script sends the same string.
const CodeContainerChanged = "container_changed"

// ParseControl reads a docker.start, docker.stop or docker.restart result.
func ParseControl(result []byte) (Control, error) {
	var doc struct {
		Format    string `json:"format"`
		Phase     string `json:"phase"`
		Code      string `json:"code"`
		Reason    string `json:"reason"`
		Verb      string `json:"verb"`
		Container string `json:"container"`
		Exit      int    `json:"exit"`
		Before    string `json:"before"`
		After     string `json:"after"`
		Output    string `json:"output"`
	}
	if json.Unmarshal(result, &doc) != nil || doc.Format != "docker-control-v1" || (doc.Phase != "done" && doc.Phase != "precheck") {
		return Control{}, ErrControlFormat
	}
	c := Control{Phase: doc.Phase}
	if doc.Phase == "precheck" {
		c.Reason = text(doc.Reason, 300)
		if doc.Code == CodeContainerChanged {
			c.Code = doc.Code
		}
		return c, nil
	}
	switch doc.Verb {
	case "start", "stop", "restart":
		c.Verb = doc.Verb
	}
	if containerRe.MatchString(doc.Container) {
		c.Container = doc.Container
	}
	if doc.Exit >= 0 && doc.Exit <= 255 {
		c.Exit = doc.Exit
	}
	state := func(s string) string {
		if v, ok := decode(s); ok && states[strings.TrimSpace(v)] {
			return strings.TrimSpace(v)
		}
		return ""
	}
	c.Before, c.After = state(doc.Before), state(doc.After)
	if raw, err := base64.StdEncoding.DecodeString(doc.Output); err == nil && len(raw) <= 4096 {
		for _, l := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
			if l != "" && len(c.Output) < 20 {
				c.Output = append(c.Output, logLine(l))
			}
		}
	}
	return c, nil
}
