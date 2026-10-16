// SPDX-License-Identifier: AGPL-3.0-or-later

package dockerhost

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"
)

// ImageUpdate is one image of a docker.check_updates result.
type ImageUpdate struct {
	Image string
	// Status is current, update, pinned or unknown.
	Status string
	// Remote is the registry's digest for the tag (current, update).
	Remote string
	Note   string
}

// ImageUpdates is a parsed docker.check_updates result.
type ImageUpdates struct {
	Phase   string
	Reason  string
	Images  []ImageUpdate
	Updates int
}

// ErrUpdatesFormat means the result is not a docker.check_updates result.
var ErrUpdatesFormat = errors.New("dockerhost: not a docker.check_updates result")

var (
	imageRefRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,299}$`)
	digestOnlyRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	updateStates = map[string]bool{"current": true, "update": true, "pinned": true, "unknown": true}
)

const maxImages = 50

// ParseImageUpdates reads a docker.check_updates result. Lines that do not
// fit are left out.
func ParseImageUpdates(result []byte) (ImageUpdates, error) {
	var doc struct {
		Format string `json:"format"`
		Phase  string `json:"phase"`
		Reason string `json:"reason"`
		Lines  string `json:"lines"`
	}
	if json.Unmarshal(result, &doc) != nil || doc.Format != "docker-updates-v1" || (doc.Phase != "done" && doc.Phase != "precheck") {
		return ImageUpdates{}, ErrUpdatesFormat
	}
	u := ImageUpdates{Phase: doc.Phase}
	if doc.Phase == "precheck" {
		u.Reason = text(doc.Reason, 300)
		return u, nil
	}
	t, ok := decode(doc.Lines)
	if !ok {
		return ImageUpdates{}, ErrUpdatesFormat
	}
	for _, line := range strings.Split(t, "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 4 || len(u.Images) >= maxImages || !imageRefRe.MatchString(f[0]) || !updateStates[f[1]] {
			continue
		}
		x := ImageUpdate{Image: f[0], Status: f[1], Note: text(f[3], 200)}
		if digestOnlyRe.MatchString(f[2]) {
			x.Remote = f[2]
		} else if f[1] == "current" || f[1] == "update" {
			x.Status, x.Note = "unknown", "no valid digest"
		}
		if x.Status == "update" {
			u.Updates++
		}
		u.Images = append(u.Images, x)
	}
	return u, nil
}
