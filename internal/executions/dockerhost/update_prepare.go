// SPDX-License-Identifier: AGPL-3.0-or-later

package dockerhost

import (
	"bytes"
	"errors"
	"fmt"
	"unicode/utf8"
)

// docker-update-prepare-v1 is the result of docker.update_prepare 1.0.0
// (container update plan cu02, Q5): whether this run created the host's
// salt or found one, or why it could not. It never carries the salt; a
// result with any other member, or any other value, is refused.

// MaxPrepareResultBytes bounds a docker-update-prepare-v1 result. The
// longest valid result is well under it.
const MaxPrepareResultBytes = 256

// ErrPrepareFormat: the bytes are not a docker-update-prepare-v1 result.
var ErrPrepareFormat = errors.New("dockerhost: not a docker-update-prepare-v1 result")

// Prepare statuses.
const (
	// PrepareCreated: this run created the salt.
	PrepareCreated = "created"
	// PreparePresent: a usable salt existed and was left as it is.
	PreparePresent = "present"
)

// prepareStatuses are every status the script reports; created and present
// mean the host is prepared, every other one is a failure.
var prepareStatuses = map[string]bool{
	PrepareCreated: true, PreparePresent: true, "not_root": true, "tooling_missing": true, "params_invalid": true,
	"state_unsafe": true, "salt_unsafe": true, "write_failed": true, "internal_error": true,
}

// UpdatePrepare is a parsed docker-update-prepare-v1 result.
type UpdatePrepare struct {
	Status string
}

// Prepared reports whether the host has a usable salt after the run.
func (p UpdatePrepare) Prepared() bool {
	return p.Status == PrepareCreated || p.Status == PreparePresent
}

// PrepareRequired reports whether the preview found no salt on the host:
// the host is not prepared, so it has no digests and every unit is
// unavailable until docker.update_prepare has run there.
func (p UpdatePreview) PrepareRequired() bool { return p.Status == PreviewPrepareRequired }

type prepareDoc struct {
	Format *string `json:"format"`
	Status *string `json:"status"`
}

// ParseUpdatePrepare parses a docker-update-prepare-v1 result: one JSON
// object with exactly the members format and status, a known status, and
// at most a trailing newline.
func ParseUpdatePrepare(result []byte) (UpdatePrepare, error) {
	if len(result) == 0 || len(result) > MaxPrepareResultBytes || !utf8.Valid(result) {
		return UpdatePrepare{}, fmt.Errorf("%w: size or encoding", ErrPrepareFormat)
	}
	body := bytes.TrimSuffix(result, []byte("\n"))
	if bytes.ContainsAny(body, "\n\r") {
		return UpdatePrepare{}, fmt.Errorf("%w: more than one line", ErrPrepareFormat)
	}
	var d prepareDoc
	if err := strictDecode(body, &d); err != nil {
		return UpdatePrepare{}, fmt.Errorf("%w: %v", ErrPrepareFormat, err)
	}
	if d.Format == nil || *d.Format != "docker-update-prepare-v1" {
		return UpdatePrepare{}, fmt.Errorf("%w: format", ErrPrepareFormat)
	}
	if d.Status == nil || !prepareStatuses[*d.Status] {
		return UpdatePrepare{}, fmt.Errorf("%w: status", ErrPrepareFormat)
	}
	return UpdatePrepare{Status: *d.Status}, nil
}
