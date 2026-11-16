// SPDX-License-Identifier: AGPL-3.0-or-later

package fimsshd

import (
	"fmt"

	"github.com/nebula-operation-station/nebula-operation-station/internal/fimbaseline"
)

// Set is the derived SSH login set of one configuration (ADR 0015 D7 (d)). It
// satisfies fimbaseline.SSHSet. A nil Set matches nothing.
type Set struct {
	entries []entry
}

var _ fimbaseline.SSHSet = (*Set)(nil)

// Match classifies an absolute path against the set. A path that a value
// names is SSHFile; a directory on or above such a path is SSHPosition; any
// other path, including a relative one, is SSHNone.
func (s *Set) Match(path []byte) fimbaseline.SSHMatch {
	if s == nil || len(path) == 0 || path[0] != '/' {
		return fimbaseline.SSHNone
	}
	comps, err := splitRecordPath(string(path[1:]))
	if err != nil {
		// Record paths are canonical (fimscan validates them). A
		// non-canonical path is not understood: fail closed as a file.
		return fimbaseline.SSHFile
	}
	position := false
	for _, e := range s.entries {
		full, ext := e.run(comps)
		if full {
			return fimbaseline.SSHFile
		}
		position = position || ext
	}
	if position {
		return fimbaseline.SSHPosition
	}
	return fimbaseline.SSHNone
}

// String reports the number of values. It never contains configuration or
// path content.
func (s *Set) String() string {
	if s == nil {
		return "fimsshd.Set{nil}"
	}
	return fmt.Sprintf("fimsshd.Set{values: %d}", len(s.entries))
}
