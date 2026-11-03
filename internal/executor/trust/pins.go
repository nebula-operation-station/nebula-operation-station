// SPDX-License-Identifier: AGPL-3.0-or-later

package trust

import (
	"errors"
	"fmt"
	"sort"
)

// maxPinKey bounds a name@version key accepted by Unpin.
const maxPinKey = 256

// ErrNotPinned is an Unpin of a version that is not retained with a pin.
var ErrNotPinned = errors.New("trust: the version is not pinned")

// Pins returns the durably pinned versions (name@version) in ASCII order.
func (s *Store) Pins() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, m := range s.idx.Modules {
		for _, v := range versions(m) {
			if v.Pinned {
				out = append(out, m.Name+"@"+v.Version)
			}
		}
	}
	sort.Strings(out)
	return out
}

// Unpin clears the durable pin of key (name@version) and commits a new
// generation. It deletes nothing: the version falls back to normal
// retention (two most recent predecessors, 90-day floor) and the next
// admission may collect it. A key that names no pinned version is
// ErrNotPinned; a store changed on disk since it was loaded is ErrStale.
// On any error nothing is changed.
func (s *Store) Unpin(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if key == "" || len(key) > maxPinKey {
		return fmt.Errorf("%w: invalid version key", ErrNotPinned)
	}
	x := s.idx.clone()
	found := false
	for i := range x.Modules {
		m := &x.Modules[i]
		if m.Active != nil && m.Active.Pinned && m.Name+"@"+m.Active.Version == key {
			m.Active.Pinned, found = false, true
		}
		for j := range m.History {
			if m.History[j].Pinned && m.Name+"@"+m.History[j].Version == key {
				m.History[j].Pinned, found = false, true
			}
		}
	}
	if !found {
		return fmt.Errorf("%w: %q", ErrNotPinned, key)
	}
	now := s.clock()
	x.Generation++
	x.ClockHighWater = maxTime(x.ClockHighWater, now)
	if err := x.validate(); err != nil {
		return err
	}
	if err := s.persistNext(x); err != nil {
		return err
	}
	s.idx = x
	return nil
}
