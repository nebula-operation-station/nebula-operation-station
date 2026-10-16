// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"context"
	"errors"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/runbooks"
)

// Runbooks supplies runbook versions (internal/runbooks.Store).
type Runbooks interface {
	Get(ctx context.Context, slug string, version int) (runbooks.Version, error)
	Latest(ctx context.Context) ([]runbooks.Version, error)
}

// SetRunbooks makes runbooks plannable next to the built-in actions. Call
// it before the service starts dispatching.
func (s *Service) SetRunbooks(r Runbooks) { s.runbooks = r }

// Action returns the action id at version ("" for the current built-in or
// the latest runbook version). A runbook version is found by its number,
// so an execution always runs the exact version it was planned with.
func (s *Service) Action(ctx context.Context, id, version string) (actions.Action, bool, error) {
	if slug, n, ok := runbooks.ParseActionVersion(id, version); ok {
		if s.runbooks == nil {
			return actions.Action{}, false, nil
		}
		v, err := s.runbooks.Get(ctx, slug, n)
		if errors.Is(err, runbooks.ErrNotFound) {
			return actions.Action{}, false, nil
		}
		if err != nil {
			return actions.Action{}, false, err
		}
		return v.Action(), true, nil
	}
	a, ok := actions.Lookup(id)
	if !ok || (version != "" && a.Version != version) {
		return actions.Action{}, false, nil
	}
	return a, true, nil
}

// Catalog lists the plannable actions: the built-ins, then the latest
// version of every runbook.
func (s *Service) Catalog(ctx context.Context) ([]actions.Action, error) {
	out := append([]actions.Action(nil), actions.Builtin...)
	if s.runbooks == nil {
		return out, nil
	}
	rb, err := s.runbooks.Latest(ctx)
	if err != nil {
		return out, err
	}
	for _, v := range rb {
		out = append(out, v.Action())
	}
	return out, nil
}
