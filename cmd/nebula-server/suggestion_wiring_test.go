// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/opsnotes"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// stepStore is a suggestion store that never finds a step; the wiring test
// only needs the store value, not its answers.
type stepStore struct{}

func (stepStore) Step(context.Context, int64, int) (opsnotes.Step, bool, error) {
	return opsnotes.Step{}, false, nil
}

// TestServerUIOpensOperationSuggestions fails while the server leaves
// ui.Options.OperationSuggestions unset: every "Open form" link from an
// agent suggestion would then answer 404 in production (ADR 0016 D8).
func TestServerUIOpensOperationSuggestions(t *testing.T) {
	store := stepStore{}
	admin := true
	o := withOperationSuggestions(ui.Options{PublicOrigin: "https://nebula.example.org"}, store,
		func(context.Context) bool { return admin })
	if o.OperationSuggestions == nil {
		t.Fatal("OperationSuggestions is nil: suggestion forms would be refused in production")
	}
	if o.OperationSuggestions.Store != store {
		t.Fatalf("Store = %#v, want the notes store", o.OperationSuggestions.Store)
	}
	if ok, err := o.OperationSuggestions.IsAdmin(context.Background(), "alice"); err != nil || !ok {
		t.Fatalf("IsAdmin for an admin = %v, %v; want true, nil", ok, err)
	}
	admin = false
	if ok, err := o.OperationSuggestions.IsAdmin(context.Background(), "alice"); err != nil || ok {
		t.Fatalf("IsAdmin for a non-admin = %v, %v; want false, nil", ok, err)
	}
	if _, err := ui.New(o); err != nil {
		t.Fatalf("ui.New with the server's suggestion options: %v", err)
	}
}
