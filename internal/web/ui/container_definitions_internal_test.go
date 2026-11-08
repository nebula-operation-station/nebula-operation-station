// SPDX-License-Identifier: AGPL-3.0-or-later
package ui

import (
	"reflect"
	"slices"
	"testing"
)

// The view of a definition has metadata fields only, so no template can
// render definition content or a digest of it.
func TestDefinitionViewHoldsMetadataOnly(t *testing.T) {
	var got []string
	for f := range reflect.TypeFor[ctrDefinitionView]().Fields() {
		got = append(got, f.Name)
	}
	if want := []string{"Version", "CreatedBy", "CreatedAt"}; !slices.Equal(got, want) {
		t.Fatalf("ctrDefinitionView fields %v, want %v; a new field must never carry content", got, want)
	}
}
