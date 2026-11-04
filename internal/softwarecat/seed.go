// SPDX-License-Identifier: AGPL-3.0-or-later

package softwarecat

import (
	_ "embed"
	"fmt"

	"gopkg.in/yaml.v3"
)

//go:embed seed.yaml
var seedYAML []byte

// seedEntry is one reviewed seed map entry: a catalog key and a
// display name. Display names only — no icons, no URLs.
type seedEntry struct {
	key     string
	display string
}

// seed maps observed identifiers to seed entries. It is populated in
// init from the embedded, reviewed seed map.
var seed map[string]seedEntry

// seedErr is non-nil when the embedded seed map failed to load or
// validation. That can only happen with a broken build; in that case
// the seed map stays empty and every normalizer degrades to reporting
// unknown identifiers.
var seedErr error

// SeedError reports whether the embedded seed map failed to load or
// validate. Callers should check it once at startup and log a non-nil
// error: normalization still works but reports every identifier as
// unknown.
func SeedError() error {
	return seedErr
}

func init() {
	seed, seedErr = loadSeed(seedYAML)
}

// loadSeed parses and validates a seed map. It is all-or-nothing: on
// any error it returns an empty map, never a partially filled one, so
// mapping does not depend on map iteration order.
func loadSeed(data []byte) (map[string]seedEntry, error) {
	var raw map[string]struct {
		Key     string `yaml:"key"`
		Display string `yaml:"display"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return map[string]seedEntry{}, fmt.Errorf("softwarecat: embedded seed map: %w", err)
	}
	m := make(map[string]seedEntry, len(raw))
	for id, e := range raw {
		if _, err := NewKey(id); err != nil {
			return map[string]seedEntry{}, fmt.Errorf("softwarecat: seed identifier: %w", err)
		}
		k, err := NewKey(e.Key)
		if err != nil {
			return map[string]seedEntry{}, fmt.Errorf("softwarecat: seed entry %q: %w", id, err)
		}
		if e.Display == "" {
			return map[string]seedEntry{}, fmt.Errorf("softwarecat: seed entry %q: empty display name", id)
		}
		m[id] = seedEntry{key: string(k), display: e.Display}
	}
	return m, nil
}
