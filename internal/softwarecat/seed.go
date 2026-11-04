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

// ErrSeed is non-nil when the embedded seed map failed to load or
// validation. That can only happen with a broken build; in that case
// every normalizer degrades to reporting unknown identifiers.
var ErrSeed error

func init() {
	var raw map[string]struct {
		Key     string `yaml:"key"`
		Display string `yaml:"display"`
	}
	if err := yaml.Unmarshal(seedYAML, &raw); err != nil {
		ErrSeed = fmt.Errorf("softwarecat: embedded seed map: %w", err)
		return
	}
	seed = make(map[string]seedEntry, len(raw))
	for id, e := range raw {
		if _, err := NewKey(id); err != nil {
			ErrSeed = fmt.Errorf("softwarecat: seed identifier: %w", err)
			return
		}
		k, err := NewKey(e.Key)
		if err != nil {
			ErrSeed = fmt.Errorf("softwarecat: seed entry %q: %w", id, err)
			return
		}
		if e.Display == "" {
			ErrSeed = fmt.Errorf("softwarecat: seed entry %q: empty display name", id)
			return
		}
		seed[id] = seedEntry{key: string(k), display: e.Display}
	}
}
