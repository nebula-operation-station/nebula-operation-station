// SPDX-License-Identifier: AGPL-3.0-or-later

package bootstrap

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/modulelock"
	"github.com/nebula-operation-station/nebula-operation-station/internal/prelude"

	"gopkg.in/yaml.v3"
)

// authorModule is the shape of module.yaml, the author's input file.
// Pack turns it into the canonical first-party lock.
type authorModule struct {
	Name        string                  `yaml:"name"`
	Version     string                  `yaml:"version"`
	Title       string                  `yaml:"title"`
	Description string                  `yaml:"description"`
	Actions     map[string]authorAction `yaml:"actions"`
}

type authorAction struct {
	Title       string          `yaml:"title"`
	Description string          `yaml:"description"`
	Script      string          `yaml:"script"`
	Risk        string          `yaml:"risk"`
	Durable     bool            `yaml:"durable"`
	Timeout     string          `yaml:"timeout"`
	Params      []prelude.Param `yaml:"params"`
	Secrets     []string        `yaml:"secrets"`
	Declares    []string        `yaml:"declares"`
}

// Pack reads dir/module.yaml, hashes the scripts it references, and
// returns the canonical first-party lock bytes that dir/module.lock.json
// must hold. The result is validated with modulelock.ParseFirstParty
// before it is returned, so a generated lock is always one the executor
// accepts. Regenerate a lock with
//
//	go run ./internal/modules/bootstrap/cmd/packlock <module-dir>
//
// and commit the output as module.lock.json.
func Pack(dir string) ([]byte, error) {
	raw, err := os.ReadFile(filepath.Join(dir, AuthorFile))
	if err != nil {
		return nil, fmt.Errorf("bootstrap: read %s: %w", AuthorFile, err)
	}
	var am authorModule
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&am); err != nil {
		return nil, fmt.Errorf("bootstrap: %s: %w", AuthorFile, err)
	}
	if len(am.Actions) == 0 {
		return nil, fmt.Errorf("bootstrap: %s: the module needs at least one action", AuthorFile)
	}
	l := modulelock.Lock{
		Format:      modulelock.Format,
		Name:        am.Name,
		Version:     am.Version,
		Title:       am.Title,
		Description: am.Description,
		Actions:     make(map[string]modulelock.Action, len(am.Actions)),
	}
	for name, a := range am.Actions {
		scriptPath := filepath.Join(dir, filepath.FromSlash(a.Script))
		script, err := os.ReadFile(scriptPath)
		if err != nil {
			return nil, fmt.Errorf("bootstrap: action %s: %w", name, err)
		}
		sum := sha256.Sum256(script)
		ta, err := time.ParseDuration(a.Timeout)
		if err != nil || ta < time.Second {
			return nil, fmt.Errorf("bootstrap: action %s: the timeout must be a duration of at least 1s", name)
		}
		l.Actions[name] = modulelock.Action{
			Title:       a.Title,
			Description: a.Description,
			Script:      a.Script,
			SHA256:      hex.EncodeToString(sum[:]),
			Risk:        strings.ToUpper(a.Risk),
			Durable:     a.Durable,
			TimeoutS:    int(ta.Seconds()),
			Params:      a.Params,
			Secrets:     a.Secrets,
			Declares:    a.Declares,
		}
	}
	out, err := json.Marshal(l)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: %w", err)
	}
	canon, _, err := canonical.CanonicalParameters(out)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: %w", err)
	}
	if _, _, err := modulelock.ParseFirstParty(canon); err != nil {
		return nil, fmt.Errorf("bootstrap: the packed lock is not valid: %w", err)
	}
	return canon, nil
}
