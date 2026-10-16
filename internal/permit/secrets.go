// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
)

// SecretsKey is the reserved member of the parameters document that maps a
// run's secret slots to vault secret IDs (M7-3): {"nebula_secrets":
// {"influx_token":"telegraf-influx"}}. The mapping is part of the
// canonical parameters, so it is hashed into the approval; the executor
// alone resolves the IDs and sends the values to the host (spec 06).
const SecretsKey = "nebula_secrets"

// MaxSecretRefs bounds the slots of one run.
const MaxSecretRefs = 8

var (
	secretSlotRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	secretIDRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
)

// ErrSecretRefs is a malformed secrets mapping.
var ErrSecretRefs = errors.New("nebula_secrets must map 1 to 8 slot names to vault secret IDs")

// SecretRefs returns the slot -> vault secret ID mapping of a parameters
// document (nil if it has none).
func SecretRefs(parametersJSON []byte) (map[string]string, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(parametersJSON, &doc); err != nil {
		return nil, err
	}
	raw, ok := doc[SecretsKey]
	if !ok {
		return nil, nil
	}
	var refs map[string]string
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&refs); err != nil || len(refs) == 0 || len(refs) > MaxSecretRefs {
		return nil, ErrSecretRefs
	}
	for slot, id := range refs {
		if !secretSlotRe.MatchString(slot) || !secretIDRe.MatchString(id) {
			return nil, ErrSecretRefs
		}
	}
	return refs, nil
}

// secretFloor is the minimum risk of a run that uses secrets (decision 4
// of the M7 plan): never approved by a session click alone. A document
// that cannot be read counts as using secrets.
func secretFloor(parametersJSON []byte) (canonical.Risk, bool) {
	if len(bytes.TrimSpace(parametersJSON)) == 0 {
		return "", false
	}
	refs, err := SecretRefs(parametersJSON)
	if err != nil || len(refs) > 0 {
		return canonical.RiskMedium, true
	}
	return "", false
}
