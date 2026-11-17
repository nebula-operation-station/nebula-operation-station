// SPDX-License-Identifier: AGPL-3.0-or-later

package opsfacts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Digest returns "sha256:<hex>" over the canonical JSON of a lab projection
// (ADR 0016 D3). The encoding is deterministic: the projection holds no maps,
// encoding/json writes fields in declaration order, and build has sorted
// every slice. The same input therefore gives the same digest, and any change
// to a listed value gives a new one. A projection above MaxItemBytes is an
// error, so no oversized item is ever sent.
func Digest(p LabProjection) (string, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("encode projection: %w", err)
	}
	if len(b) > MaxItemBytes {
		return "", fmt.Errorf("group %q is %d bytes: %w", p.Group, len(b), ErrItemTooLarge)
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
