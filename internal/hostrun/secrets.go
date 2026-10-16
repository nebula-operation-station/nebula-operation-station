// SPDX-License-Identifier: AGPL-3.0-or-later

package hostrun

import (
	"encoding/base64"
	"errors"
	"regexp"
	"strconv"
	"strings"
)

// Secret is one secret value for a run (spec 06): it travels on the SSH
// channel only and is written on the host to a private file on a tmpfs,
// removed when the script ends. The script gets the directory in
// $NEBULA_SECRETS_DIR and reads <dir>/<slot>.
type Secret struct {
	Slot  string
	Value []byte
}

// Limits.
const (
	MaxSecrets     = 8
	MaxSecretValue = 64 << 10
)

var slotRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

func validSecrets(ss []Secret) error {
	if len(ss) > MaxSecrets {
		return errors.New("hostrun: too many secrets")
	}
	seen := map[string]bool{}
	for _, s := range ss {
		if !slotRe.MatchString(s.Slot) || seen[s.Slot] {
			return errors.New("hostrun: invalid or repeated secret slot")
		}
		if len(s.Value) == 0 || len(s.Value) > MaxSecretValue {
			return errors.New("hostrun: secret value size out of range")
		}
		seen[s.Slot] = true
	}
	return nil
}

// secretLines is the stdin section for secrets: "N\n" and one
// "slot base64\n" per secret; empty without secrets.
func secretLines(ss []Secret) string {
	if len(ss) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(strconv.Itoa(len(ss)) + "\n")
	for _, s := range ss {
		b.WriteString(s.Slot + " " + base64.StdEncoding.EncodeToString(s.Value) + "\n")
	}
	return b.String()
}

// Redact replaces every secret value (of at least 4 bytes) in b. It is an
// extra safeguard for logs and results, not the protection itself.
func Redact(b []byte, ss []Secret) []byte {
	for _, s := range ss {
		if len(s.Value) >= 4 {
			b = []byte(strings.ReplaceAll(string(b), string(s.Value), "[secret "+s.Slot+" redacted]"))
		}
	}
	return b
}
