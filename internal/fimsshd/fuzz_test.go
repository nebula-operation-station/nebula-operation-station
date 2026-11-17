// SPDX-License-Identifier: AGPL-3.0-or-later

package fimsshd

import (
	"errors"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/fimscan"
)

// FuzzParse feeds arbitrary sshd_config content to Parse and Match. It checks
// that nothing panics, that the value limit holds, and that errors never
// contain the content (ADR 0015 D7 (d); configuration content is never logged).
func FuzzParse(f *testing.F) {
	seeds := []string{
		"",
		"AuthorizedKeysFile .ssh/authorized_keys\n",
		"AuthorizedKeysFile %h/.config/keys /etc/ssh/authorized_keys/%u\n",
		"AuthorizedKeysFile none\n",
		"TrustedUserCAKeys etc/ssh/ca.pub\nRevokedKeys ~/revoked\n",
		"AuthorizedKeysCommand /usr/sbin/keys %u\nAuthorizedPrincipalsCommand none\n",
		"Include sshd_config.d/*.conf\nMatch User bob\n  authorizedkeysfile /srv/%u\n",
		"AuthorizedKeysFile=.ssh/x\n",
		"AuthorizedKeysFile \"x\"\n",
		"Include /etc/ssh/[\n",
		"AuthorizedKeysFile %",
		"RevokedKeys ~bob/x\n",
		"AuthorizedKeysCommand bin/x\n",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	paths := []string{
		"/", "/root/.ssh/authorized_keys", "/etc/ssh/sshd_config.d/a.conf",
		"/home/alice/.config/keys", "/etc/ssh/authorized_keys/x", "/etc//x", "relative",
	}
	f.Fuzz(func(t *testing.T, content []byte) {
		files := []fimscan.SSHConfigFile{{Path: []byte("/etc/ssh/sshd_config"), Content: content}}
		d, err := Parse(files)
		if err != nil {
			if !errors.Is(err, ErrUnclassifiable) && !errors.Is(err, ErrOverflow) {
				t.Fatalf("Parse: unexpected error kind: %v", err)
			}
			// The message is exactly the file, the line and the sentinel:
			// "sshd config <quoted path> line <n>: <sentinel>". Anything else
			// could carry configuration content.
			msg := err.Error()
			prefix := `sshd config "/etc/ssh/sshd_config" line `
			if strings.HasPrefix(msg, prefix) {
				rest := strings.TrimPrefix(msg, prefix)
				num, sentinel, ok := strings.Cut(rest, ": ")
				if ok && num != "" && strings.Trim(num, "0123456789") == "" && (sentinel == ErrUnclassifiable.Error() || sentinel == ErrOverflow.Error()) {
					return
				}
			}
			if msg != ErrOverflow.Error() && msg != ErrUnclassifiable.Error() {
				t.Fatalf("error has unexpected form (possible content leak): %q", msg)
			}
			return
		}
		if d.Count() > MaxDerivedValues {
			t.Fatalf("Count = %d, above limit %d", d.Count(), MaxDerivedValues)
		}
		s := d.Set()
		for _, p := range paths {
			s.Match([]byte(p))
		}
		_ = s.String()
	})
}
