// SPDX-License-Identifier: AGPL-3.0-or-later

package helpdocs

import (
	"strings"
	"testing"
)

// FuzzBuild feeds arbitrary bytes to Build. Build must never panic;
// when it succeeds, the index must satisfy checkInvariants.
func FuzzBuild(f *testing.F) {
	for _, seed := range []string{
		"",
		"# T\n",
		"# T\n\n## A\n\nx\n\n### B\n\n```sh\nnebula x\n```\n",
		"## !!!\n",
		"```\n## inside\n",
		"~~~~\n```\n~~~~\n## after\n",
		"# T\n\n## A\n\n\n\n## A\n",
		"\x00\r\n\t## tab\r\n",
		"````````````````````````````````\n## after\n```` \n## closed\n",
		"```" + strings.Repeat("`", 4096) + "\n" + strings.Repeat("a\n", 64),
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		ix, err := Build([]Source{{Slug: "fz", File: "fz.md", Data: data}})
		if err != nil {
			return
		}
		checkInvariants(t, ix)
	})
}
