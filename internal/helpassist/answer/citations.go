// SPDX-License-Identifier: AGPL-3.0-or-later

package answer

// MapCitations keeps the citations of an answer that were in its prompt
// (ADR 0014 D2). valid lists them in the order of the answer, without
// duplicates. The model never writes a URL or a path: NOS renders the links
// from its own index for each valid ID.
//
// supported is false when the answer cites an ID that was not in the prompt,
// or when an in-scope answer keeps no valid ID. The caller then shows "no
// documentation section supports this answer" and marks every command. An
// out-of-scope answer without citations is supported, because it shows the
// fixed text of NOS.
func MapCitations(a Answer, prompted []string) (valid []string, supported bool) {
	known := make(map[string]bool, len(prompted))
	for _, id := range prompted {
		known[id] = true
	}
	seen := make(map[string]bool, len(a.Citations))
	unknown := false
	for _, c := range a.Citations {
		if !known[c] {
			unknown = true
			continue
		}
		if seen[c] {
			continue
		}
		seen[c] = true
		valid = append(valid, c)
	}
	supported = !unknown && (len(valid) > 0 || !a.InScope)
	return valid, supported
}
