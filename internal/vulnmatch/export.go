// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnmatch

import (
	"fmt"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnagent/nosclient"
)

// SubjectsFromExport merges the subject parts of a vuln-inventory-v1
// export (D3), in page order, into matcher subjects. A subject's parts
// must arrive in order, starting at part 0, and end with its last part;
// otherwise the export is incomplete and nothing is returned, since a
// subject without all parts is not covered.
func SubjectsFromExport(parts []nosclient.SubjectPart) ([]Subject, error) {
	var out []Subject
	open := map[string]int{} // subject key → index in out, while parts are pending
	next := map[string]int{}
	done := map[string]bool{}
	for _, p := range parts {
		key := string(p.Kind) + "\x00" + p.Ref.ID + "\x00" + p.Ref.ImageDigest
		if done[key] || p.Part != next[key] {
			return nil, fmt.Errorf("export subject part %d: %w", p.Part, ErrIncompleteSubject)
		}
		idx, ok := open[key]
		if !ok {
			if len(out) >= MaxSubjects {
				return nil, fmt.Errorf("export subjects: %w", ErrLimit)
			}
			s := Subject{Kind: p.Kind, Ref: p.Ref, Ecosystem: p.Ecosystem}
			if p.Kernel != nil {
				s.Kernel = &Kernel{Release: p.Kernel.Release, Mapped: p.Kernel.Mapped,
					SourcePackage: p.Kernel.SourcePackage, SourceVersion: p.Kernel.SourceVersion}
			}
			out = append(out, s)
			idx = len(out) - 1
			open[key] = idx
		}
		for _, c := range p.Components {
			mc := Component{SourcePackage: c.SourcePackage, SourceVersion: c.SourceVersion}
			for _, b := range c.Binaries {
				mc.Binaries = append(mc.Binaries, Binary{Name: b.Name, Version: b.Version})
			}
			out[idx].Components = append(out[idx].Components, mc)
		}
		next[key]++
		if p.LastPart {
			done[key] = true
			delete(open, key)
		}
	}
	if len(open) != 0 {
		return nil, fmt.Errorf("export ended with %d subjects without last part: %w", len(open), ErrIncompleteSubject)
	}
	return out, nil
}
