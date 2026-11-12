// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnmatch

import (
	"fmt"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnagent/nosclient"
)

// deviceFromExport maps a device's export data to the matcher's device. A
// value the export states as "unknown" is left empty, so the matcher reports
// the firmware as a version gap and never as clean.
func deviceFromExport(d *nosclient.Device) *Device {
	out := &Device{Model: d.Model, Firmware: d.FirmwareVersion}
	if out.Model == exportUnknown {
		out.Model = ""
	}
	if out.Firmware == exportUnknown {
		out.Firmware = ""
	}
	return out
}

// exportUnknown is the value the export states for what NOS cannot vouch for.
const exportUnknown = "unknown"

// SubjectsFromExport merges the subject parts of a vuln-inventory-v1
// export (D3), in page order, into matcher subjects. Part numbering is the
// one nosclient validates: a subject's parts are consecutive, start at
// part 1, count up by one and end with its last part. Anything else means
// the export is incomplete and nothing is returned, since a subject
// without all parts is not covered. A subject NOS reports as not complete
// is kept with Subject.Incomplete set, so the matcher reports it as a
// coverage gap.
func SubjectsFromExport(parts []nosclient.SubjectPart) ([]Subject, error) {
	var out []Subject
	seen := map[string]bool{}
	open := -1 // index in out of the subject whose last part is pending
	openKey := ""
	next := 0 // part number expected for the open subject
	for _, p := range parts {
		key := string(p.Kind) + "\x00" + p.Ref.ID + "\x00" + p.Ref.ImageDigest
		switch {
		case open >= 0 && key != openKey:
			return nil, fmt.Errorf("export subject starts before the previous one's last part: %w", ErrIncompleteSubject)
		case open < 0 && seen[key]:
			return nil, fmt.Errorf("export subject appears again after its last part: %w", ErrIncompleteSubject)
		case open < 0:
			if p.Part != 1 {
				return nil, fmt.Errorf("export subject starts with part %d, not 1: %w", p.Part, ErrIncompleteSubject)
			}
			if len(out) >= MaxSubjects {
				return nil, fmt.Errorf("export subjects: %w", ErrLimit)
			}
			s := Subject{Kind: p.Kind, Ref: p.Ref, Ecosystem: p.Ecosystem, Incomplete: !p.Complete}
			if p.Kernel != nil {
				s.Kernel = &Kernel{Release: p.Kernel.Release, Mapped: p.Kernel.Mapped,
					SourcePackage: p.Kernel.SourcePackage, SourceVersion: p.Kernel.SourceVersion}
			}
			if p.Device != nil {
				s.Device = deviceFromExport(p.Device)
			}
			out = append(out, s)
			open, openKey, next = len(out)-1, key, 1
			seen[key] = true
		}
		if p.Part != next {
			return nil, fmt.Errorf("export subject part %d, want %d: %w", p.Part, next, ErrIncompleteSubject)
		}
		if !p.Complete {
			out[open].Incomplete = true
		}
		for _, c := range p.Components {
			mc := Component{SourcePackage: c.SourcePackage, SourceVersion: c.SourceVersion}
			for _, b := range c.Binaries {
				mc.Binaries = append(mc.Binaries, Binary{Name: b.Name, Version: b.Version})
			}
			out[open].Components = append(out[open].Components, mc)
		}
		next++
		if p.LastPart {
			open, openKey = -1, ""
		}
	}
	if open >= 0 {
		return nil, fmt.Errorf("export ended before a subject's last part: %w", ErrIncompleteSubject)
	}
	return out, nil
}
