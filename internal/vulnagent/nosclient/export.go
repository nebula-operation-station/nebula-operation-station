// SPDX-License-Identifier: AGPL-3.0-or-later

package nosclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

// InventoryFormat is the export format this client reads (ADR 0011 D3).
const InventoryFormat = "vuln-inventory-v1"

// Patterns of the export, as the server enforces them.
var (
	snapshotIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:._-]{0,127}$`)
	subjectIDRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	digestRe     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	cursorRe     = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	// deviceVendorRe, deviceModelRe and deviceFirmwareRe mirror the server's
	// device patterns (vuln_export.go): a vendor slug, a model without dot or
	// colon, and a version without colon. deviceUnknown is the server's
	// placeholder for a value it does not export.
	deviceVendorRe   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	deviceModelRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_+-]{0,63}$`)
	deviceFirmwareRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~-]{0,127}$`)
)

// ErrIncompleteExport: the export ended while a subject still lacked its
// last part.
var ErrIncompleteExport = errors.New("export ended before every subject's last part")

// Binary is one installed binary package of a source package.
type Binary struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch,omitempty"`
}

// Component is one installed source package with its binaries.
type Component struct {
	SourcePackage string   `json:"source_package"`
	SourceVersion string   `json:"source_version"`
	Binaries      []Binary `json:"binaries,omitempty"`
}

// Kernel is a host's running kernel and, when it maps, its source package.
type Kernel struct {
	Release       string `json:"release"`
	Mapped        bool   `json:"mapped"`
	SourcePackage string `json:"source_package,omitempty"`
	SourceVersion string `json:"source_version,omitempty"`
}

// deviceUnknown is the placeholder the export states for a device value NOS
// cannot vouch for (ADR 0011 D3).
const deviceUnknown = "unknown"

// Device is a network device's vendor, model and firmware version as the
// export states them (ADR 0011 D3). A value NOS cannot vouch for is the
// string "unknown".
type Device struct {
	Vendor          string `json:"vendor"`
	Model           string `json:"model"`
	FirmwareVersion string `json:"firmware_version"`
}

// MaxDeviceFieldBytes bounds each device value on an export page.
const MaxDeviceFieldBytes = 128

// SubjectPart is one part of a subject on an export page. A subject whose
// components do not fit on one page continues on the next as its next
// part; it is covered only after its LastPart. A device subject carries
// Device and no components or kernel.
type SubjectPart struct {
	Kind       vulnfinding.SubjectKind `json:"subject_kind"`
	Ref        vulnfinding.SubjectRef  `json:"subject_ref"`
	Ecosystem  string                  `json:"ecosystem,omitempty"`
	Kernel     *Kernel                 `json:"running_kernel,omitempty"`
	Device     *Device                 `json:"device,omitempty"`
	Complete   bool                    `json:"complete"`
	Part       int                     `json:"part"`
	LastPart   bool                    `json:"last_part"`
	Components []Component             `json:"components"`
}

// pageJSON is one page as the server sends it.
type pageJSON struct {
	Format     string        `json:"format"`
	SnapshotID string        `json:"snapshot_id"`
	Generation int64         `json:"generation"`
	TakenAt    string        `json:"taken_at"`
	Page       int           `json:"page"`
	Pages      int           `json:"pages"`
	Subjects   []SubjectPart `json:"subjects"`
	NextCursor string        `json:"next_cursor,omitempty"`
}

// Page is one validated export page.
type Page struct {
	SnapshotID string
	Generation int64
	TakenAt    time.Time
	// Index counts from 0; Pages is the snapshot's page count.
	Index, Pages int
	Subjects     []SubjectPart
}

// SubjectCoverage is a subject of a snapshot after the whole export.
type SubjectCoverage struct {
	Kind vulnfinding.SubjectKind
	Ref  vulnfinding.SubjectRef
	// Parts is the number of parts the export split the subject into.
	Parts int
	// Complete is NOS's completeness: only a complete subject can be
	// covered by a run.
	Complete bool
}

// BatchSubjects returns the batch entries that name every part of the
// subject, in order.
func (s SubjectCoverage) BatchSubjects() []BatchSubject {
	out := make([]BatchSubject, 0, s.Parts)
	for p := 1; p <= s.Parts; p++ {
		out = append(out, BatchSubject{Kind: s.Kind, Ref: s.Ref, Part: p, LastPart: p == s.Parts})
	}
	return out
}

// Snapshot is a fully read inventory snapshot: its identity and every
// subject with its part count. A run starts on it (Client.StartRun).
type Snapshot struct {
	ID         string
	Generation int64
	TakenAt    time.Time
	Pages      int
	Subjects   []SubjectCoverage
	byKey      map[string]int
}

// Subject returns the coverage of a subject.
func (s *Snapshot) Subject(kind vulnfinding.SubjectKind, ref vulnfinding.SubjectRef) (SubjectCoverage, bool) {
	i, ok := s.byKey[subjectKey(kind, ref)]
	if !ok {
		return SubjectCoverage{}, false
	}
	return s.Subjects[i], true
}

func subjectKey(kind vulnfinding.SubjectKind, ref vulnfinding.SubjectRef) string {
	return string(kind) + "|" + ref.ID + "|" + ref.ImageDigest
}

// exportState tracks a running export.
type exportState struct {
	snap Snapshot
	// open is the subject whose last part has not arrived yet, by index;
	// -1 if none. Parts of one subject are consecutive.
	open int
	// comps counts the components of each subject over its parts.
	comps []int
	// head is the subject header of the open subject's first part.
	head SubjectPart
}

// Export reads the current inventory snapshot page by page and calls visit
// for each validated page. Every page must carry the snapshot ID, generation
// and time of the first page, and the cursor of the previous page, so the
// pages read belong to one snapshot. Subject parts must arrive in order and
// every subject must reach its last part. If the server no longer holds the
// snapshot, Export returns ErrSnapshotGone; the caller starts again and must
// discard the pages it got. A visit error ends the export.
func (c *Client) Export(ctx context.Context, visit func(Page) error) (*Snapshot, error) {
	st := &exportState{open: -1, snap: Snapshot{byKey: map[string]int{}}}
	cursor := ""
	for index := 0; ; index++ {
		if index >= MaxExportPages {
			return nil, fmt.Errorf("export: more than %d pages: %w", MaxExportPages, ErrProtocol)
		}
		q := url.Values{}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		body, err := c.do(ctx, request{op: "export page " + fmt.Sprint(index), method: http.MethodGet, path: inventoryPath, query: q,
			limit: MaxExportBytes, window: &c.export, retry: retryIdempotent, timeout: requestTimeout, okStatus: http.StatusOK})
		if err != nil {
			return nil, err
		}
		var pj pageJSON
		if err := decodeJSON("export", body, &pj, true); err != nil {
			return nil, err
		}
		page, err := st.accept(index, pj)
		if err != nil {
			return nil, fmt.Errorf("export page %d: %w", index, err)
		}
		if err := visit(page); err != nil {
			return nil, fmt.Errorf("export page %d: visit: %w", index, err)
		}
		if pj.NextCursor == "" {
			break
		}
		cursor = pj.NextCursor
	}
	if st.open >= 0 {
		return nil, fmt.Errorf("export: %w", ErrIncompleteExport)
	}
	snap := st.snap
	return &snap, nil
}

// accept validates page index against the export so far.
func (st *exportState) accept(index int, pj pageJSON) (Page, error) {
	if pj.Format != InventoryFormat {
		return Page{}, fmt.Errorf("format is not %s: %w", InventoryFormat, ErrProtocol)
	}
	takenAt, err := time.Parse(time.RFC3339, pj.TakenAt)
	if err != nil || !snapshotIDRe.MatchString(pj.SnapshotID) || pj.Generation < 0 {
		return Page{}, fmt.Errorf("malformed snapshot metadata: %w", ErrProtocol)
	}
	if pj.Pages < 1 || pj.Pages > MaxExportPages || pj.Page != index || pj.Page >= pj.Pages {
		return Page{}, fmt.Errorf("page numbering: %w", ErrProtocol)
	}
	if index == 0 {
		st.snap.ID, st.snap.Generation, st.snap.TakenAt, st.snap.Pages = pj.SnapshotID, pj.Generation, takenAt.UTC(), pj.Pages
	} else if pj.SnapshotID != st.snap.ID || pj.Generation != st.snap.Generation || !takenAt.Equal(st.snap.TakenAt) || pj.Pages != st.snap.Pages {
		return Page{}, fmt.Errorf("page is not of snapshot being read: %w", ErrProtocol)
	}
	last := index+1 == pj.Pages
	if last != (pj.NextCursor == "") {
		return Page{}, fmt.Errorf("next_cursor does not match the page count: %w", ErrProtocol)
	}
	if pj.NextCursor != "" && (len(pj.NextCursor) > maxCursorBytes || !cursorRe.MatchString(pj.NextCursor)) {
		return Page{}, fmt.Errorf("malformed next_cursor: %w", ErrProtocol)
	}
	if len(pj.Subjects) > MaxSubjectsPerPage {
		return Page{}, fmt.Errorf("more than %d subjects on a page: %w", MaxSubjectsPerPage, ErrProtocol)
	}
	for i := range pj.Subjects {
		if err := st.part(pj.Subjects[i]); err != nil {
			return Page{}, fmt.Errorf("subject %d: %w", i, err)
		}
	}
	return Page{SnapshotID: st.snap.ID, Generation: st.snap.Generation, TakenAt: st.snap.TakenAt, Index: index, Pages: pj.Pages,
		Subjects: pj.Subjects}, nil
}

// part checks one subject part: a known kind and reference, parts in
// order and consecutive, the same header on every part, and the
// component limits.
func (st *exportState) part(s SubjectPart) error {
	limit := MaxHostPackages
	switch s.Kind {
	case vulnfinding.SubjectHost:
		if s.Ref.ImageDigest != "" {
			return fmt.Errorf("host with an image digest: %w", ErrProtocol)
		}
	case vulnfinding.SubjectImage:
		if !digestRe.MatchString(s.Ref.ImageDigest) {
			return fmt.Errorf("image without a valid digest: %w", ErrProtocol)
		}
		limit = MaxImagePackages
		if s.Kernel != nil {
			return fmt.Errorf("image with a running kernel: %w", ErrProtocol)
		}
	case vulnfinding.SubjectDevice:
		// A device has no digest, kernel or packages (ADR 0011 D2, D3); its
		// model and firmware version are its only components.
		if s.Ref.ImageDigest != "" || s.Kernel != nil {
			return fmt.Errorf("device with an image digest or a kernel: %w", ErrProtocol)
		}
		if err := checkDevice(s.Device); err != nil {
			return err
		}
		limit = 0
	default:
		return fmt.Errorf("unknown subject kind: %w", ErrProtocol)
	}
	if s.Kind != vulnfinding.SubjectDevice && s.Device != nil {
		return fmt.Errorf("%s subject with device data: %w", s.Kind, ErrProtocol)
	}
	if !subjectIDRe.MatchString(s.Ref.ID) {
		return fmt.Errorf("malformed subject ID: %w", ErrProtocol)
	}
	for _, comp := range s.Components {
		if comp.SourcePackage == "" || comp.SourceVersion == "" || len(comp.Binaries) > MaxBinariesPerComponent {
			return fmt.Errorf("malformed component: %w", ErrProtocol)
		}
	}
	key := subjectKey(s.Kind, s.Ref)
	idx, seen := st.snap.byKey[key]
	switch {
	case st.open >= 0 && (!seen || idx != st.open):
		return fmt.Errorf("a subject starts before the previous one's last part: %w", ErrProtocol)
	case st.open < 0 && seen:
		return fmt.Errorf("a subject appears again after its last part: %w", ErrProtocol)
	case st.open < 0:
		if s.Part != 1 {
			return fmt.Errorf("a subject does not start with part 1: %w", ErrProtocol)
		}
		if len(st.snap.Subjects) >= MaxExportSubjects {
			return fmt.Errorf("more than %d subjects: %w", MaxExportSubjects, ErrProtocol)
		}
		idx = len(st.snap.Subjects)
		st.snap.byKey[key] = idx
		st.snap.Subjects = append(st.snap.Subjects, SubjectCoverage{Kind: s.Kind, Ref: s.Ref, Complete: s.Complete})
		st.comps = append(st.comps, 0)
		st.head = s
	default:
		cov := st.snap.Subjects[idx]
		if s.Part != cov.Parts+1 {
			return fmt.Errorf("subject parts out of order: %w", ErrProtocol)
		}
		if !sameHead(st.head, s) {
			return fmt.Errorf("subject header changes between parts: %w", ErrProtocol)
		}
	}
	st.snap.Subjects[idx].Parts = s.Part
	st.comps[idx] += len(s.Components)
	if st.comps[idx] > limit {
		return fmt.Errorf("more than %d components: %w", limit, ErrProtocol)
	}
	if s.LastPart {
		st.open = -1
	} else {
		st.open = idx
	}
	return nil
}

// checkDevice validates the device data of a device subject part. Each value
// must match the server's pattern for its field (ADR 0011 D2/D3) or be the
// server's "unknown" placeholder; a value outside the pattern never reaches
// the matcher.
func checkDevice(d *Device) error {
	if d == nil {
		return fmt.Errorf("device subject without device data: %w", ErrProtocol)
	}
	fields := []struct {
		name, value string
		re          *regexp.Regexp
	}{
		{"vendor", d.Vendor, deviceVendorRe},
		{"model", d.Model, deviceModelRe},
		{"firmware_version", d.FirmwareVersion, deviceFirmwareRe},
	}
	for _, f := range fields {
		if f.value == "" || len(f.value) > MaxDeviceFieldBytes {
			return fmt.Errorf("device %s empty or over %d bytes: %w", f.name, MaxDeviceFieldBytes, ErrProtocol)
		}
		if f.value != deviceUnknown && !f.re.MatchString(f.value) {
			return fmt.Errorf("device %s outside the export pattern: %w", f.name, ErrProtocol)
		}
	}
	return nil
}

func sameHead(a, b SubjectPart) bool {
	if a.Ecosystem != b.Ecosystem || a.Complete != b.Complete || (a.Kernel == nil) != (b.Kernel == nil) {
		return false
	}
	if (a.Device == nil) != (b.Device == nil) || (a.Device != nil && *a.Device != *b.Device) {
		return false
	}
	return a.Kernel == nil || *a.Kernel == *b.Kernel
}
