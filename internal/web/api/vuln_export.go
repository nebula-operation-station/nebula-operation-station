// SPDX-License-Identifier: AGPL-3.0-or-later

package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnver"
)

// VulnInventoryFormat is the version of the inventory export (ADR 0011 D3).
const VulnInventoryFormat = "vuln-inventory-v1"

// Export limits (ADR 0011 D3).
const (
	// MaxHostPackages and MaxImagePackages bound one subject's component
	// list (osdebian.MaxPackages; image.packages). A longer list is cut and
	// the subject exported as incomplete.
	MaxHostPackages  = 20000
	MaxImagePackages = 5000
	// MaxSubjectsPerPage and MaxExportBytes bound one page; a page ends at
	// whichever comes first.
	MaxSubjectsPerPage = 1000
	MaxExportBytes     = 4 << 20
	// MaxExportSubjects bounds the subjects of one snapshot; it equals the
	// number of subjects one run may cover (vulnstore.MaxCoveredPerRun).
	MaxExportSubjects = vulnstore.MaxCoveredPerRun
	// maxExportBinaries bounds the binaries listed for one component.
	maxExportBinaries = vulnfinding.MaxBinaries
	// exportEnvelope is room kept on every page for the envelope (format,
	// snapshot, cursor) around the subjects.
	exportEnvelope = 4 << 10
)

// ErrVulnSnapshotGone is returned by a VulnInventory that no longer holds
// the requested snapshot; the client restarts from the current one.
var ErrVulnSnapshotGone = errors.New("inventory snapshot no longer available")

// VulnInventory provides the inventory snapshots the export pages through
// and the runs re-check against. A snapshot is immutable for its ID. It
// reuses parsed observations and never triggers a read (D3).
type VulnInventory interface {
	// VulnSnapshot returns the snapshot with the given ID, or the current
	// one when id is empty. A snapshot it no longer holds is
	// ErrVulnSnapshotGone.
	VulnSnapshot(ctx context.Context, id string) (VulnSnapshot, error)
}

// VulnSnapshot is one inventory snapshot. It has, on purpose, no field for
// addresses, host names, labels, secrets, environment, logs or topology:
// the export can only carry what these types hold.
type VulnSnapshot struct {
	// ID is opaque and stable for the snapshot.
	ID string
	// Generation is the monotonic inventory generation.
	Generation int64
	// TakenAt is when the snapshot was taken.
	TakenAt time.Time
	// Subjects are hosts and images. Devices follow with VU-15.
	Subjects []VulnSubject
}

// VulnSubject is one subject of a snapshot.
type VulnSubject struct {
	Kind vulnfinding.SubjectKind
	// Ref is the opaque subject reference: inventory ID, and the platform
	// digest for an image.
	Ref vulnfinding.SubjectRef
	// Ecosystem is the OS release ("debian:bookworm", "ubuntu:24.04",
	// "alpine:3.20"); empty when unknown.
	Ecosystem string
	// Kernel is the running kernel of a host; nil when unknown.
	Kernel *VulnKernel
	// Complete is the D3 completeness of NOS's package read. A partial
	// read can add findings but never lets a run cover the subject.
	Complete bool
	// Components are the installed source packages.
	Components []VulnComponent
}

// VulnKernel is the running kernel and its D4 version basis.
type VulnKernel struct {
	// Release is `uname -r`.
	Release string
	// Source and SourceVersion are the unsigned kernel source package and
	// its version the running kernel maps to; empty when it does not map
	// ("kernel version unknown").
	Source        string
	SourceVersion string
}

// VulnComponent is one installed source package with its binaries.
type VulnComponent struct {
	// Source is the source package; SourceVersion its installed
	// source:Version, the D4 version basis.
	Source        string
	SourceVersion string
	Binaries      []VulnBinary
}

// VulnBinary is one installed binary package of a source package.
type VulnBinary struct {
	Name    string
	Version string
	Arch    string
}

var (
	exportSnapshotIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:._-]{0,127}$`)
	exportSubjectIDRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	exportDigestRe     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	exportEcosystemRe  = regexp.MustCompile(`^(debian:[a-z]{2,32}|ubuntu:[0-9]{2}\.[0-9]{2}|alpine:[0-9]{1,2}\.[0-9]{1,3})$`)
	exportPackageRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9+._-]{1,127}$`)
	exportVersionRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+~:_-]{0,127}$`)
	exportArchRe       = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	exportReleaseRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_~-]{0,127}$`)
)

// Export JSON. Every string in it has passed a strict pattern above.
type exportBinaryJSON struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch,omitempty"`
}

type exportComponentJSON struct {
	SourcePackage string             `json:"source_package"`
	SourceVersion string             `json:"source_version"`
	Binaries      []exportBinaryJSON `json:"binaries,omitempty"`
}

type exportKernelJSON struct {
	Release       string `json:"release"`
	Mapped        bool   `json:"mapped"`
	SourcePackage string `json:"source_package,omitempty"`
	SourceVersion string `json:"source_version,omitempty"`
}

type exportSubjectJSON struct {
	SubjectKind vulnfinding.SubjectKind `json:"subject_kind"`
	SubjectRef  vulnfinding.SubjectRef  `json:"subject_ref"`
	Ecosystem   string                  `json:"ecosystem,omitempty"`
	Kernel      *exportKernelJSON       `json:"running_kernel,omitempty"`
	// Complete: NOS's read was complete and nothing was dropped; only
	// then can a run cover the subject.
	Complete   bool                  `json:"complete"`
	Part       int                   `json:"part"`
	LastPart   bool                  `json:"last_part"`
	Components []exportComponentJSON `json:"components"`
}

type exportPageJSON struct {
	Format     string              `json:"format"`
	SnapshotID string              `json:"snapshot_id"`
	Generation int64               `json:"generation"`
	TakenAt    string              `json:"taken_at"`
	Page       int                 `json:"page"`
	Pages      int                 `json:"pages"`
	Subjects   []exportSubjectJSON `json:"subjects"`
	NextCursor string              `json:"next_cursor,omitempty"`
}

// preparedSubject is a validated subject of a snapshot.
type preparedSubject struct {
	key   string
	head  exportSubjectJSON // without part, last_part and components
	comps []exportComponentJSON
	// sizes are the encoded sizes of comps.
	sizes []int
	// basis maps a source package to its installed source version.
	basis map[string]string
	// kernel is the mapped running kernel basis; empty when unknown.
	kernelSource, kernelVersion string
	// coverable: complete read, nothing dropped (D3).
	coverable bool
}

// partSlice is one part of a subject on a page.
type partSlice struct {
	subject  int
	part     int
	last     bool
	from, to int
}

// prepared is a validated, paginated snapshot. Pagination is a pure
// function of the snapshot, so the parts of a subject are the same for the
// export and for the run that later names them.
type prepared struct {
	id         string
	generation int64
	takenAt    time.Time
	subjects   []preparedSubject
	byKey      map[string]int
	pages      [][]partSlice
	// parts is the number of parts of each subject, by key.
	parts map[string]int
	// dropped counts subjects left out as invalid.
	dropped int
}

// prepare validates a snapshot and paginates it. Invalid subjects are left
// out (and counted); invalid components or binaries are left out and make
// the subject incomplete, so no run can cover it and close findings by
// omission of something NOS did not export.
func prepare(s VulnSnapshot) (*prepared, error) {
	if !exportSnapshotIDRe.MatchString(s.ID) || s.Generation < 0 || s.TakenAt.IsZero() {
		return nil, errors.New("vuln inventory: malformed snapshot metadata")
	}
	p := &prepared{id: s.ID, generation: s.Generation, takenAt: s.TakenAt.UTC(), byKey: map[string]int{}, parts: map[string]int{}}
	for _, sub := range s.Subjects {
		if len(p.subjects) >= MaxExportSubjects {
			p.dropped++
			continue
		}
		ps, ok := prepareSubject(sub)
		if !ok {
			p.dropped++
			continue
		}
		if _, dup := p.byKey[ps.key]; dup {
			p.dropped++
			continue
		}
		p.byKey[ps.key] = len(p.subjects)
		p.subjects = append(p.subjects, ps)
	}
	if err := p.paginate(); err != nil {
		return nil, err
	}
	return p, nil
}

// notAddress reports that s does not parse as an IP address: an opaque
// subject ID must not be an address (D3: no addresses in the export).
func notAddress(s string) bool {
	_, err := netip.ParseAddr(s)
	return err != nil
}

func subjectKey(kind vulnfinding.SubjectKind, ref vulnfinding.SubjectRef) string {
	return vulnstore.Subject{Kind: kind, ID: ref.ID, ImageDigest: ref.ImageDigest}.String()
}

func prepareSubject(sub VulnSubject) (preparedSubject, bool) {
	limit := MaxHostPackages
	switch sub.Kind {
	case vulnfinding.SubjectHost:
		if sub.Ref.ImageDigest != "" {
			return preparedSubject{}, false
		}
	case vulnfinding.SubjectImage:
		if !exportDigestRe.MatchString(sub.Ref.ImageDigest) {
			return preparedSubject{}, false
		}
		limit = MaxImagePackages
	default:
		// Devices follow with VU-15; nothing else is exported.
		return preparedSubject{}, false
	}
	if !exportSubjectIDRe.MatchString(sub.Ref.ID) || !notAddress(sub.Ref.ID) {
		return preparedSubject{}, false
	}
	ps := preparedSubject{
		key:       subjectKey(sub.Kind, sub.Ref),
		head:      exportSubjectJSON{SubjectKind: sub.Kind, SubjectRef: vulnfinding.SubjectRef{ID: sub.Ref.ID, ImageDigest: sub.Ref.ImageDigest}},
		basis:     map[string]string{},
		coverable: sub.Complete,
	}
	if sub.Ecosystem != "" {
		if exportEcosystemRe.MatchString(sub.Ecosystem) {
			ps.head.Ecosystem = sub.Ecosystem
		} else {
			ps.coverable = false
		}
	}
	if sub.Kind == vulnfinding.SubjectHost && sub.Kernel != nil && exportReleaseRe.MatchString(sub.Kernel.Release) {
		k := &exportKernelJSON{Release: sub.Kernel.Release}
		if vulnver.IsKernelSource(sub.Kernel.Source) && exportVersionRe.MatchString(sub.Kernel.SourceVersion) {
			k.Mapped, k.SourcePackage, k.SourceVersion = true, sub.Kernel.Source, sub.Kernel.SourceVersion
			ps.kernelSource, ps.kernelVersion = sub.Kernel.Source, sub.Kernel.SourceVersion
		}
		ps.head.Kernel = k
	}
	for i, c := range sub.Components {
		if i >= limit {
			ps.coverable = false
			break
		}
		cj, ok := exportComponent(c)
		if !ok {
			ps.coverable = false
			continue
		}
		if _, dup := ps.basis[cj.SourcePackage]; dup {
			ps.coverable = false
			continue
		}
		b, err := json.Marshal(cj)
		if err != nil {
			ps.coverable = false
			continue
		}
		ps.basis[cj.SourcePackage] = cj.SourceVersion
		ps.comps = append(ps.comps, cj)
		ps.sizes = append(ps.sizes, len(b)+1)
	}
	ps.head.Complete = ps.coverable
	return ps, true
}

func exportComponent(c VulnComponent) (exportComponentJSON, bool) {
	if !exportPackageRe.MatchString(c.Source) || !exportVersionRe.MatchString(c.SourceVersion) || len(c.Binaries) > maxExportBinaries {
		return exportComponentJSON{}, false
	}
	out := exportComponentJSON{SourcePackage: c.Source, SourceVersion: c.SourceVersion}
	for _, b := range c.Binaries {
		if !exportPackageRe.MatchString(b.Name) || !exportVersionRe.MatchString(b.Version) || (b.Arch != "" && !exportArchRe.MatchString(b.Arch)) {
			return exportComponentJSON{}, false
		}
		out.Binaries = append(out.Binaries, exportBinaryJSON{Name: b.Name, Version: b.Version, Arch: b.Arch})
	}
	return out, true
}

// paginate splits the subjects into pages of at most MaxSubjectsPerPage
// subject parts and MaxExportBytes; a subject that does not fit continues
// on the next page as its next part.
func (p *prepared) paginate() error {
	budget := MaxExportBytes - exportEnvelope
	var page []partSlice
	used := 0
	flush := func() {
		p.pages = append(p.pages, page)
		page, used = nil, 0
	}
	for i := range p.subjects {
		s := &p.subjects[i]
		hb, err := json.Marshal(s.head)
		if err != nil {
			return fmt.Errorf("vuln inventory: encode subject: %w", err)
		}
		// Room for part numbers and the comma between subjects.
		head := len(hb) + 64
		part, from := 1, 0
		for {
			need := head
			if from < len(s.comps) {
				need += s.sizes[from]
			}
			if len(page) >= MaxSubjectsPerPage || (len(page) > 0 && used+need > budget) {
				flush()
			}
			used += head
			to := from
			for to < len(s.comps) && used+s.sizes[to] <= budget {
				used += s.sizes[to]
				to++
			}
			if to == from && from < len(s.comps) {
				return errors.New("vuln inventory: one component exceeds the page size")
			}
			last := to == len(s.comps)
			page = append(page, partSlice{subject: i, part: part, last: last, from: from, to: to})
			if last {
				p.parts[s.key] = part
				break
			}
			flush()
			part, from = part+1, to
		}
	}
	if len(page) > 0 || len(p.pages) == 0 {
		flush()
	}
	return nil
}

func (p *prepared) page(n int) exportPageJSON {
	out := exportPageJSON{Format: VulnInventoryFormat, SnapshotID: p.id, Generation: p.generation, TakenAt: rfc3339(p.takenAt),
		Page: n, Pages: len(p.pages), Subjects: []exportSubjectJSON{}}
	for _, ps := range p.pages[n] {
		s := p.subjects[ps.subject]
		v := s.head
		v.Part, v.LastPart = ps.part, ps.last
		v.Components = append([]exportComponentJSON{}, s.comps[ps.from:ps.to]...)
		out.Subjects = append(out.Subjects, v)
	}
	if n+1 < len(p.pages) {
		out.NextCursor = encodeCursor(p.id, n+1)
	}
	return out
}

const cursorPrefix = VulnInventoryFormat + "|"

// encodeCursor returns the opaque cursor of page n, bound to the snapshot.
func encodeCursor(snapshotID string, n int) string {
	return base64.RawURLEncoding.EncodeToString([]byte(cursorPrefix + snapshotID + "|" + strconv.Itoa(n)))
}

func decodeCursor(c string) (string, int, bool) {
	if len(c) > 512 {
		return "", 0, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return "", 0, false
	}
	rest, ok := strings.CutPrefix(string(raw), cursorPrefix)
	if !ok {
		return "", 0, false
	}
	id, num, ok := strings.Cut(rest, "|")
	if !ok || !exportSnapshotIDRe.MatchString(id) {
		return "", 0, false
	}
	n, err := strconv.Atoi(num)
	if err != nil || n < 1 || strconv.Itoa(n) != num {
		return "", 0, false
	}
	return id, n, true
}

// snapshot returns the prepared snapshot with the ID ("" = current). The
// inventory is always asked, so it alone decides whether a snapshot is
// still available; the last prepared snapshot is reused when the IDs
// match, because a snapshot is immutable for its ID.
func (h *VulnHandler) snapshot(ctx context.Context, id string) (*prepared, error) {
	s, err := h.inv.VulnSnapshot(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("vuln inventory snapshot: %w", err)
	}
	if id != "" && s.ID != id {
		return nil, fmt.Errorf("vuln inventory snapshot: %w", ErrVulnSnapshotGone)
	}
	h.mu.Lock()
	c := h.cache
	h.mu.Unlock()
	if c != nil && c.id == s.ID {
		return c, nil
	}
	p, err := prepare(s)
	if err != nil {
		return nil, err
	}
	h.mu.Lock()
	h.cache = p
	h.mu.Unlock()
	return p, nil
}

// serveInventory serves one page of the export.
func (h *VulnHandler) serveInventory(ctx context.Context, w http.ResponseWriter, r *http.Request, t *token) {
	q := r.URL.Query()
	for k := range q {
		if k != "cursor" {
			writeError(w, http.StatusBadRequest, "unknown query parameter")
			return
		}
	}
	id, n := "", 0
	if c := q.Get("cursor"); c != "" || q.Has("cursor") {
		var ok bool
		if id, n, ok = decodeCursor(c); !ok {
			writeError(w, http.StatusBadRequest, "malformed cursor")
			return
		}
	}
	p, err := h.snapshot(ctx, id)
	if errors.Is(err, ErrVulnSnapshotGone) {
		writeError(w, http.StatusGone, "inventory snapshot no longer available; start again without a cursor")
		return
	}
	if err != nil {
		h.log.Error("vuln inventory", "error", err)
		writeError(w, http.StatusServiceUnavailable, "inventory unavailable")
		return
	}
	if n >= len(p.pages) {
		writeError(w, http.StatusBadRequest, "malformed cursor")
		return
	}
	page := p.page(n)
	h.log.Info("audit", "kind", "vuln_inventory_read", "token", t.name, "snapshot", p.id, "page", n, "subjects", len(page.Subjects),
		"dropped_subjects", p.dropped)
	writeJSON(w, http.StatusOK, page)
}
