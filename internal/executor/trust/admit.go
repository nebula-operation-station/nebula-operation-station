// SPDX-License-Identifier: AGPL-3.0-or-later

package trust

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
)

// Result describes a committed admission.
type Result struct {
	// Generation is the new store generation.
	Generation int64
	// Activated lists name@version made active; Superseded those that
	// ceased to be active.
	Activated, Superseded []string
	// Collected lists name@version whose bytes were garbage-collected.
	Collected []string
	// CleanupFailures counts unreferenced objects that could not be
	// deleted; callers audit it. Committed state is unaffected and the
	// next admission retries.
	CleanupFailures int
}

// Admit commits a reviewed candidate atomically: it recomputes the review
// (rehashing the candidate bytes) and requires the same digest and store
// generation, reserves worst-case space before any change, stores the
// module bytes and provenance, applies the active/predecessor transitions
// and tombstones, then garbage-collects only what retention allows. On
// any error nothing is changed. It does not create trust tuples or
// execution authority. Admit collects every eligible version; use
// AdmitPinned to keep versions pinned by a retained execution or an open
// review (spec 10, "not otherwise pinned").
func (s *Store) Admit(in release.Candidate, reviewed Review) (Result, error) {
	return s.admit(in, reviewed, nil)
}

// AdmitPinned is Admit with pins: versions in pinned (keyed name@version)
// are skipped by garbage collection even when they are beyond the two most
// recent predecessors and their 90-day floor has passed. A retained
// execution or an open review pins the versions it references, so their
// bytes are never collected while the pin holds (spec 10, "not otherwise
// pinned").
func (s *Store) AdmitPinned(in release.Candidate, reviewed Review, pinned map[string]bool) (Result, error) {
	return s.admit(in, reviewed, pinned)
}

// admit is the shared admission path; pinned lists name@version keys that
// garbage collection must skip.
func (s *Store) admit(in release.Candidate, reviewed Review, pinned map[string]bool) (Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if reviewed.Generation != s.idx.Generation {
		return Result{}, fmt.Errorf("%w: the store changed since the review (generation %d, now %d)", ErrStale, reviewed.Generation, s.idx.Generation)
	}
	fresh, c, err := s.review(in)
	if err != nil {
		return Result{}, err
	}
	if fresh.Digest != reviewed.Digest {
		return Result{}, fmt.Errorf("%w: the candidate no longer matches the review", ErrStale)
	}
	if !verifiedNow(c, s.idx.Roots.Active()) {
		return Result{}, fmt.Errorf("%w: the manifest signer is no longer a trusted root", release.ErrUntrusted)
	}
	now := s.clock()
	x := s.idx.clone()
	var res Result
	newBytes := map[string][]byte{}
	byName := map[string]int{}
	for i, m := range x.Modules {
		byName[m.Name] = i
	}
	inRelease := map[string]bool{}
	for _, mb := range c.Modules {
		md := mb.Module
		inRelease[md.Name] = true
		i, ok := byName[md.Name]
		if !ok {
			x.Modules = append(x.Modules, ModuleRecord{Name: md.Name, History: []VersionRecord{}})
			i = len(x.Modules) - 1
			byName[md.Name] = i
		}
		m := &x.Modules[i]
		newBytes[md.SHA256] = mb.Tar
		if m.Active != nil && m.Active.Version == md.Version {
			continue // unchanged (or bytes repaired): no transition, no age reset
		}
		next := VersionRecord{Version: md.Version, Size: md.Size, SHA256: md.SHA256, ManifestDigest: c.Manifest.Digest,
			AcceptedAt: now, ActivatedAt: now}
		for j, h := range m.History {
			if h.Version == md.Version {
				// Reactivation reuses the retained record; its 90-day
				// floor stays and is extended on the next supersession.
				next = h
				next.ActivatedAt, next.SupersededAt = now, time.Time{}
				m.History = append(m.History[:j:j], m.History[j+1:]...)
				break
			}
		}
		if m.Active != nil {
			res.Superseded = append(res.Superseded, m.Name+"@"+m.Active.Version)
			supersede(&x, m, now)
		}
		m.Active = &next
		res.Activated = append(res.Activated, md.Name+"@"+md.Version)
		addTombstone(&x, Tombstone{Name: md.Name, Version: md.Version, Size: md.Size, SHA256: md.SHA256,
			ManifestDigest: c.Manifest.Digest, AcceptedAt: now})
	}
	for i := range x.Modules {
		m := &x.Modules[i]
		if m.Active != nil && !inRelease[m.Name] {
			res.Superseded = append(res.Superseded, m.Name+"@"+m.Active.Version)
			supersede(&x, m, now)
			m.Active = nil
		}
	}
	sort.Slice(x.Modules, func(i, j int) bool { return x.Modules[i].Name < x.Modules[j].Name })
	addProvenance(&x, c, now)

	// Collect what retention allows in the same index write, so expired
	// predecessors never block an admission; protected history (two most
	// recent predecessors, 90-day floors) is never counted as freed.
	// Collected objects are deleted only after the index is committed.
	if !s.clockBackward() && !s.clockForward() {
		res.Collected = collect(&x, now, pinned)
	}
	// Reserve the worst case before changing anything.
	if err := s.reserve(x, c, newBytes); err != nil {
		return Result{}, err
	}
	sigSum, err := s.putObject(c.Signature)
	if err != nil {
		return Result{}, err
	}
	if _, err := s.putObject(c.ManifestBytes); err != nil {
		return Result{}, err
	}
	for _, b := range newBytes {
		if _, err := s.putObject(b); err != nil {
			return Result{}, err
		}
	}
	setSignature(&x, c.Manifest.Digest, sigSum)
	x.Generation++
	x.ClockHighWater = maxTime(x.ClockHighWater, now)
	if err := x.validate(); err != nil {
		return Result{}, err
	}
	if err := s.persist(x); err != nil {
		return Result{}, err
	}
	s.idx = x
	res.CleanupFailures = s.removeUnreferenced()
	res.Generation = x.Generation
	return res, nil
}

// verifiedNow requires the manifest's signer to still be an active root.
func verifiedNow(c release.Candidate, roots []release.Root) bool {
	for _, r := range roots {
		if r.ID == c.Manifest.SignedBy.ID && r.Key != nil && c.Manifest.SignedBy.Key != nil &&
			string(r.Key.Marshal()) == string(c.Manifest.SignedBy.Key.Marshal()) {
			return true
		}
	}
	return false
}

// supersede moves the active version to the front of the history with a
// fresh 90-day floor that never shortens an earlier one.
func supersede(x *index, m *ModuleRecord, now time.Time) {
	old := *m.Active
	old.SupersededAt = now
	old.RetainUntil = maxTime(old.RetainUntil, now.Add(Retention))
	m.History = append([]VersionRecord{old}, m.History...)
	for i := range x.Tombstones {
		if x.Tombstones[i].Name == m.Name && x.Tombstones[i].Version == old.Version {
			x.Tombstones[i].SupersededAt = now
		}
	}
}

func addTombstone(x *index, t Tombstone) {
	if _, ok := x.tombstone(t.Name, t.Version); ok {
		return
	}
	k := tombKey(t)
	i := sort.Search(len(x.Tombstones), func(i int) bool { return tombKey(x.Tombstones[i]) >= k })
	x.Tombstones = append(x.Tombstones, Tombstone{})
	copy(x.Tombstones[i+1:], x.Tombstones[i:])
	x.Tombstones[i] = t
}

func addProvenance(x *index, c release.Candidate, now time.Time) {
	for _, p := range x.Provenance {
		if p.ManifestDigest == c.Manifest.Digest {
			return
		}
	}
	x.Provenance = append(x.Provenance, Provenance{ManifestDigest: c.Manifest.Digest, ManifestSize: int64(len(c.ManifestBytes)),
		SignatureSize: int64(len(c.Signature)), ReleaseVersion: c.Manifest.ReleaseVersion,
		RootID: c.Manifest.SignedBy.ID, RootFingerprint: c.Manifest.SignedBy.Fingerprint(),
		RootSequence: x.Roots.Sequence, AdmittedAt: now})
	sort.Slice(x.Provenance, func(i, j int) bool { return x.Provenance[i].ManifestDigest < x.Provenance[j].ManifestDigest })
}

func setSignature(x *index, digest, sigSum string) {
	for i := range x.Provenance {
		if x.Provenance[i].ManifestDigest == digest && x.Provenance[i].SignatureSHA256 == "" {
			x.Provenance[i].SignatureSHA256 = sigSum
		}
	}
}

// collect drops predecessors that are beyond the two most recent and
// whose 90-day floor has passed, and provenance no retained version
// references. Versions in pinned (keyed name@version) are never collected,
// whatever their age or depth (spec 10, "not otherwise pinned").
// Tombstones are kept.
func collect(x *index, now time.Time, pinned map[string]bool) []string {
	var out []string
	for i := range x.Modules {
		m := &x.Modules[i]
		kept := m.History[:0:0]
		for j, h := range m.History {
			if j < KeepPredecessors || now.Before(h.RetainUntil) || pinned[m.Name+"@"+h.Version] {
				kept = append(kept, h)
				continue
			}
			out = append(out, m.Name+"@"+h.Version)
		}
		m.History = kept
	}
	used := map[string]bool{}
	for _, m := range x.Modules {
		for _, v := range versions(m) {
			used[v.ManifestDigest] = true
		}
	}
	prov := x.Provenance[:0:0]
	for _, p := range x.Provenance {
		if used[p.ManifestDigest] {
			prov = append(prov, p)
		}
	}
	x.Provenance = prov
	return out
}

// reserve checks the prospective state against every ceiling and the
// free disk space, before anything is written.
func (s *Store) reserve(x index, c release.Candidate, newBytes map[string][]byte) error {
	quota := func(what string, got, limit int64) error {
		if got > limit {
			return fmt.Errorf("%w: %s would be %d bytes, limit %d", ErrQuota, what, got, int64(limit))
		}
		return nil
	}
	if len(x.Modules) > MaxNames {
		return fmt.Errorf("%w: more than %d module names", ErrQuota, MaxNames)
	}
	if len(x.Tombstones) > MaxTombstones {
		return fmt.Errorf("%w: more than %d version tombstones", ErrQuota, MaxTombstones)
	}
	var active, history, staging int64
	for _, m := range x.Modules {
		if m.Active != nil {
			active += m.Active.Size
		}
		for _, h := range m.History {
			history += h.Size
		}
	}
	for _, b := range newBytes {
		staging += int64(len(b))
	}
	var meta int64 = int64(len(c.ManifestBytes) + len(c.Signature))
	for _, p := range x.Provenance {
		meta += p.ManifestSize + p.SignatureSize
	}
	for _, r := range x.Rotations {
		meta += r.Size + r.SignatureSize
	}
	idxSize, err := encodedSize(x)
	if err != nil {
		return err
	}
	meta += idxSize
	for _, e := range []error{
		quota("active module bytes", active, s.limits.active),
		quota("historical module bytes", history, s.limits.history),
		quota("staging bytes", staging, s.limits.staging),
		quota("metadata bytes", meta, s.limits.metadata),
		quota("total bytes", active+history+staging+meta, s.limits.total),
	} {
		if e != nil {
			return e
		}
	}
	free, err := s.freeSpace(s.dir)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrQuota, err)
	}
	// New objects, the index and its temporary copy must fit.
	if need := uint64(staging + int64(len(c.ManifestBytes)+len(c.Signature)) + 2*idxSize); free < need {
		return fmt.Errorf("%w: %d bytes free, %d needed", ErrQuota, free, need)
	}
	return nil
}

// removeUnreferenced deletes object files nothing in the index refers to
// and returns how many deletions failed. Failures are retried next time;
// they never affect committed state.
func (s *Store) removeUnreferenced() int {
	used := map[string]bool{}
	for _, m := range s.idx.Modules {
		for _, v := range versions(m) {
			used[v.SHA256] = true
		}
	}
	for _, p := range s.idx.Provenance {
		used[p.ManifestDigest], used[p.SignatureSHA256] = true, true
	}
	for _, r := range s.idx.Rotations {
		used[r.Digest], used[r.SignatureSHA256] = true, true
	}
	dir := filepath.Join(s.dir, objectsDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 1
	}
	failed := 0
	for _, e := range entries {
		if !used[e.Name()] {
			if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
				failed++
			}
		}
	}
	return failed
}
