// SPDX-License-Identifier: AGPL-3.0-or-later

package trust

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
	"github.com/nebula-operation-station/nebula-operation-station/internal/textdiff"
)

// Status is the review status of a module or action.
type Status string

// Statuses.
const (
	// StatusNew is a module or action without a locally retained
	// predecessor: it is shown in full.
	StatusNew Status = "new"
	// StatusChanged differs from the active version.
	StatusChanged Status = "changed"
	// StatusUnchanged is byte-identical to the active version and needs
	// no confirmation.
	StatusUnchanged Status = "unchanged"
	// StatusReactivated returns to a retained earlier version.
	StatusReactivated Status = "reactivated"
	// StatusRemoved is active locally but absent from the release.
	StatusRemoved Status = "removed"
)

// ActionReview is the review of one action.
type ActionReview struct {
	// ActionID is <family>.<action>.
	ActionID string
	// Status is new, changed, unchanged or removed.
	Status Status
	// OldRisk/NewRisk, OldScriptSHA256/NewScriptSHA256 and
	// OldArtifactSHA256/NewArtifactSHA256 describe both sides; empty on
	// the missing side.
	OldRisk, NewRisk                     string
	OldScriptSHA256, NewScriptSHA256     string
	OldArtifactSHA256, NewArtifactSHA256 string
	// Diff is the full script diff from old to new; for a new action
	// every line is an insertion, for a removed one a deletion. Render
	// it as text only.
	Diff []textdiff.Line
}

// ModuleReview is the review of one module family.
type ModuleReview struct {
	// Name is the module family.
	Name string
	// Status is the module's status.
	Status Status
	// OldVersion/OldSHA256 is the active version, NewVersion/NewSHA256
	// the candidate's; empty on the missing side.
	OldVersion, OldSHA256 string
	NewVersion, NewSHA256 string
	// FullReview is set when no exact previous bytes are available
	// (first use, garbage-collected or missing/corrupt bytes): nothing
	// is inferred unchanged. Reason says why.
	FullReview bool
	Reason     string
	// Actions are sorted by action ID.
	Actions []ActionReview
}

// Review is the local review of a verified release bundle, bound to the
// manifest digest, the candidate bytes and the store generation.
type Review struct {
	// ManifestDigest and ReleaseVersion identify the release.
	ManifestDigest string
	ReleaseVersion string
	// RootID and RootFingerprint name the signing root.
	RootID, RootFingerprint string
	// Generation is the store generation the review was made against.
	Generation int64
	// Modules are sorted by name, removals included.
	Modules []ModuleReview
	// Digest binds manifest, candidate bytes, generation and statuses;
	// admission recomputes and compares it.
	Digest string
}

// NeedsConfirmation reports whether any module needs confirmation.
func (r Review) NeedsConfirmation() bool {
	for _, m := range r.Modules {
		if m.Status != StatusUnchanged {
			return true
		}
	}
	return false
}

// Review builds the review of a verified candidate. Same-version
// substitution against the active, retained or tombstoned bytes rejects
// the whole candidate.
func (s *Store) Review(c release.Candidate) (Review, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.review(c)
}

func (s *Store) review(c release.Candidate) (Review, error) {
	if err := s.checkCandidate(c); err != nil {
		return Review{}, err
	}
	r := Review{ManifestDigest: c.Manifest.Digest, ReleaseVersion: c.Manifest.ReleaseVersion,
		RootID: c.Manifest.SignedBy.ID, RootFingerprint: c.Manifest.SignedBy.Fingerprint(), Generation: s.idx.Generation}
	inRelease := map[string]bool{}
	for _, mb := range c.Modules {
		inRelease[mb.Module.Name] = true
		mr, err := s.reviewModule(mb)
		if err != nil {
			return Review{}, err
		}
		r.Modules = append(r.Modules, mr)
	}
	for _, m := range s.idx.Modules {
		if m.Active == nil || inRelease[m.Name] {
			continue
		}
		mr := ModuleReview{Name: m.Name, Status: StatusRemoved, OldVersion: m.Active.Version, OldSHA256: m.Active.SHA256}
		if old, err := s.loadVersion(m.Name, *m.Active); err == nil {
			for _, a := range old.Actions {
				mr.Actions = append(mr.Actions, ActionReview{ActionID: a.ActionID, Status: StatusRemoved, OldRisk: a.Risk,
					OldScriptSHA256: a.ScriptSHA256, OldArtifactSHA256: a.SHA256,
					Diff: textdiff.Diff(string(old.Files[a.Script]), "")})
			}
		} else {
			mr.FullReview, mr.Reason = true, "the active version's bytes are missing or corrupt"
		}
		r.Modules = append(r.Modules, mr)
	}
	sortModules(r.Modules)
	r.Digest = reviewDigest(r, c)
	return r, nil
}

// checkCandidate rechecks the candidate's module bytes against its
// manifest and rejects same-version substitution.
func (s *Store) checkCandidate(c release.Candidate) error {
	if len(c.Modules) != len(c.Manifest.Modules) || c.Manifest.Digest == "" {
		return fmt.Errorf("%w: candidate does not match its manifest", ErrStale)
	}
	for i, mb := range c.Modules {
		md := c.Manifest.Modules[i]
		sum := sha256.Sum256(mb.Tar)
		if mb.Module != md || int64(len(mb.Tar)) != md.Size || hex.EncodeToString(sum[:]) != md.SHA256 {
			return fmt.Errorf("%w: module %s bytes changed after verification", ErrStale, md.Name)
		}
		if t, ok := s.idx.tombstone(md.Name, md.Version); ok && (t.Size != md.Size || t.SHA256 != md.SHA256) {
			return fmt.Errorf("%w: %s %s was accepted with sha256 %s, the release has %s", ErrSubstitution, md.Name, md.Version, t.SHA256, md.SHA256)
		}
		if m, ok := s.module(md.Name); ok {
			for _, v := range versions(m) {
				if v.Version == md.Version && (v.SHA256 != md.SHA256 || v.Size != md.Size) {
					return fmt.Errorf("%w: %s %s differs from the retained bytes", ErrSubstitution, md.Name, md.Version)
				}
			}
		}
	}
	return nil
}

func versions(m ModuleRecord) []VersionRecord {
	var out []VersionRecord
	if m.Active != nil {
		out = append(out, *m.Active)
	}
	return append(out, m.History...)
}

func (s *Store) module(name string) (ModuleRecord, bool) {
	for _, m := range s.idx.Modules {
		if m.Name == name {
			return m, true
		}
	}
	return ModuleRecord{}, false
}

func (s *Store) reviewModule(mb release.ModuleBundle) (ModuleReview, error) {
	md := mb.Module
	mr := ModuleReview{Name: md.Name, NewVersion: md.Version, NewSHA256: md.SHA256}
	m, ok := s.module(md.Name)
	if !ok || m.Active == nil {
		mr.Status, mr.FullReview = StatusNew, true
		mr.Reason = "first use: no locally retained predecessor"
		if ok {
			mr.Reason = "the module was removed; no active predecessor"
		}
		mr.Actions = actionsAgainst(nil, mb)
		return mr, nil
	}
	mr.OldVersion, mr.OldSHA256 = m.Active.Version, m.Active.SHA256
	if m.Active.Version == md.Version && m.Active.SHA256 == md.SHA256 {
		// Unchanged only while the exact retained bytes are intact.
		if _, err := s.getObject(m.Active.SHA256, m.Active.Size); err == nil {
			mr.Status = StatusUnchanged
			return mr, nil
		}
		mr.Status, mr.FullReview = StatusChanged, true
		mr.Reason = "the active version's exact bytes are missing or corrupt; nothing is inferred unchanged"
		mr.Actions = actionsAgainst(nil, mb)
		return mr, nil
	}
	mr.Status = StatusChanged
	for _, h := range m.History {
		if h.Version == md.Version {
			mr.Status = StatusReactivated
		}
	}
	old, err := s.loadVersion(md.Name, *m.Active)
	if err != nil {
		mr.FullReview, mr.Reason = true, "the active version's exact bytes are missing or corrupt; nothing is inferred unchanged"
		mr.Actions = actionsAgainst(nil, mb)
		return mr, nil
	}
	mr.Actions = actionsAgainst(&old, mb)
	return mr, nil
}

// loadVersion reads and re-verifies retained module bytes.
func (s *Store) loadVersion(name string, v VersionRecord) (release.ModuleBundle, error) {
	b, err := s.getObject(v.SHA256, v.Size)
	if err != nil {
		return release.ModuleBundle{}, err
	}
	return release.ParseModuleTar(release.Module{Name: name, Version: v.Version, Size: v.Size, SHA256: v.SHA256}, b)
}

// actionsAgainst compares the candidate's actions with old (nil: every
// action is new and shown in full).
func actionsAgainst(old *release.ModuleBundle, nb release.ModuleBundle) []ActionReview {
	prev := map[string]release.ActionArtifact{}
	if old != nil {
		for _, a := range old.Actions {
			prev[a.ActionID] = a
		}
	}
	var out []ActionReview
	for _, a := range nb.Actions {
		ar := ActionReview{ActionID: a.ActionID, NewRisk: a.Risk, NewScriptSHA256: a.ScriptSHA256, NewArtifactSHA256: a.SHA256}
		p, had := prev[a.ActionID]
		delete(prev, a.ActionID)
		switch {
		case !had:
			ar.Status = StatusNew
			ar.Diff = textdiff.Diff("", string(nb.Files[a.Script]))
		default:
			ar.OldRisk, ar.OldScriptSHA256, ar.OldArtifactSHA256 = p.Risk, p.ScriptSHA256, p.SHA256
			ar.Diff = textdiff.Diff(string(old.Files[p.Script]), string(nb.Files[a.Script]))
			ar.Status = StatusChanged
			if p.SHA256 == a.SHA256 && p.Risk == a.Risk {
				ar.Status = StatusUnchanged
			}
		}
		out = append(out, ar)
	}
	for _, p := range prev {
		out = append(out, ActionReview{ActionID: p.ActionID, Status: StatusRemoved, OldRisk: p.Risk,
			OldScriptSHA256: p.ScriptSHA256, OldArtifactSHA256: p.SHA256, Diff: textdiff.Diff(string(old.Files[p.Script]), "")})
	}
	sortActions(out)
	return out
}

// reviewDigest binds what admission must find unchanged.
func reviewDigest(r Review, c release.Candidate) string {
	var b strings.Builder
	b.WriteString("nebula-builtin-review-v1\n" + r.ManifestDigest + "\n" + strconv.FormatInt(r.Generation, 10) + "\n")
	for _, mb := range c.Modules {
		b.WriteString(mb.Module.Name + " " + mb.Module.Version + " " + mb.Module.SHA256 + "\n")
	}
	for _, m := range r.Modules {
		b.WriteString(m.Name + " " + string(m.Status) + " " + m.OldSHA256 + " " + m.NewSHA256 + " " + strconv.FormatBool(m.FullReview) + "\n")
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}
