// SPDX-License-Identifier: AGPL-3.0-or-later

package fimbaseline

import (
	"bytes"
	"fmt"
	"slices"

	"github.com/nebula-operation-station/nebula-operation-station/internal/fimscan"
)

// Kind says whether a path was added, removed or changed.
type Kind uint8

const (
	// KindAdded: the path is in the scan, not in the baseline.
	KindAdded Kind = iota + 1
	// KindRemoved: the path is in the baseline and a complete scan does not
	// have it. A partial scan never yields it (ADR 0015 D6).
	KindRemoved
	// KindChanged: the path is in both and differs; see Changes. It also
	// covers a /boot/efi mount-type change (ChangeFSType) where one side has
	// no record at /boot/efi; then Old or New is nil.
	KindChanged
)

// String returns the kind name.
func (k Kind) String() string {
	switch k {
	case KindAdded:
		return "added"
	case KindRemoved:
		return "removed"
	case KindChanged:
		return "changed"
	default:
		return "invalid"
	}
}

// Change is a bit set of what differs between the old and the new record.
type Change uint16

const (
	// ChangeContent: both records carry a content hash and they differ.
	ChangeContent Change = 1 << iota
	// ChangeNotHashed: the new record is a file without a content hash and
	// its metadata differs or it is new ("changed, not yet hashed", D9), or
	// it lies under a vfat /boot/efi root, where every file must be hashed
	// (D5).
	ChangeNotHashed
	// ChangeType: the file type differs.
	ChangeType
	// ChangeLink: the symlink target differs.
	ChangeLink
	// ChangeMode: the permission, setuid, setgid or sticky bits differ.
	ChangeMode
	// ChangeOwner: uid or gid differs.
	ChangeOwner
	// ChangeSize: the size differs.
	ChangeSize
	// ChangeInode: the inode number differs.
	ChangeInode
	// ChangeTimes: mtime or ctime differs.
	ChangeTimes
	// ChangeFSType: the reported file-system type of the /boot/efi root
	// differs (D5 "EFI system partition").
	ChangeFSType
)

// Deviation is one path that differs between baseline and scan.
type Deviation struct {
	// Path is the raw path (show only through fimscan.EscapePath).
	Path []byte
	// Kind is added, removed or changed.
	Kind Kind
	// Changes is the bit set of what differs. It is non-zero for KindChanged
	// (ChangeFSType for a /boot/efi mount-type change; see Kind). For
	// KindAdded it is 0, or ChangeNotHashed for a new file that is not
	// hashed. For KindRemoved it is always 0. ChangeFSType is never set on
	// an added or removed /boot/efi entry: that entry already is the mount
	// change.
	Changes Change
	// Old is the baseline record (nil for KindAdded); New the scan record
	// (nil for KindRemoved). Both are copies owned by the caller.
	Old, New *fimscan.Record
	// Class is the D9 class; Rules says why it is critical.
	Class Class
	Rules Rule
}

// Report is the result of Diff.
type Report struct {
	// Complete is the scan's completeness. A partial scan may show
	// deviations but proves neither absence nor that a path is unchanged
	// (D6), so it never yields KindRemoved.
	Complete bool
	// Deviations are sorted by raw path bytes, one per path, at most
	// MaxDeviations.
	Deviations []Deviation
}

// efiRoot is the EFI system partition root of D5.
const efiRoot = "/boot/efi"

// Diff compares a parsed scan with the baseline. It returns ErrInvalidInput,
// ErrLimit or ErrProfileMismatch (wrapped) for unusable input and never
// truncates. The scan's records may be in any order; the output depends
// only on the set of records.
func Diff(b *Baseline, scan *fimscan.Result, opts Options) (*Report, error) {
	if b == nil || scan == nil {
		return nil, fmt.Errorf("diff: %w: nil input", ErrInvalidInput)
	}
	if scan.ProfileID != b.profileID {
		return nil, fmt.Errorf("diff: %w", ErrProfileMismatch)
	}
	if err := checkLatest(b, opts.LatestComplete); err != nil {
		return nil, fmt.Errorf("diff: latest complete run: %w", err)
	}
	cur, err := sortedRecords(scan.Records)
	if err != nil {
		return nil, fmt.Errorf("diff: scan: %w", err)
	}
	curMounts, err := sortedMounts(scan.Mounts)
	if err != nil {
		return nil, fmt.Errorf("diff: scan: %w", err)
	}
	complete := scan.Complete()
	oldEFI, curEFI := mountType(b.mounts, efiRoot), mountType(curMounts, efiRoot)
	// D5: the vfat relaxation applies only when /boot/efi is a covered
	// root and both the baseline and the run report vfat for it.
	relaxEFI := rootScanned(scan, efiRoot) && oldEFI == "vfat" && curEFI == "vfat"

	cl := newClassifier(b.entries, cur, opts)
	rep := &Report{Complete: complete}
	add := func(p []byte, kind Kind, ch Change, old, nw *fimscan.Record) {
		d := Deviation{Path: bytes.Clone(p), Kind: kind, Changes: ch}
		if old != nil {
			o := cloneRecord(*old)
			d.Old = &o
		}
		if nw != nil {
			n := cloneRecord(*nw)
			d.New = &n
		}
		d.Class, d.Rules = cl.classify(p, old, nw)
		rep.Deviations = append(rep.Deviations, d)
	}

	i, j := 0, 0
	for i < len(b.entries) || j < len(cur) {
		var c int
		switch {
		case i == len(b.entries):
			c = 1
		case j == len(cur):
			c = -1
		default:
			c = bytes.Compare(b.entries[i].Path, cur[j].Path)
		}
		switch {
		case c < 0:
			if complete {
				add(b.entries[i].Path, KindRemoved, 0, &b.entries[i], nil)
			}
			i++
		case c > 0:
			var ch Change
			if cur[j].Type == fimscan.TypeFile && cur[j].Hash.Kind == fimscan.HashNone {
				ch = ChangeNotHashed
			}
			add(cur[j].Path, KindAdded, ch, nil, &cur[j])
			j++
		default:
			relax := relaxEFI && inTree(string(cur[j].Path), efiRoot)
			if ch := compare(&b.entries[i], &cur[j], relax); ch != 0 {
				add(cur[j].Path, KindChanged, ch, &b.entries[i], &cur[j])
			}
			i++
			j++
		}
	}

	// D5: the /boot/efi file-system type is part of the baseline; a change
	// is a change of a critical-class path. A partial scan that does not
	// report the mount proves nothing.
	if oldEFI != curEFI && (complete || curEFI != "") {
		p := []byte(efiRoot)
		k, found := slices.BinarySearchFunc(rep.Deviations, p, func(d Deviation, t []byte) int {
			return bytes.Compare(d.Path, t)
		})
		if found {
			// An added or removed /boot/efi entry already is the mount
			// change; only a changed entry carries ChangeFSType (see
			// Deviation.Changes).
			if rep.Deviations[k].Kind == KindChanged {
				rep.Deviations[k].Changes |= ChangeFSType
			}
		} else {
			old, nw := findRecord(b.entries, p), findRecord(cur, p)
			add(p, KindChanged, ChangeFSType, old, nw)
			last := rep.Deviations[len(rep.Deviations)-1]
			rep.Deviations = slices.Insert(rep.Deviations[:len(rep.Deviations)-1], k, last)
		}
	}
	return rep, nil
}

// compare returns what differs between two records of the same path. With
// relax (an entry under a vfat /boot/efi root, D5), owner, permission bits
// (0777), inode and times are not compared; the setuid, setgid and sticky
// bits still are.
func compare(old, cur *fimscan.Record, relax bool) Change {
	var ch Change
	if old.Type != cur.Type {
		ch |= ChangeType
	}
	if (old.Link != nil || cur.Link != nil) && !bytes.Equal(old.Link, cur.Link) {
		ch |= ChangeLink
	}
	if old.Size != cur.Size {
		ch |= ChangeSize
	}
	modeMask := uint32(fimscan.MaxMode)
	if relax {
		modeMask = 0o7000
	}
	if old.Mode&modeMask != cur.Mode&modeMask {
		ch |= ChangeMode
	}
	if !relax {
		if old.UID != cur.UID || old.GID != cur.GID {
			ch |= ChangeOwner
		}
		if old.Inode != cur.Inode {
			ch |= ChangeInode
		}
		if old.Mtime != cur.Mtime || old.Ctime != cur.Ctime {
			ch |= ChangeTimes
		}
	}
	switch {
	case cur.Type == fimscan.TypeFile && cur.Hash.Kind == fimscan.HashNone:
		// Incremental run: content unknown. Any metadata change of a file
		// that was not hashed is "changed, not yet hashed" (D9). Under the
		// vfat relaxation every file is hashed in every run (D5), so an
		// unhashed record there is a deviation even without a metadata
		// change (fail closed).
		if ch != 0 || relax {
			ch |= ChangeNotHashed
		}
	case old.Type == fimscan.TypeFile && cur.Type == fimscan.TypeFile && old.Hash != cur.Hash:
		ch |= ChangeContent
	}
	return ch
}

func mountType(ms []fimscan.Mount, p string) string {
	for _, m := range ms {
		if string(m.Path) == p {
			return m.FSType
		}
	}
	return ""
}

// checkLatest validates the latest complete run given in Options: it must
// be complete, of the baseline's profile and within the limits. Only its
// records are used, for the D7 (c) shadowing set.
func checkLatest(b *Baseline, latest *fimscan.Result) error {
	if latest == nil {
		return nil
	}
	if !latest.Complete() {
		return fmt.Errorf("%w: partial scan", ErrInvalidInput)
	}
	if latest.ProfileID != b.profileID {
		return ErrProfileMismatch
	}
	if len(latest.Records) > MaxEntries {
		return fmt.Errorf("%w: %d records", ErrLimit, len(latest.Records))
	}
	for i := range latest.Records {
		if err := checkRecord(&latest.Records[i]); err != nil {
			return fmt.Errorf("record %d: %w", i, err)
		}
	}
	return nil
}

func rootScanned(scan *fimscan.Result, pattern string) bool {
	for _, r := range scan.Roots {
		if r.Pattern == pattern {
			return r.State == fimscan.RootScanned
		}
	}
	return false
}

func findRecord(recs []fimscan.Record, p []byte) *fimscan.Record {
	k, found := slices.BinarySearchFunc(recs, p, func(r fimscan.Record, t []byte) int {
		return bytes.Compare(r.Path, t)
	})
	if !found {
		return nil
	}
	return &recs[k]
}
