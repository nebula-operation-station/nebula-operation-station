// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sync"
	"syscall"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executor/trust"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/integrity"
	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
	"github.com/nebula-operation-station/nebula-operation-station/internal/version"
)

// ErrReferenceFileTooLarge is a release file above its limit from
// internal/release.
var ErrReferenceFileTooLarge = errors.New("executor: release file exceeds its size limit")

// ReferenceOutcome is the result of one admission attempt (ADR 0015 D4
// "Reference").
type ReferenceOutcome string

// Admission outcomes.
const (
	// ReferenceNotRun: no admission ran (built-in trust not wired).
	ReferenceNotRun ReferenceOutcome = "not-run"
	// ReferenceAdmitted: the files were verified and stored as the new
	// active reference.
	ReferenceAdmitted ReferenceOutcome = "admitted"
	// ReferenceUnchanged: the files are the active reference already.
	ReferenceUnchanged ReferenceOutcome = "unchanged"
	// ReferenceNoFiles: the release directory or its installed-files.json
	// is missing; nothing was admitted.
	ReferenceNoFiles ReferenceOutcome = "no-files"
	// ReferenceNotCheckable: a development build has no release version
	// to admit a list for.
	ReferenceNotCheckable ReferenceOutcome = "not-checkable"
	// ReferenceRejected: the files failed verification or the rollback
	// rule; nothing was stored. Rejection says why.
	ReferenceRejected ReferenceOutcome = "rejected"
	// ReferenceFailed: the root state or the executor database could not
	// be read or written.
	ReferenceFailed ReferenceOutcome = "failed"
)

// ReferenceRejection is the fixed reason of a rejected admission. No
// text from the release files is ever placed in it.
type ReferenceRejection string

// Rejection reasons.
const (
	// RejectRead: a file is missing next to a present list, not a
	// regular file (a symlink, FIFO, directory) or unreadable.
	RejectRead ReferenceRejection = "read"
	// RejectOversize: a file exceeds its limit.
	RejectOversize ReferenceRejection = "oversize"
	// RejectFormat: the manifest or list is malformed.
	RejectFormat ReferenceRejection = "format"
	// RejectSignature: the manifest signature does not verify against
	// the durable root state.
	RejectSignature ReferenceRejection = "signature"
	// RejectHash: the list does not match the size and SHA-256 the
	// signed manifest names.
	RejectHash ReferenceRejection = "hash"
	// RejectVersion: the signed release version is not the running one.
	RejectVersion ReferenceRejection = "version"
	// RejectRollback: the release version is lower than the last
	// admitted one.
	RejectRollback ReferenceRejection = "rollback"
	// RejectConflict: another manifest was already admitted for the
	// same release version (ADR 0015 D2 alarm).
	RejectConflict ReferenceRejection = "conflict"
)

// ReferenceAdmission is what an admission attempt found.
type ReferenceAdmission struct {
	Outcome   ReferenceOutcome
	Rejection ReferenceRejection
	// Err is the cause of a rejected or failed admission.
	Err error
	// Available reports that an admitted reference for the running
	// version exists and re-verified; ReleaseVersion and ManifestSHA256
	// describe it. Without it, the executor has no admitted reference.
	Available      bool
	ReleaseVersion string
	ManifestSHA256 string
}

// IntegrityReferenceStore is the executor-owned storage of admitted
// references (*executordb.DB).
type IntegrityReferenceStore interface {
	AdmitIntegrityReference(executordb.IntegrityReference) (bool, error)
	ActiveIntegrityReference() (executordb.IntegrityReference, error)
}

// AdmitInstalledFiles reads release-manifest.json, its signature and
// installed-files.json from dir (the package's /usr/share/nebula/release;
// no symlinks, sizes bounded by the release limits), verifies them with
// integrity.Admit against state, the executor's durable root state, and
// running, the running NOS version, and stores the verified bytes as the
// active reference under the rollback rule. It then re-verifies the
// active stored reference for the running version (Available).
//
// A rejection is an outcome, not an error; the returned error is non-nil
// only when the store cannot be read or written.
func AdmitInstalledFiles(store IntegrityReferenceStore, state release.RootState, running, dir string) (ReferenceAdmission, error) {
	if !release.ValidReleaseVersion(running) {
		return ReferenceAdmission{Outcome: ReferenceNotCheckable, Err: integrity.ErrDevelopmentBuild}, nil
	}
	a := admitFiles(store, state, running, dir)
	if a.Outcome == ReferenceFailed {
		return a, a.Err
	}
	ref, err := LoadAdmittedReference(store, state, running)
	switch {
	case err == nil:
		a.Available, a.ReleaseVersion, a.ManifestSHA256 = true, ref.ReleaseVersion(), ref.ManifestDigest()
	case errors.Is(err, executordb.ErrNoIntegrityReference), errors.Is(err, integrity.ErrVersion):
	default:
		// A stored copy that no longer verifies is no reference; the
		// caller reports it like a missing one.
		if a.Err == nil {
			a.Err = err
		}
	}
	return a, nil
}

func admitFiles(store IntegrityReferenceStore, state release.RootState, running, dir string) ReferenceAdmission {
	man, sig, list, err := readReleaseFiles(dir)
	if errors.Is(err, errNoReleaseFiles) {
		return ReferenceAdmission{Outcome: ReferenceNoFiles}
	}
	if err != nil {
		reason := RejectRead
		if errors.Is(err, ErrReferenceFileTooLarge) {
			reason = RejectOversize
		}
		return ReferenceAdmission{Outcome: ReferenceRejected, Rejection: reason, Err: err}
	}
	ref, err := integrity.Admit(state, running, man, sig, list)
	if err != nil {
		return ReferenceAdmission{Outcome: ReferenceRejected, Rejection: classifyAdmitError(err), Err: err}
	}
	added, err := store.AdmitIntegrityReference(executordb.IntegrityReference{
		ReleaseVersion: ref.ReleaseVersion(),
		Manifest:       man, Signature: sig, List: list,
		ManifestSHA256: ref.ManifestDigest(), ListSHA256: ref.ListDigest(),
		SignedBy: ref.SignedBy(),
	})
	switch {
	case errors.Is(err, executordb.ErrReferenceRollback):
		return ReferenceAdmission{Outcome: ReferenceRejected, Rejection: RejectRollback, Err: err}
	case errors.Is(err, executordb.ErrReferenceConflict):
		return ReferenceAdmission{Outcome: ReferenceRejected, Rejection: RejectConflict, Err: err}
	case err != nil:
		return ReferenceAdmission{Outcome: ReferenceFailed, Err: fmt.Errorf("store integrity reference: %w", err)}
	case added:
		return ReferenceAdmission{Outcome: ReferenceAdmitted}
	}
	return ReferenceAdmission{Outcome: ReferenceUnchanged}
}

func classifyAdmitError(err error) ReferenceRejection {
	switch {
	case errors.Is(err, integrity.ErrVersion):
		return RejectVersion
	case errors.Is(err, release.ErrInstalledFiles), errors.Is(err, release.ErrManifestInstalledFiles):
		return RejectHash
	case errors.Is(err, release.ErrFormat):
		return RejectFormat
	}
	// ErrSignature, ErrUntrusted and anything unknown: never trusted.
	return RejectSignature
}

// LoadAdmittedReference returns the active admitted reference from the
// executor's storage, re-verified with integrity.Admit against state and
// the running version. It never reads the release directory.
func LoadAdmittedReference(store IntegrityReferenceStore, state release.RootState, running string) (integrity.Reference, error) {
	r, err := store.ActiveIntegrityReference()
	if err != nil {
		return integrity.Reference{}, err
	}
	return integrity.Admit(state, running, r.Manifest, r.Signature, r.List)
}

// errNoReleaseFiles: the release directory or its list is missing.
var errNoReleaseFiles = errors.New("executor: no installed-files list in the release directory")

// readReleaseFiles reads the three files from dir. A missing directory or
// list is errNoReleaseFiles; a present list without its manifest or
// signature is a read error.
func readReleaseFiles(dir string) (man, sig, list []byte, err error) {
	root, err := os.OpenRoot(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, nil, errNoReleaseFiles
	}
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open release directory: %w", err)
	}
	defer root.Close()
	list, err = readReleaseFile(root, release.InstalledFilesArtifact, release.MaxInstalledFilesDocument)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, nil, errNoReleaseFiles
	}
	if err != nil {
		return nil, nil, nil, err
	}
	if man, err = readReleaseFile(root, release.ManifestFile, release.MaxManifest); err != nil {
		return nil, nil, nil, err
	}
	if sig, err = readReleaseFile(root, release.SignatureFile, release.MaxSignature); err != nil {
		return nil, nil, nil, err
	}
	return man, sig, list, nil
}

// readReleaseFile reads a regular file (never a symlink) of at most limit
// bytes from root.
func readReleaseFile(root *os.Root, name string, limit int64) ([]byte, error) {
	lfi, err := root.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	if !lfi.Mode().IsRegular() {
		return nil, fmt.Errorf("read %s: not a regular file", name)
	}
	// O_NONBLOCK: a FIFO swapped in after the Lstat must not block.
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	if !fi.Mode().IsRegular() || !os.SameFile(lfi, fi) {
		return nil, fmt.Errorf("read %s: file changed while opened", name)
	}
	if fi.Size() > limit {
		return nil, fmt.Errorf("read %s: %w (%d bytes)", name, ErrReferenceFileTooLarge, limit)
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("read %s: %w (%d bytes)", name, ErrReferenceFileTooLarge, limit)
	}
	return b, nil
}

// integrityRefState is the Service's admission status and the source of
// its durable root state.
type integrityRefState struct {
	mu     sync.Mutex
	status ReferenceAdmission
	// roots reads the durable root state; nil until wired.
	roots func() (release.RootState, error)
}

func (s *Service) version() string {
	if s.runningVersion != "" {
		return s.runningVersion
	}
	return version.Version
}

// admitIntegrityReferenceAtStart admits the installed-files reference of
// the running release from bundleDir against the durable root state in
// the built-in trust store at storeDir, and logs the outcome as audit
// records. It never stops the executor: without files or on rejection it
// records that no admitted reference exists (reactions follow in IG-04).
func (s *Service) admitIntegrityReferenceAtStart(d *dirBuiltinTrust) {
	if s.db == nil {
		return
	}
	roots := func() (release.RootState, error) {
		st, err := trust.OpenExisting(d.storeDir, d.now)
		if err != nil {
			return release.RootState{}, fmt.Errorf("open built-in trust store: %w", err)
		}
		return st.RootState(), nil
	}
	a := ReferenceAdmission{Outcome: ReferenceFailed}
	state, err := roots()
	if err == nil {
		a, err = AdmitInstalledFiles(s.db, state, s.version(), d.bundleDir)
	}
	if err != nil {
		a = ReferenceAdmission{Outcome: ReferenceFailed, Err: err}
	}
	s.integrityRef.mu.Lock()
	s.integrityRef.status = a
	s.integrityRef.roots = roots
	s.integrityRef.mu.Unlock()
	s.auditIntegrityReference(a)
}

func (s *Service) auditIntegrityReference(a ReferenceAdmission) {
	if s.log == nil {
		return
	}
	switch a.Outcome {
	case ReferenceAdmitted:
		s.log.Info("audit", "kind", "integrity_reference_admitted",
			"release_version", a.ReleaseVersion, "manifest_sha256", a.ManifestSHA256)
	case ReferenceRejected:
		s.log.Warn("audit", "kind", "integrity_reference_rejected", "reason", string(a.Rejection), "detail", errDetail(a.Err))
	case ReferenceFailed:
		s.log.Error("audit", "kind", "integrity_reference_failed", "detail", errDetail(a.Err))
	}
	if a.Available {
		return
	}
	s.log.Warn("audit", "kind", "integrity_reference_unavailable",
		"outcome", string(a.Outcome), "detail", "no admitted installed-files reference for the running version")
}

func errDetail(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// IntegrityReferenceStatus reports the admission at executor start.
func (s *Service) IntegrityReferenceStatus() ReferenceAdmission {
	s.integrityRef.mu.Lock()
	defer s.integrityRef.mu.Unlock()
	if s.integrityRef.roots == nil {
		return ReferenceAdmission{Outcome: ReferenceNotRun}
	}
	return s.integrityRef.status
}

// AdmittedIntegrityReference returns the admitted reference from the
// executor's own storage, re-verified against the current durable root
// state and the running version; it never reads /usr/share. It fits
// integrity.Monitor.Load.
func (s *Service) AdmittedIntegrityReference(_ context.Context) (integrity.Reference, error) {
	s.integrityRef.mu.Lock()
	roots := s.integrityRef.roots
	s.integrityRef.mu.Unlock()
	if roots == nil || s.db == nil {
		return integrity.Reference{}, integrity.ErrNoReference
	}
	state, err := roots()
	if err != nil {
		return integrity.Reference{}, err
	}
	return LoadAdmittedReference(s.db, state, s.version())
}
