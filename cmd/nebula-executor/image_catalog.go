// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"syscall"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executor/trust"
	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
)

// This file loads the signed image catalog at executor start (ADR 0008
// PV-03c; docs/implementation/pve-image-prepare-wiring.md D2 (a)). The
// catalog and its detached signature are read from the release bundle
// directory (release.CatalogFile, release.CatalogSignatureFile), verified
// with the active release roots of the executor's durable root state (the
// built-in trust store) and loaded with LoadPVEImageCatalog, whose
// LoadSigned keeps the rollback floor across restarts. There is no network
// fetch, no RPC and no reload while running: a new catalog takes effect
// after a release install and a restart.
//
// Every failure is fail closed for the signed catalog and never stops the
// start: a missing or incomplete file pair, a file that is not a regular
// file, unreadable roots, a bad signature and a rollback each write an
// audit line, load no signed catalog and persist no catalog state. Local
// entries (D3 (a)) are served independently of the signed part.

// Audit kinds of the start-time catalog load written here. The service
// writes pve_image_catalog_loaded and pve_image_catalog_refused itself
// for everything that reaches LoadPVEImageCatalog.
const (
	auditImageCatalogAbsent  = "pve_image_catalog_absent"
	auditImageCatalogRefused = "pve_image_catalog_refused"
)

// imageCatalogLoader is the part of *executor.Service the start-time
// catalog load needs.
type imageCatalogLoader interface {
	LoadPVEImageCatalog(roots []release.Root, catalog, sig io.Reader) error
}

// errImageCatalogFile is a catalog or signature path in the bundle
// directory that is not a regular file (symlink, directory, device, ...).
var errImageCatalogFile = errors.New("image catalog: not a regular file")

// loadBundleImageCatalog reads the signed image catalog from bundleDir,
// verifies it with the active roots of the built-in trust store in
// storeDir and loads it into svc. It reports whether a signed catalog was
// loaded. It never fails the start; every refusal is an audit line on log
// (the service's audit lines included) and leaves the signed part empty.
func loadBundleImageCatalog(svc imageCatalogLoader, storeDir, bundleDir string, now func() time.Time, log *slog.Logger) bool {
	cat, sig, err := openBundleImageCatalog(bundleDir)
	if errors.Is(err, fs.ErrNotExist) {
		if cat == nil && sig == nil {
			log.Info("audit", "kind", auditImageCatalogAbsent, "bundle", bundleDir,
				"detail", "no signed image catalog in the release bundle; only local image entries are served")
			return false
		}
		log.Warn("audit", "kind", auditImageCatalogRefused, "reason", "incomplete", "bundle", bundleDir)
		closeAll(cat, sig)
		return false
	}
	if err != nil {
		log.Warn("audit", "kind", auditImageCatalogRefused, "reason", "unreadable", "bundle", bundleDir, "err", err)
		return false
	}
	defer closeAll(cat, sig)

	roots, err := activeReleaseRoots(storeDir, now)
	if err != nil {
		log.Warn("audit", "kind", auditImageCatalogRefused, "reason", "roots", "store", storeDir, "err", err)
		return false
	}
	// LoadPVEImageCatalog writes its own audit line on success and on
	// every refusal; nothing is persisted when it refuses.
	if err := svc.LoadPVEImageCatalog(roots, cat, sig); err != nil {
		log.Warn("no signed image catalog loaded; signed images stay unknown", "bundle", bundleDir)
		return false
	}
	return true
}

// openBundleImageCatalog opens the catalog and its signature inside
// bundleDir as regular files, without following a symlink. When exactly
// one of them is missing, the other is returned open together with an
// error wrapping fs.ErrNotExist; on any other error nothing stays open.
func openBundleImageCatalog(bundleDir string) (cat, sig *os.File, err error) {
	r, err := os.OpenRoot(bundleDir)
	if err != nil {
		return nil, nil, fmt.Errorf("open bundle directory: %w", err)
	}
	defer r.Close()
	cat, cerr := openRegular(r, release.CatalogFile)
	sig, serr := openRegular(r, release.CatalogSignatureFile)
	switch {
	case cerr == nil && serr == nil:
		return cat, sig, nil
	case errors.Is(cerr, fs.ErrNotExist) && (serr == nil || errors.Is(serr, fs.ErrNotExist)),
		errors.Is(serr, fs.ErrNotExist) && cerr == nil:
		return cat, sig, fmt.Errorf("image catalog pair: %w", fs.ErrNotExist)
	default:
		closeAll(cat, sig)
		return nil, nil, errors.Join(cerr, serr)
	}
}

// openRegular opens name in r read-only without following a final
// symlink and requires a regular file.
func openRegular(r *os.Root, name string) (*os.File, error) {
	fi, err := r.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: %w", name, errImageCatalogFile)
	}
	f, err := r.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if fi, err = f.Stat(); err != nil || !fi.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("%s: %w", name, errImageCatalogFile)
	}
	return f, nil
}

func closeAll(files ...*os.File) {
	for _, f := range files {
		if f != nil {
			_ = f.Close()
		}
	}
}

// activeReleaseRoots returns the active release roots of the durable root
// state in the built-in trust store at storeDir. It never bootstraps the
// store (setupBuiltinTrust does that first); a missing or unreadable store
// is an error, so no catalog is admitted against compiled anchors alone.
func activeReleaseRoots(storeDir string, now func() time.Time) ([]release.Root, error) {
	st, err := trust.OpenExisting(storeDir, now)
	if err != nil {
		return nil, fmt.Errorf("open built-in trust store: %w", err)
	}
	// The same active roots the built-in trust review verifies with.
	roots := st.Roots()
	if len(roots) == 0 {
		return nil, errors.New("no active release root")
	}
	return roots, nil
}
