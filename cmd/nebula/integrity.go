// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strconv"

	"github.com/nebula-operation-station/nebula-operation-station/internal/integrity"
	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
)

// Exit statuses of `nebula integrity verify --offline` (ADR 0015 D4).
// 0 means a complete run in which every listed file matched and no extra
// /usr/bin/nebula* entry exists; nothing else is ever 0.
const (
	// ExitIntegrityDeviation: at least one file is different, missing or
	// extra.
	ExitIntegrityDeviation = 5
	// ExitIntegrityIncomplete: no deviation was found, but the run could
	// not check everything (a limit, an I/O error, an unreadable file or
	// an unresolvable owner, a root or flavour that could not be opened).
	// It is never clean.
	ExitIntegrityIncomplete = 6
)

const integrityUsage = "usage: nebula integrity verify --offline RELEASE-DIR --root MOUNT --version X.Y.Z --flavour FLAVOUR"

// offlineConfig is one offline check. The version and flavour come from
// the admin, never from the checked installation (ADR 0015 D2).
type offlineConfig struct {
	releaseDir string
	root       string
	version    string
	flavour    string
	// maxFiles and maxBytes lower the integrity limits; 0 means the
	// package default. Only tests set them.
	maxFiles int
	maxBytes int64
	// owners resolves listed owners; nil means integrity.OfflineOwners.
	owners func(string) (uint32, uint32, error)
}

// integrityCmd runs `nebula integrity ...`. It needs no executor and no
// socket: the offline check reads a release directory and a mounted
// installation, trusts only the release anchors compiled into this
// binary, and writes nothing.
func integrityCmd(args []string, w io.Writer) error {
	if len(args) == 0 || args[0] != "verify" {
		return errors.New(integrityUsage)
	}
	cfg, err := parseOfflineArgs(args[1:])
	if err != nil {
		return err
	}
	return runOffline(context.Background(), cfg, release.Anchors, w)
}

func parseOfflineArgs(args []string) (offlineConfig, error) {
	fs := flag.NewFlagSet("integrity verify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var cfg offlineConfig
	fs.StringVar(&cfg.releaseDir, "offline", "", "directory with release-manifest.json, its .sig and installed-files.json, fetched and kept on another machine")
	fs.StringVar(&cfg.root, "root", "", "mount point of the NOS installation to check")
	fs.StringVar(&cfg.version, "version", "", "release version the installation must be (never taken from the installation)")
	fs.StringVar(&cfg.flavour, "flavour", "", "install flavour, for example deb:amd64")
	if err := fs.Parse(args); err != nil {
		return offlineConfig{}, fmt.Errorf("%s: %w", integrityUsage, err)
	}
	if fs.NArg() != 0 || cfg.releaseDir == "" || cfg.root == "" || cfg.version == "" || cfg.flavour == "" {
		return offlineConfig{}, errors.New(integrityUsage)
	}
	if !filepath.IsAbs(cfg.releaseDir) || !filepath.IsAbs(cfg.root) {
		return offlineConfig{}, errors.New("integrity verify: --offline and --root must be absolute paths")
	}
	return cfg, nil
}

// runOffline admits the release in cfg.releaseDir against anchors (the
// compiled release anchors outside tests) and checks cfg.root against it.
// Nothing is printed before the release is admitted.
func runOffline(ctx context.Context, cfg offlineConfig, anchors func() ([]release.Anchor, error), w io.Writer) error {
	a, err := anchors()
	if err != nil {
		return fmt.Errorf("integrity verify: compiled release anchors: %w", err)
	}
	rel, err := integrity.ReadRelease(cfg.releaseDir)
	if err != nil {
		return fmt.Errorf("integrity verify: %w", err)
	}
	ref, err := integrity.AdmitRelease(a, cfg.version, rel)
	if err != nil {
		return fmt.Errorf("integrity verify: release not admitted, nothing checked: %w", err)
	}
	owners := cfg.owners
	if owners == nil {
		owners = integrity.OfflineOwners
	}
	rep, err := integrity.Check(ctx, ref, integrity.Options{
		Root:     cfg.root,
		Flavour:  cfg.flavour,
		MaxFiles: cfg.maxFiles,
		MaxBytes: cfg.maxBytes,
		Budget:   integrity.MaxBudget,
		Owners:   owners,
	})
	if err != nil {
		return &exitError{code: ExitIntegrityIncomplete, msg: "integrity verify: INCOMPLETE, nothing checked: " + err.Error(), err: err}
	}
	return printOffline(w, cfg, ref, rep)
}

func printOffline(w io.Writer, cfg offlineConfig, ref integrity.Reference, rep integrity.Report) error {
	fmt.Fprintf(w, "offline integrity check (ADR 0015 D4)\n")
	fmt.Fprintf(w, "release %s, flavour %s, signed by %s (compiled release anchors)\n",
		safeText(rep.ReleaseVersion), safeText(rep.Flavour), safeText(ref.SignedBy()))
	fmt.Fprintf(w, "manifest sha256:%s\nlist     sha256:%s\nroot     %s\n",
		safeText(rep.ManifestDigest), safeText(rep.ListDigest), safeText(cfg.root))
	counts := map[integrity.Status]int{}
	listed := 0
	for _, f := range rep.Files {
		counts[f.Status]++
		if f.Status != integrity.StatusExtra {
			listed++
		}
		if f.Status == integrity.StatusOK || f.Status == integrity.StatusNotChecked {
			continue
		}
		line := fmt.Sprintf("%-10s %-10s %s", f.Status, f.Class, safeText(f.Path))
		if f.Reason != "" {
			line += " (" + string(f.Reason) + ")"
		}
		fmt.Fprintln(w, line)
	}
	fmt.Fprintf(w, "summary: %d listed: %d matching, %d different, %d missing, %d unreadable, %d not checked; %d extra\n",
		listed, counts[integrity.StatusOK], counts[integrity.StatusDifferent], counts[integrity.StatusMissing],
		counts[integrity.StatusUnreadable], counts[integrity.StatusNotChecked], counts[integrity.StatusExtra])

	deviations := counts[integrity.StatusDifferent] + counts[integrity.StatusMissing] + counts[integrity.StatusExtra]
	incomplete := !rep.Complete || rep.Incomplete != "" || counts[integrity.StatusUnreadable] > 0 || counts[integrity.StatusNotChecked] > 0
	why := ""
	if rep.Incomplete != "" {
		why = " (" + string(rep.Incomplete) + ")"
	}
	switch {
	case deviations > 0:
		if incomplete {
			fmt.Fprintf(w, "result: DEVIATIONS; the run was also INCOMPLETE%s\n", why)
		} else {
			fmt.Fprintln(w, "result: DEVIATIONS")
		}
		return &exitError{code: ExitIntegrityDeviation, msg: "integrity verify: the installation differs from the signed release"}
	case incomplete:
		fmt.Fprintf(w, "result: INCOMPLETE%s: not clean\n", why)
		return &exitError{code: ExitIntegrityIncomplete, msg: "integrity verify: the check is incomplete, not clean"}
	case !rep.Clean():
		// Unreachable by the counts above; never report clean by accident.
		return &exitError{code: ExitIntegrityIncomplete, msg: "integrity verify: the check is incomplete, not clean"}
	}
	fmt.Fprintln(w, "result: clean")
	return nil
}

// safeText returns s, or s with every non-printable or non-ASCII rune
// escaped when it has any. Paths from the signed list are restricted to
// [A-Za-z0-9/._+-] and extra names are already escaped by the integrity
// package; this is a second guard for terminal output.
func safeText(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			q := strconv.QuoteToASCII(s)
			return q[1 : len(q)-1]
		}
	}
	return s
}
