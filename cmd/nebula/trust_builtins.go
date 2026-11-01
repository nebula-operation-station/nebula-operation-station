// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executor/trust"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
	"github.com/nebula-operation-station/nebula-operation-station/internal/textdiff"
)

// defaultTrustStoreDir is where the executor keeps its built-in trust store,
// under the executor data dir.
const defaultTrustStoreDir = "/var/lib/nebula/executor/trust"

// trustVersionsFlag is a repeatable flag holding old versions (name@version).
type trustVersionsFlag []string

func (f *trustVersionsFlag) String() string { return strings.Join(*f, ",") }
func (f *trustVersionsFlag) Set(s string) error {
	*f = append(*f, s)
	return nil
}

// artifactTrustBuiltins implements `nebula artifact trust-builtins` (ADR 0007
// E16). It runs as root (sudo), reads a locally verified release bundle,
// reviews it against the executor's built-in trust store, shows every
// addition, change and removal with the executor scanner's findings, and after
// one digest-bound confirmation commits the whole review atomically. Each old
// version is explicitly retained (pinned) or retired.
func artifactTrustBuiltins(args []string) error {
	return artifactTrustBuiltinsIO(args, os.Stdin, os.Stdout)
}

// artifactTrustBuiltinsIO is the testable core of artifactTrustBuiltins.
func artifactTrustBuiltinsIO(args []string, in io.Reader, out io.Writer) error {
	fs := flag.NewFlagSet("artifact trust-builtins", flag.ContinueOnError)
	fs.SetOutput(out)
	bundle := fs.String("bundle", "", "the locally verified release bundle directory (required)")
	store := fs.String("store", defaultTrustStoreDir, "the built-in trust store directory")
	yesDigest := fs.String("yes-digest", "", "non-interactive: the reviewed manifest digest to commit")
	var pins, retired trustVersionsFlag
	fs.Var(&pins, "pin", "non-interactive: old version name@version to retain (repeatable)")
	fs.Var(&retired, "retire", "non-interactive: old version name@version to retire (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *bundle == "" {
		return errors.New("usage: nebula artifact trust-builtins --bundle DIR [--store DIR] [--yes-digest DIGEST] [--pin name@ver] [--retire name@ver]")
	}
	return runTrustBuiltins(*bundle, *store, *yesDigest, pins, retired, in, out)
}

// runTrustBuiltins opens the trust store with the release anchors, reviews the
// bundle, shows the review and, after one digest-bound confirmation, commits
// it atomically.
func runTrustBuiltins(bundleDir, storeDir, yesDigest string, pins, retired trustVersionsFlag, in io.Reader, out io.Writer) error {
	anchors, err := release.Anchors()
	if err != nil {
		return fmt.Errorf("release anchors: %w", err)
	}
	s, err := trust.Open(storeDir, anchors, time.Now)
	if err != nil {
		return fmt.Errorf("open trust store %s: %w", storeDir, err)
	}

	c, err := release.ReadBundleDir(bundleDir, s.Roots())
	if err != nil {
		return fmt.Errorf("read bundle %s: %w", bundleDir, err)
	}

	// Dry run: review + scanner floors, no commit.
	dry, err := s.BulkAdmit(c, trust.BulkAdmitOpts{})
	if err != nil {
		return fmt.Errorf("review bundle: %w", err)
	}
	printTrustReview(out, dry)

	if !dry.NeedsConfirmation {
		fmt.Fprintln(out, "no changes: every action is unchanged, nothing to commit")
		return nil
	}

	pinSet := map[string]bool{}
	retiredList := []string{}
	if yesDigest != "" {
		for _, v := range pins {
			pinSet[v] = true
		}
		retiredList = append(retiredList, retired...)
	} else {
		pinSet, retiredList, err = promptOldVersions(dry.OldVersions, in, out)
		if err != nil {
			return err
		}
		yesDigest, err = promptDigest(dry.ManifestDigest, in, out)
		if err != nil {
			return err
		}
	}

	res, err := s.BulkAdmit(c, trust.BulkAdmitOpts{
		ConfirmedDigest: yesDigest,
		Pins:            pinSet,
		Retired:         retiredList,
		AdminUID:        adminUID(),
	})
	if err != nil {
		return err
	}
	printTrustResult(out, res, s.Generation())

	// We ran as root; hand the store back to the executor so it stays
	// executor-owned.
	if err := chownTrustStore(storeDir); err != nil {
		return fmt.Errorf("restore trust store ownership: %w", err)
	}
	return nil
}

// printTrustReview shows the executor-verdict banner and the action-by-action
// review (old/new versions, hashes, risk, full script diff, scanner findings).
// Script content and scanner excerpts are host-author text: rendered as text
// only.
func printTrustReview(out io.Writer, res trust.BulkAdmitResult) {
	r := res.Review
	fmt.Fprintln(out, "Built-ins are untrusted: every operation using them needs UV until you trust them.")
	fmt.Fprintln(out, "Trust may restore declared risks; it never approves a mutation.")
	fmt.Fprintln(out)
	fmt.Fprintf(out, "  release:  %s\n", r.ReleaseVersion)
	fmt.Fprintf(out, "  manifest: %s\n", r.ManifestDigest)
	fmt.Fprintf(out, "  root:     %s (%s)\n", r.RootID, r.RootFingerprint)
	fmt.Fprintf(out, "  store:    generation %d\n", r.Generation)
	fmt.Fprintln(out)

	for _, m := range r.Modules {
		printModuleReview(out, m, res.Scans)
	}

	if len(res.OldVersions) > 0 {
		fmt.Fprintln(out, "Old versions to decide (retain or retire):")
		for _, v := range res.OldVersions {
			fmt.Fprintf(out, "  %s\n", v)
		}
		fmt.Fprintln(out)
	}
}

func printModuleReview(out io.Writer, m trust.ModuleReview, scans []trust.ScanFinding) {
	fmt.Fprintf(out, "MODULE %s\n", m.Name)
	fmt.Fprintf(out, "  status:  %s\n", m.Status)
	if m.FullReview {
		fmt.Fprintf(out, "  full:    yes (%s)\n", m.Reason)
	}
	switch {
	case m.OldVersion != "" && m.NewVersion != "":
		fmt.Fprintf(out, "  version: %s -> %s\n", m.OldVersion, m.NewVersion)
		fmt.Fprintf(out, "  sha256:  %s -> %s\n", shortHash(m.OldSHA256), shortHash(m.NewSHA256))
	case m.OldVersion != "":
		fmt.Fprintf(out, "  version: %s -> (removed)\n", m.OldVersion)
	default:
		fmt.Fprintf(out, "  version: (new) -> %s\n", m.NewVersion)
	}
	for _, a := range m.Actions {
		printActionReview(out, a, scans)
	}
	fmt.Fprintln(out)
}

func printActionReview(out io.Writer, a trust.ActionReview, scans []trust.ScanFinding) {
	fmt.Fprintf(out, "  ACTION %s\n", a.ActionID)
	fmt.Fprintf(out, "    status: %s\n", a.Status)
	fmt.Fprintf(out, "    risk:   %s -> %s\n", orDash(a.OldRisk), orDash(a.NewRisk))
	fmt.Fprintf(out, "    script: %s -> %s\n", shortHash(a.OldScriptSHA256), shortHash(a.NewScriptSHA256))
	if len(a.Diff) > 0 {
		fmt.Fprintln(out, "    diff:")
		for _, l := range a.Diff {
			prefix := "      "
			switch l.Op {
			case textdiff.Insert:
				prefix = "      +"
			case textdiff.Delete:
				prefix = "      -"
			}
			fmt.Fprintf(out, "%s%s\n", prefix, displaySafe([]byte(l.Text), 4000))
		}
	}
	if sf := findScan(scans, a.ActionID); sf != nil {
		if len(sf.Findings) == 0 {
			fmt.Fprintf(out, "    scanner: clean (floor %s)\n", orDash(sf.Floor))
		} else {
			fmt.Fprintf(out, "    scanner: floor %s\n", orDash(sf.Floor))
			for _, f := range sf.Findings {
				fmt.Fprintf(out, "      [%s] line %d: %s\n", f.Risk, f.Line, displaySafe([]byte(f.Excerpt), 200))
			}
		}
	}
}

func findScan(scans []trust.ScanFinding, actionID string) *trust.ScanFinding {
	for i := range scans {
		if scans[i].ActionID == actionID {
			return &scans[i]
		}
	}
	return nil
}

// printTrustResult shows the commit result: the retirement audit (admin UID,
// old/new trust tuples, pinned, retired, collected versions, cleanup failures).
func printTrustResult(out io.Writer, res trust.BulkAdmitResult, newGen int64) {
	if !res.Committed {
		fmt.Fprintln(out, "not committed")
		return
	}
	fmt.Fprintln(out, "committed:")
	fmt.Fprintf(out, "  admin uid:  %d\n", res.AdminUID)
	fmt.Fprintf(out, "  generation: %d\n", newGen)
	fmt.Fprintf(out, "  manifest:   %s\n", res.ManifestDigest)
	fmt.Fprintf(out, "  release:    %s\n", res.Review.ReleaseVersion)
	for _, t := range res.Tuples {
		fmt.Fprintf(out, "  trust: %s %s -> %s (%s)\n", t.Module, orDash(t.OldVersion), orDash(t.NewVersion), t.Status)
	}
	if len(res.Pinned) > 0 {
		fmt.Fprintf(out, "  pinned:    %s\n", strings.Join(res.Pinned, ", "))
	}
	if len(res.Retired) > 0 {
		fmt.Fprintf(out, "  retired:   %s\n", strings.Join(res.Retired, ", "))
	}
	if len(res.Collected) > 0 {
		fmt.Fprintf(out, "  collected: %s\n", strings.Join(res.Collected, ", "))
	}
	if res.CleanupFailures > 0 {
		fmt.Fprintf(out, "  cleanup failures: %d unreferenced object(s) could not be deleted\n", res.CleanupFailures)
	}
}

// promptOldVersions asks the admin to retain or retire each old version.
func promptOldVersions(oldVersions []string, in io.Reader, out io.Writer) (map[string]bool, []string, error) {
	pins := map[string]bool{}
	retired := []string{}
	sc := bufio.NewScanner(in)
	for _, v := range oldVersions {
		for {
			fmt.Fprintf(out, "retain %s [r] or retire [t]? ", v)
			if !sc.Scan() {
				return nil, nil, errors.New("reading decision")
			}
			switch strings.ToLower(strings.TrimSpace(sc.Text())) {
			case "r", "retain":
				pins[v] = true
			case "t", "retire":
				retired = append(retired, v)
			default:
				fmt.Fprintln(out, "  enter r (retain) or t (retire)")
				continue
			}
			break
		}
	}
	return pins, retired, nil
}

// promptDigest asks the admin to type the reviewed manifest digest to commit.
// An empty line aborts.
func promptDigest(digest string, in io.Reader, out io.Writer) (string, error) {
	sc := bufio.NewScanner(in)
	for {
		fmt.Fprintf(out, "type the manifest digest to commit (empty to abort): ")
		if !sc.Scan() {
			return "", errors.New("reading digest")
		}
		entered := strings.TrimSpace(sc.Text())
		if entered == "" {
			return "", errors.New("aborted: no digest entered")
		}
		if entered == digest {
			return entered, nil
		}
		fmt.Fprintln(out, "  digest does not match; try again")
	}
}

// adminUID is the UID of the admin running the command: SUDO_USER when we run
// as root (sudo), the current user otherwise.
func adminUID() int {
	if os.Geteuid() != 0 {
		return os.Getuid()
	}
	if su := os.Getenv("SUDO_USER"); su != "" {
		if uid, err := peercred.LookupUID(su); err == nil {
			return int(uid)
		}
	}
	return 0
}

// chownTrustStore hands the trust store back to the executor user after we
// (as root) wrote to it. It is a no-op when not running as root.
func chownTrustStore(dir string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	name := envOr("NEBULA_EXECUTOR_USER", "nebula-executor")
	u, err := user.Lookup(name)
	if err != nil {
		return fmt.Errorf("executor user %s: %w", name, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return fmt.Errorf("executor uid %q: %w", u.Uid, err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return fmt.Errorf("executor gid %q: %w", u.Gid, err)
	}
	return filepath.Walk(dir, func(p string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(p, uid, gid)
	})
}

// shortHash shows the first 12 hex chars of a hash (or a dash when empty).
func shortHash(h string) string {
	if h == "" {
		return "-"
	}
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// orDash shows a string or a dash when empty.
func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
