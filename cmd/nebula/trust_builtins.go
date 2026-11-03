// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// trustBuiltinsTimeout bounds one review-and-commit session, including the
// time the admin takes to read the review and confirm.
const trustBuiltinsTimeout = 2 * time.Hour

// maxBuiltinDiffLine bounds one rendered diff line.
const maxBuiltinDiffLine = 4000

// trustVersionsFlag is a repeatable flag holding old versions (name@version).
type trustVersionsFlag []string

func (f *trustVersionsFlag) String() string { return strings.Join(*f, ",") }
func (f *trustVersionsFlag) Set(s string) error {
	*f = append(*f, s)
	return nil
}

// artifactTrustBuiltins implements `nebula artifact trust-builtins` (ADR 0007
// E16). It runs as a local admin user and talks to the executor, which reads
// its own configured, locally verified release bundle, reviews it against
// its built-in trust store and, after one digest-bound confirmation, commits
// the whole review atomically: the store, the exact artifact trust the risk
// policy reads (as `nebula artifact trust` writes it) and an audit record
// with the admin UID and every old/new trust tuple. Each old version is
// explicitly retained or retired; retirement revokes its trust.
func artifactTrustBuiltins(args []string) error {
	if os.Geteuid() == 0 {
		return errors.New("run `nebula artifact trust-builtins` as your admin user, not as root or with sudo: the executor commits it and records your UID")
	}
	conn, err := dialExecutor()
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), trustBuiltinsTimeout)
	defer cancel()
	return artifactTrustBuiltinsIO(ctx, pb.NewExecutorServiceClient(conn), args, os.Stdin, os.Stdout)
}

// builtinTrustClient is the part of the executor client the command uses.
type builtinTrustClient interface {
	ReviewBuiltinTrust(ctx context.Context, in *pb.ReviewBuiltinTrustRequest, opts ...grpc.CallOption) (*pb.ReviewBuiltinTrustResponse, error)
	CommitBuiltinTrust(ctx context.Context, in *pb.CommitBuiltinTrustRequest, opts ...grpc.CallOption) (*pb.CommitBuiltinTrustResponse, error)
}

// artifactTrustBuiltinsIO is the testable core of artifactTrustBuiltins.
func artifactTrustBuiltinsIO(ctx context.Context, c builtinTrustClient, args []string, in io.Reader, out io.Writer) error {
	fs := flag.NewFlagSet("artifact trust-builtins", flag.ContinueOnError)
	fs.SetOutput(out)
	yesDigest := fs.String("yes-digest", "", "non-interactive: the reviewed manifest digest to commit")
	var pins, retired trustVersionsFlag
	fs.Var(&pins, "pin", "non-interactive: old version name@version to retain (repeatable)")
	fs.Var(&retired, "retire", "non-interactive: old version name@version to retire (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || (*yesDigest == "" && (len(pins) > 0 || len(retired) > 0)) {
		return errors.New("usage: nebula artifact trust-builtins [--yes-digest DIGEST [--pin name@ver] [--retire name@ver]]")
	}

	rev, err := c.ReviewBuiltinTrust(ctx, &pb.ReviewBuiltinTrustRequest{})
	if err != nil {
		return fmt.Errorf("review built-ins: %w", err)
	}
	printTrustReview(out, rev)
	if !rev.GetNeedsConfirmation() {
		fmt.Fprintln(out, "no changes: every action is unchanged, nothing to commit")
		return nil
	}

	var retain, retire []string
	if *yesDigest != "" {
		retain, retire = pins, retired
	} else {
		// One scanner for every answer, so no prompt swallows the next line.
		sc := bufio.NewScanner(in)
		pinSet, retiredList, err := promptOldVersions(rev.GetOldVersions(), sc, out)
		if err != nil {
			return err
		}
		for _, v := range rev.GetOldVersions() {
			if pinSet[v] {
				retain = append(retain, v)
			}
		}
		retire = retiredList
		if *yesDigest, err = promptDigest(rev.GetManifestDigest(), sc, out); err != nil {
			return err
		}
	}

	res, err := c.CommitBuiltinTrust(ctx, &pb.CommitBuiltinTrustRequest{
		ManifestDigest: *yesDigest, Retain: retain, Retire: retire,
	})
	if err != nil {
		return fmt.Errorf("commit built-ins: %w", err)
	}
	printTrustResult(out, res)
	return nil
}

// printTrustReview shows the executor-verdict banner and the action-by-action
// review (old/new versions, hashes, risk, full script diff, scanner findings).
// Everything from the bundle is rendered as escaped text only.
func printTrustReview(out io.Writer, r *pb.ReviewBuiltinTrustResponse) {
	if r.GetNeedsConfirmation() {
		fmt.Fprintln(out, "Built-ins are untrusted: every operation using them needs UV until you trust them.")
	}
	fmt.Fprintln(out, "Trust may restore declared risks; it never approves a mutation.")
	fmt.Fprintln(out)
	fmt.Fprintf(out, "  release:  %s\n", safe(r.GetReleaseVersion()))
	fmt.Fprintf(out, "  manifest: %s\n", safe(r.GetManifestDigest()))
	fmt.Fprintf(out, "  root:     %s (%s)\n", safe(r.GetRootId()), safe(r.GetRootFingerprint()))
	fmt.Fprintf(out, "  store:    generation %d\n", r.GetGeneration())
	fmt.Fprintln(out)

	for _, m := range r.GetModules() {
		printModuleReview(out, m)
	}

	if len(r.GetOldVersions()) > 0 {
		fmt.Fprintln(out, "Old versions to decide (retain keeps their trust, retire revokes it):")
		for _, v := range r.GetOldVersions() {
			fmt.Fprintf(out, "  %s\n", safe(v))
		}
		fmt.Fprintln(out)
	}
}

func printModuleReview(out io.Writer, m *pb.BuiltinModuleReview) {
	fmt.Fprintf(out, "MODULE %s\n", safe(m.GetName()))
	fmt.Fprintf(out, "  status:  %s\n", changeName(m.GetChange()))
	if m.GetFullReview() {
		fmt.Fprintf(out, "  full:    yes (%s)\n", safe(m.GetFullReviewReason()))
	}
	switch {
	case m.GetOldVersion() != "" && m.GetNewVersion() != "":
		fmt.Fprintf(out, "  version: %s -> %s\n", safe(m.GetOldVersion()), safe(m.GetNewVersion()))
		fmt.Fprintf(out, "  sha256:  %s -> %s\n", shortHash(m.GetOldSha256()), shortHash(m.GetNewSha256()))
	case m.GetOldVersion() != "":
		fmt.Fprintf(out, "  version: %s -> (removed)\n", safe(m.GetOldVersion()))
	default:
		fmt.Fprintf(out, "  version: (new) -> %s\n", safe(m.GetNewVersion()))
	}
	for _, a := range m.GetActions() {
		printActionReview(out, a)
	}
	fmt.Fprintln(out)
}

func printActionReview(out io.Writer, a *pb.BuiltinActionReview) {
	fmt.Fprintf(out, "  ACTION %s\n", safe(a.GetActionId()))
	fmt.Fprintf(out, "    status:   %s\n", changeName(a.GetChange()))
	fmt.Fprintf(out, "    risk:     %s -> %s\n", orDash(safe(a.GetOldRisk())), orDash(safe(a.GetNewRisk())))
	fmt.Fprintf(out, "    script:   %s -> %s\n", shortHash(a.GetOldScriptSha256()), shortHash(a.GetNewScriptSha256()))
	fmt.Fprintf(out, "    artifact: %s -> %s\n", orDash(a.GetOldArtifactSha256()), orDash(a.GetNewArtifactSha256()))
	if len(a.GetDiff()) > 0 {
		fmt.Fprintln(out, "    diff:")
		for _, l := range a.GetDiff() {
			prefix := "      "
			switch l.GetOp() {
			case pb.BuiltinDiffOp_BUILTIN_DIFF_OP_INSERT:
				prefix = "      +"
			case pb.BuiltinDiffOp_BUILTIN_DIFF_OP_DELETE:
				prefix = "      -"
			}
			fmt.Fprintf(out, "%s%s\n", prefix, displaySafe([]byte(l.GetText()), maxBuiltinDiffLine))
		}
	}
	if a.GetScannerFloor() != pb.RiskClass_RISK_CLASS_UNSPECIFIED || len(a.GetFindings()) > 0 {
		if len(a.GetFindings()) == 0 {
			fmt.Fprintf(out, "    scanner: clean (floor %s)\n", shortRisk(a.GetScannerFloor()))
		} else {
			fmt.Fprintf(out, "    scanner: floor %s\n", shortRisk(a.GetScannerFloor()))
			for _, f := range a.GetFindings() {
				fmt.Fprintf(out, "      [%s] line %d: %s\n", shortRisk(f.GetRisk()), f.GetLine(), displaySafe([]byte(f.GetExcerpt()), 200))
			}
		}
	}
}

// printTrustResult shows the executor's commit result: the audit facts
// (admin UID, old/new trust tuples, retained, retired and collected
// versions, cleanup failures).
func printTrustResult(out io.Writer, r *pb.CommitBuiltinTrustResponse) {
	fmt.Fprintln(out, "committed:")
	fmt.Fprintf(out, "  admin uid:  %d\n", r.GetAdminUid())
	fmt.Fprintf(out, "  generation: %d\n", r.GetGeneration())
	fmt.Fprintf(out, "  manifest:   %s\n", safe(r.GetManifestDigest()))
	for _, t := range r.GetTuples() {
		fmt.Fprintf(out, "  trust: %s %s -> %s (%s)\n", safe(t.GetModule()), orDash(safe(t.GetOldVersion())),
			orDash(safe(t.GetNewVersion())), changeName(t.GetChange()))
	}
	if len(r.GetRetained()) > 0 {
		fmt.Fprintf(out, "  retained:  %s\n", safe(strings.Join(r.GetRetained(), ", ")))
	}
	if len(r.GetRetired()) > 0 {
		fmt.Fprintf(out, "  retired:   %s (trust revoked)\n", safe(strings.Join(r.GetRetired(), ", ")))
	}
	if len(r.GetCollected()) > 0 {
		fmt.Fprintf(out, "  collected: %s\n", safe(strings.Join(r.GetCollected(), ", ")))
	}
	if r.GetCleanupFailures() > 0 {
		fmt.Fprintf(out, "  cleanup failures: %d unreferenced object(s) could not be deleted\n", r.GetCleanupFailures())
	}
	fmt.Fprintln(out, "The committed versions are now trusted exactly like `nebula artifact trust` (see `nebula artifact list`).")
	fmt.Fprintln(out, "Read leases bind exact versions: approve a replacement lease for new versions.")
}

// changeName is the lower-case review status.
func changeName(c pb.BuiltinTrustChange) string {
	return strings.ToLower(strings.TrimPrefix(c.String(), "BUILTIN_TRUST_CHANGE_"))
}

// promptOldVersions asks the admin to retain or retire each old version.
func promptOldVersions(oldVersions []string, sc *bufio.Scanner, out io.Writer) (map[string]bool, []string, error) {
	pins := map[string]bool{}
	retired := []string{}
	for _, v := range oldVersions {
		for {
			fmt.Fprintf(out, "retain %s [r] or retire [t]? ", safe(v))
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
func promptDigest(digest string, sc *bufio.Scanner, out io.Writer) (string, error) {
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

// shortHash shows the first 12 hex chars of a hash (or a dash when empty).
func shortHash(h string) string {
	if h == "" {
		return "-"
	}
	if len(h) > 12 {
		return safe(h[:12])
	}
	return safe(h)
}

// orDash shows a string or a dash when empty.
func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
