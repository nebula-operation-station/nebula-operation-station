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

// trustRotationTimeout bounds one review-and-commit session, including the
// time the admin takes to compare fingerprints and confirm.
const trustRotationTimeout = time.Hour

// errRotationAborted is an admin abort at the digest prompt; nothing was
// committed.
var errRotationAborted = errors.New("aborted: no digest entered, the root state is unchanged")

// artifactTrustRotation implements `nebula artifact trust-rotation`. It runs
// as the local admin user. The executor reads root-rotation.json and its
// signature from its own local rotation directory, verifies them against
// its durable root state and shows the old and new roots; only after the
// admin types the rotation digest does it apply the rotation, records the
// admin UID and audits it.
func artifactTrustRotation(args []string) error {
	if os.Geteuid() == 0 {
		return errors.New("run `nebula artifact trust-rotation` as your admin user, not as root or with sudo: the executor applies it and records your UID")
	}
	conn, err := dialExecutor()
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), trustRotationTimeout)
	defer cancel()
	return artifactTrustRotationIO(ctx, pb.NewExecutorServiceClient(conn), args, os.Stdin, os.Stdout)
}

// rootRotationClient is the part of the executor client the command uses.
type rootRotationClient interface {
	ReviewRootRotation(ctx context.Context, in *pb.ReviewRootRotationRequest, opts ...grpc.CallOption) (*pb.ReviewRootRotationResponse, error)
	CommitRootRotation(ctx context.Context, in *pb.CommitRootRotationRequest, opts ...grpc.CallOption) (*pb.CommitRootRotationResponse, error)
}

// artifactTrustRotationIO is the testable core of artifactTrustRotation.
func artifactTrustRotationIO(ctx context.Context, c rootRotationClient, args []string, in io.Reader, out io.Writer) error {
	fs := flag.NewFlagSet("artifact trust-rotation", flag.ContinueOnError)
	fs.SetOutput(out)
	yesDigest := fs.String("yes-digest", "", "non-interactive: the reviewed rotation digest to apply")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: nebula artifact trust-rotation [--yes-digest DIGEST]")
	}
	rev, err := c.ReviewRootRotation(ctx, &pb.ReviewRootRotationRequest{})
	if err != nil {
		return fmt.Errorf("review root rotation: %w", err)
	}
	printRotationReview(out, rev)

	digest := *yesDigest
	if digest == "" {
		if digest, err = promptRotationDigest(rev.GetRotationDigest(), bufio.NewScanner(in), out); err != nil {
			return err
		}
	}
	res, err := c.CommitRootRotation(ctx, &pb.CommitRootRotationRequest{RotationDigest: digest})
	if err != nil {
		return fmt.Errorf("commit root rotation: %w", err)
	}
	printRotationResult(out, res)
	return nil
}

// printRotationReview shows the rotation and the old and new roots. Root
// IDs are labels; the admin compares the fingerprints.
func printRotationReview(out io.Writer, r *pb.ReviewRootRotationResponse) {
	fmt.Fprintln(out, "Release root rotation. Compare every fingerprint with the published, offline-checked value;")
	fmt.Fprintln(out, "root IDs are labels, not identities. Rotation never approves an operation.")
	fmt.Fprintln(out)
	fmt.Fprintf(out, "  rotation:  %s\n", safe(r.GetRotationDigest()))
	fmt.Fprintf(out, "  sequence:  %d -> %d\n", r.GetCurrentSequence(), r.GetSequence())
	fmt.Fprintf(out, "  signed by: %s\n", rootLine(r.GetSignedBy()))
	fmt.Fprintf(out, "  store:     generation %d\n", r.GetGeneration())
	fmt.Fprintln(out)
	for _, a := range r.GetAdded() {
		fmt.Fprintf(out, "  ADD    %s\n", rootLine(a))
	}
	for _, id := range r.GetRevoked() {
		fmt.Fprintf(out, "  REVOKE %s\n", safe(id))
	}
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Roots before:")
	for _, x := range r.GetOldRoots() {
		fmt.Fprintf(out, "  %s\n", rootLine(x))
	}
	fmt.Fprintln(out, "Roots after:")
	for _, x := range r.GetNewRoots() {
		fmt.Fprintf(out, "  %s\n", rootLine(x))
	}
	fmt.Fprintln(out)
}

// rootLine renders one root: ID, fingerprint and lifecycle, as text only.
func rootLine(r *pb.ReleaseRoot) string {
	state := "active"
	if r.GetRevokedSequence() != 0 {
		state = fmt.Sprintf("revoked at %d", r.GetRevokedSequence())
	}
	return fmt.Sprintf("%s %s (%s, added at %d)", safe(r.GetId()), safe(r.GetFingerprint()), state, r.GetAddedSequence())
}

// promptRotationDigest asks the admin to type the reviewed rotation
// digest. An empty line or end of input aborts without committing.
func promptRotationDigest(digest string, sc *bufio.Scanner, out io.Writer) (string, error) {
	for {
		fmt.Fprint(out, "type the rotation digest to apply (empty to abort): ")
		if !sc.Scan() {
			return "", errRotationAborted
		}
		entered := strings.TrimSpace(sc.Text())
		if entered == "" {
			return "", errRotationAborted
		}
		if entered == digest {
			return entered, nil
		}
		fmt.Fprintln(out, "  digest does not match; try again")
	}
}

// printRotationResult shows what the executor applied and audited.
func printRotationResult(out io.Writer, r *pb.CommitRootRotationResponse) {
	fmt.Fprintln(out, "applied:")
	fmt.Fprintf(out, "  admin uid:  %d\n", r.GetAdminUid())
	fmt.Fprintf(out, "  rotation:   %s\n", safe(r.GetRotationDigest()))
	fmt.Fprintf(out, "  sequence:   %d\n", r.GetSequence())
	fmt.Fprintf(out, "  generation: %d\n", r.GetGeneration())
	fmt.Fprintf(out, "  signed by:  %s\n", rootLine(r.GetSignedBy()))
	for _, x := range r.GetRoots() {
		fmt.Fprintf(out, "  root: %s\n", rootLine(x))
	}
	fmt.Fprintln(out, "New releases are verified against these roots; existing trust is not changed.")
}
