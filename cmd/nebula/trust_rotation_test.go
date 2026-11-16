// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// fakeRotationClient records the requests sent to the executor.
type fakeRotationClient struct {
	review    *pb.ReviewRootRotationResponse
	reviewErr error
	commitErr error
	reviews   int
	commits   []*pb.CommitRootRotationRequest
}

func (f *fakeRotationClient) ReviewRootRotation(context.Context, *pb.ReviewRootRotationRequest, ...grpc.CallOption) (*pb.ReviewRootRotationResponse, error) {
	f.reviews++
	return f.review, f.reviewErr
}

func (f *fakeRotationClient) CommitRootRotation(_ context.Context, in *pb.CommitRootRotationRequest, _ ...grpc.CallOption) (*pb.CommitRootRotationResponse, error) {
	f.commits = append(f.commits, in)
	if f.commitErr != nil {
		return nil, f.commitErr
	}
	return &pb.CommitRootRotationResponse{RotationDigest: in.GetRotationDigest(), Sequence: 1, Generation: 5, AdminUid: 1000,
		SignedBy: f.review.GetSignedBy(), Roots: f.review.GetNewRoots()}, nil
}

func sampleRotation() *pb.ReviewRootRotationResponse {
	r1 := &pb.ReleaseRoot{Id: "root-1", Fingerprint: "SHA256:one"}
	return &pb.ReviewRootRotationResponse{
		RotationDigest: sampleDigest, Sequence: 1, CurrentSequence: 0, Generation: 4, SignedBy: r1,
		OldRoots: []*pb.ReleaseRoot{r1},
		NewRoots: []*pb.ReleaseRoot{{Id: "root-1", Fingerprint: "SHA256:one", RevokedSequence: 1},
			{Id: "root-2", Fingerprint: "SHA256:two\x1b[2J", AddedSequence: 1}},
		Added:   []*pb.ReleaseRoot{{Id: "root-2", Fingerprint: "SHA256:two\x1b[2J", AddedSequence: 1}},
		Revoked: []string{"root-1"},
	}
}

// The review shows old and new roots with fingerprints, escaped; typing the
// digest applies exactly the reviewed digest.
func TestTrustRotationShowsRootsAndCommitsTypedDigest(t *testing.T) {
	f := &fakeRotationClient{review: sampleRotation()}
	var out bytes.Buffer
	in := strings.NewReader("wrong\n" + sampleDigest + "\n")
	if err := artifactTrustRotationIO(context.Background(), f, nil, in, &out); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	for _, want := range []string{"sequence:  0 -> 1", "signed by: root-1 SHA256:one", "ADD    root-2", "REVOKE root-1",
		"Roots before:", "Roots after:", "revoked at 1", "digest does not match", "admin uid:  1000"} {
		if !strings.Contains(s, want) {
			t.Errorf("output lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "\x1b") {
		t.Error("terminal escape rendered raw")
	}
	if len(f.commits) != 1 || f.commits[0].GetRotationDigest() != sampleDigest {
		t.Fatalf("commits = %v", f.commits)
	}
}

// Aborting without input (empty line or end of input) commits nothing.
func TestTrustRotationAbortWithoutInputChangesNothing(t *testing.T) {
	for _, in := range []string{"", "\n", "  \n"} {
		f := &fakeRotationClient{review: sampleRotation()}
		var out bytes.Buffer
		err := artifactTrustRotationIO(context.Background(), f, nil, strings.NewReader(in), &out)
		if !errors.Is(err, errRotationAborted) {
			t.Fatalf("input %q: err = %v, want abort", in, err)
		}
		if f.reviews != 1 || len(f.commits) != 0 {
			t.Fatalf("input %q: reviews=%d commits=%d", in, f.reviews, len(f.commits))
		}
	}
}

// A refused review (bad signature, replay, server role) commits nothing.
func TestTrustRotationRefusedReviewCommitsNothing(t *testing.T) {
	f := &fakeRotationClient{reviewErr: errors.New("rpc error: code = FailedPrecondition desc = release: signature does not verify")}
	var out bytes.Buffer
	err := artifactTrustRotationIO(context.Background(), f, nil, strings.NewReader(sampleDigest+"\n"), &out)
	if err == nil || !strings.Contains(err.Error(), "signature does not verify") || len(f.commits) != 0 {
		t.Fatalf("err = %v commits = %d", err, len(f.commits))
	}
}

// --yes-digest commits non-interactively; the executor still checks it
// against the review it delivered.
func TestTrustRotationYesDigest(t *testing.T) {
	f := &fakeRotationClient{review: sampleRotation()}
	var out bytes.Buffer
	if err := artifactTrustRotationIO(context.Background(), f, []string{"--yes-digest", sampleDigest}, strings.NewReader(""), &out); err != nil {
		t.Fatal(err)
	}
	if len(f.commits) != 1 || f.commits[0].GetRotationDigest() != sampleDigest {
		t.Fatalf("commits = %v", f.commits)
	}
	if err := artifactTrustRotationIO(context.Background(), f, []string{"extra"}, strings.NewReader(""), &out); err == nil {
		t.Fatal("extra argument accepted")
	}
}
