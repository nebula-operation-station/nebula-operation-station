// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

const sampleDigest = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

// sampleReview builds a review with one changed module/action, a scanner
// finding and two old versions, for the display and flow tests.
func sampleReview() *pb.ReviewBuiltinTrustResponse {
	return &pb.ReviewBuiltinTrustResponse{
		ManifestDigest:    sampleDigest,
		ReleaseVersion:    "1.2.3",
		RootId:            "nebula-root-1",
		RootFingerprint:   "fp123",
		Generation:        4,
		NeedsConfirmation: true,
		OldVersions:       []string{"core@1.0.0", "core@0.9.0"},
		Modules: []*pb.BuiltinModuleReview{{
			Name:       "core",
			Change:     pb.BuiltinTrustChange_BUILTIN_TRUST_CHANGE_CHANGED,
			OldVersion: "1.0.0",
			NewVersion: "1.1.0",
			OldSha256:  "oldsha",
			NewSha256:  "newsha",
			Actions: []*pb.BuiltinActionReview{{
				ActionId:          "core.install",
				Change:            pb.BuiltinTrustChange_BUILTIN_TRUST_CHANGE_CHANGED,
				OldRisk:           "LOW",
				NewRisk:           "HIGH",
				OldScriptSha256:   "oldscript",
				NewScriptSha256:   "newscript",
				NewArtifactSha256: "newartifact",
				Diff: []*pb.BuiltinDiffLine{
					{Op: pb.BuiltinDiffOp_BUILTIN_DIFF_OP_DELETE, Text: "old line"},
					{Op: pb.BuiltinDiffOp_BUILTIN_DIFF_OP_INSERT, Text: "new line \x1b[2J"},
				},
				ScannerFloor: pb.RiskClass_RISK_CLASS_HIGH,
				Findings: []*pb.BuiltinScanFinding{{
					Category: "network", Risk: pb.RiskClass_RISK_CLASS_HIGH, Line: 3, Excerpt: "curl http://...",
				}},
			}},
		}},
	}
}

// fakeTrustClient records the requests sent to the executor.
type fakeTrustClient struct {
	review    *pb.ReviewBuiltinTrustResponse
	reviewErr error
	commitErr error
	reviews   int
	commits   []*pb.CommitBuiltinTrustRequest
}

func (f *fakeTrustClient) ReviewBuiltinTrust(context.Context, *pb.ReviewBuiltinTrustRequest, ...grpc.CallOption) (*pb.ReviewBuiltinTrustResponse, error) {
	f.reviews++
	return f.review, f.reviewErr
}

func (f *fakeTrustClient) CommitBuiltinTrust(_ context.Context, r *pb.CommitBuiltinTrustRequest, _ ...grpc.CallOption) (*pb.CommitBuiltinTrustResponse, error) {
	f.commits = append(f.commits, r)
	if f.commitErr != nil {
		return nil, f.commitErr
	}
	return &pb.CommitBuiltinTrustResponse{ManifestDigest: r.ManifestDigest, Generation: 5, AdminUid: 1000,
		Retained: r.Retain, Retired: r.Retire,
		Tuples: []*pb.BuiltinTrustTuple{{Module: "core", OldVersion: "1.0.0", NewVersion: "1.1.0", Change: pb.BuiltinTrustChange_BUILTIN_TRUST_CHANGE_CHANGED}}}, nil
}

var _ builtinTrustClient = pb.ExecutorServiceClient(nil)

func TestPrintTrustReview(t *testing.T) {
	var out bytes.Buffer
	printTrustReview(&out, sampleReview())
	got := out.String()
	for _, want := range []string{
		"Built-ins are untrusted",
		"release:  1.2.3",
		"manifest: " + sampleDigest,
		"root:     nebula-root-1 (fp123)",
		"store:    generation 4",
		"MODULE core",
		"status:  changed",
		"version: 1.0.0 -> 1.1.0",
		"ACTION core.install",
		"risk:     LOW -> HIGH",
		"artifact: - -> newartifact",
		"-old line",
		"+new line \\u001b[2J",
		"scanner: floor HIGH",
		"[HIGH] line 3: curl http://...",
		"Old versions to decide",
		"core@1.0.0",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q\ngot:\n%s", want, got)
		}
	}
	if strings.Contains(got, "\x1b") {
		t.Error("terminal escape from the bundle reached the output")
	}
}

func TestPrintTrustResult(t *testing.T) {
	res := &pb.CommitBuiltinTrustResponse{
		AdminUid:        1000,
		Generation:      5,
		ManifestDigest:  "abcdef0123456789",
		Retained:        []string{"core@1.0.0"},
		Retired:         []string{"core@0.9.0"},
		Collected:       []string{"core@0.8.0"},
		CleanupFailures: 2,
		Tuples: []*pb.BuiltinTrustTuple{{
			Module: "core", OldVersion: "1.0.0", NewVersion: "1.1.0", Change: pb.BuiltinTrustChange_BUILTIN_TRUST_CHANGE_CHANGED,
		}},
	}
	var out bytes.Buffer
	printTrustResult(&out, res)
	got := out.String()
	for _, want := range []string{
		"committed:",
		"admin uid:  1000",
		"generation: 5",
		"manifest:   abcdef0123456789",
		"trust: core 1.0.0 -> 1.1.0 (changed)",
		"retained:  core@1.0.0",
		"retired:   core@0.9.0 (trust revoked)",
		"collected: core@0.8.0",
		"cleanup failures: 2",
		"trusted exactly like `nebula artifact trust`",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q\ngot:\n%s", want, got)
		}
	}
}

// The interactive flow reviews through the executor, asks for every old
// version and the digest on one input stream, and commits exactly the
// reviewed digest with the decisions.
func TestTrustBuiltinsInteractiveCommitsThroughExecutor(t *testing.T) {
	f := &fakeTrustClient{review: sampleReview()}
	var out bytes.Buffer
	in := strings.NewReader("r\nt\n" + sampleDigest + "\n")
	if err := artifactTrustBuiltinsIO(context.Background(), f, nil, in, &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if f.reviews != 1 || len(f.commits) != 1 {
		t.Fatalf("reviews %d commits %d", f.reviews, len(f.commits))
	}
	c := f.commits[0]
	if c.ManifestDigest != sampleDigest || !reflect.DeepEqual(c.Retain, []string{"core@1.0.0"}) || !reflect.DeepEqual(c.Retire, []string{"core@0.9.0"}) {
		t.Fatalf("commit = %+v", c)
	}
	if !strings.Contains(out.String(), "admin uid:  1000") {
		t.Fatalf("result not shown:\n%s", out.String())
	}
}

// Non-interactive: the flags carry digest and decisions; nothing is read.
func TestTrustBuiltinsNonInteractive(t *testing.T) {
	f := &fakeTrustClient{review: sampleReview()}
	var out bytes.Buffer
	args := []string{"--yes-digest", sampleDigest, "--pin", "core@1.0.0", "--retire", "core@0.9.0"}
	if err := artifactTrustBuiltinsIO(context.Background(), f, args, strings.NewReader(""), &out); err != nil {
		t.Fatal(err)
	}
	if len(f.commits) != 1 || f.commits[0].ManifestDigest != sampleDigest ||
		!reflect.DeepEqual(f.commits[0].Retain, []string{"core@1.0.0"}) || !reflect.DeepEqual(f.commits[0].Retire, []string{"core@0.9.0"}) {
		t.Fatalf("commits = %+v", f.commits)
	}
}

// An unchanged release commits nothing.
func TestTrustBuiltinsNoChanges(t *testing.T) {
	r := sampleReview()
	r.NeedsConfirmation = false
	f := &fakeTrustClient{review: r}
	var out bytes.Buffer
	if err := artifactTrustBuiltinsIO(context.Background(), f, nil, strings.NewReader(""), &out); err != nil {
		t.Fatal(err)
	}
	if len(f.commits) != 0 || !strings.Contains(out.String(), "no changes") {
		t.Fatalf("commits %d, output:\n%s", len(f.commits), out.String())
	}
	if strings.Contains(out.String(), "Built-ins are untrusted") {
		t.Fatal("untrusted banner shown for a trusted release")
	}
}

// Review and commit failures are reported; an aborted digest commits
// nothing.
func TestTrustBuiltinsErrors(t *testing.T) {
	var out bytes.Buffer
	f := &fakeTrustClient{reviewErr: errors.New("unavailable")}
	if err := artifactTrustBuiltinsIO(context.Background(), f, nil, strings.NewReader(""), &out); err == nil || !strings.Contains(err.Error(), "review built-ins") {
		t.Fatalf("review err = %v", err)
	}
	f = &fakeTrustClient{review: sampleReview(), commitErr: errors.New("stale")}
	if err := artifactTrustBuiltinsIO(context.Background(), f, []string{"--yes-digest", sampleDigest}, nil, &out); err == nil || !strings.Contains(err.Error(), "commit built-ins") {
		t.Fatalf("commit err = %v", err)
	}
	f = &fakeTrustClient{review: sampleReview()}
	if err := artifactTrustBuiltinsIO(context.Background(), f, nil, strings.NewReader("r\nt\n\n"), &out); err == nil {
		t.Fatal("aborted digest committed")
	}
	if len(f.commits) != 0 {
		t.Fatalf("commits after abort: %d", len(f.commits))
	}
}

func TestPromptOldVersions(t *testing.T) {
	sc := bufio.NewScanner(strings.NewReader("r\nt\n"))
	var out bytes.Buffer
	pins, retired, err := promptOldVersions([]string{"core@1.0.0", "core@0.9.0"}, sc, &out)
	if err != nil {
		t.Fatalf("promptOldVersions: %v", err)
	}
	if !pins["core@1.0.0"] {
		t.Errorf("expected core@1.0.0 pinned, got %v", pins)
	}
	if len(retired) != 1 || retired[0] != "core@0.9.0" {
		t.Errorf("expected [core@0.9.0] retired, got %v", retired)
	}
}

func TestPromptOldVersionsInvalidThenRetain(t *testing.T) {
	sc := bufio.NewScanner(strings.NewReader("x\nretain\n"))
	var out bytes.Buffer
	pins, retired, err := promptOldVersions([]string{"core@1.0.0"}, sc, &out)
	if err != nil {
		t.Fatalf("promptOldVersions: %v", err)
	}
	if !pins["core@1.0.0"] {
		t.Errorf("expected core@1.0.0 pinned, got %v", pins)
	}
	if len(retired) != 0 {
		t.Errorf("expected no retired, got %v", retired)
	}
}

func TestPromptDigestMatch(t *testing.T) {
	digest := "abcdef0123456789"
	var out bytes.Buffer
	got, err := promptDigest(digest, bufio.NewScanner(strings.NewReader(digest+"\n")), &out)
	if err != nil {
		t.Fatalf("promptDigest: %v", err)
	}
	if got != digest {
		t.Errorf("expected %q, got %q", digest, got)
	}
}

func TestPromptDigestMismatchThenMatch(t *testing.T) {
	digest := "abcdef0123456789"
	var out bytes.Buffer
	got, err := promptDigest(digest, bufio.NewScanner(strings.NewReader("wrong\n"+digest+"\n")), &out)
	if err != nil {
		t.Fatalf("promptDigest: %v", err)
	}
	if got != digest {
		t.Errorf("expected %q, got %q", digest, got)
	}
}

func TestPromptDigestAbort(t *testing.T) {
	var out bytes.Buffer
	if _, err := promptDigest("abcdef", bufio.NewScanner(strings.NewReader("\n")), &out); err == nil {
		t.Fatalf("expected abort error, got nil")
	}
}

// Decisions without a digest, and stray arguments (the removed --bundle
// path among them), are usage errors; the executor is not asked.
func TestArtifactTrustBuiltinsUsage(t *testing.T) {
	for _, args := range [][]string{{"--pin", "core@1.0.0"}, {"--retire", "core@1.0.0"}, {"extra"}, {"--bundle", "/tmp/x"}} {
		f := &fakeTrustClient{review: sampleReview()}
		var out bytes.Buffer
		if err := artifactTrustBuiltinsIO(context.Background(), f, args, nil, &out); err == nil {
			t.Fatalf("%v: expected usage error, got nil", args)
		}
		if f.reviews != 0 {
			t.Fatalf("%v: executor asked", args)
		}
	}
}

func TestShortHash(t *testing.T) {
	if got := shortHash(""); got != "-" {
		t.Errorf("shortHash(\"\") = %q, want -", got)
	}
	if got := shortHash("abcdef0123456789"); got != "abcdef012345" {
		t.Errorf("shortHash = %q, want abcdef012345", got)
	}
	if got := shortHash("abc"); got != "abc" {
		t.Errorf("shortHash(abc) = %q, want abc", got)
	}
}

func TestOrDash(t *testing.T) {
	if got := orDash(""); got != "-" {
		t.Errorf("orDash(\"\") = %q, want -", got)
	}
	if got := orDash("x"); got != "x" {
		t.Errorf("orDash(x) = %q, want x", got)
	}
}
