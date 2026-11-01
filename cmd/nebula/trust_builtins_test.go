// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executor/trust"
	"github.com/nebula-operation-station/nebula-operation-station/internal/scanner"
	"github.com/nebula-operation-station/nebula-operation-station/internal/textdiff"
)

// sampleResult builds a BulkAdmitResult with one changed module/action, a
// scanner finding and one old version, for the display tests.
func sampleResult() trust.BulkAdmitResult {
	return trust.BulkAdmitResult{
		Review: trust.Review{
			ManifestDigest:  "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
			ReleaseVersion:  "1.2.3",
			RootID:          "nebula-root-1",
			RootFingerprint: "fp123",
			Generation:      4,
			Modules: []trust.ModuleReview{{
				Name:       "core",
				Status:     trust.StatusChanged,
				OldVersion: "1.0.0",
				NewVersion: "1.1.0",
				OldSHA256:  "oldsha",
				NewSHA256:  "newsha",
				Actions: []trust.ActionReview{{
					ActionID:        "core.install",
					Status:          trust.StatusChanged,
					OldRisk:         "low",
					NewRisk:         "high",
					OldScriptSHA256: "oldscript",
					NewScriptSHA256: "newscript",
					Diff: []textdiff.Line{
						{Op: textdiff.Delete, Text: "old line"},
						{Op: textdiff.Insert, Text: "new line"},
					},
				}},
			}},
		},
		ManifestDigest:    "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		NeedsConfirmation: true,
		OldVersions:       []string{"core@1.0.0"},
		Scans: []trust.ScanFinding{{
			Module:   "core",
			ActionID: "core.install",
			Floor:    "HIGH",
			Findings: []scanner.Finding{{
				Category: "network",
				Risk:     canonical.RiskHigh,
				Line:     3,
				Excerpt:  "curl http://...",
			}},
		}},
	}
}

func TestPrintTrustReview(t *testing.T) {
	var out bytes.Buffer
	printTrustReview(&out, sampleResult())
	got := out.String()
	for _, want := range []string{
		"Built-ins are untrusted",
		"release:  1.2.3",
		"manifest: abcdef012345",
		"root:     nebula-root-1 (fp123)",
		"store:    generation 4",
		"MODULE core",
		"status:  changed",
		"version: 1.0.0 -> 1.1.0",
		"ACTION core.install",
		"risk:   low -> high",
		"-old line",
		"+new line",
		"scanner: floor HIGH",
		"[HIGH] line 3: curl http://...",
		"Old versions to decide (retain or retire):",
		"core@1.0.0",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q\ngot:\n%s", want, got)
		}
	}
}

func TestPrintTrustResult(t *testing.T) {
	res := trust.BulkAdmitResult{
		Committed:       true,
		AdminUID:        1000,
		ManifestDigest:  "abcdef0123456789",
		Review:          trust.Review{ReleaseVersion: "1.2.3"},
		Pinned:          []string{"core@1.0.0"},
		Retired:         []string{"core@0.9.0"},
		Collected:       []string{"core@0.8.0"},
		CleanupFailures: 2,
		Tuples: []trust.TrustTuple{{
			Module:     "core",
			OldVersion: "1.0.0",
			NewVersion: "1.1.0",
			Status:     "changed",
		}},
	}
	var out bytes.Buffer
	printTrustResult(&out, res, 5)
	got := out.String()
	for _, want := range []string{
		"committed:",
		"admin uid:  1000",
		"generation: 5",
		"manifest:   abcdef0123456789",
		"release:    1.2.3",
		"trust: core 1.0.0 -> 1.1.0 (changed)",
		"pinned:    core@1.0.0",
		"retired:   core@0.9.0",
		"collected: core@0.8.0",
		"cleanup failures: 2",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q\ngot:\n%s", want, got)
		}
	}
}

func TestPrintTrustResultNotCommitted(t *testing.T) {
	var out bytes.Buffer
	printTrustResult(&out, trust.BulkAdmitResult{Committed: false}, 0)
	if got := out.String(); !strings.Contains(got, "not committed") {
		t.Errorf("expected 'not committed', got:\n%s", got)
	}
}

func TestPromptOldVersions(t *testing.T) {
	in := strings.NewReader("r\nt\n")
	var out bytes.Buffer
	pins, retired, err := promptOldVersions([]string{"core@1.0.0", "core@0.9.0"}, in, &out)
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
	in := strings.NewReader("x\nretain\n")
	var out bytes.Buffer
	pins, retired, err := promptOldVersions([]string{"core@1.0.0"}, in, &out)
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
	in := strings.NewReader(digest + "\n")
	var out bytes.Buffer
	got, err := promptDigest(digest, in, &out)
	if err != nil {
		t.Fatalf("promptDigest: %v", err)
	}
	if got != digest {
		t.Errorf("expected %q, got %q", digest, got)
	}
}

func TestPromptDigestMismatchThenMatch(t *testing.T) {
	digest := "abcdef0123456789"
	in := strings.NewReader("wrong\n" + digest + "\n")
	var out bytes.Buffer
	got, err := promptDigest(digest, in, &out)
	if err != nil {
		t.Fatalf("promptDigest: %v", err)
	}
	if got != digest {
		t.Errorf("expected %q, got %q", digest, got)
	}
}

func TestPromptDigestAbort(t *testing.T) {
	in := strings.NewReader("\n")
	var out bytes.Buffer
	if _, err := promptDigest("abcdef", in, &out); err == nil {
		t.Fatalf("expected abort error, got nil")
	}
}

func TestArtifactTrustBuiltinsUsage(t *testing.T) {
	var out bytes.Buffer
	if err := artifactTrustBuiltinsIO([]string{}, nil, &out); err == nil {
		t.Fatalf("expected usage error, got nil")
	} else if !strings.Contains(err.Error(), "usage:") {
		t.Errorf("expected usage error, got %v", err)
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

func TestAdminUIDNonRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; adminUID non-root path not exercised")
	}
	if got := adminUID(); got != os.Getuid() {
		t.Errorf("adminUID() = %d, want %d", got, os.Getuid())
	}
}

func TestChownTrustStoreNonRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; chownTrustStore no-op path not exercised")
	}
	// As non-root the chown is a no-op and must not error, even for a
	// directory that does not exist (it never walks).
	if err := chownTrustStore("/nonexistent/trust-store"); !errors.Is(err, nil) {
		t.Errorf("chownTrustStore non-root = %v, want nil", err)
	}
}
