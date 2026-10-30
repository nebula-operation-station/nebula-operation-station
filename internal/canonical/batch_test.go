// SPDX-License-Identifier: AGPL-3.0-or-later

package canonical

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func batchFixture(count int) Batch {
	b := Batch{BatchVersion: BatchVersion, BatchID: "0b9c2f7e-4a51-4c8e-9a51-6f0d3c2b1b00", ExpiryUnix: testNow.Add(time.Hour).Unix()}
	stage := BatchStage{StageID: "first", Gate: BatchGateManual}
	for i := 0; i < count; i++ {
		r := validRequest()
		r.ExecutionID = fmt.Sprintf("0b9c2f7e-4a51-4c8e-9a51-%012d", i)
		r.ResolvedTargets = []Target{{HostID: fmt.Sprintf("host-%d", i), HostKeyFingerprint: fpA}}
		id := fmt.Sprintf("member-%d", i)
		b.Members = append(b.Members, BatchMember{MemberID: id, Request: r, CredentialVersions: []CredentialVersion{{Reference: "nebula-default", Version: 1}}, PreconditionHashes: []string{strings.Repeat("d", 64)}})
		stage.MemberIDs = append(stage.MemberIDs, id)
	}
	b.StagePlan.Stages = []BatchStage{stage}
	sealGraph(&b)
	return b
}

func sealGraph(b *Batch) {
	if b.StagePlan.Dependencies == nil {
		b.StagePlan.Dependencies = []BatchDependency{}
	}
	for i := range b.StagePlan.Stages {
		if b.StagePlan.Stages[i].RequiredPostchecks == nil {
			b.StagePlan.Stages[i].RequiredPostchecks = []string{}
		}
	}
	// Test fixtures also need invalid graphs; hash their bytes independently.
	raw, _ := json.Marshal(b.StagePlan)
	// These fixtures have only ASCII strings and integers, so key sorting via
	// the production JCS encoder is checked separately by the golden document.
	var v any
	_ = json.Unmarshal(raw, &v)
	raw, _ = json.Marshal(v)
	sum := sha256.Sum256(raw)
	b.StagePlanHash = Digest(sum).String()
	for i := range b.Members {
		b.Members[i].Request.StagePlanHash = b.StagePlanHash
	}
}

func TestBatchGolden(t *testing.T) {
	n, got, d, err := CanonicalizeBatch(batchFixture(1), testNow)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/batch-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	want = bytes.TrimSuffix(want, []byte("\n"))
	if !bytes.Equal(got, want) {
		t.Fatalf("canonical bytes changed:\ngot %s\nwant %s", got, want)
	}
	const wantDigest = "001abcda69502f11b3dba3393c892c3abaaf3978db66cdd1fdbccda711fa8276"
	if d.String() != wantDigest {
		t.Fatalf("digest = %s", d)
	}
	parsed, back, backDigest, err := ParseBatch(got, testNow)
	if err != nil || !bytes.Equal(back, got) || backDigest != d || !reflect.DeepEqual(parsed, n) {
		t.Fatalf("round trip: %v", err)
	}
}

func TestBatchEveryBindingChangesDigest(t *testing.T) {
	_, _, base, err := CanonicalizeBatch(batchFixture(2), testNow)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*Batch){
		"batch id": func(b *Batch) { b.BatchID = "0b9c2f7e-4a51-4c8e-9a51-6f0d3c2b1b01" },
		"expiry": func(b *Batch) {
			b.ExpiryUnix++
			for i := range b.Members {
				b.Members[i].Request.ExpiryUnix++
			}
		},
		"member id":    func(b *Batch) { b.Members[0].MemberID = "renamed"; b.StagePlan.Stages[0].MemberIDs[0] = "renamed" },
		"member order": func(b *Batch) { b.Members[0], b.Members[1] = b.Members[1], b.Members[0] },
		"remove member": func(b *Batch) {
			b.Members = b.Members[:1]
			b.StagePlan.Stages[0].MemberIDs = b.StagePlan.Stages[0].MemberIDs[:1]
		},
		"execution id": func(b *Batch) { b.Members[0].Request.ExecutionID = "0b9c2f7e-4a51-4c8e-9a51-6f0d3c2b1c00" },
		"action":       func(b *Batch) { b.Members[0].Request.ActionID = "patching.install_all" },
		"module":       func(b *Batch) { b.Members[0].Request.ModuleVersion = "1.2.1" },
		"artifact":     func(b *Batch) { b.Members[0].Request.ArtifactSHA256 = strings.Repeat("e", 64) },
		"parameters":   func(b *Batch) { b.Members[0].Request.ParametersHash = strings.Repeat("e", 64) },
		"target":       func(b *Batch) { b.Members[0].Request.ResolvedTargets[0].HostID = "other" },
		"key":          func(b *Batch) { b.Members[0].Request.ResolvedTargets[0].HostKeyFingerprint = fpB },
		"credentials": func(b *Batch) {
			b.Members[0].Request.CredentialRefs = []string{"other"}
			b.Members[0].CredentialVersions[0].Reference = "other"
		},
		"credential version": func(b *Batch) { b.Members[0].CredentialVersions[0].Version++ },
		"risk":               func(b *Batch) { b.Members[0].Request.RiskClass = RiskHigh },
		"preconditions":      func(b *Batch) { b.Members[0].PreconditionHashes = []string{strings.Repeat("e", 64)} },
		"stage name":         func(b *Batch) { b.StagePlan.Stages[0].StageID = "renamed" },
		"stage order": func(b *Batch) {
			b.StagePlan.Stages = []BatchStage{{StageID: "a", MemberIDs: []string{"member-1"}, Gate: BatchGateManual}, {StageID: "b", MemberIDs: []string{"member-0"}, Gate: BatchGateManual}}
		},
		"stage member order":    func(b *Batch) { s := b.StagePlan.Stages[0].MemberIDs; s[0], s[1] = s[1], s[0] },
		"gate":                  func(b *Batch) { b.StagePlan.Stages[0].Gate = BatchGateAutomatic },
		"failure threshold":     func(b *Batch) { b.StagePlan.Stages[0].FailureThreshold = 1 },
		"unreachable threshold": func(b *Batch) { b.StagePlan.Stages[0].UnreachableThreshold = 1 },
		"postcheck":             func(b *Batch) { b.StagePlan.Stages[0].RequiredPostchecks = []string{strings.Repeat("f", 64)} },
		"dependency": func(b *Batch) {
			b.StagePlan.Dependencies = []BatchDependency{{MemberID: "member-1", DependsOn: []string{"member-0"}}}
		},
		"container": func(b *Batch) { b.Members[0].Container = containerFixture() },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			b := batchFixture(2)
			mutate(&b)
			sealGraph(&b)
			_, _, got, err := CanonicalizeBatch(b, testNow)
			if err != nil {
				t.Fatal(err)
			}
			if got == base {
				t.Fatal("binding did not change digest")
			}
		})
	}
}

func containerFixture() *BatchContainer {
	return &BatchContainer{ContainerID: strings.Repeat("a", 64), ConfigurationHash: strings.Repeat("b", 64), OldImageDigest: "sha256:" + strings.Repeat("c", 64), NewImageDigest: "sha256:" + strings.Repeat("d", 64)}
}

func TestBatchRejectsInvalidContracts(t *testing.T) {
	cases := map[string]func(*Batch){
		"version":                func(b *Batch) { b.BatchVersion = "batch-v2" },
		"batch id":               func(b *Batch) { b.BatchID = "bad" },
		"expired":                func(b *Batch) { b.ExpiryUnix = testNow.Unix() },
		"over 24h":               func(b *Batch) { b.ExpiryUnix = testNow.Add(MaxPermitLifetime + time.Second).Unix() },
		"no members":             func(b *Batch) { b.Members = nil },
		"101 members":            func(b *Batch) { *b = batchFixture(101) },
		"no stages":              func(b *Batch) { b.StagePlan.Stages = nil },
		"21 stages":              func(b *Batch) { b.StagePlan.Stages = make([]BatchStage, 21) },
		"duplicate member id":    func(b *Batch) { b.Members[1].MemberID = b.Members[0].MemberID },
		"duplicate execution id": func(b *Batch) { b.Members[1].Request.ExecutionID = b.Members[0].Request.ExecutionID },
		"duplicate tuple": func(b *Batch) {
			b.Members[1].Request.ResolvedTargets = b.Members[0].Request.ResolvedTargets
			b.Members[1].Request.ModuleVersion = "1.2.1"
			b.Members[1].Request.ResolvedTargets[0].HostKeyFingerprint = fpB
		},
		"expanded targets":           func(b *Batch) { b.Members[0].Request.ResolvedTargets = validRequest().ResolvedTargets },
		"no target":                  func(b *Batch) { b.Members[0].Request.ResolvedTargets = nil },
		"bad request":                func(b *Batch) { b.Members[0].Request.ArtifactSHA256 = "bad" },
		"member expiry":              func(b *Batch) { b.Members[0].Request.ExpiryUnix++ },
		"missing version":            func(b *Batch) { b.Members[0].CredentialVersions = nil },
		"zero credential version":    func(b *Batch) { b.Members[0].CredentialVersions[0].Version = 0 },
		"unknown credential version": func(b *Batch) { b.Members[0].CredentialVersions[0].Reference = "other" },
		"duplicate credential version": func(b *Batch) {
			b.Members[0].CredentialVersions = append(b.Members[0].CredentialVersions, b.Members[0].CredentialVersions[0])
		},
		"precondition": func(b *Batch) { b.Members[0].PreconditionHashes = []string{"bad"} },
		"duplicate precondition": func(b *Batch) {
			b.Members[0].PreconditionHashes = append(b.Members[0].PreconditionHashes, b.Members[0].PreconditionHashes[0])
		},
		"short container id": func(b *Batch) {
			b.Members[0].Container = containerFixture()
			b.Members[0].Container.ContainerID = "short"
		},
		"container config": func(b *Batch) {
			b.Members[0].Container = containerFixture()
			b.Members[0].Container.ConfigurationHash = "bad"
		},
		"old image": func(b *Batch) {
			b.Members[0].Container = containerFixture()
			b.Members[0].Container.OldImageDigest = "latest"
		},
		"new image": func(b *Batch) {
			b.Members[0].Container = containerFixture()
			b.Members[0].Container.NewImageDigest = "latest"
		},
		"missing container binding": func(b *Batch) { b.Members[0].Request.ActionID = "docker.restart" },
		"invalid utf8":              func(b *Batch) { b.Members[0].MemberID = string([]byte{0xff}) },
		"duplicate stage":           func(b *Batch) { b.StagePlan.Stages = append(b.StagePlan.Stages, b.StagePlan.Stages[0]) },
		"missing member in graph":   func(b *Batch) { b.StagePlan.Stages[0].MemberIDs = b.StagePlan.Stages[0].MemberIDs[:1] },
		"unknown stage member":      func(b *Batch) { b.StagePlan.Stages[0].MemberIDs[0] = "missing" },
		"repeated stage member":     func(b *Batch) { b.StagePlan.Stages[0].MemberIDs = append(b.StagePlan.Stages[0].MemberIDs, "member-0") },
		"unknown gate":              func(b *Batch) { b.StagePlan.Stages[0].Gate = "unknown" },
		"negative threshold":        func(b *Batch) { b.StagePlan.Stages[0].FailureThreshold = -1 },
		"large threshold":           func(b *Batch) { b.StagePlan.Stages[0].UnreachableThreshold = 3 },
		"invalid postcheck":         func(b *Batch) { b.StagePlan.Stages[0].RequiredPostchecks = []string{"bad"} },
		"missing dependency": func(b *Batch) {
			b.StagePlan.Dependencies = []BatchDependency{{MemberID: "member-0", DependsOn: []string{"missing"}}}
		},
		"unknown dependent": func(b *Batch) {
			b.StagePlan.Dependencies = []BatchDependency{{MemberID: "missing", DependsOn: []string{"member-0"}}}
		},
		"self dependency": func(b *Batch) {
			b.StagePlan.Dependencies = []BatchDependency{{MemberID: "member-0", DependsOn: []string{"member-0"}}}
		},
		"duplicate dependency": func(b *Batch) {
			b.StagePlan.Dependencies = []BatchDependency{{MemberID: "member-0", DependsOn: []string{"member-1", "member-1"}}}
		},
		"duplicate dependent": func(b *Batch) {
			b.StagePlan.Dependencies = []BatchDependency{{MemberID: "member-0", DependsOn: []string{"member-1"}}, {MemberID: "member-0", DependsOn: []string{"member-1"}}}
		},
		"cycle": func(b *Batch) {
			b.StagePlan.Dependencies = []BatchDependency{{MemberID: "member-0", DependsOn: []string{"member-1"}}, {MemberID: "member-1", DependsOn: []string{"member-0"}}}
		},
		"later stage dependency": func(b *Batch) {
			b.StagePlan.Stages = []BatchStage{{StageID: "a", MemberIDs: []string{"member-0"}, Gate: BatchGateManual}, {StageID: "b", MemberIDs: []string{"member-1"}, Gate: BatchGateManual}}
			b.StagePlan.Dependencies = []BatchDependency{{MemberID: "member-0", DependsOn: []string{"member-1"}}}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			b := batchFixture(2)
			mutate(&b)
			sealGraph(&b)
			_, _, _, err := CanonicalizeBatch(b, testNow)
			var ve *ValidationError
			if !errors.As(err, &ve) {
				t.Fatalf("want ValidationError, got %v", err)
			}
		})
	}
	for _, field := range []string{"graph", "member"} {
		t.Run("mismatched hash "+field, func(t *testing.T) {
			b := batchFixture(1)
			if field == "graph" {
				b.StagePlanHash = strings.Repeat("e", 64)
			} else {
				b.Members[0].Request.StagePlanHash = strings.Repeat("e", 64)
			}
			if _, _, _, err := CanonicalizeBatch(b, testNow); err == nil {
				t.Fatal("mismatched hash accepted")
			}
		})
	}
}

func TestBatchLimits(t *testing.T) {
	for _, count := range []int{1, 100} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			if _, _, _, err := CanonicalizeBatch(batchFixture(count), testNow); err != nil {
				t.Fatal(err)
			}
		})
	}
	b := batchFixture(20)
	b.StagePlan.Stages = nil
	for i, m := range b.Members {
		b.StagePlan.Stages = append(b.StagePlan.Stages, BatchStage{StageID: fmt.Sprintf("s%d", i), MemberIDs: []string{m.MemberID}, Gate: BatchGateManual})
	}
	sealGraph(&b)
	if _, _, _, err := CanonicalizeBatch(b, testNow); err != nil {
		t.Fatal(err)
	}
	b = batchFixture(1)
	b.ExpiryUnix = testNow.Add(MaxPermitLifetime).Unix()
	b.Members[0].Request.ExpiryUnix = b.ExpiryUnix
	if _, _, _, err := CanonicalizeBatch(b, testNow); err != nil {
		t.Fatal(err)
	}
}

func oversizedBatchFixture() Batch {
	b := batchFixture(100)
	for i := range b.Members {
		for j := 1; j < MaxBatchBindings; j++ {
			b.Members[i].PreconditionHashes = append(b.Members[i].PreconditionHashes, fmt.Sprintf("%064x", j))
		}
		for j := 0; j < 40; j++ {
			ref := fmt.Sprintf("key-%d", j)
			b.Members[i].Request.CredentialRefs = append(b.Members[i].Request.CredentialRefs, ref)
			b.Members[i].CredentialVersions = append(b.Members[i].CredentialVersions, CredentialVersion{Reference: ref, Version: 1})
		}
	}
	return b
}

func TestBatchCanonicalByteLimit(t *testing.T) {
	b := oversizedBatchFixture()
	raw, _ := json.Marshal(b)
	if len(raw) <= MaxBatchSize {
		t.Fatalf("fixture must exceed size limit: %d", len(raw))
	}
	if _, _, _, err := CanonicalizeBatch(b, testNow); err == nil {
		t.Fatal("oversize typed batch accepted")
	}
	// Trim bindings to just below the boundary, then extend a valid action ID to
	// land on exactly 1 MiB. ASCII JSON byte count is unchanged by JCS sorting.
	// Each removed hash contributes 64 hex bytes, two quotes and one comma.
	// Remove them in bulk so constructing the fixture stays cheap under -race.
	drop := (len(raw) - (MaxBatchSize - 128) + 66) / 67
	for i := range b.Members {
		take := min(drop, len(b.Members[i].PreconditionHashes)-1)
		b.Members[i].PreconditionHashes = b.Members[i].PreconditionHashes[take:]
		drop -= take
		if drop == 0 {
			break
		}
	}
	if drop != 0 {
		t.Fatal("fixture cannot fit at the boundary")
	}
	raw, _ = json.Marshal(b)
	delta := MaxBatchSize - len(raw)
	b.Members[0].Request.ActionID += "." + strings.Repeat("a", delta-1)
	// Split the extension into action segments within the existing 64-char bound.
	b.Members[0].Request.ActionID = strings.ReplaceAll(b.Members[0].Request.ActionID, strings.Repeat("a", 64), strings.Repeat("a", 63)+".")
	_, encoded, _, err := CanonicalizeBatch(b, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) != MaxBatchSize {
		t.Fatalf("size=%d", len(encoded))
	}
	b.Members[0].Request.ActionID += "a"
	if _, _, _, err := CanonicalizeBatch(b, testNow); err == nil {
		t.Fatal("1 MiB + 1 accepted")
	}
}

func TestParseBatchRejectsAmbiguousJSON(t *testing.T) {
	_, raw, _, err := CanonicalizeBatch(batchFixture(1), testNow)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"unknown":           bytes.Replace(raw, []byte(`"batch_id":`), []byte(`"unknown":1,"batch_id":`), 1),
		"duplicate":         bytes.Replace(raw, []byte(`"batch_id":`), []byte(`"batch_id":"x","batch_id":`), 1),
		"escaped duplicate": bytes.Replace(raw, []byte(`"batch_id":`), []byte(`"batch_\u0069d":"x","batch_id":`), 1),
		"nested duplicate":  bytes.Replace(raw, []byte(`"action_id":`), []byte(`"action_id":"x","action_id":`), 1),
		"nested unknown":    bytes.Replace(raw, []byte(`"action_id":`), []byte(`"unknown":1,"action_id":`), 1),
		"case alias":        bytes.Replace(raw, []byte(`"batch_id":`), []byte(`"Batch_ID":`), 1),
		"null required":     bytes.Replace(raw, []byte(`"failure_threshold":0`), []byte(`"failure_threshold":null`), 1),
		"null member":       bytes.Replace(raw, []byte(`"members":[{`), []byte(`"members":[null,{`), 1),
		"trailing value":    append(bytes.Clone(raw), []byte(` {}`)...),
		"trailing junk":     append(bytes.Clone(raw), []byte(` !`)...),
		"utf8":              bytes.Replace(raw, []byte("member-0"), []byte{0xff}, 1),
		"surrogate":         bytes.Replace(raw, []byte("member-0"), []byte(`\ud800`), 1),
		"missing version":   bytes.Replace(raw, []byte(`"batch_version":"batch-v1",`), nil, 1),
		"array":             []byte(`[]`),
		"empty":             nil,
		"input size":        bytes.Repeat([]byte(" "), MaxBatchInputSize+1),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := ParseBatch(in, testNow); err == nil {
				t.Fatal("ambiguous JSON accepted")
			}
		})
	}
}

func TestBatchMemberSubstitutionIsRejected(t *testing.T) {
	b := batchFixture(2)
	_, _, digest, err := CanonicalizeBatch(b, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBatchMember(b, digest, 0, b.Members[0], testNow); err != nil {
		t.Fatal(err)
	}
	for name, alter := range map[string]func(*Batch, *Digest, *int, *BatchMember){
		"parent":         func(_ *Batch, d *Digest, _ *int, _ *BatchMember) { d[0] ^= 1 },
		"index":          func(_ *Batch, _ *Digest, i *int, _ *BatchMember) { *i = 1 },
		"negative index": func(_ *Batch, _ *Digest, i *int, _ *BatchMember) { *i = -1 },
		"past end":       func(_ *Batch, _ *Digest, i *int, _ *BatchMember) { *i = 2 },
		"member id":      func(_ *Batch, _ *Digest, _ *int, m *BatchMember) { m.MemberID = "substitute" },
		"request":        func(_ *Batch, _ *Digest, _ *int, m *BatchMember) { m.Request.ParametersHash = strings.Repeat("e", 64) },
		"expiry":         func(_ *Batch, _ *Digest, _ *int, m *BatchMember) { m.Request.ExpiryUnix++ },
		"version": func(_ *Batch, _ *Digest, _ *int, m *BatchMember) {
			m.CredentialVersions = []CredentialVersion{{Reference: "nebula-default", Version: 2}}
		},
		"precondition": func(_ *Batch, _ *Digest, _ *int, m *BatchMember) { m.PreconditionHashes = nil },
		"reordered parent": func(b *Batch, _ *Digest, _ *int, _ *BatchMember) {
			b.Members[0], b.Members[1] = b.Members[1], b.Members[0]
		},
	} {
		t.Run(name, func(t *testing.T) {
			b := batchFixture(2)
			d := digest
			i := 0
			m := b.Members[0]
			alter(&b, &d, &i, &m)
			if err := VerifyBatchMember(b, d, i, m, testNow); !errors.Is(err, ErrBatchMemberMismatch) {
				t.Fatalf("want mismatch, got %v", err)
			}
		})
	}
	if err := VerifyBatchMember(b, digest, 0, b.Members[0], testNow.Add(2*time.Hour)); err == nil {
		t.Fatal("expired parent accepted")
	}
}

func TestBatchDoesNotAliasInput(t *testing.T) {
	b := batchFixture(2)
	before, _ := json.Marshal(b)
	n, _, _, err := CanonicalizeBatch(b, testNow)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(b)
	if !bytes.Equal(before, after) {
		t.Fatal("input mutated")
	}
	n.Members[0].Request.ResolvedTargets[0].HostID = "changed"
	n.Members[0].Request.CredentialRefs[0] = "changed"
	n.Members[0].CredentialVersions[0].Version = 2
	n.Members[0].PreconditionHashes[0] = "changed"
	n.StagePlan.Stages[0].MemberIDs[0] = "changed"
	after, _ = json.Marshal(b)
	if !bytes.Equal(before, after) {
		t.Fatal("output aliases input")
	}
}

func FuzzParseBatch(f *testing.F) {
	raw, _ := json.Marshal(batchFixture(2))
	oversized, _ := json.Marshal(oversizedBatchFixture())
	duplicate := batchFixture(2)
	duplicate.Members[1].MemberID = duplicate.Members[0].MemberID
	duplicateRaw, _ := json.Marshal(duplicate)
	cycle := batchFixture(2)
	cycle.StagePlan.Dependencies = []BatchDependency{{MemberID: "member-0", DependsOn: []string{"member-1"}}, {MemberID: "member-1", DependsOn: []string{"member-0"}}}
	sealGraph(&cycle)
	cycleRaw, _ := json.Marshal(cycle)
	for _, seed := range [][]byte{raw, oversized, duplicateRaw, cycleRaw, []byte(`{"batch_version":"batch-v1","batch_version":"batch-v1"}`), []byte(`{"members":[]}`), []byte{0xff}, bytes.Repeat([]byte(" "), MaxBatchInputSize+1)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		b, c, d, err := ParseBatch(in, testNow)
		if err != nil {
			return
		}
		if len(c) > MaxBatchSize || len(b.Members) < 1 || len(b.Members) > MaxBatchMembers || len(b.StagePlan.Stages) > MaxBatchStages {
			t.Fatal("accepted out of bounds")
		}
		_, again, back, err := ParseBatch(c, testNow)
		if err != nil || !bytes.Equal(c, again) || back != d {
			t.Fatalf("unstable round trip: %v", err)
		}
		for i, m := range b.Members {
			if err := VerifyBatchMember(b, d, i, m, testNow); err != nil {
				t.Fatal(err)
			}
			m.Request.ParametersHash = strings.Repeat("0", 64)
			if m.Request.ParametersHash == b.Members[i].Request.ParametersHash {
				m.Request.ParametersHash = strings.Repeat("1", 64)
			}
			if err := VerifyBatchMember(b, d, i, m, testNow); !errors.Is(err, ErrBatchMemberMismatch) {
				t.Fatal("substitution accepted")
			}
		}
	})
}

func providerFixture() Batch {
	b := batchFixture(1)
	b.Members[0].Request.ResolvedTargets = []Target{}
	b.Members[0].ProviderTarget = &BatchProviderTarget{RemoteID: "remote-a", Kind: "qemu", Node: "pve-a", VMID: 100, Generation: 1, Pin: strings.Repeat("a", 64), TrustGeneration: 1, APIEndpoints: []string{"https://pve-a.example:8006"}}
	return b
}

func TestBatchProviderBindingsChangeDigest(t *testing.T) {
	b := providerFixture()
	_, raw, base, err := CanonicalizeBatch(b, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, d, err := ParseBatch(raw, testNow); err != nil || d != base {
		t.Fatalf("provider round trip: %v", err)
	}
	for name, mutate := range map[string]func(*BatchProviderTarget){
		"remote":           func(p *BatchProviderTarget) { p.RemoteID = "remote-b" },
		"kind":             func(p *BatchProviderTarget) { p.Kind = "lxc" },
		"node":             func(p *BatchProviderTarget) { p.Node = "pve-b" },
		"vmid":             func(p *BatchProviderTarget) { p.VMID++ },
		"generation":       func(p *BatchProviderTarget) { p.Generation++ },
		"pin":              func(p *BatchProviderTarget) { p.Pin = strings.Repeat("b", 64) },
		"trust generation": func(p *BatchProviderTarget) { p.TrustGeneration++ },
		"endpoint":         func(p *BatchProviderTarget) { p.APIEndpoints = []string{"https://pve-b.example:8006"} },
	} {
		t.Run(name, func(t *testing.T) {
			b := providerFixture()
			mutate(b.Members[0].ProviderTarget)
			_, _, d, err := CanonicalizeBatch(b, testNow)
			if err != nil {
				t.Fatal(err)
			}
			if d == base {
				t.Fatal("provider binding missing")
			}
			if err := VerifyBatchMember(providerFixture(), base, 0, b.Members[0], testNow); !errors.Is(err, ErrBatchMemberMismatch) {
				t.Fatal("provider substitution accepted")
			}
		})
	}
}

func TestBatchContainerBindingsChangeDigest(t *testing.T) {
	b := batchFixture(1)
	b.Members[0].Request.ActionID = "docker.restart"
	b.Members[0].Container = containerFixture()
	_, _, base, err := CanonicalizeBatch(b, testNow)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*BatchContainer){
		"incarnation":   func(c *BatchContainer) { c.ContainerID = strings.Repeat("e", 64) },
		"configuration": func(c *BatchContainer) { c.ConfigurationHash = strings.Repeat("e", 64) },
		"old image":     func(c *BatchContainer) { c.OldImageDigest = "sha256:" + strings.Repeat("e", 64) },
		"new image":     func(c *BatchContainer) { c.NewImageDigest = "sha256:" + strings.Repeat("e", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := b.Members[0]
			c := *candidate.Container
			candidate.Container = &c
			mutate(candidate.Container)
			changed := batchFixture(1)
			changed.Members[0] = candidate
			_, _, d, err := CanonicalizeBatch(changed, testNow)
			if err != nil {
				t.Fatal(err)
			}
			if d == base {
				t.Fatal("container binding missing")
			}
			if err := VerifyBatchMember(b, base, 0, candidate, testNow); !errors.Is(err, ErrBatchMemberMismatch) {
				t.Fatal("container substitution accepted")
			}
		})
	}
}

func TestBatchRejectsInvalidProviderBindings(t *testing.T) {
	for name, mutate := range map[string]func(*Batch){
		"ssh and provider":         func(b *Batch) { b.Members[0].Request.ResolvedTargets = validRequest().ResolvedTargets[:1] },
		"remote":                   func(b *Batch) { b.Members[0].ProviderTarget.RemoteID = "*" },
		"node":                     func(b *Batch) { b.Members[0].ProviderTarget.Node = "*" },
		"kind":                     func(b *Batch) { b.Members[0].ProviderTarget.Kind = "all" },
		"missing vmid":             func(b *Batch) { b.Members[0].ProviderTarget.VMID = 0 },
		"node vmid":                func(b *Batch) { b.Members[0].ProviderTarget.Kind = "node" },
		"zero generation":          func(b *Batch) { b.Members[0].ProviderTarget.Generation = 0 },
		"rounded generation":       func(b *Batch) { b.Members[0].ProviderTarget.Generation = 1<<53 + 1 },
		"zero trust generation":    func(b *Batch) { b.Members[0].ProviderTarget.TrustGeneration = 0 },
		"rounded trust generation": func(b *Batch) { b.Members[0].ProviderTarget.TrustGeneration = 1<<53 + 1 },
		"pin":                      func(b *Batch) { b.Members[0].ProviderTarget.Pin = "bad" },
		"no endpoints":             func(b *Batch) { b.Members[0].ProviderTarget.APIEndpoints = nil },
		"many endpoints":           func(b *Batch) { b.Members[0].ProviderTarget.APIEndpoints = make([]string, maxBatchEndpoints+1) },
		"duplicate endpoints": func(b *Batch) {
			p := b.Members[0].ProviderTarget
			p.APIEndpoints = append(p.APIEndpoints, p.APIEndpoints[0])
		},
		"http endpoint":     func(b *Batch) { b.Members[0].ProviderTarget.APIEndpoints = []string{"http://pve-a.example"} },
		"endpoint userinfo": func(b *Batch) { b.Members[0].ProviderTarget.APIEndpoints = []string{"https://user@pve-a.example"} },
		"endpoint query": func(b *Batch) {
			b.Members[0].ProviderTarget.APIEndpoints = []string{"https://pve-a.example?query=true"}
		},
		"endpoint fragment":  func(b *Batch) { b.Members[0].ProviderTarget.APIEndpoints = []string{"https://pve-a.example#fragment"} },
		"endpoint path":      func(b *Batch) { b.Members[0].ProviderTarget.APIEndpoints = []string{"https://pve-a.example/arbitrary"} },
		"endpoint host":      func(b *Batch) { b.Members[0].ProviderTarget.APIEndpoints = []string{"https:///"} },
		"endpoint malformed": func(b *Batch) { b.Members[0].ProviderTarget.APIEndpoints = []string{"https://%"} },
		"endpoint long": func(b *Batch) {
			b.Members[0].ProviderTarget.APIEndpoints = []string{"https://" + strings.Repeat("a", maxBatchStringSize) + ".example"}
		},
		"endpoint utf8": func(b *Batch) {
			b.Members[0].ProviderTarget.APIEndpoints = []string{"https://" + string([]byte{0xff}) + ".example"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			b := providerFixture()
			mutate(&b)
			if _, _, _, err := CanonicalizeBatch(b, testNow); err == nil {
				t.Fatal("invalid provider binding accepted")
			}
		})
	}
	// Guest identity is remote/kind/VMID, independent of current node and pin.
	b := providerFixture()
	m := b.Members[0]
	m.MemberID = "second"
	m.Request.ExecutionID = "0b9c2f7e-4a51-4c8e-9a51-000000000001"
	p := *m.ProviderTarget
	p.Node = "pve-b"
	p.Generation++
	m.ProviderTarget = &p
	b.Members = append(b.Members, m)
	b.StagePlan.Stages[0].MemberIDs = append(b.StagePlan.Stages[0].MemberIDs, m.MemberID)
	sealGraph(&b)
	if _, _, _, err := CanonicalizeBatch(b, testNow); err == nil {
		t.Fatal("duplicate provider tuple accepted")
	}
}

func TestBatchAuxiliaryLimits(t *testing.T) {
	for name, mutate := range map[string]func(*Batch){
		"preconditions":         func(b *Batch) { b.Members[0].PreconditionHashes = make([]string, MaxBatchBindings+1) },
		"postchecks":            func(b *Batch) { b.StagePlan.Stages[0].RequiredPostchecks = make([]string, MaxBatchBindings+1) },
		"credential references": func(b *Batch) { b.Members[0].Request.CredentialRefs = make([]string, MaxBatchBindings+1) },
		"action length": func(b *Batch) {
			b.Members[0].Request.ActionID = "a." + strings.Repeat("b.", maxBatchStringSize/2) + "c"
		},
		"rounded credential version": func(b *Batch) { b.Members[0].CredentialVersions[0].Version = 1<<53 + 1 },
		"dependency entries":         func(b *Batch) { b.StagePlan.Dependencies = make([]BatchDependency, MaxBatchMembers+1) },
		"dependency edges": func(b *Batch) {
			b.StagePlan.Dependencies = []BatchDependency{{MemberID: "member-0", DependsOn: make([]string, MaxBatchMembers+1)}}
		},
		"empty dependency":   func(b *Batch) { b.StagePlan.Dependencies = []BatchDependency{{MemberID: "member-0"}} },
		"stage member count": func(b *Batch) { b.StagePlan.Stages[0].MemberIDs = make([]string, MaxBatchMembers+1) },
		"empty stage":        func(b *Batch) { b.StagePlan.Stages[0].MemberIDs = nil },
		"too many expanded graph members": func(b *Batch) {
			for i := 0; i <= MaxBatchMembers; i++ {
				if i == MaxBatchMembers {
					b.StagePlan.Stages = append(b.StagePlan.Stages, BatchStage{StageID: "second", MemberIDs: []string{"extra"}, Gate: BatchGateManual})
					break
				}
				b.StagePlan.Stages[0].MemberIDs = append(b.StagePlan.Stages[0].MemberIDs, fmt.Sprintf("extra-%d", i))
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			b := batchFixture(1)
			mutate(&b)
			sealGraph(&b)
			if _, _, _, err := CanonicalizeBatch(b, testNow); err == nil {
				t.Fatal("auxiliary limit bypassed")
			}
			if _, err := BatchStagePlanHash(b.StagePlan); strings.Contains(name, "dependency") && err == nil {
				t.Fatal("invalid graph hash accepted")
			}
		})
	}
}

func TestBatchDeepCycleAndFullAcyclicGraph(t *testing.T) {
	b := batchFixture(100)
	for i := 1; i < len(b.Members); i++ {
		b.StagePlan.Dependencies = append(b.StagePlan.Dependencies, BatchDependency{MemberID: b.Members[i].MemberID, DependsOn: []string{b.Members[i-1].MemberID}})
	}
	sealGraph(&b)
	if _, _, _, err := CanonicalizeBatch(b, testNow); err != nil {
		t.Fatal(err)
	}
	b.StagePlan.Dependencies = append(b.StagePlan.Dependencies, BatchDependency{MemberID: "member-0", DependsOn: []string{"member-99"}})
	sealGraph(&b)
	if _, _, _, err := CanonicalizeBatch(b, testNow); err == nil {
		t.Fatal("100-member cycle accepted")
	}
}

func TestBatchParserAllowsWhitespaceAndKeyOrder(t *testing.T) {
	_, raw, want, err := CanonicalizeBatch(batchFixture(1), testNow)
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	pretty, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	_, got, d, err := ParseBatch(append(pretty, []byte("\n\t ")...), testNow)
	if err != nil || d != want || !bytes.Equal(got, raw) {
		t.Fatalf("equivalent JSON changed digest: %v", err)
	}
}

func FuzzBatchGraphAndLimits(f *testing.F) {
	for _, seed := range [][4]int{{1, 1, 0, 0}, {100, 20, 0, 0}, {101, 20, 0, 0}, {100, 21, 0, 0}, {2, 1, 1, 0}, {2, 1, 0, 1}, {2, 1, 0, 2}, {100, 1, 1, 0}} {
		f.Add(seed[0], seed[1], seed[2], seed[3])
	}
	f.Fuzz(func(t *testing.T, count, stages, cycle, duplicate int) {
		// Map arbitrary fuzz integers into boundary-adjacent, bounded fixtures.
		count = int(uint(count) % 103)
		stages = int(uint(stages) % 23)
		duplicate = int(uint(duplicate) % 3)
		b := batchFixture(count)
		b.StagePlan.Stages = nil
		for i := 0; i < stages; i++ {
			b.StagePlan.Stages = append(b.StagePlan.Stages, BatchStage{StageID: fmt.Sprintf("s%d", i), Gate: BatchGateManual})
		}
		if stages > 0 {
			for i, m := range b.Members {
				b.StagePlan.Stages[i%stages].MemberIDs = append(b.StagePlan.Stages[i%stages].MemberIDs, m.MemberID)
			}
		}
		if count > 1 && cycle&1 != 0 {
			b.StagePlan.Dependencies = []BatchDependency{{MemberID: "member-0", DependsOn: []string{"member-1"}}, {MemberID: "member-1", DependsOn: []string{"member-0"}}}
		}
		if count > 1 && duplicate == 1 {
			b.Members[1].Request.ResolvedTargets[0] = b.Members[0].Request.ResolvedTargets[0]
		}
		if count > 1 && duplicate == 2 {
			b.Members[1].MemberID = b.Members[0].MemberID
		}
		sealGraph(&b)
		_, c, d, err := CanonicalizeBatch(b, testNow)
		valid := count >= 1 && count <= MaxBatchMembers && stages >= 1 && stages <= MaxBatchStages && stages <= count && (count <= 1 || (cycle&1 == 0 && duplicate == 0))
		if (err == nil) != valid {
			t.Fatalf("count=%d stages=%d cycle=%d duplicate=%d: %v", count, stages, cycle, duplicate, err)
		}
		if err == nil {
			_, again, d2, err := ParseBatch(c, testNow)
			if err != nil || !bytes.Equal(c, again) || d != d2 {
				t.Fatalf("graph round trip: %v", err)
			}
		}
	})
}
