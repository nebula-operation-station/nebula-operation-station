// SPDX-License-Identifier: AGPL-3.0-or-later

package canonical

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gowebpki/jcs"
)

// BatchVersion identifies the canonical batch contract, independently of RequestVersion.
const BatchVersion = "batch-v1"

// Batch limits bound expanded plans and their transport representation.
const (
	MaxBatchMembers    = 100
	MaxBatchStages     = 20
	MaxBatchSize       = 1 << 20
	MaxBatchInputSize  = 2 * MaxBatchSize
	MaxBatchBindings   = 128
	maxBatchStringSize = 4096
	maxBatchEndpoints  = 32
)

// Stage gates are explicit in the approved graph. Approval and dispatch enforce
// the fresh-assertion requirements for HIGH gates.
const (
	BatchGateManual    = "manual"
	BatchGateAutomatic = "automatic"
)

// ErrBatchMemberMismatch means a proposed child differs from its approved parent binding.
var ErrBatchMemberMismatch = errors.New("batch member does not match approved plan")

// Batch binds a complete ordered plan. StagePlanHash and every request's
// StagePlanHash must equal BatchStagePlanHash(StagePlan); member expiry must
// equal parent expiry. No authority or replay state is stored by this package.
type Batch struct {
	BatchVersion  string         `json:"batch_version"`
	BatchID       string         `json:"batch_id"`
	ExpiryUnix    int64          `json:"expiry_unix"`
	StagePlan     BatchStagePlan `json:"stage_plan"`
	StagePlanHash string         `json:"stage_plan_hash"`
	Members       []BatchMember  `json:"members"`
}

// BatchMember is one expanded action-target request, including additional
// bindings unavailable in the legacy execution request. Secret parameters are
// opaque references in the separately validated parameter document, never values.
type BatchMember struct {
	MemberID           string               `json:"member_id"`
	Request            Request              `json:"request"`
	CredentialVersions []CredentialVersion  `json:"credential_versions"`
	PreconditionHashes []string             `json:"precondition_hashes"`
	Container          *BatchContainer      `json:"container,omitempty"`
	ProviderTarget     *BatchProviderTarget `json:"provider_target,omitempty"`
}

// CredentialVersion pins an exact executor credential version, not its secret.
type CredentialVersion struct {
	Reference string `json:"reference"`
	Version   uint64 `json:"version"`
}

// BatchContainer freezes a container incarnation and its planned image transition.
type BatchContainer struct {
	ContainerID       string `json:"container_id"`
	ConfigurationHash string `json:"configuration_hash"`
	OldImageDigest    string `json:"old_image_digest"`
	NewImageDigest    string `json:"new_image_digest"`
}

// BatchProviderTarget is an exact typed provider resource. Provider members
// have no SSH targets. Endpoint changes, resource generations and trust changes
// are part of the digest; this document does not authorize path construction or
// discovery of additional resources.
type BatchProviderTarget struct {
	RemoteID        string   `json:"remote_id"`
	Kind            string   `json:"kind"`
	Node            string   `json:"node"`
	VMID            uint32   `json:"vmid"`
	Generation      uint64   `json:"generation"`
	Pin             string   `json:"pin"`
	TrustGeneration uint64   `json:"trust_generation"`
	APIEndpoints    []string `json:"api_endpoints"`
}

// BatchStagePlan binds ordered stages and explicit member dependencies.
type BatchStagePlan struct {
	Stages       []BatchStage      `json:"stages"`
	Dependencies []BatchDependency `json:"dependencies"`
}

// BatchStage assigns each expanded member to exactly one stage. Thresholds are
// absolute counts; zero stops on the first failure/unreachable member. Required
// postchecks are exact contract hashes. Order is preserved, including within a stage.
type BatchStage struct {
	StageID              string   `json:"stage_id"`
	MemberIDs            []string `json:"member_ids"`
	Gate                 string   `json:"gate"`
	FailureThreshold     int      `json:"failure_threshold"`
	UnreachableThreshold int      `json:"unreachable_threshold"`
	RequiredPostchecks   []string `json:"required_postchecks"`
}

// BatchDependency requires every listed member to satisfy its postchecks before
// MemberID may dispatch. Skipping a member cannot satisfy this relationship.
type BatchDependency struct {
	MemberID  string   `json:"member_id"`
	DependsOn []string `json:"depends_on"`
}

func batchError(format string, args ...any) error {
	return &ValidationError{Problems: []string{fmt.Sprintf("batch: "+format, args...)}}
}

// BatchStagePlanHash validates and hashes the RFC 8785 stage/dependency graph.
// Use its result for the parent and member StagePlanHash fields before approval.
func BatchStagePlanHash(plan BatchStagePlan) (Digest, error) {
	n, _, err := normalizeBatchGraph(plan)
	if err != nil {
		return Digest{}, err
	}
	raw, err := json.Marshal(n)
	if err != nil {
		return Digest{}, fmt.Errorf("marshal batch graph: %w", err)
	}
	c, err := jcs.Transform(raw)
	if err != nil {
		return Digest{}, fmt.Errorf("canonicalize batch graph: %w", err)
	}
	return sha256.Sum256(c), nil
}

func normalizeBatchGraph(plan BatchStagePlan) (BatchStagePlan, map[string]int, error) {
	if len(plan.Stages) < 1 || len(plan.Stages) > MaxBatchStages {
		return BatchStagePlan{}, nil, batchError("stage count must be 1..%d", MaxBatchStages)
	}
	if len(plan.Dependencies) > MaxBatchMembers {
		return BatchStagePlan{}, nil, batchError("too many dependency entries")
	}
	n := BatchStagePlan{Stages: slices.Clone(plan.Stages), Dependencies: append([]BatchDependency{}, plan.Dependencies...)}
	members := make(map[string]int)
	stages := make(map[string]bool)
	for i, s := range n.Stages {
		if !credRefRe.MatchString(s.StageID) || stages[s.StageID] {
			return BatchStagePlan{}, nil, batchError("invalid or duplicate stage ID")
		}
		stages[s.StageID] = true
		if len(s.MemberIDs) < 1 || len(s.MemberIDs) > MaxBatchMembers {
			return BatchStagePlan{}, nil, batchError("stage member count must be 1..%d", MaxBatchMembers)
		}
		if s.Gate != BatchGateManual && s.Gate != BatchGateAutomatic {
			return BatchStagePlan{}, nil, batchError("unknown stage gate")
		}
		if s.FailureThreshold < 0 || s.FailureThreshold > len(s.MemberIDs) || s.UnreachableThreshold < 0 || s.UnreachableThreshold > len(s.MemberIDs) {
			return BatchStagePlan{}, nil, batchError("stage threshold exceeds member count")
		}
		if err := validateBatchHashes(s.RequiredPostchecks); err != nil {
			return BatchStagePlan{}, nil, err
		}
		n.Stages[i].RequiredPostchecks = append([]string{}, s.RequiredPostchecks...)
		n.Stages[i].MemberIDs = slices.Clone(s.MemberIDs)
		for _, id := range s.MemberIDs {
			if !credRefRe.MatchString(id) {
				return BatchStagePlan{}, nil, batchError("malformed stage member ID")
			}
			if _, ok := members[id]; ok {
				return BatchStagePlan{}, nil, batchError("member appears more than once in stages")
			}
			members[id] = i
			if len(members) > MaxBatchMembers {
				return BatchStagePlan{}, nil, batchError("too many expanded stage members")
			}
		}
	}
	edges := make(map[string][]string)
	for i, d := range n.Dependencies {
		stage, ok := members[d.MemberID]
		if !ok {
			return BatchStagePlan{}, nil, batchError("dependency names an unknown member")
		}
		if _, ok := edges[d.MemberID]; ok {
			return BatchStagePlan{}, nil, batchError("duplicate dependency entry")
		}
		if len(d.DependsOn) < 1 || len(d.DependsOn) > MaxBatchMembers {
			return BatchStagePlan{}, nil, batchError("invalid dependency count")
		}
		seen := make(map[string]bool)
		for _, id := range d.DependsOn {
			dependencyStage, ok := members[id]
			if !ok || id == d.MemberID || seen[id] {
				return BatchStagePlan{}, nil, batchError("missing, self or duplicate dependency")
			}
			if dependencyStage > stage {
				return BatchStagePlan{}, nil, batchError("dependency is in a later stage")
			}
			seen[id] = true
		}
		edges[d.MemberID] = d.DependsOn
		n.Dependencies[i].DependsOn = slices.Clone(d.DependsOn)
	}
	// Depth is bounded by MaxBatchMembers. Check same-stage cycles as well as
	// cross-stage constraints, without changing any approved ordering.
	state := make(map[string]uint8)
	var visit func(string) bool
	visit = func(id string) bool {
		if state[id] == 1 {
			return false
		}
		if state[id] == 2 {
			return true
		}
		state[id] = 1
		for _, dep := range edges[id] {
			if !visit(dep) {
				return false
			}
		}
		state[id] = 2
		return true
	}
	for id := range members {
		if !visit(id) {
			return BatchStagePlan{}, nil, batchError("dependency cycle")
		}
	}
	return n, members, nil
}

func validateBatchHashes(hashes []string) error {
	if len(hashes) > MaxBatchBindings {
		return batchError("too many hash bindings")
	}
	seen := make(map[string]bool)
	for _, h := range hashes {
		if !hex64.MatchString(h) || seen[h] {
			return batchError("malformed or duplicate hash binding")
		}
		seen[h] = true
	}
	return nil
}

func normalizeBatchMember(m BatchMember, now time.Time) (BatchMember, error) {
	if !credRefRe.MatchString(m.MemberID) {
		return BatchMember{}, batchError("malformed member ID")
	}
	if len(m.Request.ActionID) > maxBatchStringSize || len(m.Request.CredentialRefs) > MaxBatchBindings {
		return BatchMember{}, batchError("request bindings exceed limits")
	}
	if len(m.Request.ResolvedTargets) != 1 && m.ProviderTarget == nil {
		return BatchMember{}, batchError("member must have exactly one expanded target")
	}
	if m.ProviderTarget != nil && len(m.Request.ResolvedTargets) != 0 {
		return BatchMember{}, batchError("provider member must not contain SSH targets")
	}
	n := m
	var err error
	n.Request, err = normalizeRequest(m.Request, now, m.ProviderTarget != nil)
	if err != nil {
		return BatchMember{}, err
	}
	if len(m.CredentialVersions) != len(n.Request.CredentialRefs) {
		return BatchMember{}, batchError("every credential needs exactly one version")
	}
	n.CredentialVersions = slices.Clone(m.CredentialVersions)
	versions := make(map[string]uint64)
	for _, v := range m.CredentialVersions {
		// Integers must round-trip exactly through the RFC 8785 double model.
		if !credRefRe.MatchString(v.Reference) || v.Version == 0 || v.Version > maxBatchExactInteger || versions[v.Reference] != 0 {
			return BatchMember{}, batchError("invalid or duplicate credential version")
		}
		versions[v.Reference] = v.Version
	}
	for _, ref := range n.Request.CredentialRefs {
		if versions[ref] == 0 {
			return BatchMember{}, batchError("credential version missing")
		}
	}
	if err := validateBatchHashes(m.PreconditionHashes); err != nil {
		return BatchMember{}, err
	}
	n.PreconditionHashes = append([]string{}, m.PreconditionHashes...)
	if m.ProviderTarget != nil {
		n.Request.ResolvedTargets = []Target{}
	}
	if m.Container != nil {
		c := *m.Container
		if !hex64.MatchString(c.ContainerID) || !hex64.MatchString(c.ConfigurationHash) || !validImageDigest(c.OldImageDigest) || !validImageDigest(c.NewImageDigest) {
			return BatchMember{}, batchError("malformed container binding")
		}
		n.Container = &c
	}
	// Enumeration actions do not address an existing container incarnation.
	switch m.Request.ActionID {
	case "docker.inspect", "docker.restart", "docker.stop", "docker.start", "docker.update", "docker.remove", "docker.logs", "docker.stats", "docker.check_updates":
		if n.Container == nil {
			return BatchMember{}, batchError("container action requires an incarnation binding")
		}
	}
	if m.ProviderTarget != nil {
		p := *m.ProviderTarget
		if !hostIDRe.MatchString(p.RemoteID) || !hostIDRe.MatchString(p.Node) || p.Generation == 0 || p.Generation > maxBatchExactInteger || p.TrustGeneration == 0 || p.TrustGeneration > maxBatchExactInteger || !hex64.MatchString(p.Pin) {
			return BatchMember{}, batchError("malformed provider identity or trust binding")
		}
		switch p.Kind {
		case "node":
			if p.VMID != 0 {
				return BatchMember{}, batchError("node provider target must not have a VMID")
			}
		case "qemu", "lxc":
			if p.VMID == 0 {
				return BatchMember{}, batchError("guest provider target requires a VMID")
			}
		default:
			return BatchMember{}, batchError("unknown provider resource kind")
		}
		if len(p.APIEndpoints) < 1 || len(p.APIEndpoints) > maxBatchEndpoints {
			return BatchMember{}, batchError("invalid provider endpoint count")
		}
		seen := make(map[string]bool)
		for _, endpoint := range p.APIEndpoints {
			u, err := url.Parse(endpoint)
			if len(endpoint) > maxBatchStringSize || !utf8.ValidString(endpoint) || err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") || seen[endpoint] {
				return BatchMember{}, batchError("invalid or duplicate provider endpoint")
			}
			seen[endpoint] = true
		}
		p.APIEndpoints = slices.Clone(p.APIEndpoints)
		n.ProviderTarget = &p
	}
	return n, nil
}

const maxBatchExactInteger = 1<<53 - 1

func validImageDigest(s string) bool {
	return strings.HasPrefix(s, "sha256:") && hex64.MatchString(strings.TrimPrefix(s, "sha256:"))
}

// CanonicalizeBatch validates and copies b, preserving member, stage and
// dependency ordering. It returns RFC 8785 bytes and their complete SHA-256.
// Callers must supply executor-derived risk and separately validate artifact
// and parameter bytes against the bound hashes before granting authority.
func CanonicalizeBatch(b Batch, now time.Time) (Batch, []byte, Digest, error) {
	if b.BatchVersion != BatchVersion || !uuidRe.MatchString(b.BatchID) {
		return Batch{}, nil, Digest{}, batchError("invalid batch version or ID")
	}
	expiry := time.Unix(b.ExpiryUnix, 0)
	if !expiry.After(now) || expiry.Sub(now) > MaxPermitLifetime {
		return Batch{}, nil, Digest{}, batchError("expiry must be in the next 24 hours")
	}
	if len(b.Members) < 1 || len(b.Members) > MaxBatchMembers {
		return Batch{}, nil, Digest{}, batchError("member count must be 1..%d", MaxBatchMembers)
	}
	n := b
	graph, members, err := normalizeBatchGraph(b.StagePlan)
	if err != nil {
		return Batch{}, nil, Digest{}, err
	}
	if len(members) != len(b.Members) {
		return Batch{}, nil, Digest{}, batchError("stage graph must contain every member exactly once")
	}
	n.StagePlan = graph
	graphDigest, err := BatchStagePlanHash(graph)
	if err != nil {
		return Batch{}, nil, Digest{}, err
	}
	if b.StagePlanHash != graphDigest.String() {
		return Batch{}, nil, Digest{}, batchError("stage graph hash mismatch")
	}
	n.Members = make([]BatchMember, len(b.Members))
	ids := make(map[string]bool)
	executions := make(map[string]bool)
	tuples := make(map[string]bool)
	for i, m := range b.Members {
		if ids[m.MemberID] || executions[m.Request.ExecutionID] {
			return Batch{}, nil, Digest{}, batchError("duplicate member or execution ID")
		}
		if _, ok := members[m.MemberID]; !ok {
			return Batch{}, nil, Digest{}, batchError("member is absent from stage graph")
		}
		ids[m.MemberID] = true
		executions[m.Request.ExecutionID] = true
		if m.Request.ExpiryUnix != b.ExpiryUnix || m.Request.StagePlanHash != b.StagePlanHash {
			return Batch{}, nil, Digest{}, batchError("member expiry or stage graph differs from parent")
		}
		normalized, err := normalizeBatchMember(m, now)
		if err != nil {
			return Batch{}, nil, Digest{}, fmt.Errorf("batch member %d: %w", i, err)
		}
		n.Members[i] = normalized
		target := ""
		if p := normalized.ProviderTarget; p != nil {
			// Ignore pin/trust/credential changes when detecting duplicate actions on
			// the same resource; none creates another expanded target.
			target = fmt.Sprintf("provider:%s:%s:%d", p.RemoteID, p.Kind, p.VMID)
			if p.Kind == "node" {
				target += ":" + p.Node
			}
		} else {
			target = "ssh:" + normalized.Request.ResolvedTargets[0].HostID
		}
		tuple := normalized.Request.ActionID + "/" + target + "/" + normalized.Request.ParametersHash
		if tuples[tuple] {
			return Batch{}, nil, Digest{}, batchError("duplicate action-target-parameter tuple")
		}
		tuples[tuple] = true
	}
	raw, err := json.Marshal(n)
	if err != nil {
		return Batch{}, nil, Digest{}, fmt.Errorf("marshal batch: %w", err)
	}
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return Batch{}, nil, Digest{}, fmt.Errorf("canonicalize batch: %w", err)
	}
	if len(canonical) > MaxBatchSize {
		return Batch{}, nil, Digest{}, batchError("canonical plan exceeds %d bytes", MaxBatchSize)
	}
	return n, canonical, sha256.Sum256(canonical), nil
}

// ParseBatch accepts bounded JSON with the exact batch-v1 schema. Duplicate,
// unknown (including case aliases), missing and null required fields are rejected
// before Go's permissive decoder can discard or replace their meaning.
func ParseBatch(raw []byte, now time.Time) (Batch, []byte, Digest, error) {
	if len(raw) > MaxBatchInputSize || !utf8.Valid(raw) {
		return Batch{}, nil, Digest{}, batchError("invalid UTF-8 or input size")
	}
	if err := requireObjectWithoutDuplicates(raw); err != nil {
		return Batch{}, nil, Digest{}, fmt.Errorf("parse batch: %w", err)
	}
	// JCS rejects invalid Unicode escapes, including unpaired surrogates.
	if _, err := jcs.Transform(raw); err != nil {
		return Batch{}, nil, Digest{}, fmt.Errorf("parse batch JSON: %w", err)
	}
	if err := validateBatchSchema(raw, reflect.TypeFor[Batch]()); err != nil {
		return Batch{}, nil, Digest{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var b Batch
	if err := dec.Decode(&b); err != nil {
		return Batch{}, nil, Digest{}, fmt.Errorf("decode batch: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return Batch{}, nil, Digest{}, batchError("trailing JSON data")
	}
	return CanonicalizeBatch(b, now)
}

func validateBatchSchema(raw json.RawMessage, typ reflect.Type) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return batchError("null field is not allowed")
	}
	if typ.Kind() == reflect.Pointer {
		return validateBatchSchema(raw, typ.Elem())
	}
	switch typ.Kind() {
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			return batchError("expected object")
		}
		allowed := make(map[string]bool)
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			parts := strings.Split(field.Tag.Get("json"), ",")
			key := parts[0]
			allowed[key] = true
			value, ok := fields[key]
			optional := slices.Contains(parts[1:], "omitempty")
			if !ok {
				if optional {
					continue
				}
				return batchError("missing field %s", key)
			}
			if err := validateBatchSchema(value, field.Type); err != nil {
				return err
			}
		}
		for key := range fields {
			if !allowed[key] {
				return batchError("unknown field")
			}
		}
	case reflect.Slice:
		var values []json.RawMessage
		if err := json.Unmarshal(raw, &values); err != nil {
			return batchError("expected array")
		}
		for _, value := range values {
			if err := validateBatchSchema(value, typ.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}

// VerifyBatchMember compares a child with the exact approved parent digest,
// member index/ID, complete request and expiry. It grants no authority and does
// not claim execution IDs; permit code must atomically do that before dispatch.
func VerifyBatchMember(b Batch, parent Digest, index int, member BatchMember, now time.Time) error {
	n, _, digest, err := CanonicalizeBatch(b, now)
	if err != nil {
		return err
	}
	if digest != parent || index < 0 || index >= len(n.Members) {
		return ErrBatchMemberMismatch
	}
	candidate, err := normalizeBatchMember(member, now)
	if err != nil {
		return fmt.Errorf("%w: invalid child", ErrBatchMemberMismatch)
	}
	want, err := json.Marshal(n.Members[index])
	if err != nil {
		return fmt.Errorf("marshal approved member: %w", err)
	}
	got, err := json.Marshal(candidate)
	if err != nil {
		return fmt.Errorf("marshal proposed member: %w", err)
	}
	if !bytes.Equal(want, got) {
		return ErrBatchMemberMismatch
	}
	return nil
}
