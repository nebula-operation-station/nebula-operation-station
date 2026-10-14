// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Repinner re-pins a host blocked by a host key mismatch (spec 08): the
// executor builds the request from its own records, the user approves it
// with the security key (user verification), the executor commits it.
type Repinner interface {
	ProposeRepin(ctx context.Context, in *pb.ProposeRepinRequest, opts ...grpc.CallOption) (*pb.ProposeRepinResponse, error)
	SubmitAssertion(ctx context.Context, in *pb.SubmitAssertionRequest, opts ...grpc.CallOption) (*pb.SubmitAssertionResponse, error)
	CommitRepin(ctx context.Context, in *pb.CommitRepinRequest, opts ...grpc.CallOption) (*pb.CommitRepinResponse, error)
}

// repinCallTimeout covers the executor's probe of the host at commit.
const repinCallTimeout = time.Minute

func (h *Handler) repinEnabled(w http.ResponseWriter, r *http.Request) bool {
	if h.repin == nil {
		http.NotFound(w, r)
		return false
	}
	return true
}

func (h *Handler) handleRepinPropose(w http.ResponseWriter, r *http.Request) {
	if !h.repinEnabled(w, r) {
		return
	}
	var in struct {
		Host string `json:"host"`
	}
	if !readOpsJSON(w, r, &in) {
		return
	}
	if !canonical.ValidHostID(in.Host) {
		writeJSONError(w, http.StatusBadRequest, "invalid host ID")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	p, err := h.repin.ProposeRepin(ctx, &pb.ProposeRepinRequest{HostId: in.Host})
	if err != nil {
		h.executorRefusal(w, "propose repin", err)
		return
	}
	perm, pin := p.GetPermit(), p.GetPin()
	h.audit(r, "repin_proposed", in.Host)
	out := map[string]any{
		"digest":      perm.GetExecutionDigest(),
		"risk":        strings.TrimPrefix(perm.GetRiskClass().String(), "RISK_CLASS_"),
		"requirement": requirementText(perm.GetApprovalRequirement()),
		"host":        pin.GetHostId(),
		"pinned":      pin.GetFingerprint(),
		"presented":   pin.GetBlockedFingerprint(),
		"endpoint":    pin.GetBlockedEndpoint(),
		"since":       time.Unix(pin.GetBlockedAtUnix(), 0).UTC().Format("2006-01-02 15:04 MST"),
	}
	if opts := perm.GetRequestOptionsJson(); len(opts) > 0 && json.Valid(opts) {
		out["options"] = json.RawMessage(opts)
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) handleRepinCommit(w http.ResponseWriter, r *http.Request) {
	if !h.repinEnabled(w, r) {
		return
	}
	var in struct {
		Host       string          `json:"host"`
		Digest     string          `json:"digest"`
		Assertion  json.RawMessage `json:"assertion"`
		TypedCount uint32          `json:"typed_count"`
	}
	if !readOpsJSON(w, r, &in) {
		return
	}
	if !canonical.ValidHostID(in.Host) {
		writeJSONError(w, http.StatusBadRequest, "invalid host ID")
		return
	}
	if _, err := canonical.ParseDigest(in.Digest); err != nil || len(in.Digest) != 64 {
		writeJSONError(w, http.StatusBadRequest, "invalid digest")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), repinCallTimeout)
	defer cancel()
	// Without an assertion the permit was approved with `nebula approve`.
	if len(in.Assertion) > 0 && string(in.Assertion) != "null" {
		if _, err := h.repin.SubmitAssertion(ctx, &pb.SubmitAssertionRequest{ExecutionDigest: in.Digest, AssertionJson: in.Assertion,
			TypedTargetCount: in.TypedCount}); err != nil {
			switch status.Code(err) {
			case codes.PermissionDenied, codes.Unauthenticated:
				writeJSONError(w, http.StatusForbidden, "security key not accepted (or the typed number of hosts is wrong)")
			default:
				h.executorRefusal(w, "approve repin", err)
			}
			return
		}
	}
	c, err := h.repin.CommitRepin(ctx, &pb.CommitRepinRequest{ExecutionDigest: in.Digest, HostId: in.Host})
	if err != nil {
		switch status.Code(err) {
		case codes.Unavailable, codes.Aborted:
			// Fixed texts from the executor; nothing was changed.
			msg := status.Convert(err).Message()
			if len(msg) > 300 {
				msg = msg[:300]
			}
			writeJSONError(w, http.StatusConflict, "the executor refused: "+msg)
		default:
			h.executorRefusal(w, "commit repin", err)
		}
		return
	}
	h.audit(r, "host_key_repinned", in.Host)
	writeJSON(w, http.StatusOK, map[string]string{"host": c.GetPin().GetHostId(), "fingerprint": c.GetPin().GetFingerprint()})
}

func requirementText(r pb.ApprovalRequirement) string {
	switch r {
	case pb.ApprovalRequirement_APPROVAL_REQUIREMENT_CLI_ONLY:
		return "cli"
	case pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_VERIFIED_TYPED_COUNT:
		return "typed_count"
	default:
		return "key"
	}
}
