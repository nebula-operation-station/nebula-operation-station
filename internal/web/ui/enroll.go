// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Enroller pins new hosts in bulk (spec 08): the executor reads the host
// keys, the user approves the table with the security key, the executor
// pins what still matches.
type Enroller interface {
	ProposeEnroll(ctx context.Context, in *pb.ProposeEnrollRequest, opts ...grpc.CallOption) (*pb.ProposeEnrollResponse, error)
	SubmitAssertion(ctx context.Context, in *pb.SubmitAssertionRequest, opts ...grpc.CallOption) (*pb.SubmitAssertionResponse, error)
	CommitEnroll(ctx context.Context, in *pb.CommitEnrollRequest, opts ...grpc.CallOption) (*pb.CommitEnrollResponse, error)
}

// maxEnrollHosts matches the executor's limit.
const maxEnrollHosts = 50

type enrollRow struct {
	ID, Name  string
	Endpoints []string
}

type enrollHost struct {
	Host        string `json:"host"`
	Endpoint    string `json:"endpoint"`
	SSHUser     string `json:"ssh_user"`
	Credential  string `json:"credential"`
	Fingerprint string `json:"fingerprint,omitempty"`
	KeyType     string `json:"key_type,omitempty"`
	Error       string `json:"error,omitempty"`
}

func endpointStrings(h inventory.Host) []string {
	out := make([]string, 0, len(h.Endpoints))
	for _, e := range h.Endpoints {
		port := e.Port
		if port == 0 {
			port = 22
		}
		out = append(out, net.JoinHostPort(e.Address, strconv.Itoa(port)))
	}
	return out
}

func (h *Handler) enrollEnabled(w http.ResponseWriter, r *http.Request) bool {
	if h.enroll == nil || h.inventory == nil || h.hosts == nil {
		http.NotFound(w, r)
		return false
	}
	return true
}

func (h *Handler) handleEnrollPage(w http.ResponseWriter, r *http.Request) {
	if !h.enrollEnabled(w, r) {
		return
	}
	data := pageData{Title: "Enroll hosts", Active: "inventory", Content: "inventory_enroll", Scripts: []string{"webauthn.js", "inventory-enroll.js"}}
	ctx, cancel := context.WithTimeout(r.Context(), inventoryCallTimeout)
	defer cancel()
	hosts, err := h.hosts(ctx)
	if err != nil {
		h.log.Error("list hosts", "error", err)
		data.InventoryUnavailable = true
		h.render(w, r, data)
		return
	}
	pinned := map[string]bool{}
	if h.hostKeys != nil {
		pins, err := h.hostKeys(ctx)
		if err != nil {
			h.log.Error("list host keys", "error", err)
			data.InventoryUnavailable = true
			h.render(w, r, data)
			return
		}
		for _, p := range pins {
			pinned[p.GetHostId()] = true
		}
	}
	for _, x := range hosts {
		if pinned[x.ID] || len(x.Endpoints) == 0 {
			continue
		}
		name := x.DisplayName
		if name == "" {
			name = x.ID
		}
		data.Enroll = append(data.Enroll, enrollRow{ID: x.ID, Name: name, Endpoints: endpointStrings(x)})
	}
	h.render(w, r, data)
}

// checkEnrollHosts verifies that every host is in the inventory and the
// endpoint is one of its endpoints.
func (h *Handler) checkEnrollHosts(ctx context.Context, in []enrollHost) error {
	if len(in) == 0 || len(in) > maxEnrollHosts {
		return errors.New("choose 1 to 50 hosts")
	}
	for _, x := range in {
		if !canonical.ValidHostID(x.Host) {
			return errors.New("invalid host ID")
		}
		host, err := h.inventory.Get(ctx, x.Host)
		if errors.Is(err, inventory.ErrHostNotFound) {
			return errors.New("host " + x.Host + " is not in the inventory")
		}
		if err != nil {
			return err
		}
		if !slices.Contains(endpointStrings(host), x.Endpoint) {
			return errors.New("host " + x.Host + ": the endpoint is not one of its endpoints")
		}
	}
	return nil
}

func toEnrollProto(in []enrollHost) []*pb.EnrollHost {
	out := make([]*pb.EnrollHost, 0, len(in))
	for _, x := range in {
		out = append(out, &pb.EnrollHost{HostId: x.Host, Endpoint: x.Endpoint, SshUser: x.SSHUser, CredentialRef: x.Credential, Fingerprint: x.Fingerprint})
	}
	return out
}

func (h *Handler) handleEnrollPropose(w http.ResponseWriter, r *http.Request) {
	if !h.enrollEnabled(w, r) {
		return
	}
	var in struct {
		Hosts []enrollHost `json:"hosts"`
	}
	if !readOpsJSON(w, r, &in) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), repinCallTimeout+2*repinCallTimeout)
	defer cancel()
	if err := h.checkEnrollHosts(ctx, in.Hosts); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	p, err := h.enroll.ProposeEnroll(ctx, &pb.ProposeEnrollRequest{Hosts: toEnrollProto(in.Hosts)})
	if err != nil {
		h.executorRefusal(w, "propose enroll", err)
		return
	}
	hosts := make([]enrollHost, 0, len(p.GetHosts()))
	for _, x := range p.GetHosts() {
		hosts = append(hosts, enrollHost{Host: x.GetHostId(), Endpoint: x.GetEndpoint(), SSHUser: x.GetSshUser(), Credential: x.GetCredentialRef(),
			Fingerprint: x.GetFingerprint(), KeyType: x.GetKeyType(), Error: x.GetError()})
	}
	out := map[string]any{"hosts": hosts}
	if perm := p.GetPermit(); perm != nil {
		out["digest"] = perm.GetExecutionDigest()
		out["risk"] = strings.TrimPrefix(perm.GetRiskClass().String(), "RISK_CLASS_")
		out["requirement"] = requirementText(perm.GetApprovalRequirement())
		if opts := perm.GetRequestOptionsJson(); len(opts) > 0 && json.Valid(opts) {
			out["options"] = json.RawMessage(opts)
		}
	}
	h.log.Info("audit", "kind", "enroll_proposed", "user", webUser(r), "hosts", len(in.Hosts))
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) handleEnrollCommit(w http.ResponseWriter, r *http.Request) {
	if !h.enrollEnabled(w, r) {
		return
	}
	var in struct {
		Digest     string          `json:"digest"`
		Hosts      []enrollHost    `json:"hosts"`
		Assertion  json.RawMessage `json:"assertion"`
		TypedCount uint32          `json:"typed_count"`
	}
	if !readOpsJSON(w, r, &in) {
		return
	}
	if _, err := canonical.ParseDigest(in.Digest); err != nil || len(in.Digest) != 64 {
		writeJSONError(w, http.StatusBadRequest, "invalid digest")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 6*repinCallTimeout)
	defer cancel()
	if err := h.checkEnrollHosts(ctx, in.Hosts); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(in.Assertion) > 0 && string(in.Assertion) != "null" {
		if _, err := h.enroll.SubmitAssertion(ctx, &pb.SubmitAssertionRequest{ExecutionDigest: in.Digest, AssertionJson: in.Assertion,
			TypedTargetCount: in.TypedCount}); err != nil {
			switch status.Code(err) {
			case codes.PermissionDenied, codes.Unauthenticated:
				writeJSONError(w, http.StatusForbidden, "security key not accepted (or the typed number of hosts is wrong)")
			default:
				h.executorRefusal(w, "approve enroll", err)
			}
			return
		}
	}
	c, err := h.enroll.CommitEnroll(ctx, &pb.CommitEnrollRequest{ExecutionDigest: in.Digest, Hosts: toEnrollProto(in.Hosts)})
	if err != nil {
		h.executorRefusal(w, "commit enroll", err)
		return
	}
	type result struct {
		Host        string `json:"host"`
		Pinned      bool   `json:"pinned"`
		Fingerprint string `json:"fingerprint,omitempty"`
		Error       string `json:"error,omitempty"`
		LoginOK     bool   `json:"login_ok"`
		LoginDetail string `json:"login_detail,omitempty"`
	}
	out := make([]result, 0, len(c.GetResults()))
	for _, x := range c.GetResults() {
		out = append(out, result{Host: x.GetHostId(), Pinned: x.GetPinned(), Fingerprint: x.GetFingerprint(), Error: x.GetError(),
			LoginOK: x.GetLoginOk(), LoginDetail: x.GetLoginDetail()})
		if x.GetPinned() {
			h.audit(r, "host_enrolled", x.GetHostId())
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": out})
}
