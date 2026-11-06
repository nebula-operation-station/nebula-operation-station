// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveapi"
)

const mixedCaseNode = "ProxmoxBAI"

// A guest is provisioned on a node with upper-case letters through the whole
// mutation path: permit target, job record, stored UPID and the PVE calls.
func TestProvisionRunsOnMixedCaseNode(t *testing.T) {
	e := newProvisionEnv(t, fixedRisk{})
	e.client.fakeMutClient.liveNode = mixedCaseNode
	prep := prepareReq(imgUbuntuID, 9001)
	prep.Node = mixedCaseNode
	tpl := e.prepare(prep)
	e.reader.inv.Nodes = append(e.reader.inv.Nodes, pveapi.Node{Name: mixedCaseNode, MaxMemory: 64 * gib})
	e.reader.inv.Guests = append(e.reader.inv.Guests, pveapi.Guest{Node: mixedCaseNode, VMID: 9001, MaxMemory: int64(gib)})

	req := e.request()
	req.Node, req.Template = mixedCaseNode, bindingOf(tpl)
	res, err := e.prov.Provision(context.Background(), e.approve(req))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Steps) != 4 {
		t.Fatalf("steps %+v", res.Steps)
	}
	for _, s := range res.Steps {
		if s.State != executordb.PveJobSucceeded || s.Node != mixedCaseNode || !strings.HasPrefix(s.UPID, "UPID:ProxmoxBAI:") {
			t.Fatalf("step %+v", s)
		}
	}

	gs := &guestServer{}
	w := newGuestWriter(t, gs)
	for _, s := range e.pc.provisionSteps() {
		if _, err := DispatchProvisionStep(context.Background(), w, e.pe.vault, mixedCaseNode, s); err != nil {
			t.Fatalf("%s: %v", s.Method, err)
		}
	}
	want := []string{"POST /api2/json/nodes/ProxmoxBAI/qemu/9001/clone", "POST /api2/json/nodes/ProxmoxBAI/qemu/101/config",
		"PUT /api2/json/nodes/ProxmoxBAI/qemu/101/resize", "POST /api2/json/nodes/ProxmoxBAI/qemu/101/status/start"}
	if strings.Join(gs.paths, "|") != strings.Join(want, "|") {
		t.Fatalf("paths %v", gs.paths)
	}
}

// A guest on a mixed-case node can be proposed for mutation; the name read
// back from the remote must match it exactly.
func TestPveMutationProposedOnMixedCaseNode(t *testing.T) {
	e := newPveMutEnv(t, true)
	e.client.liveNode = mixedCaseNode
	req := mutRequest("guest.start")
	req.Node = mixedCaseNode
	propose := func() error {
		_, _, err := e.m.ProposalRequest(context.Background(), req, "00000000-0000-4000-a000-999999999997", canonical.RiskMedium, strings.Repeat("c", 64), time.Now().Add(time.Hour))
		return err
	}
	if err := propose(); err != nil {
		t.Fatalf("proposal on the exact node: %v", err)
	}
	e.client.liveNode = "proxmoxbai"
	if err := propose(); err == nil {
		t.Fatal("proposal accepted a case-variant live node")
	}
}

func TestProvisionRefusesMalformedMixedCaseNode(t *testing.T) {
	e := newProvisionEnv(t, fixedRisk{})
	req := e.request()
	req.Node, req.Template.Node = "../ProxmoxBAI", "../ProxmoxBAI"
	if _, err := e.prov.config(req, 101); !errors.Is(err, ErrPveProvisionInvalid) {
		t.Fatalf("err = %v", err)
	}
}

func TestGuestJoinRequestTakesMixedCaseNode(t *testing.T) {
	req := PveGuestJoinRequest{RemoteID: mutRemote, Node: mixedCaseNode, VMID: 101, Generation: 1, GuestName: "web1.lab.test",
		GuestUUID: testJoinUUID, HostID: "web1", Endpoint: "192.0.2.10:22", SSHUser: "nos", CredentialRef: "cred"}
	if _, err := req.validate(); err != nil {
		t.Fatalf("join request refused: %v", err)
	}
	req.Node = "Proxmox/BAI"
	if _, err := req.validate(); !errors.Is(err, ErrPveJoinInvalid) {
		t.Fatalf("malformed node: err = %v", err)
	}
}
