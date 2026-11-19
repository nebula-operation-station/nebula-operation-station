// SPDX-License-Identifier: AGPL-3.0-or-later

package executorclient

import (
	"testing"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// pveGuestSnapshotTestRequest is a propose request with a recognizable node
// name, which the error text must never contain.
func pveGuestSnapshotTestRequest() (*pb.ProposePVEGuestSnapshotRequest, string) {
	const node = "node-canary-snapshot"
	return &pb.ProposePVEGuestSnapshotRequest{Target: &pb.PVEGuestSnapshotTarget{
		RemoteId: "remote-1", Kind: "qemu", Node: node, Vmid: 102, Op: "create", Name: "before-upgrade",
	}}, node
}

func TestProposePVEGuestSnapshotForwardsWithDefaultTimeout(t *testing.T) {
	request, canary := pveGuestSnapshotTestRequest()
	checkPVEGuestRPC(t, pb.ExecutorService_ProposePVEGuestSnapshot_FullMethodName, 0, request, canary, (*Client).ProposePVEGuestSnapshot)
}

func TestProposePVEGuestSnapshotCallerContextEndsCall(t *testing.T) {
	request, _ := pveGuestSnapshotTestRequest()
	checkPVEGuestCallerContext(t, request, (*Client).ProposePVEGuestSnapshot)
}

func TestCommitPVEGuestSnapshotForwardsWithLongTimeout(t *testing.T) {
	request, canary := pveGuestSnapshotTestRequest()
	commit := &pb.CommitPVEGuestSnapshotRequest{Target: request.Target, ExecutionDigest: "digest-snapshot"}
	checkPVEGuestRPC(t, pb.ExecutorService_CommitPVEGuestSnapshot_FullMethodName, pveGuestPowerCommitWait, commit, canary, (*Client).CommitPVEGuestSnapshot)
}

func TestCommitPVEGuestSnapshotCallerContextEndsCall(t *testing.T) {
	request, _ := pveGuestSnapshotTestRequest()
	commit := &pb.CommitPVEGuestSnapshotRequest{Target: request.Target, ExecutionDigest: "digest-snapshot"}
	checkPVEGuestCallerContext(t, commit, (*Client).CommitPVEGuestSnapshot)
}
