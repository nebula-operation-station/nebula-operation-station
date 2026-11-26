// SPDX-License-Identifier: AGPL-3.0-or-later

package executorclient

import (
	"testing"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// TestPVEImageRPCsForwardWithTimeoutAndMapErrors: each of the five image
// pass-throughs (ADR 0008 amendment 2, PV-03a) calls its own generated
// method once, forwards request, options and response, carries the default
// timeout and maps errors like every other executor call.
//
// CommitPVEImagePrepare is pinned to the default timeout on purpose: the
// executor handler and its run bound do not exist yet. The ticket that adds
// them has to replace this case with a long-timeout test like
// TestCommitPVEGuestProvisionForwardsWithLongTimeout.
func TestPVEImageRPCsForwardWithTimeoutAndMapErrors(t *testing.T) {
	t.Run("ProposePVEImagePrepare", func(t *testing.T) {
		checkPVEAdminRPC(t, shortMethodName(t, pb.ExecutorService_ProposePVEImagePrepare_FullMethodName), (*Client).ProposePVEImagePrepare)
	})
	t.Run("CommitPVEImagePrepare", func(t *testing.T) {
		checkPVEAdminRPC(t, shortMethodName(t, pb.ExecutorService_CommitPVEImagePrepare_FullMethodName), (*Client).CommitPVEImagePrepare)
	})
	t.Run("ListPVEImages", func(t *testing.T) {
		checkPVEAdminRPC(t, shortMethodName(t, pb.ExecutorService_ListPVEImages_FullMethodName), (*Client).ListPVEImages)
	})
	t.Run("AddPVELocalImage", func(t *testing.T) {
		checkPVEAdminRPC(t, shortMethodName(t, pb.ExecutorService_AddPVELocalImage_FullMethodName), (*Client).AddPVELocalImage)
	})
	t.Run("RemovePVELocalImage", func(t *testing.T) {
		checkPVEAdminRPC(t, shortMethodName(t, pb.ExecutorService_RemovePVELocalImage_FullMethodName), (*Client).RemovePVELocalImage)
	})
}
