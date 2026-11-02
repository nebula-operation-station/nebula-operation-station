// SPDX-License-Identifier: AGPL-3.0-or-later

package executorclient

import "testing"

func TestBatchRPCsForwardWithTimeoutAndMapErrors(t *testing.T) {
	t.Run("ProposeBatch", func(t *testing.T) { checkPVEAdminRPC(t, "ProposeBatch", (*Client).ProposeBatch) })
	t.Run("CommitBatch", func(t *testing.T) { checkPVEAdminRPC(t, "CommitBatch", (*Client).CommitBatch) })
	t.Run("ReviewBatch", func(t *testing.T) { checkPVEAdminRPC(t, "ReviewBatch", (*Client).ReviewBatch) })
	t.Run("ApproveBatchCLI", func(t *testing.T) { checkPVEAdminRPC(t, "ApproveBatchCLI", (*Client).ApproveBatchCLI) })
	t.Run("GetBatchStatus", func(t *testing.T) { checkPVEAdminRPC(t, "GetBatchStatus", (*Client).GetBatchStatus) })
}
