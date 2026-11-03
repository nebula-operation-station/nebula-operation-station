// SPDX-License-Identifier: AGPL-3.0-or-later

package executorclient

import "testing"

func TestBuiltinTrustRPCsForwardWithTimeoutAndMapErrors(t *testing.T) {
	t.Run("ReviewBuiltinTrust", func(t *testing.T) { checkPVEAdminRPC(t, "ReviewBuiltinTrust", (*Client).ReviewBuiltinTrust) })
	t.Run("CommitBuiltinTrust", func(t *testing.T) { checkPVEAdminRPC(t, "CommitBuiltinTrust", (*Client).CommitBuiltinTrust) })
	t.Run("GetBuiltinTrustStatus", func(t *testing.T) {
		checkPVEAdminRPC(t, "GetBuiltinTrustStatus", (*Client).GetBuiltinTrustStatus)
	})
}
