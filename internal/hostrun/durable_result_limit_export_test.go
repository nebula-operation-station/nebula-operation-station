// SPDX-License-Identifier: AGPL-3.0-or-later

package hostrun

import (
	"context"
	"io"
	"time"

	"golang.org/x/crypto/ssh"
)

// CollectStreamWithin is CollectStream with a fixed read timeout, so tests
// can reach the timeout quickly.
func CollectStreamWithin(ctx context.Context, client *ssh.Client, cfg JobConfig, executionID string, exitCode, limit int, w io.Writer, timeout time.Duration) (StreamedResult, error) {
	return collectStream(ctx, client, cfg, executionID, exitCode, limit, w, func(int) time.Duration { return timeout })
}
