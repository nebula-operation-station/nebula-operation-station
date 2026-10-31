// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Review PR #128: ScanBounded uses the same two slots as ordinary proposals
// and gives up when its context ends while waiting.
func TestScanBoundedSharesSlotsAndHonoursContext(t *testing.T) {
	scanSlots <- struct{}{}
	scanSlots <- struct{}{}
	defer func() { <-scanSlots; <-scanSlots }()
	c, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, _, err := ScanBounded(c, []byte("echo hi\n")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v, want deadline while both slots are held", err)
	}
}

func TestScanBoundedScansWhenSlotFree(t *testing.T) {
	f, r, err := ScanBounded(context.Background(), []byte("rm -rf /\n"))
	if err != nil || r == "" {
		t.Fatalf("ScanBounded = %v, %q, %v", f, r, err)
	}
}
