// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// The endpoint a dispatch is attempted on is stored while the run is
// still dispatching (ep02), so a dispatch that breaks mid-way names where
// it was attempted. It is set once and kept by MarkRunRunning's caller and
// FinishRun; it cannot be changed afterwards.
func TestDispatchEndpointStoredWhileDispatching(t *testing.T) {
	db := openT(t, privateDir(t))
	const id = "00000000-0000-4000-9000-0000000000e1"
	if err := db.CreateRun(Run{ExecutionID: id, HostID: "web-1", Digest: strings.Repeat("d", 64),
		Endpoints: []string{"10.0.0.1:22", "10.0.0.2:22"}, Timeout: time.Minute}); err != nil {
		t.Fatal(err)
	}
	if err := db.SetRunDispatchEndpoint(id, "web-1", "10.0.0.2:22"); err != nil {
		t.Fatal(err)
	}
	r, err := db.GetRun(id, "web-1")
	if err != nil || r.State != RunDispatching || r.Endpoint != "10.0.0.2:22" || !r.DispatchedAt.IsZero() {
		t.Fatalf("run %+v %v, want dispatching with endpoint 10.0.0.2:22 and no dispatch time", r, err)
	}
	// Set once: a second value is refused and the first one stays.
	if err := db.SetRunDispatchEndpoint(id, "web-1", "10.0.0.1:22"); !errors.Is(err, ErrRunNotDispatching) {
		t.Fatalf("second set: err = %v, want ErrRunNotDispatching", err)
	}
	// A finish without an endpoint keeps the stored one.
	if err := db.FinishRun(Run{ExecutionID: id, HostID: "web-1", Class: "not_executed", ExitCode: -1}); err != nil {
		t.Fatal(err)
	}
	r, err = db.GetRun(id, "web-1")
	if err != nil || r.Endpoint != "10.0.0.2:22" {
		t.Fatalf("finished run endpoint %q %v, want 10.0.0.2:22", r.Endpoint, err)
	}
	// Not dispatching any more: refused.
	if err := db.SetRunDispatchEndpoint(id, "web-1", "10.0.0.1:22"); !errors.Is(err, ErrRunNotDispatching) {
		t.Fatalf("set on finished run: err = %v, want ErrRunNotDispatching", err)
	}
	if err := db.SetRunDispatchEndpoint("00000000-0000-4000-9000-0000000000e2", "web-1", "10.0.0.1:22"); !errors.Is(err, ErrRunNotDispatching) {
		t.Fatalf("set on unknown run: err = %v, want ErrRunNotDispatching", err)
	}
}
