// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"testing"
)

func TestReadAdmissionBoundsConnectionsAcrossGrants(t *testing.T) {
	s := &Service{}
	var releases []func()
	for range 4 {
		release, err := s.admitRead()
		if err != nil {
			t.Fatal(err)
		}
		releases = append(releases, release)
	}
	if _, err := s.admitRead(); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("unbounded admission: %v", err)
	}
	releases[0]()
	release, err := s.admitRead()
	if err != nil {
		t.Fatalf("slot not released: %v", err)
	}
	release()
	for _, release := range releases[1:] {
		release()
	}
}
