// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"context"
	"errors"
	"testing"
)

func TestClusterNodeVotesParsesNumbersStringsAndDefault(t *testing.T) {
	f := newFakePVE(t, map[string]fakeRoute{"/api2/json/cluster/config/nodes": {body: `{"data":[` +
		`{"node":"pve1","quorum_votes":"2","ring0_addr":"10.0.0.1"},{"node":"pve2","quorum_votes":0},{"node":"pve3"}]}`}})
	got, err := clusterTestClient(t, f).ClusterNodeVotes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !got.Available || got.Votes["pve1"] != 2 || got.Votes["pve2"] != 0 || got.Votes["pve3"] != 1 || len(got.Votes) != 3 {
		t.Fatalf("votes = %+v", got)
	}
}

func TestClusterNodeVotesUnavailableWhenNotFound(t *testing.T) {
	got, err := clusterTestClient(t, newFakePVE(t, map[string]fakeRoute{})).ClusterNodeVotes(context.Background())
	if err != nil || got.Available || got.Votes != nil {
		t.Fatalf("votes = %+v, %v", got, err)
	}
}

func TestClusterNodeVotesRejectsHostileValues(t *testing.T) {
	for name, body := range map[string]string{
		"negative":   `{"data":[{"node":"pve1","quorum_votes":-1}]}`,
		"too large":  `{"data":[{"node":"pve1","quorum_votes":256}]}`,
		"fraction":   `{"data":[{"node":"pve1","quorum_votes":1.5}]}`,
		"text":       `{"data":[{"node":"pve1","quorum_votes":"one"}]}`,
		"empty":      `{"data":[{"node":"pve1","quorum_votes":""}]}`,
		"bad node":   `{"data":[{"node":"a/b"}]}`,
		"duplicate":  `{"data":[{"node":"pve1"},{"node":"pve1"}]}`,
		"not a list": `{"data":{}}`,
	} {
		f := newFakePVE(t, map[string]fakeRoute{"/api2/json/cluster/config/nodes": {body: body}})
		if _, err := clusterTestClient(t, f).ClusterNodeVotes(context.Background()); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: err = %v, want ErrMalformed", name, err)
		}
	}
}

func TestHAStatusReportsLRMMaintenance(t *testing.T) {
	f := newFakePVE(t, map[string]fakeRoute{
		"/api2/json/cluster/ha/resources": {body: `{"data":[]}`},
		"/api2/json/cluster/ha/status/current": {body: `{"data":[` +
			`{"id":"lrm:pve1","type":"lrm","node":"pve1","status":"pve1 (maintenance mode, Sat Nov  1 10:00:00 2026)"},` +
			`{"id":"lrm:pve2","type":"lrm","node":"pve2","status":"pve2 (idle, Sat Nov  1 10:00:00 2026)"}]}`},
	})
	got, err := clusterTestClient(t, f).HAStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !got.Maintenance["pve1"] || got.Maintenance["pve2"] || len(got.Maintenance) != 2 {
		t.Fatalf("maintenance = %v", got.Maintenance)
	}
}

func TestHAStatusRejectsInconsistentLRMEntries(t *testing.T) {
	for name, entries := range map[string]string{
		"id mismatch": `{"id":"lrm:pve2","type":"lrm","node":"pve1","status":"x"}`,
		"duplicate":   `{"id":"lrm:pve1","type":"lrm","node":"pve1","status":"x"},{"id":"lrm:pve1","type":"lrm","node":"pve1","status":"y"}`,
		"bad node":    `{"id":"lrm:../x","type":"lrm","node":"../x","status":"x"}`,
	} {
		f := newFakePVE(t, map[string]fakeRoute{
			"/api2/json/cluster/ha/resources":      {body: `{"data":[]}`},
			"/api2/json/cluster/ha/status/current": {body: `{"data":[` + entries + `]}`},
		})
		if _, err := clusterTestClient(t, f).HAStatus(context.Background()); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: err = %v, want ErrMalformed", name, err)
		}
	}
}
