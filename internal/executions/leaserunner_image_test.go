// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// boundAction is one action with its parameters as JSON text: in a grant
// document (through the hash of params) or in read_grant_params (as stored).
type boundAction struct {
	id     string
	params string
}

// boundJSON encodes a parameters map the way the proposal stores it.
func boundJSON(t *testing.T, p map[string]string) string {
	t.Helper()
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// imageLeaseDoc is an approved ordinary lease on web whose document binds the
// given actions to the hashes of their parameters, with the interval and
// budget of an image lease.
func imageLeaseDoc(t *testing.T, now time.Time, bound ...boundAction) permit.ReadGrantDoc {
	t.Helper()
	doc := leaseDoc(t, now, []string{"web"})
	doc.MinIntervalS = int64(ImageLeaseInterval / time.Second)
	doc.RunBudget = ImageLeaseRunBudget
	for _, b := range bound {
		a, ok := actions.Lookup(b.id)
		if !ok {
			t.Fatalf("unknown action %s", b.id)
		}
		h, err := canonical.HashParameters([]byte(b.params))
		if err != nil {
			t.Fatal(err)
		}
		doc.Actions = append(doc.Actions, permit.ReadGrantAction{ActionID: a.ID, ModuleVersion: a.Version, ArtifactSHA256: a.SHA256(), ParametersHash: h})
	}
	return doc
}

// imageRunFake is the lease runner's executor for image leases. class and
// refuse answer one action: a result class other than success, or an error.
type imageRunFake struct {
	*leaseRunFake
	class  map[string]string
	refuse map[string]error
}

func (f *imageRunFake) RunReadGrant(_ context.Context, in *pb.RunReadGrantRequest, _ ...grpc.CallOption) (*pb.RunReadGrantResponse, error) {
	f.runs = append(f.runs, in)
	action := in.GetRun().GetActionId()
	if err := f.refuse[action]; err != nil {
		return nil, err
	}
	class := "success"
	if c, ok := f.class[action]; ok {
		class = c
	}
	return &pb.RunReadGrantResponse{ExecutionId: fmt.Sprintf("00000000-0000-4000-9000-%012d", len(f.runs)),
		Result: &pb.RunAttachedResponse{Class: class, Result: []byte(`{"ok":true}`)}}, nil
}

// imageLeaseFixture is a service whose executor holds doc, with rows stored
// as read_grant_params of its grant.
func imageLeaseFixture(t *testing.T, now *time.Time, doc permit.ReadGrantDoc, rows ...boundAction) (*Service, *imageRunFake) {
	t.Helper()
	s, f := setupLeases(t, now, func(n time.Time) *pb.ReadGrant { return leaseEntry(t, doc, n) })
	ff := &imageRunFake{leaseRunFake: f}
	s.exec = ff
	for _, r := range rows {
		if _, err := s.db.Exec(`INSERT INTO read_grant_params (grant_id, action_id, params, created_at) VALUES (?, ?, ?, ?)`,
			testGrantID, r.id, r.params, now.Unix()); err != nil {
			t.Fatal(err)
		}
	}
	return s, ff
}

// runActions lists the action IDs of the runs the executor received, in order.
func runActions(f *imageRunFake) []string {
	var out []string
	for _, r := range f.runs {
		out = append(out, r.GetRun().GetActionId())
	}
	return out
}

// imageTestParams are the bound parameters of a correct image lease.
func imageTestParams(t *testing.T) (inspect, image string) {
	t.Helper()
	return boundJSON(t, map[string]string{"container": "c1"}), boundJSON(t, map[string]string{"image": imageTestRef})
}

func TestImageLeaseSendsAndStoresBoundParams(t *testing.T) {
	now := imageTestNow
	inspect, image := imageTestParams(t)
	// The document lists image.packages first: the runner must still run
	// docker.inspect first.
	doc := imageLeaseDoc(t, now, boundAction{"image.packages", image}, boundAction{"docker.inspect", inspect})
	s, f := imageLeaseFixture(t, &now, doc, boundAction{"docker.inspect", inspect}, boundAction{"image.packages", image})

	s.RunDueReadGrants(context.Background())

	if got := runActions(f); !slices.Equal(got, []string{"docker.inspect", "image.packages"}) {
		t.Fatalf("runs %v, want docker.inspect then image.packages", got)
	}
	for i, want := range []string{inspect, image} {
		canon, _, err := canonical.CanonicalParameters([]byte(want))
		if err != nil {
			t.Fatal(err)
		}
		if got := string(f.runs[i].GetRun().GetParametersJson()); got != string(canon) {
			t.Errorf("run %d sent parameters %s, want the canonical form %s", i, got, canon)
		}
	}
	rows, err := s.db.Query(`SELECT action_id, params FROM executions WHERE schedule_id = ?`, testGrantID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	stored := map[string]string{}
	for rows.Next() {
		var action, params string
		if err := rows.Scan(&action, &params); err != nil {
			t.Fatal(err)
		}
		stored[action] = params
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if stored["docker.inspect"] != inspect || stored["image.packages"] != image {
		t.Errorf("stored parameters %v, want %s and %s", stored, inspect, image)
	}
}

func TestImageLeaseSkipsOnlyTheActionWithoutMatchingParams(t *testing.T) {
	inspect, image := imageTestParams(t)
	otherImage := boundJSON(t, map[string]string{"image": "registry.example/app/db@sha256:" + fmt.Sprintf("%064d", 7)})
	invalidImage := boundJSON(t, map[string]string{"image": "not a digest"})
	extraInspect := boundJSON(t, map[string]string{"container": "c1", "x": "y"})
	// A parameterised, allowlisted action that is not an image lease action:
	// its hash matches, but it must never run from an ordinary lease.
	foreignUnit := boundJSON(t, map[string]string{"unit": "nginx.service"})

	tests := []struct {
		name string
		doc  []boundAction
		rows []boundAction
		want []string
	}{
		{
			name: "no stored row for image.packages",
			doc:  []boundAction{{"docker.inspect", inspect}, {"image.packages", image}},
			rows: []boundAction{{"docker.inspect", inspect}},
			want: []string{"docker.inspect"},
		},
		{
			name: "stored image.packages row hashes differently",
			doc:  []boundAction{{"docker.inspect", inspect}, {"image.packages", image}},
			rows: []boundAction{{"docker.inspect", inspect}, {"image.packages", otherImage}},
			want: []string{"docker.inspect"},
		},
		{
			name: "stored image value is invalid",
			doc:  []boundAction{{"docker.inspect", inspect}, {"image.packages", invalidImage}},
			rows: []boundAction{{"docker.inspect", inspect}, {"image.packages", invalidImage}},
			want: []string{"docker.inspect"},
		},
		{
			name: "stored inspect row has an extra member",
			doc:  []boundAction{{"docker.inspect", extraInspect}, {"image.packages", image}},
			rows: []boundAction{{"docker.inspect", extraInspect}, {"image.packages", image}},
			want: nil,
		},
		{
			name: "no stored row for docker.inspect, so image.packages waits too",
			doc:  []boundAction{{"docker.inspect", inspect}, {"image.packages", image}},
			rows: []boundAction{{"image.packages", image}},
			want: nil,
		},
		{
			name: "a parameterised action of another kind is never run",
			doc:  []boundAction{{"docker.inspect", inspect}, {"service.status", foreignUnit}},
			rows: []boundAction{{"docker.inspect", inspect}, {"service.status", foreignUnit}},
			want: []string{"docker.inspect"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := imageTestNow
			doc := imageLeaseDoc(t, now, tt.doc...)
			s, f := imageLeaseFixture(t, &now, doc, tt.rows...)

			s.RunDueReadGrants(context.Background())

			if got := runActions(f); !slices.Equal(got, tt.want) {
				t.Errorf("runs %v, want %v", got, tt.want)
			}
		})
	}
}

func TestImagePackagesWaitsForASuccessfulInspect(t *testing.T) {
	inspect, image := imageTestParams(t)
	tests := []struct {
		name   string
		class  string
		refuse error
	}{
		{name: "inspect ends with another class", class: "failed"},
		{name: "inspect is refused with a run error", refuse: status.Error(codes.InvalidArgument, "bad run")},
		{name: "inspect hits the executor's budget", refuse: status.Error(codes.ResourceExhausted, "read_grant_budget_exhausted")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := imageTestNow
			doc := imageLeaseDoc(t, now, boundAction{"docker.inspect", inspect}, boundAction{"image.packages", image})
			s, f := imageLeaseFixture(t, &now, doc, boundAction{"docker.inspect", inspect}, boundAction{"image.packages", image})
			f.class = map[string]string{"docker.inspect": tt.class}
			f.refuse = map[string]error{"docker.inspect": tt.refuse}

			s.RunDueReadGrants(context.Background())

			if got := runActions(f); !slices.Equal(got, []string{"docker.inspect"}) {
				t.Errorf("runs %v, want only docker.inspect", got)
			}
		})
	}
}

func TestImageLeaseStartsNothingSecondTickWithin24Hours(t *testing.T) {
	now := imageTestNow
	inspect, image := imageTestParams(t)
	doc := imageLeaseDoc(t, now, boundAction{"docker.inspect", inspect}, boundAction{"image.packages", image})
	s, f := imageLeaseFixture(t, &now, doc, boundAction{"docker.inspect", inspect}, boundAction{"image.packages", image})
	ctx := context.Background()

	s.RunDueReadGrants(ctx)
	now = now.Add(time.Hour)
	s.RunDueReadGrants(ctx)
	if got := runActions(f); !slices.Equal(got, []string{"docker.inspect", "image.packages"}) {
		t.Fatalf("runs within 24 hours %v, want only the first tick's two", got)
	}

	now = now.Add(ImageLeaseInterval + time.Minute)
	s.RunDueReadGrants(ctx)
	if got := runActions(f); len(got) != 4 {
		t.Fatalf("runs after 24 hours %v, want the due pair again", got)
	}
}
