// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
)

func TestCreateScheduleProposesAGrant(t *testing.T) {
	f := &fakeExec{}
	s, _ := setup(t, f)
	ctx := context.Background()
	c, err := s.CreateSchedule(ctx, "axel", []string{"package.list_updates", "core.facts"}, []string{"web", "web"}, time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	var d schedgrant.Doc
	if err := json.Unmarshal(f.grantDoc, &d); err != nil {
		t.Fatal(err)
	}
	a, _ := actions.Lookup("package.list_updates")
	empty, _ := canonical.HashParameters([]byte(`{}`))
	if d.ID != c.ID || len(d.Actions) != 2 || d.Actions[0].ArtifactSHA256 != a.SHA256() || d.Actions[0].ParametersHash != empty ||
		len(d.Targets) != 1 || d.Targets[0].HostKeyFingerprint != "SHA256:web" || d.MinIntervalS != 3600 ||
		time.Until(time.Unix(d.ExpiryUnix, 0)) < 29*24*time.Hour || !strings.Contains(string(c.Options), "grant") {
		t.Fatalf("%+v %+v", d, c)
	}
	x, err := s.GetSchedule(ctx, c.ID)
	if err != nil || x.State != "pending" || strings.Join(x.Hosts, ",") != "web" {
		t.Fatalf("%+v %v", x, err)
	}
	if err := s.ApproveSchedule(ctx, "axel", c.ID, []byte("bad")); err == nil {
		t.Fatal("bad assertion accepted")
	}
	if err := s.ApproveSchedule(ctx, "axel", c.ID, []byte("good")); err != nil {
		t.Fatal(err)
	}
	if err := s.ApproveSchedule(ctx, "axel", c.ID, []byte("good")); !errors.Is(err, ErrScheduleState) {
		t.Fatal(err)
	}

	for name, call := range map[string]func() error{
		"service.status has a parameter": func() error {
			_, err := s.CreateSchedule(ctx, "axel", []string{"service.status"}, []string{"web"}, time.Hour, 0)
			return err
		},
		"install is not read-only": func() error {
			_, err := s.CreateSchedule(ctx, "axel", []string{"package.install_all"}, []string{"web"}, time.Hour, 0)
			return err
		},
		"interval too short": func() error {
			_, err := s.CreateSchedule(ctx, "axel", []string{"core.facts"}, []string{"web"}, time.Minute, 0)
			return err
		},
		"too long": func() error {
			_, err := s.CreateSchedule(ctx, "axel", []string{"core.facts"}, []string{"web"}, time.Hour, 91)
			return err
		},
		"not enrolled": func() error {
			_, err := s.CreateSchedule(ctx, "axel", []string{"core.facts"}, []string{"new"}, time.Hour, 0)
			return err
		},
		"blocked": func() error {
			_, err := s.CreateSchedule(ctx, "axel", []string{"core.facts"}, []string{"bad"}, time.Hour, 0)
			return err
		},
	} {
		var se *ScheduleError
		var he *HostError
		if err := call(); !errors.As(err, &se) && !errors.As(err, &he) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestDueSchedulesRunOncePerInterval(t *testing.T) {
	f := &fakeExec{}
	s, _ := setup(t, f)
	ctx := context.Background()
	c, err := s.CreateSchedule(ctx, "axel", []string{"core.facts"}, []string{"web"}, time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	s.RunDueSchedules(ctx) // pending: nothing runs
	if len(f.scheduled) != 0 {
		t.Fatal("ran before approval")
	}
	if err := s.ApproveSchedule(ctx, "axel", c.ID, []byte("good")); err != nil {
		t.Fatal(err)
	}
	s.RunDueSchedules(ctx)
	s.RunDueSchedules(ctx)
	if len(f.scheduled) != 1 {
		t.Fatalf("%d runs", len(f.scheduled))
	}
	r := f.scheduled[0]
	a, _ := actions.Lookup("core.facts")
	if r.GetGrantId() != c.ID || r.GetRun().GetHostId() != "web" || r.GetRun().GetHostKeyFingerprint() != "SHA256:web" ||
		string(r.GetRun().GetArtifact()) != string(a.Script) || string(r.GetRun().GetParametersJson()) != "{}" || len(r.GetEndpoints()) != 2 {
		t.Fatalf("%v", r)
	}
	list, _ := s.List(ctx, 10)
	if len(list) != 1 || list[0].CreatedBy != "schedule" || list[0].State != "finished" {
		t.Fatalf("%+v", list)
	}
	// An hour later it is due again.
	s.now = func() time.Time { return time.Now().Add(61 * time.Minute) }
	s.RunDueSchedules(ctx)
	if len(f.scheduled) != 2 {
		t.Fatalf("%d runs", len(f.scheduled))
	}
	// The executor refusing for the interval is not an error.
	s.now = func() time.Time { return time.Now().Add(3 * time.Hour) }
	f.tooSoon = true
	s.RunDueSchedules(ctx)
	if err := s.RevokeSchedule(ctx, "axel", c.ID); err != nil || f.revoked != c.ID {
		t.Fatal(err)
	}
	f.tooSoon = false
	n := len(f.scheduled)
	s.RunDueSchedules(ctx)
	if len(f.scheduled) != n {
		t.Fatal("a revoked schedule ran")
	}
	if err := s.RevokeSchedule(ctx, "axel", c.ID); !errors.Is(err, ErrScheduleState) {
		t.Fatal(err)
	}
}
