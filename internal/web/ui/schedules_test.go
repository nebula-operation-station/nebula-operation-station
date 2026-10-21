// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

const schedID = "11111111-2222-4333-8444-555555555555"

type fakeSchedules struct {
	list     []executions.Schedule
	created  string
	created2 time.Duration
	err      error
	calls    []string
	cli      bool
}

func (f *fakeSchedules) CreateSchedule(_ context.Context, _ string, actions, hosts []string, interval time.Duration, days int) (executions.ScheduleCreated, error) {
	if f.err != nil {
		return executions.ScheduleCreated{}, f.err
	}
	f.created, f.created2 = strings.Join(actions, ",")+"|"+strings.Join(hosts, ","), interval
	return executions.ScheduleCreated{ID: schedID, Options: []byte(`{"publicKey":{"challenge":"g"}}`), CLI: f.cli, Digest: strings.Repeat("e", 64)}, nil
}

func (f *fakeSchedules) Schedules(context.Context) ([]executions.Schedule, error) { return f.list, nil }

func (f *fakeSchedules) ApproveSchedule(_ context.Context, _, id string, assertion []byte) error {
	f.calls = append(f.calls, "approve "+id+" "+string(assertion))
	return f.err
}

func (f *fakeSchedules) RevokeSchedule(_ context.Context, _, id string) error {
	f.calls = append(f.calls, "revoke "+id)
	return f.err
}

func schedHandler(t *testing.T, f ui.Schedules) http.Handler {
	t.Helper()
	return newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org", Schedules: f,
		Hosts: func(context.Context) ([]inventory.Host, error) {
			return []inventory.Host{{ID: "web", DisplayName: "<b>Web</b>"}, {ID: "new"}}, nil
		},
		HostKeys: func(context.Context) ([]*pb.HostKeyPin, error) {
			return []*pb.HostKeyPin{{HostId: "web", Fingerprint: "SHA256:x"}}, nil
		}}).Handler()
}

func TestSchedulesPage(t *testing.T) {
	f := &fakeSchedules{list: []executions.Schedule{
		{ID: schedID, State: "pending", Actions: []string{"package.list_updates"}, Hosts: []string{"web"}, Interval: 24 * time.Hour,
			ExpiresAt: time.Now().Add(time.Hour), Options: []byte(`{"publicKey":{"challenge":"g"}}`), CreatedBy: "axel"},
		{ID: "22222222-2222-4333-8444-555555555555", State: "active", Actions: []string{"core.facts"}, Hosts: []string{"web"}, Interval: time.Hour,
			ExpiresAt: time.Now().Add(-time.Hour), CreatedBy: "axel"},
	}}
	page := getBody(t, schedHandler(t, f), "/schedules")
	for _, want := range []string{`<h3 class="mono">11111111</h3>`, "package.list_updates", "1 day", "1 h", "schedule-approve",
		`>expired</span>`, `value="core.facts"`, `value="package.list_updates"`, `&lt;b&gt;Web&lt;/b&gt;`} {
		if !strings.Contains(page, want) {
			t.Errorf("page misses %q", want)
		}
	}
	for _, not := range []string{`value="service.status"`, `value="package.install_all"`, `value="new"`} {
		if strings.Contains(page, not) {
			t.Errorf("page offers %q", not)
		}
	}
}

// The prefill from the query parameters only checks boxes: unknown
// actions and hosts are not offered at all, invalid interval and days
// fall back to the defaults, and nothing is created.
func TestSchedulePrefillOnlyChecksBoxes(t *testing.T) {
	h := schedHandler(t, &fakeSchedules{})
	body := getBody(t, h, "/schedules?action=core.facts&action=package.install_all&action=system.reboot&host=web&host=new&interval=360&days=45")
	for _, want := range []string{
		`value="core.facts" checked>`,
		`value="web" checked>`,
		`value="360" selected>`,
		`value="45"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("prefill misses %q", want)
		}
	}
	for _, not := range []string{
		`value="package.install_all"`, // not schedulable
		`value="system.reboot"`,       // not schedulable
		`value="new"`,                 // host not enrolled
	} {
		if strings.Contains(body, not) {
			t.Errorf("prefill offers %q", not)
		}
	}
	// Invalid values are ignored; all=1 checks every offered host.
	body = getBody(t, h, "/schedules?interval=999&days=999&all=1")
	for _, want := range []string{`value="1440" selected>`, `value="30"`, `value="web" checked>`} {
		if !strings.Contains(body, want) {
			t.Errorf("defaults miss %q", want)
		}
	}
}

func TestScheduleEndpoints(t *testing.T) {
	f := &fakeSchedules{}
	h := schedHandler(t, f)
	code, body := postJSON(t, h, "/schedules/create", `{"actions":["core.facts"],"hosts":["web"],"interval_minutes":1440,"days":30}`)
	if code != http.StatusOK || f.created != "core.facts|web" || f.created2 != 24*time.Hour || !strings.Contains(body, `"options":{"publicKey"`) {
		t.Fatalf("%d %s %q", code, body, f.created)
	}
	f.cli = true
	if _, body := postJSON(t, h, "/schedules/create", `{"actions":["core.facts"],"hosts":["web"],"interval_minutes":60}`); !strings.Contains(body, "nebula schedule approve eeeeeeeeeeeeeeee") {
		t.Fatal(body)
	}
	if code, _ := postJSON(t, h, "/schedules/approve", `{"id":"`+schedID+`","assertion":{"id":"cred"}}`); code != http.StatusOK {
		t.Fatal(code)
	}
	if code, _ := postJSON(t, h, "/schedules/revoke", `{"id":"`+schedID+`"}`); code != http.StatusOK {
		t.Fatal(code)
	}
	if strings.Join(f.calls, "|") != "approve "+schedID+` {"id":"cred"}|revoke `+schedID {
		t.Fatalf("%q", f.calls)
	}
	for err, want := range map[error]int{
		executions.ErrScheduleNotFound:                                         http.StatusNotFound,
		executions.ErrScheduleState:                                            http.StatusConflict,
		&executions.ScheduleError{Reason: "x"}:                                 http.StatusBadRequest,
		status.Error(codes.InvalidArgument, "schedule_grant_invalid: not LOW"): http.StatusConflict,
		status.Error(codes.Unavailable, "dial /run/x.sock"):                    http.StatusBadGateway,
	} {
		f.err = err
		for _, path := range []string{"/schedules/approve", "/schedules/revoke"} {
			if c, body := postJSON(t, h, path, `{"id":"`+schedID+`"}`); c != want || strings.Contains(body, "/run/") {
				t.Errorf("%v %s: %d %s", err, path, c, body)
			}
		}
		if c, _ := postJSON(t, h, "/schedules/create", `{"actions":["core.facts"],"hosts":["web"],"interval_minutes":60}`); c != want {
			t.Errorf("%v create: %d", err, c)
		}
	}
	// Without Options.Schedules the pages do not exist.
	nh := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org"}).Handler()
	if code, _ := postJSON(t, nh, "/schedules/create", `{}`); code != http.StatusNotFound {
		t.Fatal(code)
	}
}
