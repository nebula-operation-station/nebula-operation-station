// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func taskStatusBody(upid, status, exit string) string {
	b := `{"data":{"upid":"` + upid + `","node":"pve1","type":"qmclone","id":"9000","pid":4660,"starttime":1761648640,"status":"` + status + `"`
	if exit != "" {
		b += `,"exitstatus":"` + exit + `"`
	}
	return b + `}}`
}

func TestTaskStatusStates(t *testing.T) {
	cases := []struct {
		status, exit string
		want         TaskState
	}{
		{"running", "", TaskRunning},
		{"stopped", "OK", TaskOK},
		{"stopped", "WARNINGS: 2", TaskWarnings},
		{"stopped", "clone failed: storage full", TaskFailed},
	}
	for _, tc := range cases {
		t.Run(string(tc.want), func(t *testing.T) {
			f := &fakeWriteServer{body: taskStatusBody(upidClone, tc.status, tc.exit)}
			w := newTestWriter(t, f)
			got, err := w.TaskStatus(context.Background(), upidClone)
			if err != nil {
				t.Fatal(err)
			}
			if got.State != tc.want || got.ExitStatus != tc.exit || got.UPID != upidClone ||
				got.Node != "pve1" || got.Type != "qmclone" || got.ID != "9000" {
				t.Errorf("got %+v", got)
			}
			r := f.only(t)
			if r.method != http.MethodGet || r.path != "/api2/json/nodes/pve1/tasks/"+upidClone+"/status" {
				t.Errorf("request = %s %s", r.method, r.path)
			}
		})
	}
}

func TestTaskStatusSanitizesExitStatus(t *testing.T) {
	f := &fakeWriteServer{body: taskStatusBody(upidClone, "stopped", `bad\u001b[31mred\nline`)}
	w := newTestWriter(t, f)
	got, err := w.TaskStatus(context.Background(), upidClone)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != TaskFailed || strings.ContainsAny(got.ExitStatus, "\x1b\n") {
		t.Errorf("got %+v", got)
	}
}

func TestTaskStatusRejectsInvalidUPID(t *testing.T) {
	f := &fakeWriteServer{}
	w := newTestWriter(t, f)
	for _, upid := range []string{
		"", "UPID:pve1", "../../nodes", upidClone + "/../../x",
		"UPID:pve1:00001234:00ABCDEF:6900A000:qmclone:9000:nos@pve!action:extra",
		"UPID:PVE1:00001234:00ABCDEF:6900A000:qmclone:9000:nos@pve!action:",
	} {
		if _, err := w.TaskStatus(context.Background(), upid); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("TaskStatus(%q) err = %v", upid, err)
		}
	}
	if f.count() != 0 {
		t.Error("invalid request reached the server")
	}
}

func TestTaskStatusRejectsHostileResponses(t *testing.T) {
	cases := map[string]string{
		"other upid":      taskStatusBody(upidStart, "running", ""),
		"unknown status":  taskStatusBody(upidClone, "paused", ""),
		"stopped no exit": taskStatusBody(upidClone, "stopped", ""),
		"long exit":       taskStatusBody(upidClone, "stopped", strings.Repeat("x", MaxErrorMessageBytes+1)),
		"array":           `{"data":[]}`,
		"string":          `{"data":"OK"}`,
		"null":            `{"data":null}`,
		"oversize":        `{"data":{"upid":"` + strings.Repeat("A", MaxWriteResponseBytes) + `"}}`,
		"bad utf8":        "{\"data\":{\"upid\":\"\xff\"}}",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			w := newTestWriter(t, &fakeWriteServer{body: body})
			_, err := w.TaskStatus(context.Background(), upidClone)
			if !errors.Is(err, ErrWriteFailed) {
				t.Fatalf("err = %v, want ErrWriteFailed", err)
			}
		})
	}
}
