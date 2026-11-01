// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

// TaskState is the reconciled state of one PVE task.
type TaskState string

// Task states returned by TaskStatus.
const (
	// TaskRunning means the task has not finished.
	TaskRunning TaskState = "running"
	// TaskOK means the task finished with exit status "OK".
	TaskOK TaskState = "ok"
	// TaskWarnings means the task finished with "WARNINGS: n".
	TaskWarnings TaskState = "warnings"
	// TaskFailed means the task finished with any other exit status.
	TaskFailed TaskState = "failed"
)

// TaskStatusResult is the validated status of one task.
type TaskStatusResult struct {
	// UPID is the task, identical to the requested UPID.
	UPID string
	// Node, Type and ID come from the parsed UPID.
	Node string
	// Type is the task type, e.g. "qmclone".
	Type string
	// ID is the task target id, e.g. the VMID.
	ID string
	// State is the reconciled state.
	State TaskState
	// ExitStatus is the sanitized PVE exit status of a finished task
	// (untrusted text, render as text only); empty while running.
	ExitStatus string
}

// TaskStatus reads GET /nodes/{node}/tasks/{upid}/status for a UPID
// returned by a Writer method. The node is taken from the validated UPID;
// the response must name the same UPID. Task logs are never read.
func (w *Writer) TaskStatus(ctx context.Context, upid string) (TaskStatusResult, error) {
	const op = "task-status"
	task, err := parseUPID(upid)
	if err != nil || validNodeName(task.Node) != nil {
		return TaskStatusResult{}, invalid(op, "upid")
	}
	path := "/nodes/" + url.PathEscape(task.Node) + "/tasks/" + url.PathEscape(upid) + "/status"
	data, err := w.call(ctx, writeRequest{op: op, method: http.MethodGet, path: path})
	if err != nil {
		return TaskStatusResult{}, err
	}
	var st struct {
		UPID       string  `json:"upid"`
		Status     string  `json:"status"`
		ExitStatus *string `json:"exitstatus"`
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return TaskStatusResult{}, &WriteError{Op: op, Reason: ReasonSchema}
	}
	if st.UPID != upid {
		return TaskStatusResult{}, &WriteError{Op: op, Reason: ReasonSchema}
	}
	out := TaskStatusResult{UPID: upid, Node: task.Node, Type: task.Type, ID: task.ID}
	switch st.Status {
	case "running":
		out.State = TaskRunning
	case "stopped":
		if st.ExitStatus == nil || *st.ExitStatus == "" || len(*st.ExitStatus) > MaxErrorMessageBytes {
			return TaskStatusResult{}, &WriteError{Op: op, Reason: ReasonSchema}
		}
		exit := sanitizeText(*st.ExitStatus, MaxErrorMessageBytes)
		out.ExitStatus = exit
		switch {
		case exit == "OK":
			out.State = TaskOK
		case strings.HasPrefix(exit, "WARNINGS: "):
			out.State = TaskWarnings
		default:
			out.State = TaskFailed
		}
	default:
		return TaskStatusResult{}, &WriteError{Op: op, Reason: ReasonSchema}
	}
	return out, nil
}
