// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"time"
)

// Limits for task reading, named next to the code that enforces them.
const (
	// maxUPIDTypeLen bounds a task type name.
	maxUPIDTypeLen = 64
	// maxUPIDUserLen bounds a task user name.
	maxUPIDUserLen = 256
	// taskPageSize bounds each task metadata request.
	taskPageSize = 100
	// maxTaskScan bounds total task objects scanned, even if none match Since.
	maxTaskScan = 1000
)

var (
	// nodeNameRe validates a PVE node name.
	nodeNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	// UPID numeric fields are hexadecimal; pstart can grow to nine digits.
	// The target may be empty or nonnumeric and the final colon is required.
	upidRe = regexp.MustCompile(fmt.Sprintf(
		`^UPID:([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?):([0-9A-Fa-f]{8}):([0-9A-Fa-f]{8,9}):([0-9A-Fa-f]{8}):`+
			`([^:\s/]{1,%d}):([^:\s/]*):([^:\s/]{1,%d}):$`,
		maxUPIDTypeLen, maxUPIDUserLen))
)

// TaskFilter selects and bounds the task summaries returned by NodeTasks.
type TaskFilter struct {
	// Since restricts the result to tasks that started at or after this
	// time. Zero means no restriction.
	Since time.Time
	// Limit bounds the number of returned summaries. Zero means
	// MaxTaskLimit. Values above MaxTaskLimit are rejected.
	Limit int
	// Type restricts the result to one task type (PVE "typefilter", for
	// example "vzdump"). Empty means all types. The filter is sent to PVE
	// and re-applied to every returned task, so a server ignoring it can
	// never widen the result.
	Type string
	// VMID restricts the result to tasks whose target ID is exactly this
	// guest (PVE "vmid"). Zero means all targets. Re-applied like Type.
	VMID uint64
}

// taskTypeRe validates a TaskFilter.Type.
var taskTypeRe = regexp.MustCompile(`^[a-z][a-z0-9]{0,31}$`)

// matches re-applies the type and VMID filter to one parsed task.
func (f TaskFilter) matches(t TaskSummary) bool {
	if f.Type != "" && t.Type != f.Type {
		return false
	}
	return f.VMID == 0 || t.ID == strconv.FormatUint(f.VMID, 10)
}

// TaskList is a bounded summary of one node's task list.
type TaskList struct {
	// Available reports whether the node's task list could be read.
	Available bool
	// Reason explains an unavailable result.
	Reason string
	// Tasks are the matching task summaries, newest first.
	Tasks []TaskSummary
	// Truncated reports more matching tasks than Limit or an incomplete scan.
	Truncated bool
}

// TaskSummary is one task object from /nodes/{node}/tasks. It is task
// metadata only (actor, type, time, target, status); the client never
// fetches task logs, task status detail or command output.
type TaskSummary struct {
	Actor        string
	Target       string
	VMID         uint64
	StartedUnix  int64
	FinishedUnix int64
	// ExitStatus is the terminal task result; empty means no terminal
	// result was observed. A result also requires valid start/end times.
	ExitStatus string
	// UPID is the validated raw UPID string.
	UPID string
	// Node is the node the task ran on.
	Node string
	// Type is the task type, e.g. "qmstart", "vzdump", "update".
	Type string
	// ID is the target identifier; empty for tasks without a target.
	ID string
	// User is the actor, e.g. "root@pam".
	User string
	// Start is when the task started.
	Start time.Time
	// End is when the task ended from metadata; zero means unknown.
	End time.Time
	// Status is the metadata status or exit result (e.g. "RUNNING", "OK",
	// or an error message); empty means unknown.
	Status string
}

type taskData struct {
	UPID    string `json:"upid"`
	EndTime *int64 `json:"endtime"`
	Status  string `json:"status"`
	User    string `json:"user"`
}

// NodeTasks reads GET /nodes/{node}/tasks using bounded start/limit pages.
// It returns task metadata only; it never calls the per-task status or
// log endpoints under /nodes/{node}/tasks/{upid}, and it has no mutation
// endpoints.
func (c *Client) NodeTasks(ctx context.Context, node string, f TaskFilter) (TaskList, error) {
	if !nodeNameRe.MatchString(node) {
		return TaskList{}, fmt.Errorf("pveapi: invalid node name")
	}
	limit := f.Limit
	if limit <= 0 {
		limit = MaxTaskLimit
	}
	if limit > MaxTaskLimit {
		return TaskList{}, fmt.Errorf("pveapi: task limit %d exceeds %d", limit, MaxTaskLimit)
	}
	if f.Type != "" && !taskTypeRe.MatchString(f.Type) {
		return TaskList{}, fmt.Errorf("pveapi: invalid task type filter")
	}
	if f.VMID > MaxVMID {
		return TaskList{}, fmt.Errorf("pveapi: invalid task vmid filter")
	}

	out := TaskList{Available: true}
	for start := 0; start < maxTaskScan; start += taskPageSize {
		query := url.Values{"start": {strconv.Itoa(start)}, "limit": {strconv.Itoa(taskPageSize)}}
		if !f.Since.IsZero() {
			query.Set("since", strconv.FormatInt(f.Since.Unix(), 10))
		}
		if f.Type != "" {
			query.Set("typefilter", f.Type)
		}
		if f.VMID != 0 {
			query.Set("vmid", strconv.FormatUint(f.VMID, 10))
		}
		body, reason, err := c.clusterGet(ctx, "/nodes/"+url.PathEscape(node)+"/tasks?"+query.Encode())
		if err != nil {
			return TaskList{}, err
		}
		if body == nil {
			if reason == reasonNotFound {
				reason = "unknown node: no task list"
			}
			return TaskList{Reason: reason}, nil
		}
		page, err := decodeData[[]taskData](body)
		if err != nil {
			return TaskList{}, err
		}
		if len(*page) > taskPageSize {
			return TaskList{}, fmt.Errorf("%w: task page exceeds requested limit", ErrMalformed)
		}
		for _, entry := range *page {
			task, err := parseUPID(entry.UPID)
			if err != nil {
				return TaskList{}, err
			}
			if task.Node != node {
				return TaskList{}, fmt.Errorf("%w: task node mismatch", ErrMalformed)
			}
			if task.Status, err = checkText("status", entry.Status); err != nil {
				return TaskList{}, err
			}
			// PVE may render token actors as the owning user in task metadata.
			if entry.User != "" {
				if task.User, err = checkText("user", entry.User); err != nil {
					return TaskList{}, err
				}
			}
			if entry.EndTime != nil {
				if *entry.EndTime < task.Start.Unix() || *entry.EndTime > maxStartUnix {
					return TaskList{}, fmt.Errorf("%w: task end time out of range", ErrMalformed)
				}
				task.End = time.Unix(*entry.EndTime, 0).UTC()
			}
			if (!f.Since.IsZero() && task.Start.Before(f.Since)) || !f.matches(task) {
				continue
			}
			if len(out.Tasks) == limit {
				out.Truncated = true
				return out, nil
			}
			out.Tasks = append(out.Tasks, task)
		}
		if len(*page) < taskPageSize {
			return out, nil
		}
	}
	out.Truncated = true
	return out, nil
}

// parseUPID parses one PVE UPID string into a TaskSummary.
func parseUPID(raw string) (TaskSummary, error) {
	if _, err := checkText("upid", raw); err != nil {
		return TaskSummary{}, err
	}
	m := upidRe.FindStringSubmatch(raw)
	if m == nil {
		return TaskSummary{}, fmt.Errorf("%w: invalid upid", ErrMalformed)
	}
	start, err := strconv.ParseInt(m[4], 16, 64)
	if err != nil || start <= 0 || start > maxStartUnix {
		return TaskSummary{}, fmt.Errorf("%w: invalid upid start time", ErrMalformed)
	}
	// Decode both process fields using their actual hexadecimal representation.
	for _, field := range []string{m[2], m[3]} {
		if _, err := strconv.ParseUint(field, 16, 64); err != nil {
			return TaskSummary{}, fmt.Errorf("%w: invalid upid process field", ErrMalformed)
		}
	}
	return TaskSummary{
		UPID:  raw,
		Node:  m[1],
		Type:  m[5],
		ID:    m[6],
		User:  m[7],
		Start: time.Unix(start, 0).UTC(),
	}, nil
}
