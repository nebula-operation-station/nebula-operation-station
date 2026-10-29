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
	// maxUPIDStatusLen bounds a task status name.
	maxUPIDStatusLen = 64
)

var (
	// nodeNameRe validates a PVE node name.
	nodeNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	// upidRe parses a PVE UPID:
	//
	//	UPID:<node>:<pid>:<pveuuid>:<start>:<type>:<vmid>:<user>[:<status>]
	//
	// The trailing status field is present in PVE 9 tasklists and absent in
	// older PVE 8 lists; both shapes are accepted.
	upidRe = regexp.MustCompile(fmt.Sprintf(
		`^UPID:([^:]{1,64}):(\d{1,10}):(\d{1,10}):(\d{1,10}):`+
			`([^:]{1,%d}):(\d{1,10}):`+
			`([^:]{1,%d})(?::([^:]{0,%d}))?$`,
		maxUPIDTypeLen, maxUPIDUserLen, maxUPIDStatusLen))
)

// TaskFilter selects and bounds the task summaries returned by NodeTasks.
type TaskFilter struct {
	// Since restricts the result to tasks that started at or after this
	// time. Zero means no restriction.
	Since time.Time
	// Limit bounds the number of returned summaries. Zero means
	// MaxTaskLimit. Values above MaxTaskLimit are rejected.
	Limit int
}

// TaskList is a bounded summary of one node's task list.
type TaskList struct {
	// Available reports whether the node's task list could be read.
	Available bool
	// Reason explains an unavailable result.
	Reason string
	// Tasks are the matching task summaries, newest first.
	Tasks []TaskSummary
	// Truncated reports that more tasks matched the filter than Limit.
	Truncated bool
}

// TaskSummary is one parsed UPID from /nodes/{node}/tasklist. It is task
// metadata only (actor, type, time, target, status); the client never
// fetches task logs, task status detail or command output.
type TaskSummary struct {
	// UPID is the validated raw UPID string.
	UPID string
	// Node is the node the task ran on.
	Node string
	// Type is the task type, e.g. "qmstart", "vzdump", "update".
	Type string
	// ID is the target id (vmid) as digits; "0" for cluster-wide tasks.
	ID string
	// User is the actor, e.g. "root@pam".
	User string
	// Start is when the task started.
	Start time.Time
	// End is when the task ended; zero means unknown. The tasklist does
	// not carry end times and the client does not fetch per-task status.
	End time.Time
	// Status is the UPID status field ("started"/"stopped"); empty when
	// the UPID carries no status (older PVE 8 lists).
	Status string
}

// NodeTasks reads GET /nodes/{node}/tasklist and returns bounded task
// summaries. It parses UPIDs only; it never calls the per-task status or
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

	body, reason, err := c.do(ctx, "/nodes/"+url.PathEscape(node)+"/tasklist")
	if err != nil {
		return TaskList{}, err
	}
	if body == nil {
		if reason == reasonNotFound {
			reason = "unknown node: no task list"
		}
		return TaskList{Available: false, Reason: reason}, nil
	}

	ups, err := decodeData[[]string](body)
	if err != nil {
		return TaskList{}, err
	}
	if len(*ups) > maxTaskObjects {
		return TaskList{}, fmt.Errorf("%w: tasklist exceeds %d objects", ErrMalformed, maxTaskObjects)
	}

	out := TaskList{Available: true}
	for _, raw := range *ups {
		task, err := parseUPID(raw)
		if err != nil {
			return TaskList{}, err
		}
		if !f.Since.IsZero() && task.Start.Before(f.Since) {
			continue
		}
		if len(out.Tasks) < limit {
			out.Tasks = append(out.Tasks, task)
		} else {
			out.Truncated = true
		}
	}
	return out, nil
}

// parseUPID parses one PVE UPID string into a TaskSummary.
func parseUPID(raw string) (TaskSummary, error) {
	if len(raw) > maxTextLen {
		return TaskSummary{}, fmt.Errorf("%w: upid too long", ErrMalformed)
	}
	m := upidRe.FindStringSubmatch(raw)
	if m == nil {
		return TaskSummary{}, fmt.Errorf("%w: invalid upid", ErrMalformed)
	}
	start, err := strconv.ParseInt(m[4], 10, 64)
	if err != nil || start <= 0 || start > maxStartUnix {
		return TaskSummary{}, fmt.Errorf("%w: invalid upid start time", ErrMalformed)
	}
	id, err := strconv.ParseInt(m[6], 10, 64)
	if err != nil || id > maxVMID {
		return TaskSummary{}, fmt.Errorf("%w: invalid upid vmid", ErrMalformed)
	}
	status := m[8]
	// The status field is a fixed PVE vocabulary; anything else means the
	// string is not a tasklist UPID (e.g. a user field containing ':').
	if status != "" && status != "started" && status != "stopped" && status != "aborted" {
		return TaskSummary{}, fmt.Errorf("%w: invalid upid status", ErrMalformed)
	}
	return TaskSummary{
		UPID:  raw,
		Node:  m[1],
		Type:  m[5],
		ID:    m[6],
		User:  m[7],
		Start: time.Unix(start, 0).UTC(),
		// The tasklist does not carry end times; End stays zero (unknown).
		Status: status, // empty when the UPID has no status field
	}, nil
}
