// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"
)

// RebootNode reboots one exact PVE node (POST /nodes/{node}/status with
// command=reboot). PVE answers a node reboot without a UPID: only the
// documented empty/null data response is accepted, and anything else is a
// *WriteError. A timeout is OutcomeUnknown like the other writes, so callers
// reconcile through the task list and never redispatch blindly (ADR 0006,
// phase 2: "Node reboot: HIGH standalone; CRITICAL cluster; exact node").
// Shutdown is not offered: the only command sent is "reboot".
//
// The node is validated before anything is sent; an invalid node name is
// refused with ErrInvalidArgument and no request is made.
func (w *Writer) RebootNode(ctx context.Context, node string) error {
	const op = "reboot-node"
	if validNodeName(node) != nil {
		return invalid(op, "node")
	}
	data, err := w.nodeStatusCall(ctx, writeRequest{
		op:     op,
		method: http.MethodPost,
		path:   "/nodes/" + url.PathEscape(node) + "/status",
		form:   url.Values{"command": {"reboot"}},
	})
	if err != nil {
		return err
	}
	// PVE answers a node reboot without a UPID: accept only the documented
	// empty/null data response; anything else is a schema error with an
	// unknown outcome.
	if len(data) != 0 && !bytes.Equal(data, []byte("null")) {
		return &WriteError{Op: op, Reason: ReasonSchema}
	}
	return nil
}

// nodeStatusCall performs one POST to a node status endpoint and returns the
// raw "data" member of the response envelope. It mirrors call in write.go
// exactly (token, timeout, request construction, size limit, UTF-8, JSON
// envelope, HTTP status mapping, 400 parameter extraction, redirect refusal,
// and timeout → OutcomeUnknown), with one deliberate difference: it does not
// reject an empty/null data member, because a node reboot answers without a
// UPID. The caller (RebootNode) decides whether the returned data is the
// documented empty/null response.
func (w *Writer) nodeStatusCall(ctx context.Context, r writeRequest) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	reqCtx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()

	tok, err := w.token(reqCtx)
	if err != nil {
		return nil, &WriteError{Op: r.op, Reason: ReasonNoToken}
	}
	var body io.Reader
	if r.form != nil {
		body = strings.NewReader(r.form.Encode())
	}
	req, err := http.NewRequestWithContext(reqCtx, r.method, w.base+apiRoot+r.path, body)
	if err != nil {
		return nil, &WriteError{Op: r.op, Reason: ReasonTransport}
	}
	req.Header.Set("Authorization", tok)
	req.Header.Set("Accept", "application/json")
	if r.form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	resp, err := w.http.Do(req)
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return nil, &WriteError{Op: r.op, Reason: ReasonTransport, cause: cerr}
		}
		if errors.Is(reqCtx.Err(), context.DeadlineExceeded) {
			return nil, &WriteError{Op: r.op, Reason: ReasonTimeout, cause: context.DeadlineExceeded}
		}
		return nil, &WriteError{Op: r.op, Reason: ReasonTransport}
	}
	defer resp.Body.Close()

	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, MaxWriteResponseBytes+1))
	if resp.StatusCode != http.StatusOK {
		e := &WriteError{Op: r.op, Reason: ReasonHTTPError, Status: resp.StatusCode}
		if resp.StatusCode == http.StatusBadRequest && readErr == nil && len(raw) <= MaxWriteResponseBytes {
			e.Params = rejectedParams(raw, r.form)
		}
		return nil, e
	}
	if readErr != nil {
		return nil, &WriteError{Op: r.op, Reason: ReasonTransport}
	}
	if len(raw) > MaxWriteResponseBytes {
		return nil, &WriteError{Op: r.op, Reason: ReasonOversize}
	}
	if !utf8.Valid(raw) {
		return nil, &WriteError{Op: r.op, Reason: ReasonInvalidUTF8}
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, &WriteError{Op: r.op, Reason: ReasonInvalidJSON}
	}
	return env.Data, nil
}
