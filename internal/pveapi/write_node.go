// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
)

// RebootNode reboots one exact PVE node (POST /nodes/{node}/status with
// command=reboot). PVE answers a node reboot without a UPID: only the
// documented {"data":null} response is accepted, and anything else is a
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
	// PVE answers a node reboot without a UPID: accept only an explicit
	// {"data":null}; anything else is a schema error with an unknown outcome.
	if !bytes.Equal(data, []byte("null")) {
		return &WriteError{Op: op, Reason: ReasonSchema}
	}
	return nil
}

// nodeStatusCall performs one POST to a node status endpoint and returns the
// raw "data" member of the response envelope. It shares the full transport
// path with call in write.go through doWrite (token, timeout, request
// construction, size limit, UTF-8, HTTP status mapping, 400 parameter
// extraction, redirect refusal, and timeout → OutcomeUnknown), with one
// deliberate difference in data acceptance: it does not reject a null data
// member, because a node reboot answers without a UPID, but it requires an
// object envelope whose only member is "data" and rejects a repeated
// top-level key. The caller (RebootNode) decides whether the returned data
// is the documented null response.
func (w *Writer) nodeStatusCall(ctx context.Context, r writeRequest) (json.RawMessage, error) {
	raw, err := w.doWrite(ctx, r)
	if err != nil {
		return nil, err
	}
	// A repeated top-level key is not the documented answer: the map below
	// keeps only the last value, so {"data":"UPID:…","data":null} would
	// otherwise read as the null success response.
	if duplicateTopLevelKeys(raw) {
		return nil, &WriteError{Op: r.op, Reason: ReasonSchema}
	}
	// The envelope must be an object whose only member is "data": a bare
	// null, an empty object, or an error-shaped body ("errors", "message")
	// is not the documented answer and must not read as success.
	var env map[string]json.RawMessage
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, &WriteError{Op: r.op, Reason: ReasonInvalidJSON}
	}
	data, ok := env["data"]
	if env == nil || !ok || len(env) != 1 {
		return nil, &WriteError{Op: r.op, Reason: ReasonSchema}
	}
	return data, nil
}

// duplicateTopLevelKeys reports whether raw is a JSON object that repeats a
// top-level key name. Decoding such an object into a map keeps only the last
// value, so a hostile {"data":"UPID:…","data":null} envelope must be
// rejected before the map decode. Non-object or malformed input reports
// false; the caller's unmarshal fails on it with its own reason.
func duplicateTopLevelKeys(raw []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return false
	}
	d, ok := tok.(json.Delim)
	if !ok || d != '{' {
		return false
	}
	seen := make(map[string]struct{})
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return false
		}
		key, ok := keyTok.(string)
		if !ok {
			return false
		}
		if _, dup := seen[key]; dup {
			return true
		}
		seen[key] = struct{}{}
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return false
		}
	}
	return false
}
