// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"unicode/utf8"
)

// Guest agent file read (GET /nodes/{node}/qemu/{vmid}/agent/file-read,
// ADR 0008 section 4). PVE answers {"content": "...", "truncated": bool}
// where content is the decoded file and truncated is set when the file
// exceeded PVE's own read limit. The answer is untrusted guest data.

const (
	// MaxAgentFileReadBytes is the largest maxBytes AgentFileRead accepts;
	// it keeps file reads to small, known files.
	MaxAgentFileReadBytes = 64 << 10
	// maxAgentFilePathLen bounds the guest path.
	maxAgentFilePathLen = 255
)

var (
	// ErrAgentFileTruncated is returned when PVE reports the file content
	// as truncated.
	ErrAgentFileTruncated = errors.New("pveapi: guest agent file read truncated")
	// ErrAgentFileTooLarge is returned when the file content exceeds the
	// caller's limit.
	ErrAgentFileTooLarge = errors.New("pveapi: guest agent file exceeds the size limit")
)

// validAgentFilePath accepts an absolute, clean, printable ASCII path.
func validAgentFilePath(p string) bool {
	if p == "" || len(p) > maxAgentFilePathLen || p[0] != '/' || strings.Contains(p, "//") ||
		strings.HasSuffix(p, "/") {
		return false
	}
	for _, seg := range strings.Split(p[1:], "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 0x21 || p[i] > 0x7e {
			return false
		}
	}
	return true
}

// AgentFileRead reads one file of QEMU guest vmid on node through its
// guest agent. The response must be exactly {"content": string} with an
// optional "truncated" flag (false/0 or true/1) and nothing else; a
// truncated read, content of more than maxBytes bytes, or content that is
// not valid UTF-8 is an error. maxBytes must be within
// 1..MaxAgentFileReadBytes. An unavailable agent returns an error wrapping
// ErrAgentUnavailable. The content is untrusted.
func (c *Client) AgentFileRead(ctx context.Context, node string, vmid int, file string, maxBytes int) ([]byte, error) {
	if err := validateNodeName(node); err != nil {
		return nil, err
	}
	if err := validateVMID(vmid); err != nil {
		return nil, err
	}
	if !validAgentFilePath(file) {
		return nil, errors.New("pveapi: invalid guest file path")
	}
	if maxBytes < 1 || maxBytes > MaxAgentFileReadBytes {
		return nil, fmt.Errorf("pveapi: file read limit %d outside 1..%d", maxBytes, MaxAgentFileReadBytes)
	}
	data, err := c.do(ctx, fmt.Sprintf("/nodes/%s/qemu/%d/agent/file-read?file=%s", node, vmid, url.QueryEscape(file)))
	if err != nil {
		if reason, ok := agentUnavailable(err); ok {
			return nil, fmt.Errorf("%w: %s", ErrAgentUnavailable, reason)
		}
		return nil, err
	}
	return parseAgentFileRead(data, maxBytes)
}

// parseAgentFileRead decodes the data member of a file-read answer
// strictly.
func parseAgentFileRead(data json.RawMessage, maxBytes int) ([]byte, error) {
	var raw struct {
		Content   *string         `json:"content"`
		Truncated json.RawMessage `json:"truncated"`
	}
	// encoding/json silently replaces invalid UTF-8 with U+FFFD, so the
	// raw answer is checked first.
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("%w: file read: not UTF-8", ErrAgentMalformed)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("%w: file read: %v", ErrAgentMalformed, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: file read: trailing data", ErrAgentMalformed)
	}
	if raw.Content == nil {
		return nil, fmt.Errorf("%w: file read: missing content", ErrAgentMalformed)
	}
	switch t := string(bytes.TrimSpace(raw.Truncated)); t {
	case "", "false", "0":
	case "true", "1":
		return nil, ErrAgentFileTruncated
	default:
		return nil, fmt.Errorf("%w: file read: truncated flag", ErrAgentMalformed)
	}
	if len(*raw.Content) > maxBytes {
		return nil, fmt.Errorf("%w: %d > %d bytes", ErrAgentFileTooLarge, len(*raw.Content), maxBytes)
	}
	return []byte(*raw.Content), nil
}
