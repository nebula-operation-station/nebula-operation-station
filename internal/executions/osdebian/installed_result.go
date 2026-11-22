// SPDX-License-Identifier: AGPL-3.0-or-later

package osdebian

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnver"
)

// MaxInstalledResult is the largest package.list_installed result the
// executor keeps (hostrun.MaxResult); the script stays below it.
const MaxInstalledResult = 1 << 20

// ReasonResultFormat: the result is not the package.list_installed 1.1.0
// JSON document. A plain nos-installed-v1 text result (1.0.0) is one of
// these: the executor never kept such a result, so none can be stored.
const ReasonResultFormat = "not a package.list_installed JSON result"

// ParseInstalledResult reads the result of package.list_installed 1.1.0:
// exactly one JSON object with exactly the members
//
//	"format":    "nos-installed-v1" (InstalledFormat)
//	"text":      the nos-installed-v1 text, parsed by ParseInstalled
//	"truncated": true when the script left out records to stay below
//	             MaxInstalledResult
//
// Like ParseInstalled it never fails: a result that is too large, not
// UTF-8, not that object, or has a duplicate, unknown or wrongly typed
// member gives an empty partial inventory with ReasonResultFormat (or
// ReasonReadFailed / ReasonTruncated when rs says so). The text stays
// untrusted host data; "truncated" can only make the read partial.
func ParseInstalledResult(result []byte, rs ReadStatus, distro vulnver.Distro) InstalledInventory {
	text, truncated, err := decodeInstalledResult(result)
	if err != nil {
		// The first reason wins, as in ParseInstalled: a failed or cut run
		// usually has no document at all.
		reason := ReasonResultFormat
		switch {
		case rs.ExitCode != 0:
			reason = ReasonReadFailed
		case rs.Truncated:
			reason = ReasonTruncated
		}
		return InstalledInventory{
			Complete:      false,
			Reason:        reason,
			RunningKernel: RunningKernel{State: KernelVersionUnknown, Reason: ReasonNoKernel},
		}
	}
	if truncated {
		rs.Truncated = true
	}
	return ParseInstalled(text, rs, distro)
}

var errInstalledResult = errors.New("osdebian: not a package.list_installed result")

// decodeInstalledResult checks the envelope member by member, so that a
// duplicate or case-variant key (which encoding/json would resolve
// silently) is rejected rather than shadowing another member.
func decodeInstalledResult(result []byte) ([]byte, bool, error) {
	if len(result) > MaxInstalledResult || !utf8.Valid(result) {
		return nil, false, errInstalledResult
	}
	dec := json.NewDecoder(bytes.NewReader(result))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, false, errInstalledResult
	}
	var (
		format, text string
		truncated    bool
		seen         = map[string]bool{}
	)
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			return nil, false, errInstalledResult
		}
		key, _ := k.(string)
		if seen[key] {
			return nil, false, errInstalledResult
		}
		seen[key] = true
		var dst any
		switch key {
		case "format":
			dst = &format
		case "text":
			dst = &text
		case "truncated":
			dst = &truncated
		default:
			return nil, false, errInstalledResult
		}
		// Each target is a string or a bool: a null, number, object or
		// array value is rejected, never defaulted.
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil || bytes.Equal(raw, []byte("null")) || json.Unmarshal(raw, dst) != nil {
			return nil, false, errInstalledResult
		}
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('}') {
		return nil, false, errInstalledResult
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false, errInstalledResult
	}
	if len(seen) != 3 || format != InstalledFormat {
		return nil, false, errInstalledResult
	}
	return []byte(text), truncated, nil
}
