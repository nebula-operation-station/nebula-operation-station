// SPDX-License-Identifier: AGPL-3.0-or-later

package release

import (
	"bytes"
	"errors"
	"fmt"
)

// tarBlock is the ustar block size.
const tarBlock = 512

// tarEntry is one regular file of a strictly read ustar archive. data
// aliases the archive bytes.
type tarEntry struct {
	name string
	data []byte
}

// tarLimits bounds one archive read.
type tarLimits struct {
	maxEntries int
	maxFile    int64
	maxTotal   int64
}

// readUstar reads an uncompressed POSIX ustar archive strictly: regular
// files only (no links, directories, devices, FIFOs, sparse, PAX or GNU
// records), valid header checksums, octal sizes, NUL-padded fields, zero
// padding, no duplicate paths, two zero end blocks and nothing but zeros
// after them. Ownership, modes and times are ignored. Limits are checked
// from the headers before any data is used. No data is extracted.
func readUstar(b []byte, lim tarLimits, validName func(string) bool) ([]tarEntry, error) {
	if len(b)%tarBlock != 0 {
		return nil, errors.New("archive size is not a multiple of 512")
	}
	var out []tarEntry
	seen := map[string]bool{}
	var total int64
	for off := 0; ; {
		if off+tarBlock > len(b) {
			return nil, errors.New("archive lacks its two zero end blocks")
		}
		h := b[off : off+tarBlock]
		if allZero(h) {
			if off+2*tarBlock > len(b) || !allZero(b[off+tarBlock:off+2*tarBlock]) {
				return nil, errors.New("archive lacks its second zero end block")
			}
			if !allZero(b[off+2*tarBlock:]) {
				return nil, errors.New("nonzero data after the end of the archive")
			}
			return out, nil
		}
		name, size, err := parseUstarHeader(h)
		if err != nil {
			return nil, err
		}
		if len(out) >= lim.maxEntries {
			return nil, fmt.Errorf("more than %d entries", lim.maxEntries)
		}
		if !validName(name) {
			return nil, fmt.Errorf("entry %q has an invalid path", name)
		}
		if seen[name] {
			return nil, fmt.Errorf("duplicate entry %q", name)
		}
		seen[name] = true
		if size > lim.maxFile {
			return nil, fmt.Errorf("entry %q exceeds %d bytes", name, lim.maxFile)
		}
		if total += size; total > lim.maxTotal {
			return nil, fmt.Errorf("entries exceed %d bytes in total", lim.maxTotal)
		}
		padded := (size + tarBlock - 1) / tarBlock * tarBlock
		start := int64(off + tarBlock)
		if start+padded > int64(len(b)) {
			return nil, fmt.Errorf("entry %q is truncated", name)
		}
		if !allZero(b[start+size : start+padded]) {
			return nil, fmt.Errorf("entry %q has nonzero padding", name)
		}
		out = append(out, tarEntry{name: name, data: b[start : start+size : start+size]})
		off = int(start + padded)
	}
}

// parseUstarHeader validates one header block and returns path and size.
func parseUstarHeader(h []byte) (string, int64, error) {
	if string(h[257:263]) != "ustar\x00" || string(h[263:265]) != "00" {
		return "", 0, errors.New("entry is not a POSIX ustar header")
	}
	want, err := parseOctal(h[148:156])
	if err != nil {
		return "", 0, errors.New("header checksum is malformed")
	}
	var sum int64
	for i, c := range h {
		if i >= 148 && i < 156 {
			c = ' '
		}
		sum += int64(c)
	}
	if sum != want {
		return "", 0, errors.New("header checksum does not match")
	}
	if t := h[156]; t != '0' && t != 0 {
		return "", 0, fmt.Errorf("entry type %q is not a regular file", t)
	}
	if !allZero(h[157:257]) {
		return "", 0, errors.New("regular file carries a link name")
	}
	name, ok := cString(h[0:100])
	prefix, ok2 := cString(h[345:500])
	if !ok || !ok2 || name == "" {
		return "", 0, errors.New("entry name is malformed")
	}
	if prefix != "" {
		name = prefix + "/" + name
	}
	size, err := parseOctal(h[124:136])
	if err != nil {
		return "", 0, fmt.Errorf("entry %q has a malformed size", name)
	}
	return name, size, nil
}

// parseOctal parses a NUL- or space-terminated octal field; base-256 and
// other spellings are rejected.
func parseOctal(f []byte) (int64, error) {
	f = bytes.TrimLeft(f, " ")
	end := bytes.IndexAny(f, "\x00 ")
	if end < 0 {
		end = len(f)
	}
	digits, rest := f[:end], f[end:]
	if len(digits) == 0 || len(digits) > 11 {
		return 0, errors.New("bad octal field")
	}
	for _, c := range rest {
		if c != 0 && c != ' ' {
			return 0, errors.New("bad octal field")
		}
	}
	var n int64
	for _, c := range digits {
		if c < '0' || c > '7' {
			return 0, errors.New("bad octal field")
		}
		n = n*8 + int64(c-'0')
	}
	return n, nil
}

// cString returns the NUL-terminated string of a field whose remaining
// bytes are all NUL.
func cString(f []byte) (string, bool) {
	i := bytes.IndexByte(f, 0)
	if i < 0 {
		return string(f), true
	}
	return string(f[:i]), allZero(f[i:])
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
