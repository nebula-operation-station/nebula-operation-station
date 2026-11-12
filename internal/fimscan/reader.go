// SPDX-License-Identifier: AGPL-3.0-or-later

package fimscan

import (
	"context"
	"errors"
	"io"
)

var (
	// errDocLimit: the document exceeds the per-run byte limit.
	errDocLimit = errors.New("document exceeds byte limit")
	// errWindowLimit: one entry exceeds its byte limit.
	errWindowLimit = errors.New("entry exceeds byte limit")
)

// countingReader counts the bytes it hands to the JSON decoder and refuses
// to hand out more than the document limit, or more than the current entry
// window allows. Because encoding/json only reads when it needs more input
// for the value it is scanning, the decoder buffer never holds more than one
// window of host data.
type countingReader struct {
	ctx    context.Context
	r      io.Reader
	n      int64 // bytes handed out so far
	docMax int64 // document limit
	winEnd int64 // absolute offset the current window ends at
}

// setWindow lets the decoder read up to size bytes beyond start, the
// decoder's current input offset.
func (c *countingReader) setWindow(start, size int64) {
	c.winEnd = start + size
}

func (c *countingReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	if c.n > c.docMax {
		return 0, errDocLimit
	}
	if c.n >= c.winEnd {
		return 0, errWindowLimit
	}
	// Allow one byte past the document limit so that a document of exactly
	// docMax bytes still sees io.EOF and a longer one is detected.
	limit := min(c.winEnd-c.n, c.docMax+1-c.n)
	if int64(len(p)) > limit {
		p = p[:limit]
	}
	n, err := c.r.Read(p)
	c.n += int64(n)
	if c.n > c.docMax {
		return 0, errDocLimit
	}
	return n, err
}
