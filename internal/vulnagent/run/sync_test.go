// SPDX-License-Identifier: AGPL-3.0-or-later

package run

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// countingFile records how many bytes were read from the file. Stat is
// the real one, so the size check sees the real file.
type countingFile struct {
	*os.File
	read int64
}

func (c *countingFile) Read(p []byte) (int, error) {
	n, err := c.File.Read(p)
	c.read += int64(n)
	return n, err
}

// growingFile reports the size of the real file from Stat, but reads
// from body. It models a file that grew after the size check.
type growingFile struct {
	*os.File
	body io.Reader
}

func (g *growingFile) Read(p []byte) (int, error) { return g.body.Read(p) }

// openStateFile creates a state file of the given size (a sparse file
// when size is large) and opens it for reading.
func openStateFile(t *testing.T, content string, size int64) *os.File {
	t.Helper()
	path := filepath.Join(t.TempDir(), "feed.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if size > 0 {
		if err := os.Truncate(path, size); err != nil {
			t.Fatal(err)
		}
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func TestCSAFStateOversizeRefusedBeforeRead(t *testing.T) {
	// A sparse file of MaxCSAFStateBytes+1 bytes. If the Stat check is
	// removed, the reader is called and the test fails, because the
	// loader would buffer up to the limit before it rejects the file.
	f := openStateFile(t, "", MaxCSAFStateBytes+1)
	cf := &countingFile{File: f}
	_, err := readCSAFState("csaf-test", cf, MaxCSAFStateBytes)
	if !errors.Is(err, errCSAFStateTooLarge) {
		t.Fatalf("oversize state error = %v, want errCSAFStateTooLarge", err)
	}
	if cf.read != 0 {
		t.Errorf("oversize state read %d bytes before refusing, want 0", cf.read)
	}
}

func TestCSAFStateGrowthAfterStatRefused(t *testing.T) {
	// Stat reports a small valid file, but the reader yields more than
	// the limit. The limit is injected so the test buffers little memory.
	const limit = 8
	f := openStateFile(t, "{}", 0)
	body := strings.Repeat(" ", limit+8) + "{}"
	g := &growingFile{File: f, body: strings.NewReader(body)}
	_, err := readCSAFState("csaf-test", g, limit)
	if !errors.Is(err, errCSAFStateTooLarge) {
		t.Fatalf("grown state error = %v, want errCSAFStateTooLarge", err)
	}
}

func TestCSAFStateWithinLimitDecodes(t *testing.T) {
	// Control case for the two tests above: a small valid file within
	// the injected limit decodes, so the rejections come from the limit.
	const limit = 8
	f := openStateFile(t, "{}", 0)
	g := &growingFile{File: f, body: strings.NewReader("{}")}
	if _, err := readCSAFState("csaf-test", g, limit); err != nil {
		t.Fatalf("within-limit state: %v", err)
	}
}
