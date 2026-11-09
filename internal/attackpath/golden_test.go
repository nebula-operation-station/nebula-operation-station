// SPDX-License-Identifier: AGPL-3.0-or-later

package attackpath

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// goldenLabHash is the snapshot hash of the lab fixture in builder_test.go.
// A change here means the snapshot encoding changed: bump SnapshotVersion
// and the hash domain tag, never only this value.
const goldenLabHash = "e7929581b9df85d146b3bedc02f67717c701011b34b2f928fc6d818f0dcb111f"

// readGolden returns the hand-written golden file in its compact form; the
// files are indented for review, Snapshot is compact.
func readGolden(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		t.Fatalf("compact golden: %v", err)
	}
	return buf.Bytes()
}

func TestLabSnapshotMatchesGolden(t *testing.T) {
	g := buildLab(t, 0)
	if got, want := g.Snapshot(), readGolden(t, "lab.golden.json"); !bytes.Equal(got, want) {
		t.Fatalf("snapshot differs from testdata/lab.golden.json:\ngot  %s\nwant %s", got, want)
	}
	if g.Hash() != goldenLabHash {
		t.Fatalf("hash = %s, want %s", g.Hash(), goldenLabHash)
	}
}

func TestEmptySnapshotMatchesGolden(t *testing.T) {
	got := NewBuilder().Build().Snapshot()
	if want := readGolden(t, "empty.golden.json"); !bytes.Equal(got, want) {
		t.Fatalf("snapshot differs from testdata/empty.golden.json:\ngot  %s\nwant %s", got, want)
	}
}
