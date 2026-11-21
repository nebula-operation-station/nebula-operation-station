// SPDX-License-Identifier: AGPL-3.0-or-later

package netdevcollect

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevinventory"
)

// recordingStore fails the test if the importer ever writes a dataset; the
// device metadata step only stages records until the store step exists.
type recordingStore struct {
	t     *testing.T
	calls int
}

func (r *recordingStore) ReplaceDataset(context.Context, string, netdevinventory.Read, uint64, time.Time, bool, netdevinventory.Rows) (netdevinventory.ReplaceResult, error) {
	r.calls++
	r.t.Errorf("device metadata reached the dataset store")
	return netdevinventory.ReplaceResult{}, nil
}

func TestImportStepTableSeparatesMetadataFromExecutorReads(t *testing.T) {
	if _, ok := spoolReadEnum[ReadDeviceMetadata]; ok {
		t.Fatalf("%s maps to an executor read; it must not", ReadDeviceMetadata)
	}
	for _, rp := range readPayloads {
		if got := importStepFor(rp.read); got != stepDataset {
			t.Errorf("importStepFor(%s) = %v, want stepDataset", rp.read, got)
		}
	}
	if got := importStepFor(ReadDeviceMetadata); got != stepDeviceMetadata {
		t.Errorf("importStepFor(%s) = %v, want stepDeviceMetadata", ReadDeviceMetadata, got)
	}
	for _, bad := range []string{"", "device_facts", "CBS_VLANS", "device_metadata/../x", "device_metadata2"} {
		if got := importStepFor(bad); got != stepUnknown {
			t.Errorf("importStepFor(%q) = %v, want stepUnknown", bad, got)
		}
	}
}

func TestImportStagesValidMetadataWithoutStoring(t *testing.T) {
	env := newImportEnv(t)
	store := &recordingStore{t: t}
	env.imp.Store = store
	name := env.write(t, importCBS, ReadDeviceMetadata, importGen, false,
		`{"device_id":"core-sw-01","family":"cbs","label":"Core switch","trust_generation":3,"blocked":false,"block_reason":""}`)

	rep := env.run(t)
	if rep.Staged != 1 || rep.Imported != 0 || rep.Kept != 0 || rep.Failed != 0 {
		t.Fatalf("report = %+v, want one staged record", rep)
	}
	if store.calls != 0 {
		t.Fatalf("store called %d times", store.calls)
	}
	if !slices.Contains(spoolFiles(t, env.spool), name) {
		t.Fatalf("staged record %s was removed; it must wait for the store step", name)
	}
}

func TestImportKeepsInvalidMetadataWithReason(t *testing.T) {
	cases := []struct {
		name, device, payload string
		gen                   uint64
	}{
		{"unknown field", importCBS, `{"device_id":"core-sw-01","family":"cbs","label":"a","trust_generation":3,"blocked":false,"block_reason":"","endpoint_ip":"10.0.0.2"}`, importGen},
		{"control character in label", importCBS, `{"device_id":"core-sw-01","family":"cbs","label":"a\u0007","trust_generation":3,"blocked":false,"block_reason":""}`, importGen},
		{"record and payload device differ", importCBS, `{"device_id":"fw-01","family":"cbs","label":"a","trust_generation":3,"blocked":false,"block_reason":""}`, importGen},
		{"record and payload generation differ", importCBS, `{"device_id":"core-sw-01","family":"cbs","label":"a","trust_generation":2,"blocked":false,"block_reason":""}`, importGen},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newImportEnv(t)
			writeRawRecord(t, env.spool, tc.device, ReadDeviceMetadata, tc.gen, tc.payload)
			rep := env.run(t)
			if rep.Kept != 1 || rep.Staged != 0 || rep.Imported != 0 {
				t.Fatalf("report = %+v, want one kept record", rep)
			}
			if !slices.ContainsFunc(keptNames(t, env.spool), func(n string) bool {
				return strings.HasPrefix(n, tc.device+"-"+ReadDeviceMetadata+"-")
			}) {
				t.Fatalf("rejected metadata not moved to %s: %v", KeptDirName, keptNames(t, env.spool))
			}
			if got := spoolFiles(t, env.spool); len(got) != 0 {
				t.Fatalf("spool still holds %v", got)
			}
		})
	}
}

// A file whose name is outside the closed read set is not a spool entry at
// all: List skips it, so the importer neither stores nor moves it.
func TestImportIgnoresFileWithUnknownReadName(t *testing.T) {
	env := newImportEnv(t)
	writeRawRecord(t, env.spool, importCBS, "device_facts", importGen, `{"device_id":"core-sw-01"}`)
	rep := env.run(t)
	if rep.Files != 0 || rep.Imported != 0 || rep.Staged != 0 || rep.Kept != 0 {
		t.Fatalf("report = %+v, want the unknown read ignored", rep)
	}
}

// writeRawRecord publishes a record that Spool.Write would refuse, to test
// what the importer does with a record it did not validate on the way in.
func writeRawRecord(t *testing.T, s *Spool, device, read string, gen uint64, payload string) {
	t.Helper()
	raw, err := json.Marshal(Record{DeviceID: device, Read: read, TrustGeneration: gen,
		ObservedAt: testTime.UTC(), Data: json.RawMessage(payload)})
	if err != nil {
		t.Fatal(err)
	}
	name := formatSpoolName(device, read, testTime.UnixNano(), strings.Repeat("A", randomChars))
	dir, err := s.openDir(true)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	if err := writeAt(dir, name, raw); err != nil {
		t.Fatalf("publish %s: %v", name, err)
	}
}

// keptNames lists the records in kept/, by spool name without the reason
// suffix.
func keptNames(t *testing.T, s *Spool) []string {
	t.Helper()
	var out []string
	for _, n := range dirNames(t, s.Dir+"/"+KeptDirName) {
		if !strings.HasSuffix(n, keptReasonSuffix) {
			out = append(out, n)
		}
	}
	return out
}
