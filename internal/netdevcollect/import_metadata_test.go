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
func writeRawRecord(t *testing.T, s *Spool, device, read string, gen uint64, payload string) string {
	t.Helper()
	return writeRawRecordAt(t, s, device, read, gen, testTime, strings.Repeat("A", randomChars), payload)
}

// writeRawRecordAt publishes a record observed at observed under the random
// name part random, so tests can build many distinct spool files.
func writeRawRecordAt(t *testing.T, s *Spool, device, read string, gen uint64, observed time.Time, random, payload string) string {
	t.Helper()
	raw, err := json.Marshal(Record{DeviceID: device, Read: read, TrustGeneration: gen,
		ObservedAt: observed.UTC(), Data: json.RawMessage(payload)})
	if err != nil {
		t.Fatal(err)
	}
	name := formatSpoolName(device, read, observed.UnixNano(), random)
	dir, err := s.openDir(true)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	if err := writeAt(dir, name, raw); err != nil {
		t.Fatalf("publish %s: %v", name, err)
	}
	return name
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

// metadataFiles returns the device metadata files still in the spool, in
// List order.
func metadataFiles(t *testing.T, s *Spool) []string {
	t.Helper()
	var out []string
	for _, n := range spoolFiles(t, s) {
		if p, err := parseSpoolName(n); err == nil && p.read == ReadDeviceMetadata {
			out = append(out, n)
		}
	}
	return out
}

// metadataAt publishes a metadata record of device observed at testTime plus
// offset.
func metadataAt(t *testing.T, env *importEnv, device string, offset time.Duration, payload string) string {
	t.Helper()
	return writeRawRecordAt(t, env.spool, device, ReadDeviceMetadata, importGen,
		testTime.Add(offset), strings.Repeat("A", randomChars), payload)
}

// datasetPayload returns the spooled device and payload of read.
func datasetPayload(t *testing.T, read string) (device, payload string) {
	t.Helper()
	for _, rp := range readPayloads {
		if rp.read == read {
			return rp.device, rp.payload
		}
	}
	t.Fatalf("no payload for %s", read)
	return "", ""
}

const (
	validCBSMetadata     = `{"device_id":"core-sw-01","family":"cbs","label":"Core switch","trust_generation":3,"blocked":false,"block_reason":""}`
	invalidCBSMetadata   = `{"device_id":"core-sw-01","family":"cbs","label":"a\u0007","trust_generation":3,"blocked":false,"block_reason":""}`
	metadataFloodSize    = 2 * MaxMetadataPerRun
	metadataFloodSpacing = time.Millisecond
)

func TestSecondRunKeepsStagedMetadataAndStoresNothing(t *testing.T) {
	env := newImportEnv(t)
	store := &recordingStore{t: t}
	env.imp.Store = store
	name := metadataAt(t, env, importCBS, 0, validCBSMetadata)

	if rep := env.run(t); rep.Staged != 1 {
		t.Fatalf("first run report = %+v, want one staged record", rep)
	}
	for pass := 2; pass <= 3; pass++ {
		rep := env.run(t)
		if rep.Kept+rep.Failed+rep.Retry+rep.Imported != 0 {
			t.Fatalf("pass %d report = %+v, want nothing rejected or stored", pass, rep)
		}
		if got := metadataFiles(t, env.spool); !slices.Equal(got, []string{name}) {
			t.Fatalf("pass %d spool metadata = %v, want only %s", pass, got, name)
		}
	}
	if store.calls != 0 {
		t.Fatalf("store called %d times", store.calls)
	}
}

func TestNewerStagedMetadataSupersedesOlderOfTheDevice(t *testing.T) {
	env := newImportEnv(t)
	older := metadataAt(t, env, importCBS, 0, validCBSMetadata)
	if rep := env.run(t); rep.Staged != 1 {
		t.Fatalf("first run report = %+v", rep)
	}
	newer := metadataAt(t, env, importCBS, time.Second, validCBSMetadata)
	rep := env.run(t)
	if rep.Staged != 1 || rep.Pruned != 1 || rep.Kept != 0 {
		t.Fatalf("second run report = %+v, want the newer record staged and the older pruned", rep)
	}
	if got := metadataFiles(t, env.spool); !slices.Equal(got, []string{newer}) {
		t.Fatalf("spool metadata = %v, want only %s (older %s)", got, newer, older)
	}
}

func TestInvalidNewestMetadataDoesNotRetireOlderValid(t *testing.T) {
	env := newImportEnv(t)
	valid := metadataAt(t, env, importCBS, 0, validCBSMetadata)
	metadataAt(t, env, importCBS, time.Second, invalidCBSMetadata)
	rep := env.run(t)
	if rep.Kept != 1 || rep.Staged != 1 || rep.Pruned != 0 {
		t.Fatalf("report = %+v, want the newer record kept and the older one staged", rep)
	}
	if got := metadataFiles(t, env.spool); !slices.Equal(got, []string{valid}) {
		t.Fatalf("spool metadata = %v, want only %s", got, valid)
	}
}

func TestStagedMetadataOfEachDeviceIsKept(t *testing.T) {
	env := newImportEnv(t)
	cbs := metadataAt(t, env, importCBS, 0, validCBSMetadata)
	panos := metadataAt(t, env, importPANOS, 0,
		`{"device_id":"fw-01","family":"panos","label":"Edge firewall","trust_generation":3,"blocked":false,"block_reason":""}`)
	rep := env.run(t)
	if rep.Staged != 2 || rep.Pruned != 0 {
		t.Fatalf("report = %+v, want two staged records", rep)
	}
	if got := metadataFiles(t, env.spool); len(got) != 2 || !slices.Contains(got, cbs) || !slices.Contains(got, panos) {
		t.Fatalf("spool metadata = %v, want %s and %s", got, cbs, panos)
	}
}

// Accumulated valid metadata must not hold back dataset import: the newest
// valid record per device is kept, the rest are superseded, and the dataset
// record waiting behind them is stored in the same pass.
func TestManyAcceptedMetadataFilesDoNotStarveDatasetImport(t *testing.T) {
	env := newImportEnv(t)
	for i := 0; i < metadataFloodSize; i++ {
		metadataAt(t, env, importCBS, time.Duration(i)*metadataFloodSpacing, validCBSMetadata)
	}
	device, payload := datasetPayload(t, ReadPANOSZones)
	env.write(t, device, ReadPANOSZones, importGen, false, payload)

	rep := env.run(t)
	if rep.Imported != 1 || rep.Deferred != 0 {
		t.Fatalf("report = %+v, want the dataset imported", rep)
	}
	if got := metadataFiles(t, env.spool); len(got) != 1 {
		t.Fatalf("%d metadata files remain, want only the newest", len(got))
	}
}

// Rejected metadata is bounded per pass as well: a flood of invalid metadata
// must not stop the dataset import of the same pass.
func TestManyRejectedMetadataFilesDoNotStarveDatasetImport(t *testing.T) {
	env := newImportEnv(t)
	for i := 0; i < metadataFloodSize; i++ {
		metadataAt(t, env, importCBS, time.Duration(i)*metadataFloodSpacing, invalidCBSMetadata)
	}
	device, payload := datasetPayload(t, ReadPANOSZones)
	env.write(t, device, ReadPANOSZones, importGen, false, payload)

	rep := env.run(t)
	if rep.Imported != 1 {
		t.Fatalf("report = %+v, want the dataset imported", rep)
	}
	if rep.Kept > MaxMetadataPerRun {
		t.Fatalf("kept %d metadata records in one pass, want at most %d", rep.Kept, MaxMetadataPerRun)
	}
	if got := len(metadataFiles(t, env.spool)); got != metadataFloodSize-rep.Kept {
		t.Fatalf("%d metadata files remain, want %d", got, metadataFloodSize-rep.Kept)
	}
}
