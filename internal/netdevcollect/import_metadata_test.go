// SPDX-License-Identifier: AGPL-3.0-or-later

package netdevcollect

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevinventory"
)

// recordingStore fails the test if the importer ever writes a dataset from a
// device metadata record: metadata writes device rows through MetadataStore
// only.
type recordingStore struct {
	t     *testing.T
	calls int
}

func (r *recordingStore) ReplaceDataset(context.Context, string, netdevinventory.Read, uint64, time.Time, bool, netdevinventory.Rows) (netdevinventory.ReplaceResult, error) {
	r.calls++
	r.t.Errorf("device metadata reached the dataset store")
	return netdevinventory.ReplaceResult{}, nil
}

// recordingMeta records every device row the importer writes from a metadata
// record and returns err (nil accepts) for each call.
type recordingMeta struct {
	records []netdevinventory.DeviceMetadataRecord
	refs    []netdevinventory.SpoolRef
	err     error
}

// UpsertDeviceMetadata refuses a blocked record as the store does, before
// anything is written.
func (r *recordingMeta) UpsertDeviceMetadata(_ context.Context, m netdevinventory.DeviceMetadataRecord, ref netdevinventory.SpoolRef) error {
	if m.Blocked {
		return netdevinventory.ErrBlockedDevice
	}
	r.records = append(r.records, m)
	r.refs = append(r.refs, ref)
	return r.err
}

// metaEnv returns an importEnv whose metadata goes to meta and whose dataset
// writes fail the test.
func metaEnv(t *testing.T, meta *recordingMeta) (*importEnv, *recordingStore) {
	t.Helper()
	env := newImportEnv(t)
	store := &recordingStore{t: t}
	env.imp.Store = store
	env.imp.Meta = meta
	return env, store
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

// A valid metadata record writes its device row from its own fields, with a
// spool reference that names the file and carries its digest and observation
// time, and the file is confirmed only after that.
func TestImportWritesValidMetadataAndConfirms(t *testing.T) {
	meta := &recordingMeta{}
	env, store := metaEnv(t, meta)
	name := metadataAt(t, env, importCBS, 0, validCBSMetadata)

	rep := env.run(t)
	if rep.MetadataWritten != 1 || rep.Imported != 0 || rep.Kept != 0 || rep.Failed != 0 || rep.Retry != 0 {
		t.Fatalf("report = %+v, want one metadata record written", rep)
	}
	if store.calls != 0 {
		t.Fatalf("dataset store called %d times", store.calls)
	}
	if len(meta.records) != 1 {
		t.Fatalf("metadata writes = %d, want 1", len(meta.records))
	}
	got := meta.records[0]
	want := netdevinventory.DeviceMetadataRecord{DeviceID: importCBS, Family: "cbs", Label: "Core switch",
		TrustGeneration: importGen}
	if got != want {
		t.Fatalf("written record = %+v, want %+v", got, want)
	}
	ref := meta.refs[0]
	if ref.Name != name || len(ref.Digest) != 64 || !ref.RecordedAt.Equal(testTime) {
		t.Fatalf("spool ref = %+v, want name %s, 64-character digest, recorded at %v", ref, name, testTime)
	}
	if got := metadataFiles(t, env.spool); len(got) != 0 {
		t.Fatalf("written record still in spool: %v", got)
	}
}

func TestImportMetadataWithoutMetaStoreWaits(t *testing.T) {
	env := newImportEnv(t)
	env.imp.Meta = nil
	name := metadataAt(t, env, importCBS, 0, validCBSMetadata)

	rep := env.run(t)
	if rep.MetadataWritten != 0 || rep.Kept != 0 {
		t.Fatalf("report = %+v, want nothing written", rep)
	}
	if got := metadataFiles(t, env.spool); !slices.Equal(got, []string{name}) {
		t.Fatalf("spool metadata = %v, want %s to wait", got, name)
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
			meta := &recordingMeta{}
			env, _ := metaEnv(t, meta)
			writeRawRecord(t, env.spool, tc.device, ReadDeviceMetadata, tc.gen, tc.payload)
			rep := env.run(t)
			if rep.Kept != 1 || rep.MetadataWritten != 0 || rep.Imported != 0 {
				t.Fatalf("report = %+v, want one kept record", rep)
			}
			if len(meta.records) != 0 {
				t.Fatalf("rejected metadata reached the device row writer")
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

// A blocked record is refused by the device row writer. It is kept with its
// reason, so the operator can see why the device is not listed as written.
func TestImportKeepsBlockedMetadataWithReason(t *testing.T) {
	meta := &recordingMeta{}
	env, _ := metaEnv(t, meta)
	metadataAt(t, env, importCBS, 0,
		`{"device_id":"core-sw-01","family":"cbs","label":"Core switch","trust_generation":3,"blocked":true,"block_reason":"operator"}`)
	rep := env.run(t)
	if rep.Kept != 1 || rep.MetadataWritten != 0 {
		t.Fatalf("report = %+v, want one kept record", rep)
	}
	if len(meta.records) != 0 {
		t.Fatalf("blocked device reached the device row writer")
	}
	if !slices.ContainsFunc(keptNames(t, env.spool), func(n string) bool {
		return strings.HasPrefix(n, importCBS+"-"+ReadDeviceMetadata+"-")
	}) {
		t.Fatalf("blocked metadata not kept: %v", keptNames(t, env.spool))
	}
}

// A file whose name is outside the closed read set is not a spool entry at
// all: List skips it, so the importer neither stores nor moves it.
func TestImportIgnoresFileWithUnknownReadName(t *testing.T) {
	env := newImportEnv(t)
	writeRawRecord(t, env.spool, importCBS, "device_facts", importGen, `{"device_id":"core-sw-01"}`)
	rep := env.run(t)
	if rep.Files != 0 || rep.Imported != 0 || rep.MetadataWritten != 0 || rep.Kept != 0 {
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

// The newest record the store accepts is written; the older ones of the same
// device are superseded in the same pass.
func TestNewestMetadataIsWrittenAndOlderSuperseded(t *testing.T) {
	meta := &recordingMeta{}
	env, _ := metaEnv(t, meta)
	older := metadataAt(t, env, importCBS, 0, validCBSMetadata)
	newer := metadataAt(t, env, importCBS, time.Second, validCBSMetadata)

	rep := env.run(t)
	if rep.MetadataWritten != 1 || rep.Pruned != 1 || rep.Kept != 0 {
		t.Fatalf("report = %+v, want the newer record written and the older pruned", rep)
	}
	if len(meta.refs) != 1 || meta.refs[0].Name != newer {
		t.Fatalf("written refs = %+v, want only %s", meta.refs, newer)
	}
	if got := metadataFiles(t, env.spool); len(got) != 0 {
		t.Fatalf("spool metadata = %v, want none (older %s)", got, older)
	}
}

// An invalid newest record is kept; the older valid one is still written.
func TestInvalidNewestMetadataFallsBackToOlderValid(t *testing.T) {
	meta := &recordingMeta{}
	env, _ := metaEnv(t, meta)
	valid := metadataAt(t, env, importCBS, 0, validCBSMetadata)
	metadataAt(t, env, importCBS, time.Second, invalidCBSMetadata)

	rep := env.run(t)
	if rep.Kept != 1 || rep.MetadataWritten != 1 || rep.Pruned != 0 {
		t.Fatalf("report = %+v, want the newer record kept and the older one written", rep)
	}
	if len(meta.refs) != 1 || meta.refs[0].Name != valid {
		t.Fatalf("written refs = %+v, want only %s", meta.refs, valid)
	}
}

// A blocked newest record supersedes older records of its device, so an older
// label never comes back.
func TestBlockedNewestMetadataSupersedesOlder(t *testing.T) {
	meta := &recordingMeta{}
	env, _ := metaEnv(t, meta)
	metadataAt(t, env, importCBS, 0, validCBSMetadata)
	metadataAt(t, env, importCBS, time.Second,
		`{"device_id":"core-sw-01","family":"cbs","label":"Core switch","trust_generation":3,"blocked":true,"block_reason":"operator"}`)

	rep := env.run(t)
	if rep.Kept != 1 || rep.Pruned != 1 || rep.MetadataWritten != 0 || len(meta.records) != 0 {
		t.Fatalf("report = %+v, writes = %d; want the blocked record kept, the older pruned, nothing written",
			rep, len(meta.records))
	}
	if got := metadataFiles(t, env.spool); len(got) != 0 {
		t.Fatalf("spool metadata = %v, want none", got)
	}
}

// A store failure leaves the record in the spool for a later pass, and is
// not treated as a fault of the record.
func TestStoreFailureKeepsMetadataForRetry(t *testing.T) {
	meta := &recordingMeta{err: errors.New("database is locked")}
	env, _ := metaEnv(t, meta)
	name := metadataAt(t, env, importCBS, 0, validCBSMetadata)

	rep := env.run(t)
	if rep.Retry != 1 || rep.Kept != 0 || rep.MetadataWritten != 0 {
		t.Fatalf("report = %+v, want one store retry and nothing kept", rep)
	}
	if got := metadataFiles(t, env.spool); !slices.Equal(got, []string{name}) {
		t.Fatalf("spool metadata = %v, want %s to wait", got, name)
	}
	meta.err = nil
	rep = env.run(t)
	if rep.MetadataWritten != 1 || len(metadataFiles(t, env.spool)) != 0 {
		t.Fatalf("second run report = %+v, want the record written and confirmed", rep)
	}
}

// A device row write the store refuses as not newer is a replay: the file is
// removed and nothing is kept.
func TestMetadataNotNewerIsDropped(t *testing.T) {
	meta := &recordingMeta{err: netdevinventory.ErrReportNotNewer}
	env, _ := metaEnv(t, meta)
	metadataAt(t, env, importCBS, 0, validCBSMetadata)

	rep := env.run(t)
	if rep.Kept != 0 || rep.Replayed != 1 || rep.MetadataWritten != 0 {
		t.Fatalf("report = %+v, want the replay removed and nothing kept", rep)
	}
	if got := metadataFiles(t, env.spool); len(got) != 0 {
		t.Fatalf("spool metadata = %v, want none", got)
	}
}

// Accumulated valid metadata must not hold back dataset import: the newest
// valid record per device is written, the rest are superseded, and the dataset
// record waiting behind them is stored in the same pass.
func TestManyAcceptedMetadataFilesDoNotStarveDatasetImport(t *testing.T) {
	meta := &recordingMeta{}
	env, _ := metaEnv(t, meta)
	env.imp.Store = env.store
	for i := 0; i < metadataFloodSize; i++ {
		metadataAt(t, env, importCBS, time.Duration(i)*metadataFloodSpacing, validCBSMetadata)
	}
	device, payload := datasetPayload(t, ReadPANOSZones)
	env.write(t, device, ReadPANOSZones, importGen, false, payload)

	rep := env.run(t)
	if rep.Imported != 1 || rep.Deferred != 0 {
		t.Fatalf("report = %+v, want the dataset imported", rep)
	}
	if got := metadataFiles(t, env.spool); len(got) != 0 {
		t.Fatalf("%d metadata files remain, want none", len(got))
	}
}

// Rejected metadata is bounded per pass as well: a flood of invalid metadata
// must not stop the dataset import of the same pass.
func TestManyRejectedMetadataFilesDoNotStarveDatasetImport(t *testing.T) {
	meta := &recordingMeta{}
	env, _ := metaEnv(t, meta)
	env.imp.Store = env.store
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
