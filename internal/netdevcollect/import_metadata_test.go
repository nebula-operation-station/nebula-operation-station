// SPDX-License-Identifier: AGPL-3.0-or-later

package netdevcollect

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
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
// record and returns err (nil accepts) for each call. BlockedDeviceIDs
// returns blocked, or blockedErr.
type recordingMeta struct {
	records    []netdevinventory.DeviceMetadataRecord
	refs       []netdevinventory.SpoolRef
	err        error
	blocked    []string
	blockedErr error
	loads      int
}

// UpsertDeviceMetadata records m, blocked or not, as the store writes both.
func (r *recordingMeta) UpsertDeviceMetadata(_ context.Context, m netdevinventory.DeviceMetadataRecord, ref netdevinventory.SpoolRef) error {
	r.records = append(r.records, m)
	r.refs = append(r.refs, ref)
	return r.err
}

func (r *recordingMeta) BlockedDeviceIDs(context.Context) ([]string, error) {
	r.loads++
	if r.blockedErr != nil {
		return nil, r.blockedErr
	}
	return slices.Clone(r.blocked), nil
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

// A blocked record is written through the device row writer with its block
// state and reason, so the row is marked blocked; the file is confirmed, not
// kept.
func TestImportWritesBlockedMetadataWithReason(t *testing.T) {
	meta := &recordingMeta{}
	env, _ := metaEnv(t, meta)
	metadataAt(t, env, importCBS, 0,
		`{"device_id":"core-sw-01","family":"cbs","label":"Core switch","trust_generation":3,"blocked":true,"block_reason":"operator"}`)
	rep := env.run(t)
	if rep.Kept != 0 || rep.MetadataWritten != 1 {
		t.Fatalf("report = %+v, want the blocked record written", rep)
	}
	if len(meta.records) != 1 || !meta.records[0].Blocked || meta.records[0].BlockReason != "operator" {
		t.Fatalf("written records = %+v, want one blocked with reason operator", meta.records)
	}
	if got := metadataFiles(t, env.spool); len(got) != 0 {
		t.Fatalf("spool metadata = %v, want none", got)
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

// keptNamesIfAny is keptNames for a spool whose kept/ may not exist yet: no
// kept/ directory means nothing was kept.
func keptNamesIfAny(t *testing.T, s *Spool) []string {
	t.Helper()
	if _, err := os.Stat(filepath.Join(s.Dir, KeptDirName)); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return keptNames(t, s)
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
	if rep.Kept != 0 || rep.Pruned != 1 || rep.MetadataWritten != 1 ||
		len(meta.records) != 1 || !meta.records[0].Blocked {
		t.Fatalf("report = %+v, writes = %+v; want only the blocked record written, the older pruned",
			rep, meta.records)
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

// newDevice is a device the inventory does not know yet: its first metadata
// record creates its row. Its datasets must wait until that row exists.
const (
	newDevice         = "new-sw-02"
	newDeviceMetadata = `{"device_id":"new-sw-02","family":"cbs","label":"New switch","trust_generation":3,"blocked":false,"block_reason":""}`
)

// flakyMeta writes device rows through the real store, except while err is
// set: then every write fails with err, as a store that is locked would.
type flakyMeta struct {
	inner MetadataStore
	err   error
}

func (f *flakyMeta) UpsertDeviceMetadata(ctx context.Context, m netdevinventory.DeviceMetadataRecord, ref netdevinventory.SpoolRef) error {
	if f.err != nil {
		return f.err
	}
	return f.inner.UpsertDeviceMetadata(ctx, m, ref)
}

func (f *flakyMeta) BlockedDeviceIDs(ctx context.Context) ([]string, error) {
	return f.inner.BlockedDeviceIDs(ctx)
}

// A device whose metadata write fails in a pass keeps its datasets in the
// spool: without its device row the store would refuse them as unknown_device,
// and the files would be kept for good.
func TestDatasetOfDeviceWithFailedMetadataWaits(t *testing.T) {
	env := newImportEnv(t)
	meta := &flakyMeta{inner: env.store, err: errors.New("database is locked")}
	env.imp.Meta = meta
	env.imp.Store = env.store
	metadataAt(t, env, newDevice, 0, newDeviceMetadata)
	_, payload := datasetPayload(t, ReadCBSVersion)
	dataset := env.write(t, newDevice, ReadCBSVersion, importGen, false, payload)

	rep := env.run(t)
	if rep.Retry != 1 || rep.Kept != 0 || rep.Imported != 0 || rep.Deferred != 1 {
		t.Fatalf("report = %+v, want the metadata retried and the dataset deferred", rep)
	}
	if got := keptNamesIfAny(t, env.spool); len(got) != 0 {
		t.Fatalf("kept = %v, want nothing kept", got)
	}
	if got := spoolFiles(t, env.spool); !slices.Contains(got, dataset) {
		t.Fatalf("spool = %v, want the dataset %s to wait", got, dataset)
	}

	meta.err = nil
	rep = env.run(t)
	if rep.MetadataWritten != 1 || rep.Imported != 1 || rep.Kept != 0 {
		t.Fatalf("second run report = %+v, want the metadata written and the dataset imported", rep)
	}
	if got := spoolFiles(t, env.spool); len(got) != 0 {
		t.Fatalf("spool = %v after the second pass, want empty", got)
	}
}

// When the metadata budget of a pass runs out before a device's metadata is
// tried, the device's datasets wait for a later pass, as they do after a store
// failure. The flood of rejected records of another device spends the budget
// first.
func TestDatasetOfDeviceWithUntriedMetadataWaits(t *testing.T) {
	env := newImportEnv(t)
	env.imp.Meta = &flakyMeta{inner: env.store}
	env.imp.Store = env.store
	for i := 0; i < MaxMetadataPerRun; i++ {
		metadataAt(t, env, importCBS, time.Duration(i)*metadataFloodSpacing, invalidCBSMetadata)
	}
	meta := metadataAt(t, env, newDevice, 2*time.Second, newDeviceMetadata)
	_, payload := datasetPayload(t, ReadCBSVersion)
	dataset := env.write(t, newDevice, ReadCBSVersion, importGen, false, payload)

	rep := env.run(t)
	if rep.Kept != MaxMetadataPerRun || rep.Imported != 0 || rep.Deferred != 1 {
		t.Fatalf("report = %+v, want the flood kept, the budget spent and the dataset deferred", rep)
	}
	if got := keptNamesIfAny(t, env.spool); slices.ContainsFunc(got, func(n string) bool { return strings.HasPrefix(n, newDevice) }) {
		t.Fatalf("kept = %v, want nothing of the new device kept", got)
	}
	if got := spoolFiles(t, env.spool); !slices.Contains(got, dataset) || !slices.Contains(got, meta) {
		t.Fatalf("spool = %v, want %s and its metadata %s to wait", got, dataset, meta)
	}
}

// blockedCBSMetadata is the metadata record of importCBS once the collector
// reports the device as blocked.
const blockedCBSMetadata = `{"device_id":"core-sw-01","family":"cbs","label":"Core switch","trust_generation":3,"blocked":true,"block_reason":"operator"}`

// datasetOf publishes the payload of read observed at testTime plus offset, as
// a spool record of device.
func datasetOf(t *testing.T, env *importEnv, device, read string, offset time.Duration) string {
	t.Helper()
	_, payload := datasetPayload(t, read)
	return writeRawRecordAt(t, env.spool, device, read, importGen,
		testTime.Add(offset), strings.Repeat("A", randomChars), payload)
}

// requireKeptWithReason fails unless kept/ holds a record of device and read
// whose reason file names reason.
func requireKeptWithReason(t *testing.T, env *importEnv, device, read, reason string) {
	t.Helper()
	prefix := device + "-" + read + "-"
	for _, n := range keptNames(t, env.spool) {
		if !strings.HasPrefix(n, prefix) {
			continue
		}
		got, err := os.ReadFile(filepath.Join(env.spool.Dir, KeptDirName, n+keptReasonSuffix))
		if err != nil {
			t.Fatalf("read reason of %s: %v", n, err)
		}
		if string(got) != "reason: "+reason+"\n" {
			t.Fatalf("reason of %s = %q, want %q", n, got, reason)
		}
		return
	}
	t.Fatalf("no %s record of %s in %s: %v", read, device, KeptDirName, keptNames(t, env.spool))
}

// A blocked metadata record halts its device in the pass it is judged: the
// device's dataset of the same pass is kept with the blocked reason and is
// never written.
func TestBlockedMetadataHaltsDatasetsInSamePass(t *testing.T) {
	meta := &recordingMeta{}
	env, store := metaEnv(t, meta)
	metadataAt(t, env, importCBS, 0, blockedCBSMetadata)
	datasetOf(t, env, importCBS, ReadCBSVersion, time.Second)

	rep := env.run(t)
	if rep.Kept != 1 || rep.Imported != 0 || rep.MetadataWritten != 1 || store.calls != 0 {
		t.Fatalf("report = %+v, dataset writes = %d; want the blocked metadata written, the dataset kept",
			rep, store.calls)
	}
	if got := spoolFiles(t, env.spool); len(got) != 0 {
		t.Fatalf("spool still holds %v", got)
	}
	requireKeptWithReason(t, env, importCBS, ReadCBSVersion, ReasonDeviceBlocked)
}

// A blocked device stays halted in later passes: a dataset that arrives after
// its blocked metadata was written is kept, and no dataset is written.
func TestBlockedDeviceStaysHaltedInLaterPasses(t *testing.T) {
	meta := &recordingMeta{}
	env, store := metaEnv(t, meta)
	metadataAt(t, env, importCBS, 0, blockedCBSMetadata)
	if rep := env.run(t); rep.MetadataWritten != 1 {
		t.Fatalf("first pass report = %+v, want the blocked metadata written", rep)
	}
	datasetOf(t, env, importCBS, ReadCBSVersion, time.Second)

	for pass := 2; pass <= 3; pass++ {
		rep := env.run(t)
		if rep.Imported != 0 || store.calls != 0 || len(meta.records) != 1 {
			t.Fatalf("pass %d report = %+v, dataset writes = %d; want the halt kept", pass, rep, store.calls)
		}
		if got := spoolFiles(t, env.spool); len(got) != 0 {
			t.Fatalf("pass %d: spool still holds %v", pass, got)
		}
	}
	requireKeptWithReason(t, env, importCBS, ReadCBSVersion, ReasonDeviceBlocked)
}

// A newer unblocked metadata record of a blocked device is stored, and the
// halt ends: the device's datasets of that pass are imported.
func TestNewerUnblockedMetadataLiftsTheHalt(t *testing.T) {
	meta := &recordingMeta{}
	env, _ := metaEnv(t, meta)
	env.imp.Store = env.store
	metadataAt(t, env, importCBS, 0, blockedCBSMetadata)
	env.run(t)
	metadataAt(t, env, importCBS, time.Second, validCBSMetadata)
	datasetOf(t, env, importCBS, ReadCBSVersion, 2*time.Second)

	rep := env.run(t)
	if rep.MetadataWritten != 1 || rep.Imported != 1 || rep.Kept != 0 {
		t.Fatalf("report = %+v, want the unblocked metadata written and the dataset imported", rep)
	}
}

// A store failure of a device's metadata backs the device off like a dataset
// store failure: the next pass does not retry the metadata at once, and the
// device's datasets stay bounded by MaxPendingPerRead while it waits.
func TestMetadataStoreFailureBacksOffAndBoundsDatasets(t *testing.T) {
	env := newImportEnv(t)
	meta := &flakyMeta{inner: env.store, err: errors.New("database is locked")}
	env.imp.Meta = meta
	env.imp.Store = env.store
	metadataAt(t, env, newDevice, 0, newDeviceMetadata)
	for i := 0; i < MaxPendingPerRead+3; i++ {
		datasetOf(t, env, newDevice, ReadCBSVersion, time.Duration(i+1)*time.Second)
	}

	// The first failure is retried on the next pass; the second starts the
	// backoff.
	for pass := 1; pass <= 2; pass++ {
		if rep := env.run(t); rep.Retry != 1 {
			t.Fatalf("pass %d report = %+v, want the metadata retried", pass, rep)
		}
	}
	rep := env.run(t)
	if rep.Retry != 0 || rep.Imported != 0 {
		t.Fatalf("backed-off pass report = %+v, want the metadata not tried at all", rep)
	}
	if got := spoolOf(t, env.spool, newDevice, ReadCBSVersion); len(got) == 0 || len(got) > MaxPendingPerRead {
		t.Fatalf("waiting datasets = %v, want between 1 and %d", got, MaxPendingPerRead)
	}

	meta.err = nil
	*env.now = env.now.Add(importRetryMax)
	rep = env.run(t)
	if rep.MetadataWritten != 1 || rep.Imported == 0 {
		t.Fatalf("recovered pass report = %+v, want the metadata written and datasets imported", rep)
	}
	if got := spoolOf(t, env.spool, newDevice, ReadCBSVersion); len(got) != 0 {
		t.Fatalf("datasets left after recovery: %v", got)
	}
}

// blockedNewDeviceMetadata is newDevice reported as blocked.
const blockedNewDeviceMetadata = `{"device_id":"new-sw-02","family":"cbs","label":"New switch","trust_generation":3,"blocked":true,"block_reason":"operator"}`

// After a restart the importer reads the block from the stored row: a new
// Importer over the same store and spool keeps a dataset of the device that
// was blocked before the restart, although no metadata record of it is left
// in the spool.
func TestBlockedDeviceStaysHaltedAfterRestart(t *testing.T) {
	env := newImportEnv(t)
	env.imp.Meta = env.store
	metadataAt(t, env, newDevice, 0, blockedNewDeviceMetadata)
	if rep := env.run(t); rep.MetadataWritten != 1 {
		t.Fatalf("first pass report = %+v, want the blocked metadata written", rep)
	}
	d, err := env.store.GetDevice(context.Background(), newDevice)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Blocked || d.BlockReason != "operator" {
		t.Fatalf("row %+v, want it blocked with reason operator", d)
	}

	// The restart: a fresh importer with no state of its own.
	env.imp = &Importer{Spool: env.spool, Store: env.store, Meta: env.store, Now: env.imp.Now}
	datasetOf(t, env, newDevice, ReadCBSVersion, time.Second)
	rep := env.run(t)
	if rep.Imported != 0 || rep.Kept != 1 {
		t.Fatalf("report after restart = %+v, want the dataset kept", rep)
	}
	requireKeptWithReason(t, env, newDevice, ReadCBSVersion, ReasonDeviceBlocked)
	if d, err := env.store.GetDevice(context.Background(), newDevice); err != nil || !d.LastSeen.IsZero() {
		t.Fatalf("device %+v, %v; want no dataset stored after the restart", d, err)
	}
}

// If the block state cannot be read on the first pass, the pass imports
// nothing and fails; the next pass reads it again.
func TestBlockedLoadFailureImportsNothing(t *testing.T) {
	meta := &recordingMeta{blockedErr: errors.New("database is locked")}
	env, store := metaEnv(t, meta)
	dataset := datasetOf(t, env, importCBS, ReadCBSVersion, time.Second)
	if _, err := env.imp.Run(context.Background()); err == nil {
		t.Fatalf("Run succeeded although the block state could not be read")
	}
	if store.calls != 0 {
		t.Fatalf("dataset written without the block state")
	}
	if got := spoolFiles(t, env.spool); !slices.Contains(got, dataset) {
		t.Fatalf("spool = %v, want %s to wait", got, dataset)
	}

	meta.blockedErr = nil
	meta.blocked = []string{importCBS}
	rep := env.run(t)
	if rep.Kept != 1 || store.calls != 0 || meta.loads != 2 {
		t.Fatalf("report = %+v, dataset writes = %d, loads = %d; want the dataset kept as blocked after a second load",
			rep, store.calls, meta.loads)
	}
	requireKeptWithReason(t, env, importCBS, ReadCBSVersion, ReasonDeviceBlocked)
	if env.run(t); meta.loads != 2 {
		t.Fatalf("loads = %d, want the block state read once after it succeeded", meta.loads)
	}
}

// A blocked device whose newer unblocked metadata record waits for the store
// keeps its datasets waiting too: they are neither kept as blocked nor
// written. Once the store accepts the unblock, the datasets are imported.
func TestBlockedDeviceDefersDatasetWhileUnblockWaitsOnStore(t *testing.T) {
	env := newImportEnv(t)
	env.imp.Meta = env.store
	metadataAt(t, env, newDevice, 0, blockedNewDeviceMetadata)
	if rep := env.run(t); rep.MetadataWritten != 1 {
		t.Fatalf("first pass report = %+v, want the blocked metadata written", rep)
	}

	meta := &flakyMeta{inner: env.store, err: errors.New("database is locked")}
	env.imp.Meta = meta
	unblock := metadataAt(t, env, newDevice, time.Second, newDeviceMetadata)
	dataset := datasetOf(t, env, newDevice, ReadCBSVersion, 2*time.Second)

	rep := env.run(t)
	if rep.Retry != 1 || rep.Kept != 0 || rep.Imported != 0 || rep.Deferred != 1 {
		t.Fatalf("report = %+v, want the unblock retried and the dataset deferred", rep)
	}
	if got := keptNamesIfAny(t, env.spool); len(got) != 0 {
		t.Fatalf("kept = %v, want nothing kept", got)
	}
	if got := spoolFiles(t, env.spool); !slices.Contains(got, dataset) || !slices.Contains(got, unblock) {
		t.Fatalf("spool = %v, want %s and its unblock %s to wait", got, dataset, unblock)
	}

	meta.err = nil
	rep = env.run(t)
	if rep.MetadataWritten != 1 || rep.Imported != 1 || rep.Kept != 0 {
		t.Fatalf("second pass report = %+v, want the unblock written and the dataset imported", rep)
	}
	if got := spoolFiles(t, env.spool); len(got) != 0 {
		t.Fatalf("spool = %v after the second pass, want empty", got)
	}
}

// A blocked device whose newer unblocked metadata record is not tried because
// the metadata budget of the pass ran out keeps its datasets waiting, as it
// does after a store failure. The newer invalid records of the device spend
// the budget first.
func TestBlockedDeviceDefersDatasetWhileUnblockIsUntried(t *testing.T) {
	const invalidNewDeviceMetadata = `{"device_id":"new-sw-02","family":"cbs","label":"a\u0007","trust_generation":3,"blocked":false,"block_reason":""}`
	env := newImportEnv(t)
	env.imp.Meta = env.store
	metadataAt(t, env, newDevice, 0, blockedNewDeviceMetadata)
	if rep := env.run(t); rep.MetadataWritten != 1 {
		t.Fatalf("first pass report = %+v, want the blocked metadata written", rep)
	}

	unblock := metadataAt(t, env, newDevice, time.Second, newDeviceMetadata)
	for i := 0; i < MaxMetadataPerRun; i++ {
		metadataAt(t, env, newDevice, 2*time.Second+time.Duration(i)*metadataFloodSpacing, invalidNewDeviceMetadata)
	}
	dataset := datasetOf(t, env, newDevice, ReadCBSVersion, 3*time.Second)

	rep := env.run(t)
	if rep.Kept != MaxMetadataPerRun || rep.Imported != 0 || rep.Deferred != 1 || rep.MetadataWritten != 0 {
		t.Fatalf("report = %+v, want the invalid metadata kept, the unblock untried and the dataset deferred", rep)
	}
	if got := spoolFiles(t, env.spool); !slices.Contains(got, dataset) || !slices.Contains(got, unblock) {
		t.Fatalf("spool = %v, want %s and its unblock %s to wait", got, dataset, unblock)
	}

	rep = env.run(t)
	if rep.MetadataWritten != 1 || rep.Imported != 1 || rep.Kept != 0 {
		t.Fatalf("second pass report = %+v, want the unblock written and the dataset imported", rep)
	}
	if got := spoolFiles(t, env.spool); len(got) != 0 {
		t.Fatalf("spool = %v after the second pass, want empty", got)
	}
}

// A blocked device with no newer unblocked metadata waiting keeps its new
// dataset as device_blocked, as before: the halt is not a wait.
func TestBlockedDeviceWithoutPendingUnblockKeepsDataset(t *testing.T) {
	env := newImportEnv(t)
	env.imp.Meta = env.store
	metadataAt(t, env, newDevice, 0, blockedNewDeviceMetadata)
	if rep := env.run(t); rep.MetadataWritten != 1 {
		t.Fatalf("first pass report = %+v, want the blocked metadata written", rep)
	}
	datasetOf(t, env, newDevice, ReadCBSVersion, time.Second)

	rep := env.run(t)
	if rep.Kept != 1 || rep.Deferred != 0 || rep.Imported != 0 {
		t.Fatalf("report = %+v, want the dataset kept, not deferred", rep)
	}
	requireKeptWithReason(t, env, newDevice, ReadCBSVersion, ReasonDeviceBlocked)
}
