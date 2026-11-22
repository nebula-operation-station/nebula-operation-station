// SPDX-License-Identifier: AGPL-3.0-or-later

package netdevcollect

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// metaSpool is a SpoolWriter that fails only the device metadata writes
// while failMeta is set.
type metaSpool struct {
	*fakeSpool
	failMeta bool
}

func (s *metaSpool) Write(ctx context.Context, deviceID, read string, gen uint64, incomplete bool, payload []byte) (string, error) {
	if read == ReadDeviceMetadata && s.failMeta {
		return "", errors.New("disk full")
	}
	return s.fakeSpool.Write(ctx, deviceID, read, gen, incomplete, payload)
}

// metadataWrites returns the device metadata records of s in write order.
func metadataWrites(s *fakeSpool) []spooled {
	var out []spooled
	for _, w := range s.all() {
		if w.read == ReadDeviceMetadata {
			out = append(out, w)
		}
	}
	return out
}

// labelled returns a usable CBS device with a display name.
func labelled(id, label string) *pb.NetDeviceInfo {
	d := cbsDevice(id)
	d.Label = label
	return d
}

// setDevices replaces the device list the fake executor returns.
func setDevices(c *fakeClient, devices ...*pb.NetDeviceInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.devices = devices
}

// metaSince returns the device metadata records of s written after the
// first n records of s.all().
func metaSince(s *fakeSpool, n int) []spooled {
	var out []spooled
	for _, w := range s.all()[n:] {
		if w.read == ReadDeviceMetadata {
			out = append(out, w)
		}
	}
	return out
}

func TestCycleSpoolsOneMetadataRecordPerListedDevice(t *testing.T) {
	clock := newClock()
	c := newFakeClient(clock, labelled("core-sw-01", "Core switch"), labelled("edge-fw-01", "Edge"))
	c.devices[1].Family = "panos"
	c.devices[1].TrustGeneration = 5
	s := &fakeSpool{}
	p := newTestPoller(c, s, clock, constRand(0.5))
	rep := cycle(t, p)
	if rep.MetadataWritten != 2 || rep.MetadataFailed != 0 {
		t.Fatalf("metadata report = written %d, failed %d; want 2, 0", rep.MetadataWritten, rep.MetadataFailed)
	}
	meta := metadataWrites(s)
	if len(meta) != 2 {
		t.Fatalf("metadata records = %d, want 2", len(meta))
	}
	want := map[string]DeviceMetadata{
		"core-sw-01": {DeviceID: "core-sw-01", Family: "cbs", Label: "Core switch", TrustGeneration: 3},
		"edge-fw-01": {DeviceID: "edge-fw-01", Family: "panos", Label: "Edge", TrustGeneration: 5},
	}
	for _, w := range meta {
		got, err := DecodeDeviceMetadata(w.payload)
		if err != nil {
			t.Fatalf("record of %s does not decode: %v", w.device, err)
		}
		if got != want[w.device] || w.gen != got.TrustGeneration {
			t.Fatalf("record of %s = %+v (gen %d), want %+v", w.device, got, w.gen, want[w.device])
		}
		delete(want, w.device)
	}
	if len(want) != 0 {
		t.Fatalf("no metadata record for %v", want)
	}
}

func TestUnchangedMetadataIsNotRespooledInLaterCycles(t *testing.T) {
	clock := newClock()
	c := newFakeClient(clock, labelled("core-sw-01", "Core"))
	s := &fakeSpool{}
	p := newTestPoller(c, s, clock, constRand(0.5))
	if rep := cycle(t, p); rep.MetadataWritten != 1 {
		t.Fatalf("first cycle metadata written = %d, want 1", rep.MetadataWritten)
	}
	for cyc := 2; cyc <= 4; cyc++ {
		clock.Advance(MinReadInterval + 1)
		before := s.count()
		rep := cycle(t, p)
		if rep.MetadataWritten != 0 || rep.MetadataFailed != 0 {
			t.Fatalf("cycle %d: metadata report = written %d, failed %d; want 0, 0", cyc, rep.MetadataWritten, rep.MetadataFailed)
		}
		if n := len(metaSince(s, before)); n != 0 {
			t.Fatalf("cycle %d: %d metadata records for unchanged metadata, want 0", cyc, n)
		}
		if rep.Dispatched == 0 {
			t.Fatalf("cycle %d: reads were not dispatched; the test checks nothing", cyc)
		}
	}
}

func TestChangedMetadataIsRespooledBeforeReads(t *testing.T) {
	clock := newClock()
	c := newFakeClient(clock, labelled("core-sw-01", "Core"))
	s := &fakeSpool{}
	p := newTestPoller(c, s, clock, constRand(0.5))
	cycle(t, p)
	setDevices(c, labelled("core-sw-01", "Core renamed"))
	clock.Advance(MinReadInterval + 1)
	before := s.count()
	rep := cycle(t, p)
	if rep.MetadataWritten != 1 {
		t.Fatalf("metadata written after a label change = %d, want 1", rep.MetadataWritten)
	}
	// Only the writes of this cycle: one metadata record, written before
	// the first read of the cycle.
	sawRead := false
	meta := 0
	for _, w := range s.all()[before:] {
		if w.read == ReadDeviceMetadata {
			meta++
			if sawRead {
				t.Fatal("metadata written after a read")
			}
			got, err := DecodeDeviceMetadata(w.payload)
			if err != nil || got.Label != "Core renamed" {
				t.Fatalf("record = %+v, %v; want the new label", got, err)
			}
		} else {
			sawRead = true
		}
	}
	if meta != 1 {
		t.Fatalf("metadata records = %d, want 1", meta)
	}
}

func TestMetadataWriteFailureIsRetriedInTheNextCycle(t *testing.T) {
	clock := newClock()
	c := newFakeClient(clock, labelled("core-sw-01", "Core"))
	s := &metaSpool{fakeSpool: &fakeSpool{}, failMeta: true}
	p := newTestPoller(c, s, clock, constRand(0.5))
	if rep := cycle(t, p); rep.MetadataFailed != 1 || rep.MetadataWritten != 0 {
		t.Fatalf("refused cycle = written %d, failed %d; want 0, 1", rep.MetadataWritten, rep.MetadataFailed)
	}
	s.failMeta = false
	if rep := cycle(t, p); rep.MetadataWritten != 1 || rep.MetadataFailed != 0 {
		t.Fatalf("retry cycle = written %d, failed %d; want 1, 0", rep.MetadataWritten, rep.MetadataFailed)
	}
	if n := len(metadataWrites(s.fakeSpool)); n != 1 {
		t.Fatalf("metadata records = %d, want 1", n)
	}
}

func TestBlockedDeviceGetsNoMetadataRecord(t *testing.T) {
	clock := newClock()
	blocked := labelled("blocked-sw", "Blocked")
	blocked.Blocked = true
	blocked.BlockReason = "pin changed"
	c := newFakeClient(clock, blocked, labelled("core-sw-01", "Core"))
	s := &fakeSpool{}
	p := newTestPoller(c, s, clock, constRand(0.5))
	rep := cycle(t, p)
	if rep.MetadataWritten != 1 {
		t.Fatalf("metadata written = %d, want 1 (core only)", rep.MetadataWritten)
	}
	for _, w := range metadataWrites(s) {
		if w.device == "blocked-sw" {
			t.Fatalf("blocked device got a metadata record")
		}
	}
}

func TestUnblockedDeviceGetsMetadataAgainAfterBlock(t *testing.T) {
	clock := newClock()
	c := newFakeClient(clock, labelled("core-sw-01", "Core"))
	s := &fakeSpool{}
	p := newTestPoller(c, s, clock, constRand(0.5))
	cycle(t, p)
	blocked := labelled("core-sw-01", "Core")
	blocked.Blocked = true
	setDevices(c, blocked)
	clock.Advance(MinReadInterval + 1)
	if rep := cycle(t, p); rep.MetadataWritten != 0 {
		t.Fatalf("blocked cycle wrote %d metadata records, want 0", rep.MetadataWritten)
	}
	// Same content as before the block: the record must still be written,
	// because the server may have kept the record from before the block.
	setDevices(c, labelled("core-sw-01", "Core"))
	clock.Advance(MinReadInterval + 1)
	if rep := cycle(t, p); rep.MetadataWritten != 1 {
		t.Fatalf("unblocked cycle wrote %d metadata records, want 1", rep.MetadataWritten)
	}
}

func TestCredentialMissingDeviceGetsMetadataRecordButIsNotRead(t *testing.T) {
	clock := newClock()
	noCred := labelled("nocred-sw", "No credential")
	noCred.CredentialMissing = true
	noCred.CredentialVersion = 0
	zeroVersion := labelled("zerov-sw", "Zero version")
	zeroVersion.CredentialVersion = 0
	c := newFakeClient(clock, noCred, zeroVersion)
	s := &fakeSpool{}
	p := newTestPoller(c, s, clock, constRand(0.5))
	rep := cycle(t, p)
	if rep.MetadataWritten != 2 {
		t.Fatalf("metadata written = %d, want 2: metadata does not need a credential", rep.MetadataWritten)
	}
	if rep.Dispatched != 0 || rep.Skipped != 2 {
		t.Fatalf("report = %+v; credential-less devices must be skipped and not read", rep)
	}
	got := map[string]bool{}
	for _, w := range metadataWrites(s) {
		got[w.device] = true
	}
	if !got["nocred-sw"] || !got["zerov-sw"] {
		t.Fatalf("metadata devices = %v, want both credential-less devices", got)
	}
}

func TestDeviceNotListedGetsNoMetadataRecord(t *testing.T) {
	// A tombstoned device is no longer listed by the executor. It gets no
	// record while it is absent, and a record only once it is listed again.
	clock := newClock()
	c := newFakeClient(clock, labelled("core-sw-01", "Core"), labelled("tomb-sw-01", "Tomb"))
	s := &fakeSpool{}
	p := newTestPoller(c, s, clock, constRand(0.5))
	rep := cycle(t, p)
	if rep.MetadataWritten != 2 {
		t.Fatalf("first cycle metadata written = %d, want 2", rep.MetadataWritten)
	}
	if !hasMetadata(s, "core-sw-01") || !hasMetadata(s, "tomb-sw-01") {
		t.Fatal("no metadata record for a listed device; the test checks nothing")
	}

	// tomb-sw-01 is tombstoned: it drops out of the list.
	setDevices(c, labelled("core-sw-01", "Core"))
	clock.Advance(MinReadInterval + 1)
	before := s.count()
	rep = cycle(t, p)
	if rep.MetadataWritten != 0 {
		t.Fatalf("cycle with tombstoned device wrote %d metadata records, want 0", rep.MetadataWritten)
	}
	for _, w := range metaSince(s, before) {
		t.Fatalf("metadata record for unlisted device %s", w.device)
	}

	// It is listed again with the same content: its record is written again.
	setDevices(c, labelled("core-sw-01", "Core"), labelled("tomb-sw-01", "Tomb"))
	clock.Advance(MinReadInterval + 1)
	before = s.count()
	rep = cycle(t, p)
	if rep.MetadataWritten != 1 || !hasMetadataIn(metaSince(s, before), "tomb-sw-01") {
		t.Fatalf("re-listed device: written %d, want 1 record for tomb-sw-01", rep.MetadataWritten)
	}
}

// hasMetadata reports whether s holds a device metadata record of device.
func hasMetadata(s *fakeSpool, device string) bool {
	return hasMetadataIn(metadataWrites(s), device)
}

// hasMetadataIn reports whether writes holds a device metadata record of
// device.
func hasMetadataIn(writes []spooled, device string) bool {
	for _, w := range writes {
		if w.device == device {
			return true
		}
	}
	return false
}

func TestDuplicateListedDeviceGetsOneMetadataRecord(t *testing.T) {
	clock := newClock()
	c := newFakeClient(clock, labelled("core-sw-01", "First"), labelled("core-sw-01", "Second"))
	s := &fakeSpool{}
	p := newTestPoller(c, s, clock, constRand(0.5))
	rep := cycle(t, p)
	if rep.MetadataWritten != 1 {
		t.Fatalf("metadata written = %d, want 1", rep.MetadataWritten)
	}
	meta := metadataWrites(s)
	got, err := DecodeDeviceMetadata(meta[0].payload)
	if err != nil || got.Label != "First" {
		t.Fatalf("record = %+v, %v; want the first listing", got, err)
	}
}

func TestReadErrorsDoNotPreventMetadataRecord(t *testing.T) {
	clock := newClock()
	c := newFakeClient(clock, cbsDevice("core-sw-01"))
	for _, r := range familyReads["cbs"] {
		c.setReadErr(r, status.Error(codes.Unimplemented, "not implemented"))
	}
	s := &fakeSpool{}
	p := newTestPoller(c, s, clock, constRand(0.5))
	rep := cycle(t, p)
	if rep.MetadataWritten != 1 {
		t.Fatalf("metadata written = %d, want 1 despite failing reads", rep.MetadataWritten)
	}
	if n := len(metadataWrites(s)); n != 1 {
		t.Fatalf("metadata records = %d, want 1", n)
	}
}

func TestMetadataSpoolFailureIsCountedAndCycleContinues(t *testing.T) {
	clock := newClock()
	c := newFakeClient(clock, labelled("core-sw-01", "Core"), panosDevice("edge-fw-01"))
	s := &metaSpool{fakeSpool: &fakeSpool{}, failMeta: true}
	p := newTestPoller(c, s, clock, constRand(0.5))
	rep := cycle(t, p)
	if rep.MetadataWritten != 0 || rep.MetadataFailed != 2 {
		t.Fatalf("metadata report = written %d, failed %d; want 0, 2", rep.MetadataWritten, rep.MetadataFailed)
	}
	if rep.Dispatched != 10 {
		t.Fatalf("dispatched = %d, want 10: a metadata failure must not stop the reads", rep.Dispatched)
	}
	reads := 0
	for _, w := range s.all() {
		if w.read != ReadDeviceMetadata {
			reads++
		}
	}
	if reads != 10 {
		t.Fatalf("spooled %d reads, want 10", reads)
	}
}

func TestRefusedMetadataWritesAreLoggedAggregated(t *testing.T) {
	clock := newClock()
	c := newFakeClient(clock, labelled("core-sw-01", "Core"), panosDevice("edge-fw-01"))
	s := &metaSpool{fakeSpool: &fakeSpool{}, failMeta: true}
	var buf bytes.Buffer
	p := newTestPoller(c, s, clock, constRand(0.5))
	p.Log = slog.New(slog.NewJSONHandler(&buf, nil))

	// Two refused cycles within one MinReadInterval: one warning at most.
	for i := range 2 {
		if rep := cycle(t, p); rep.MetadataFailed != 2 {
			t.Fatalf("cycle %d: metadata failed = %d, want 2", i+1, rep.MetadataFailed)
		}
	}
	if n := strings.Count(buf.String(), `"msg":"netdev metadata refused"`); n != 1 {
		t.Fatalf("refusal warnings = %d within one interval, want 1:\n%s", n, buf.String())
	}

	// After the interval the next warning counts every refusal since the
	// last one: 2 refused cycles of 2 devices each, so 4 in total.
	clock.Advance(MinReadInterval + 1)
	cycle(t, p)
	if n := strings.Count(buf.String(), `"msg":"netdev metadata refused"`); n != 2 {
		t.Fatalf("refusal warnings = %d after the interval, want 2:\n%s", n, buf.String())
	}
	if !strings.Contains(buf.String(), `"failed":4`) {
		t.Fatalf("second warning does not aggregate the refusals since the first:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), "edge-fw-01") || strings.Contains(buf.String(), "core-sw-01") {
		t.Fatalf("refusal log names a device; it must aggregate:\n%s", buf.String())
	}
}

func TestCycleSummaryReportsMetadataCounts(t *testing.T) {
	clock := newClock()
	c := newFakeClient(clock, labelled("core-sw-01", "Core"))
	s := &fakeSpool{}
	var buf bytes.Buffer
	p := newTestPoller(c, s, clock, constRand(0.5))
	p.Log = slog.New(slog.NewJSONHandler(&buf, nil))
	p.Interval = time.Nanosecond
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := p.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"metadata_written":1`) || !strings.Contains(buf.String(), `"metadata_failed":0`) {
		t.Fatalf("cycle summary lacks the metadata counts:\n%s", buf.String())
	}
}

func TestMetadataWritesRespectTheDeviceLimit(t *testing.T) {
	clock := newClock()
	devices := make([]*pb.NetDeviceInfo, 0, MaxDevices+1)
	for i := 0; i <= MaxDevices; i++ {
		devices = append(devices, cbsDevice("dev-"+strconv.Itoa(i)))
	}
	c := newFakeClient(clock, devices...)
	s := &fakeSpool{}
	p := newTestPoller(c, s, clock, constRand(0.5))
	if _, err := p.Cycle(context.Background()); !errors.Is(err, ErrTooManyDevices) {
		t.Fatalf("Cycle err = %v, want ErrTooManyDevices", err)
	}
	p.Wait()
	if n := len(metadataWrites(s)); n != 0 {
		t.Fatalf("%d metadata records written for an over-limit list, want 0", n)
	}
}
