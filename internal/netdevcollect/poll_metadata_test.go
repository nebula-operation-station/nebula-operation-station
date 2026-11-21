// SPDX-License-Identifier: AGPL-3.0-or-later

package netdevcollect

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// metaSpool is a SpoolWriter that fails only the device metadata writes.
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

func TestMetadataRecordsPrecedeReadsInEveryCycle(t *testing.T) {
	clock := newClock()
	c := newFakeClient(clock, cbsDevice("core-sw-01"))
	s := &fakeSpool{}
	p := newTestPoller(c, s, clock, constRand(0.5))
	for cyc := 1; cyc <= 2; cyc++ {
		before := len(s.all())
		cycle(t, p)
		// Only the writes of this cycle: one metadata record, written
		// before the first read of the cycle.
		this := s.all()[before:]
		sawRead := false
		meta := 0
		for _, w := range this {
			if w.read == ReadDeviceMetadata {
				meta++
				if sawRead {
					t.Fatalf("cycle %d: metadata written after a read", cyc)
				}
			} else {
				sawRead = true
			}
		}
		if meta != 1 {
			t.Fatalf("cycle %d: %d metadata records, want 1", cyc, meta)
		}
		clock.Advance(MinReadInterval + 1)
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

func TestDeviceNotListedGetsNoMetadataRecord(t *testing.T) {
	// A tombstoned device is not in ListNetDevices, so the collector has
	// nothing to write for it: no record appears for an unlisted id.
	clock := newClock()
	c := newFakeClient(clock, labelled("core-sw-01", "Core"))
	s := &fakeSpool{}
	p := newTestPoller(c, s, clock, constRand(0.5))
	cycle(t, p)
	for _, w := range metadataWrites(s) {
		if w.device != "core-sw-01" {
			t.Fatalf("metadata record for unlisted device %s", w.device)
		}
	}
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
