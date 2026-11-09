// SPDX-License-Identifier: AGPL-3.0-or-later

package jewels_test

import (
	"fmt"
	"slices"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/attackpath"
	"github.com/nebula-operation-station/nebula-operation-station/internal/attackpath/jewels"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnprio"
)

func TestEntryClassesWithoutDataAreUnknown(t *testing.T) {
	st := jewels.EntryClasses(jewels.EntryInputs{})
	if len(st) != 2 {
		t.Fatalf("classes = %d", len(st))
	}
	if st[0].Class != jewels.EntryInternet || st[0].Node != attackpath.InternetID || st[0].Coverage != jewels.CoverageUnknown || st[0].Reason == "" {
		t.Errorf("internet = %+v", st[0])
	}
	if st[1].Class != jewels.EntryNetBird || st[1].Node != attackpath.NetBirdID || st[1].Coverage != jewels.CoverageUnknown || st[1].Reason == "" {
		t.Errorf("netbird = %+v", st[1])
	}
	for _, node := range []string{"host:a", "dev:fw"} {
		if e, ok := jewels.EntryExposure(st, node); !ok || e != vulnprio.ExposureUnknown {
			t.Errorf("exposure of %s = %q, %v; want unknown", node, e, ok)
		}
	}
}

func TestNetBirdIsItsOwnClass(t *testing.T) {
	st := jewels.EntryClasses(jewels.EntryInputs{
		Internet: &jewels.Exposure{Nodes: []string{"host:web"}},
		NetBird:  &jewels.Exposure{Nodes: []string{"host:nb", "host:web"}},
	})
	cases := map[string]vulnprio.Exposure{"host:web": vulnprio.ExposureInternet, "host:nb": vulnprio.ExposureVPNEntry}
	for node, want := range cases {
		if e, ok := jewels.EntryExposure(st, node); !ok || e != want {
			t.Errorf("exposure of %s = %q, %v; want %q", node, e, ok, want)
		}
	}
	if slices.Contains(st[0].Exposed, "host:nb") {
		t.Error("NetBird peer exposure merged into the internet class")
	}
	if e, ok := jewels.EntryExposure(st, "host:inner"); ok {
		t.Errorf("unexposed node with full coverage = %q; want undecided", e)
	}
}

func TestUnknownInternetIsNeverInternal(t *testing.T) {
	st := jewels.EntryClasses(jewels.EntryInputs{NetBird: &jewels.Exposure{Nodes: []string{"host:nb"}}})
	for _, node := range []string{"host:nb", "host:inner"} {
		if e, ok := jewels.EntryExposure(st, node); !ok || e != vulnprio.ExposureUnknown {
			t.Errorf("exposure of %s = %q, %v; want unknown while internet data is missing", node, e, ok)
		}
	}
	st = jewels.EntryClasses(jewels.EntryInputs{Internet: &jewels.Exposure{}})
	if e, ok := jewels.EntryExposure(st, "host:inner"); !ok || e != vulnprio.ExposureUnknown {
		t.Errorf("unknown NetBird class gave %q, %v; want unknown", e, ok)
	}
}

func TestEntryExposureDropsHostileIDs(t *testing.T) {
	st := jewels.EntryClasses(jewels.EntryInputs{Internet: &jewels.Exposure{Nodes: []string{
		"host:b", "host:a", "host:a", "unk:203.0.113.9", "internet", "netbird", "", "host:", "x\x00", "host:\xff", "host:a b",
	}}})
	if want := []string{"host:a", "host:b", "unk:203.0.113.9"}; !slices.Equal(st[0].Exposed, want) {
		t.Errorf("exposed = %q, want %q", st[0].Exposed, want)
	}
	if st[0].Dropped != 7 {
		t.Errorf("dropped = %d, want 7", st[0].Dropped)
	}
}

func TestEntryExposureTruncatedStaysConservative(t *testing.T) {
	nodes := make([]string, jewels.MaxExposed+5)
	for i := range nodes {
		nodes[i] = fmt.Sprintf("host:%05d", i)
	}
	st := jewels.EntryClasses(jewels.EntryInputs{Internet: &jewels.Exposure{Nodes: nodes}, NetBird: &jewels.Exposure{}})
	if !st[0].Truncated || len(st[0].Exposed) != jewels.MaxExposed {
		t.Fatalf("truncated = %v, len = %d", st[0].Truncated, len(st[0].Exposed))
	}
	if e, ok := jewels.EntryExposure(st, nodes[len(nodes)-1]); !ok || e != vulnprio.ExposureUnknown {
		t.Errorf("cut-off node = %q, %v; want unknown", e, ok)
	}
	if e, _ := jewels.EntryExposure(st, nodes[0]); e != vulnprio.ExposureInternet {
		t.Errorf("listed node = %q, want internet", e)
	}
}
