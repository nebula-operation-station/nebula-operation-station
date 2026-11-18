// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecontract

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// limitProbe is a valid text value placed in the single element that is one
// beyond a limit. A rejection must name the field and the limit and must not
// echo that element back.
const limitProbe = "limit-probe-secret"

// limitCase changes exactly one field of baseObservation.
type limitCase struct {
	name   string
	mutate func(*Observation)
	// wantOK: the base observation with this one change must be accepted.
	wantOK bool
	// wantProblem: a rejection must contain a problem with this text, which
	// names the field and the limit.
	wantProblem string
	// onlyProblem: the rejection must consist of wantProblem alone.
	onlyProblem bool
}

// makeN builds n elements with f, so the caller can state the limit as a
// named constant and test the value at it and one beyond.
func makeN[T any](n int, f func(i int) T) []T {
	out := make([]T, n)
	for i := range out {
		out[i] = f(i)
	}
	return out
}

// tooMany is the problem text the per-guest count checks produce.
func tooMany(what string, n, limit int) string {
	return fmt.Sprintf("too many %s (%d > %d)", what, n, limit)
}

// runLimitCases validates the base observation with each case's single change
// and checks the outcome against the case.
func runLimitCases(t *testing.T, cases []limitCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := baseObservation()
			tc.mutate(&o)
			_, err := ValidateObservation(o)
			if tc.wantOK {
				if err != nil {
					t.Fatalf("ValidateObservation = %v, want accepted", err)
				}
				return
			}
			var ve *ValidationError
			if !errors.Is(err, ErrInvalid) || !errors.As(err, &ve) {
				t.Fatalf("ValidateObservation = %v, want *ValidationError wrapping ErrInvalid", err)
			}
			found := false
			for _, p := range ve.Problems {
				if strings.Contains(p, tc.wantProblem) {
					found = true
				}
			}
			if !found {
				t.Fatalf("problems %q do not name %q", ve.Problems, tc.wantProblem)
			}
			if tc.onlyProblem && len(ve.Problems) != 1 {
				t.Fatalf("problems = %q, want only %q", ve.Problems, tc.wantProblem)
			}
			if strings.Contains(err.Error(), limitProbe) {
				t.Fatalf("error echoes the rejected element: %v", err)
			}
		})
	}
}

// TestLimitBaseObservationIsValid guards the premise of the table tests: each
// case changes one field of an observation that is otherwise valid.
func TestLimitBaseObservationIsValid(t *testing.T) {
	if _, err := ValidateObservation(baseObservation()); err != nil {
		t.Fatalf("base observation = %v", err)
	}
}

// TestPerGuestCountLimitsAtBoundary checks each per-guest count limit: the
// limit itself is accepted, one more is rejected with the field named.
func TestPerGuestCountLimitsAtBoundary(t *testing.T) {
	template := baseObservation().Guests.Value[0]
	guest := func(f func(g *GuestObservation)) func(*Observation) {
		return func(o *Observation) { f(&o.Guests.Value[0]) }
	}
	config := func(f func(c *GuestConfig)) func(*Observation) {
		return guest(func(g *GuestObservation) { f(&g.Config.Value) })
	}

	runLimitCases(t, []limitCase{
		{
			name:   "disks at MaxDisksPerGuest accepted",
			wantOK: true,
			mutate: config(func(c *GuestConfig) {
				c.Disks = makeN(MaxDisksPerGuest, func(i int) Disk {
					return Disk{Storage: "local-lvm", Volume: fmt.Sprintf("local-lvm:vm-101-disk-%d", i), Format: "raw", SizeBytes: 1 << 30}
				})
			}),
		},
		{
			name:        "disks one beyond MaxDisksPerGuest rejected",
			wantProblem: tooMany("disks", MaxDisksPerGuest+1, MaxDisksPerGuest),
			onlyProblem: true,
			mutate: config(func(c *GuestConfig) {
				c.Disks = makeN(MaxDisksPerGuest+1, func(i int) Disk {
					vol := fmt.Sprintf("local-lvm:vm-101-disk-%d", i)
					if i == MaxDisksPerGuest {
						vol = "local-lvm:" + limitProbe
					}
					return Disk{Storage: "local-lvm", Volume: vol, Format: "raw", SizeBytes: 1 << 30}
				})
			}),
		},
		{
			name:   "boot order at MaxBootOrderEntries accepted",
			wantOK: true,
			mutate: config(func(c *GuestConfig) {
				c.BootOrder = makeN(MaxBootOrderEntries, func(i int) string { return fmt.Sprintf("scsi%d", i) })
			}),
		},
		{
			name:        "boot order one beyond MaxBootOrderEntries rejected",
			wantProblem: tooMany("boot order entries", MaxBootOrderEntries+1, MaxBootOrderEntries),
			onlyProblem: true,
			mutate: config(func(c *GuestConfig) {
				c.BootOrder = makeN(MaxBootOrderEntries+1, func(i int) string {
					if i == MaxBootOrderEntries {
						return limitProbe
					}
					return fmt.Sprintf("scsi%d", i)
				})
			}),
		},
		{
			name:   "hostpci at MaxPCIDevicesPerGuest accepted",
			wantOK: true,
			mutate: config(func(c *GuestConfig) {
				hp := template.Config.Value.HostPCI[0]
				c.HostPCI = makeN(MaxPCIDevicesPerGuest, func(i int) HostPCI {
					h := hp
					h.ID = fmt.Sprint(i)
					return h
				})
			}),
		},
		{
			name:        "hostpci one beyond MaxPCIDevicesPerGuest rejected",
			wantProblem: tooMany("hostpci devices", MaxPCIDevicesPerGuest+1, MaxPCIDevicesPerGuest),
			onlyProblem: true,
			mutate: config(func(c *GuestConfig) {
				hp := template.Config.Value.HostPCI[0]
				c.HostPCI = makeN(MaxPCIDevicesPerGuest+1, func(i int) HostPCI {
					h := hp
					h.ID = fmt.Sprint(i)
					if i == MaxPCIDevicesPerGuest {
						h.ID = limitProbe
					}
					return h
				})
			}),
		},
		{
			name:   "tags at MaxTagsPerGuest accepted",
			wantOK: true,
			mutate: config(func(c *GuestConfig) {
				c.Tags = makeN(MaxTagsPerGuest, func(i int) string { return fmt.Sprintf("tag-%d", i) })
			}),
		},
		{
			name:        "tags one beyond MaxTagsPerGuest rejected",
			wantProblem: tooMany("tags", MaxTagsPerGuest+1, MaxTagsPerGuest),
			onlyProblem: true,
			mutate: config(func(c *GuestConfig) {
				c.Tags = makeN(MaxTagsPerGuest+1, func(i int) string {
					if i == MaxTagsPerGuest {
						return limitProbe
					}
					return fmt.Sprintf("tag-%d", i)
				})
			}),
		},
		{
			name:   "nameservers at MaxNameservers accepted",
			wantOK: true,
			mutate: config(func(c *GuestConfig) {
				ci := *template.Config.Value.CloudInitIP
				ci.Nameservers = makeN(MaxNameservers, func(i int) string { return fmt.Sprintf("10.77.10.%d", i+1) })
				c.CloudInitIP = &ci
			}),
		},
		{
			name:        "nameservers one beyond MaxNameservers rejected",
			wantProblem: tooMany("nameservers", MaxNameservers+1, MaxNameservers),
			onlyProblem: true,
			mutate: config(func(c *GuestConfig) {
				ci := *template.Config.Value.CloudInitIP
				ci.Nameservers = makeN(MaxNameservers+1, func(i int) string { return fmt.Sprintf("10.77.10.%d", i+1) })
				c.CloudInitIP = &ci
			}),
		},
		{
			name:   "interfaces at MaxInterfacesPerGuest accepted",
			wantOK: true,
			mutate: guest(func(g *GuestObservation) {
				ifc := template.Interfaces.Value[0]
				g.Interfaces.Value = makeN(MaxInterfacesPerGuest, func(i int) GuestInterface {
					x := ifc
					x.Name = fmt.Sprintf("net%d", i)
					return x
				})
			}),
		},
		{
			name:        "interfaces one beyond MaxInterfacesPerGuest rejected",
			wantProblem: tooMany("interfaces", MaxInterfacesPerGuest+1, MaxInterfacesPerGuest),
			onlyProblem: true,
			mutate: guest(func(g *GuestObservation) {
				ifc := template.Interfaces.Value[0]
				g.Interfaces.Value = makeN(MaxInterfacesPerGuest+1, func(i int) GuestInterface {
					x := ifc
					x.Name = fmt.Sprintf("net%d", i)
					if i == MaxInterfacesPerGuest {
						x.Name = limitProbe
					}
					return x
				})
			}),
		},
		{
			name:   "IPs at MaxIPsPerInterface accepted",
			wantOK: true,
			mutate: guest(func(g *GuestObservation) {
				g.Interfaces.Value[0].IPs = makeN(MaxIPsPerInterface, func(i int) string { return fmt.Sprintf("10.77.10.%d/24", i+1) })
			}),
		},
		{
			name:        "IPs one beyond MaxIPsPerInterface rejected",
			wantProblem: tooMany("ips", MaxIPsPerInterface+1, MaxIPsPerInterface),
			onlyProblem: true,
			mutate: guest(func(g *GuestObservation) {
				g.Interfaces.Value[0].IPs = makeN(MaxIPsPerInterface+1, func(i int) string { return fmt.Sprintf("10.77.10.%d/24", i+1) })
			}),
		},
		{
			name:   "filesystems at MaxFilesystemsPerGuest accepted",
			wantOK: true,
			mutate: guest(func(g *GuestObservation) {
				g.Agent.Value.Filesystems = makeN(MaxFilesystemsPerGuest, func(i int) Filesystem {
					return Filesystem{MountPoint: fmt.Sprintf("/mnt/fs%d", i), FSType: "ext4", SizeBytes: 1 << 30, UsedBytes: 1 << 20}
				})
			}),
		},
		{
			name:        "filesystems one beyond MaxFilesystemsPerGuest rejected",
			wantProblem: tooMany("filesystems", MaxFilesystemsPerGuest+1, MaxFilesystemsPerGuest),
			onlyProblem: true,
			mutate: guest(func(g *GuestObservation) {
				g.Agent.Value.Filesystems = makeN(MaxFilesystemsPerGuest+1, func(i int) Filesystem {
					mp := fmt.Sprintf("/mnt/fs%d", i)
					if i == MaxFilesystemsPerGuest {
						mp = "/mnt/" + limitProbe
					}
					return Filesystem{MountPoint: mp, FSType: "ext4", SizeBytes: 1 << 30, UsedBytes: 1 << 20}
				})
			}),
		},
		{
			name:   "snapshots at MaxSnapshotsPerGuest accepted",
			wantOK: true,
			mutate: guest(func(g *GuestObservation) {
				g.Snapshots.Value = makeN(MaxSnapshotsPerGuest, func(i int) Snapshot {
					return Snapshot{Name: fmt.Sprintf("snap-%d", i), TimeUnix: 1761734400}
				})
			}),
		},
		{
			name:        "snapshots one beyond MaxSnapshotsPerGuest rejected",
			wantProblem: tooMany("snapshots", MaxSnapshotsPerGuest+1, MaxSnapshotsPerGuest),
			onlyProblem: true,
			mutate: guest(func(g *GuestObservation) {
				g.Snapshots.Value = makeN(MaxSnapshotsPerGuest+1, func(i int) Snapshot {
					name := fmt.Sprintf("snap-%d", i)
					if i == MaxSnapshotsPerGuest {
						name = limitProbe
					}
					return Snapshot{Name: name, TimeUnix: 1761734400}
				})
			}),
		},
		{
			name:   "backups at MaxBackupsPerGuest accepted",
			wantOK: true,
			mutate: guest(func(g *GuestObservation) {
				g.Backups.Value = makeN(MaxBackupsPerGuest, func(i int) BackupEvidence {
					b := template.Backups.Value[0]
					b.Name = fmt.Sprintf("101-%d", i)
					return b
				})
			}),
		},
		{
			name:        "backups one beyond MaxBackupsPerGuest rejected",
			wantProblem: tooMany("backup records", MaxBackupsPerGuest+1, MaxBackupsPerGuest),
			onlyProblem: true,
			mutate: guest(func(g *GuestObservation) {
				g.Backups.Value = makeN(MaxBackupsPerGuest+1, func(i int) BackupEvidence {
					b := template.Backups.Value[0]
					b.Name = fmt.Sprintf("101-%d", i)
					if i == MaxBackupsPerGuest {
						b.Name = limitProbe
					}
					return b
				})
			}),
		},
	})
}

// TestStorageContentCountLimitAboveEight checks the content-feature count
// limit with one more entry than it allows. Each duplicate also adds its own
// problem, so only the count problem is required.
func TestStorageContentCountLimitAboveEight(t *testing.T) {
	runLimitCases(t, []limitCase{
		{
			name:        "content features one beyond MaxContentFeatures rejected",
			wantProblem: tooMany("content features", MaxContentFeatures+1, MaxContentFeatures),
			mutate: func(o *Observation) {
				o.Storages.Value[0].Content = makeN(MaxContentFeatures+1, func(i int) string {
					return []string{"images", "iso", "backup", "vztmpl", "snippets", "container", "images", "images", "images"}[i]
				})
			},
		},
	})
}

// TestStorageContentCountLimitDoesNotTripAtEight documents a limit that cannot
// be reached with valid data: storageContent holds six kinds, so MaxContentFeatures
// (8) cannot be met by distinct known values. At eight entries the count check
// must stay quiet; the rejection then comes from the content rules only.
func TestStorageContentCountLimitDoesNotTripAtEight(t *testing.T) {
	o := baseObservation()
	o.Storages.Value[0].Content = []string{"images", "iso", "backup", "vztmpl", "snippets", "container", "iso", "backup"}
	_, err := ValidateObservation(o)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("ValidateObservation = %v, want ErrInvalid from duplicate content", err)
	}
	if strings.Contains(err.Error(), "too many content features") {
		t.Fatalf("count limit fired at %d entries: %v", MaxContentFeatures, err)
	}
}

// TestValueLimitsAtBoundary checks each value limit at the limit and at the
// next value above it.
func TestValueLimitsAtBoundary(t *testing.T) {
	node := func(f func(n *NodeObservation)) func(*Observation) {
		return func(o *Observation) { f(&o.Nodes.Value[0]) }
	}
	guest := func(f func(g *GuestObservation)) func(*Observation) {
		return func(o *Observation) { f(&o.Guests.Value[0]) }
	}
	atTime := func(y, mo, d, h, mi, s int, loc *time.Location) func(*Observation) {
		return func(o *Observation) { o.ObservedAt = time.Date(y, time.Month(mo), d, h, mi, s, 0, loc) }
	}

	runLimitCases(t, []limitCase{
		{
			name:   "node cpu_count at MaxCPUCores accepted",
			wantOK: true,
			mutate: node(func(n *NodeObservation) { n.CPUCount = MaxCPUCores }),
		},
		{
			name:        "node cpu_count one above MaxCPUCores rejected",
			wantProblem: "cpu_count 4097 out of range",
			onlyProblem: true,
			mutate:      node(func(n *NodeObservation) { n.CPUCount = MaxCPUCores + 1 }),
		},
		{
			name:   "guest cpu_count at MaxCPUCores accepted",
			wantOK: true,
			mutate: guest(func(g *GuestObservation) { g.Config.Value.CPUCount = MaxCPUCores }),
		},
		{
			name:        "guest cpu_count one above MaxCPUCores rejected",
			wantProblem: "cpu_count 4097 out of range",
			onlyProblem: true,
			mutate:      guest(func(g *GuestObservation) { g.Config.Value.CPUCount = MaxCPUCores + 1 }),
		},
		{
			// The volume regex alone admits a storage prefix plus a 255-byte
			// name, so only MaxVolumeBytes stops a 256-byte volume.
			name:   "volume of MaxVolumeBytes with storage prefix accepted",
			wantOK: true,
			mutate: guest(func(g *GuestObservation) {
				g.Config.Value.Disks[0].Volume = "local-lvm:" + strings.Repeat("v", MaxVolumeBytes-len("local-lvm:"))
			}),
		},
		{
			name:        "volume one byte above MaxVolumeBytes rejected",
			wantProblem: "disks[0]: volume",
			onlyProblem: true,
			mutate: guest(func(g *GuestObservation) {
				g.Config.Value.Disks[0].Volume = "local-lvm:" + strings.Repeat("v", MaxVolumeBytes+1-len("local-lvm:"))
			}),
		},
		{
			name:   "guest generation at MaxGuestGeneration accepted",
			wantOK: true,
			mutate: guest(func(g *GuestObservation) { g.Generation = MaxGuestGeneration }),
		},
		{
			name:        "guest generation one above MaxGuestGeneration rejected",
			wantProblem: "generation out of range",
			onlyProblem: true,
			mutate:      guest(func(g *GuestObservation) { g.Generation = MaxGuestGeneration + 1 }),
		},
		{
			// 0001-01-01T00:00:00Z is Go's zero time, which the "required"
			// check rejects first; the lowest accepted instant is one second on.
			name:   "observed_at one second into MinObservedYear accepted",
			wantOK: true,
			mutate: atTime(MinObservedYear, 1, 1, 0, 0, 1, time.UTC),
		},
		{
			name:        "observed_at zero time rejected as required",
			wantProblem: "observed_at is required",
			onlyProblem: true,
			mutate:      atTime(MinObservedYear, 1, 1, 0, 0, 0, time.UTC),
		},
		{
			name:        "observed_at one second before MinObservedYear rejected",
			wantProblem: "observed_at is out of range",
			onlyProblem: true,
			mutate:      atTime(MinObservedYear-1, 12, 31, 23, 59, 59, time.UTC),
		},
		{
			name:   "observed_at in MaxObservedYear accepted",
			wantOK: true,
			mutate: atTime(MaxObservedYear, 12, 31, 23, 59, 59, time.UTC),
		},
		{
			name:        "observed_at one second after MaxObservedYear rejected",
			wantProblem: "observed_at is out of range",
			onlyProblem: true,
			mutate:      atTime(MaxObservedYear+1, 1, 1, 0, 0, 0, time.UTC),
		},
		{
			// 23:30 at UTC-1 is 00:30 in year 10000 in UTC: the UTC year decides.
			name:        "observed_at with offset that crosses MaxObservedYear rejected",
			wantProblem: "observed_at is out of range",
			onlyProblem: true,
			mutate:      atTime(MaxObservedYear, 12, 31, 23, 30, 0, time.FixedZone("UTC-1", -3600)),
		},
	})
}
