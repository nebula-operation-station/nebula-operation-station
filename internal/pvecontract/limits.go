// SPDX-License-Identifier: AGPL-3.0-or-later

// Package pvecontract defines the typed, validated data contracts that the
// collector, executor and server exchange for Proxmox VE remotes and their
// observations (ADR 0006, ticket P1-02).
//
// Every value is untrusted input. Decoding is strict: unknown fields,
// duplicate keys, invalid UTF-8, oversize strings, counts and nesting are
// rejected. Missing data is represented explicitly as unavailable with a
// reason, never as zero or an empty value.
package pvecontract

// Document limits (ADR 0006, "Phase 1 read path and stored observations"):
// 1 MiB decoded per response/spool page, 1,000 objects per page, 10,000
// guests per remote, 128 interfaces per guest, 4 KiB per text field, bounded
// nesting.
const (
	// MaxResponseBytes bounds one decoded response or spool page.
	MaxResponseBytes = 1 << 20
	// MaxObjectsPerPage bounds record lists in one page.
	MaxObjectsPerPage = 1000
	// MaxGuestsPerRemote bounds guests per remote across all pages.
	MaxGuestsPerRemote = 10000
	// MaxInterfacesPerGuest bounds interfaces per guest.
	MaxInterfacesPerGuest = 128
	// MaxTextFieldBytes bounds any decoded string.
	MaxTextFieldBytes = 4 << 10
	// MaxNesting bounds JSON nesting depth.
	MaxNesting = 32
	// MaxObjectsPerDocument bounds the total number of JSON objects in one
	// decoded document; the 1 MiB document limit already caps the realistic
	// count far below this.
	MaxObjectsPerDocument = 100000
)

// Identity and record limits.
const (
	// MaxRemoteIDBytes bounds a remote_id slug.
	MaxRemoteIDBytes = 64
	// MaxLabelBytes bounds display labels (remote name, guest name, backup
	// record name).
	MaxLabelBytes = 255
	// MaxEndpointsPerRemote bounds ordered API endpoints per remote.
	MaxEndpointsPerRemote = 64
	// MaxNodeNameBytes bounds a PVE node name.
	MaxNodeNameBytes = 253
	// MaxRefBytes bounds short machine references (storage, pool, tag, task
	// type, actor).
	MaxRefBytes = 64
	// MaxVolumeBytes bounds a storage volume reference.
	MaxVolumeBytes = 255
	// MaxTagsPerGuest bounds tags per guest.
	MaxTagsPerGuest = 32
	// MaxSnapshotsPerGuest bounds snapshots per guest.
	MaxSnapshotsPerGuest = 256
	// MaxStoragesPerRemote bounds distinct storage IDs per remote (and per
	// node report).
	MaxStoragesPerRemote = 64
	// MaxStorageReportsPerRemote bounds per-node storage reports in one
	// observation: each node reports the storages it can use.
	MaxStorageReportsPerRemote = 1024
	// MaxDisksPerGuest bounds disk references per guest.
	MaxDisksPerGuest = 32
	// MaxPCIDevicesPerGuest bounds hostpci devices per guest.
	MaxPCIDevicesPerGuest = 16
	// MaxBootOrderEntries bounds boot order entries per guest.
	MaxBootOrderEntries = 8
	// MaxBackupsPerGuest bounds backup evidence records per guest.
	MaxBackupsPerGuest = 64
	// MaxIPsPerInterface bounds IP addresses per guest interface.
	MaxIPsPerInterface = 8
	// MaxFilesystemsPerGuest bounds filesystem summaries per guest agent.
	MaxFilesystemsPerGuest = 32
	// MaxNameservers bounds nameservers in Cloud-Init IP configuration.
	MaxNameservers = 8
	// MaxContentFeatures bounds supported features per storage.
	MaxContentFeatures = 8
	// MaxCPUCores bounds a CPU core count.
	MaxCPUCores = 4096
	// MaxTrustGeneration bounds a trust generation counter.
	MaxTrustGeneration = uint64(1) << 48
	// MaxCollectionGeneration bounds a collection generation counter.
	MaxCollectionGeneration = uint64(1) << 48
	// MaxGuestGeneration bounds a local guest generation counter.
	MaxGuestGeneration = uint64(1) << 48
)

// PVE VMID range: 100 to 9,999,999,999 (exceeds uint32).
const (
	// MinVMID is the lowest valid PVE VMID.
	MinVMID = 100
	// MaxVMID is the highest valid PVE VMID.
	MaxVMID = 9999999999
)

// 802.1Q VLAN range; 0 means untagged.
const (
	// MinVLAN is the lowest valid VLAN value (untagged).
	MinVLAN = 0
	// MaxVLAN is the highest valid 802.1Q VLAN.
	MaxVLAN = 4094
)
