// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnmatch

import (
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

// Subject is one subject of the inventory export (vuln-inventory-v1, D3),
// with all its parts merged. Hosts and images carry components; devices
// carry Device.
type Subject struct {
	// Kind is host, image or device.
	Kind vulnfinding.SubjectKind
	// Ref is the opaque subject reference.
	Ref vulnfinding.SubjectRef
	// Ecosystem is the OS release ("debian:bookworm", "ubuntu:24.04",
	// "alpine:3.20") or, for devices, the vendor ecosystem
	// ("vendor:cisco:cbs", "vendor:paloalto:panos"). Empty when unknown.
	Ecosystem string
	// Kernel is a host's running kernel; nil when unknown.
	Kernel *Kernel
	// Components are the installed source packages.
	Components []Component
	// Device is a device's model and firmware; nil for hosts and images.
	Device *Device
}

// Kernel is a host's running kernel and its D4 version basis as NOS mapped
// it (D3 export running_kernel).
type Kernel struct {
	// Release is `uname -r`.
	Release string
	// Mapped is true when NOS mapped the running kernel to an unsigned
	// kernel source package and version.
	Mapped bool
	// SourcePackage and SourceVersion are that mapping.
	SourcePackage string
	SourceVersion string
	// Installed lists other installed kernels as (unsigned source,
	// version), context only: they never decide a finding but give the
	// "fixed after reboot" note.
	Installed []InstalledKernel
}

// InstalledKernel is one installed kernel's basis (context only).
type InstalledKernel struct {
	SourcePackage string
	SourceVersion string
}

// Component is one installed source package.
type Component struct {
	// SourcePackage is the source package (dpkg source:Package, apk
	// origin).
	SourcePackage string
	// SourceVersion is the installed source version (source:Version), the
	// D4 version basis. When binaries carry differing source versions the
	// lowest of all is the basis.
	SourceVersion string
	// Binaries are the installed binaries of the source package.
	Binaries []Binary
}

// Binary is one installed binary package. Version is context only and is
// never compared.
type Binary struct {
	Name    string
	Version string
	// SourceVersion is the binary's own source:Version when the inventory
	// reports it per binary (partial upgrades); empty otherwise.
	SourceVersion string
}

// Device is a network device's model and firmware (D3, ADR 0010).
type Device struct {
	Model    string
	Firmware string
}

// Note is an agent-side note on a finding. It is not part of the D5 record.
type Note string

// Notes the matcher sets.
const (
	// NoteFixedAfterReboot: the running kernel is affected, an installed
	// kernel of the same source package is fixed (D4).
	NoteFixedAfterReboot Note = "fixed after reboot"
	// NoteFixedVersionOverBounds: the feed's fixed version exceeded the
	// record bounds; the record is sent with no_fix_yet (A1.3).
	NoteFixedVersionOverBounds Note = "fixed version over bounds"
)

// Finding is one matched record in the D5 shape plus agent-side notes.
type Finding struct {
	// Record is the finding record exactly as sent (no finding_key).
	Record vulnfinding.Record
	// Notes are agent-side context; sorted, never sent as record fields.
	Notes []Note
}

// GapReason says why a component's coverage is unknown.
type GapReason string

// Gap reasons. None of them is ever "clean".
const (
	// GapEcosystemUnknown: the subject's ecosystem is empty or not one the
	// matcher covers.
	GapEcosystemUnknown GapReason = "ecosystem_unknown"
	// GapProxmox: Proxmox packages are not in the Debian tracker (D4).
	GapProxmox GapReason = "proxmox_coverage_unknown"
	// GapKernelUnknown: the running kernel does not map (D4).
	GapKernelUnknown GapReason = "kernel_version_unknown"
	// GapVersionUnknown: the installed source version does not parse.
	GapVersionUnknown GapReason = "installed_version_unknown"
	// GapFixedVersionUnknown: the feed's fixed version does not parse.
	GapFixedVersionUnknown GapReason = "fixed_version_unknown"
	// GapTrackerState: a tracker state outside the D4 table
	// (undetermined).
	GapTrackerState GapReason = "tracker_state_unknown"
	// GapRangeUnknown: OSV ranges that cannot be evaluated.
	GapRangeUnknown GapReason = "range_unknown"
	// GapVendorRange: a vendor product given only as a version range or
	// with contradicting status lists for the firmware.
	GapVendorRange GapReason = "vendor_status_unknown"
	// GapNoValidID: a feed record without a pattern-valid ID.
	GapNoValidID GapReason = "no_valid_id"
)

// Gap is one coverage gap. Package and VulnID are empty when the gap is
// about the whole subject or component.
type Gap struct {
	Kind      vulnfinding.SubjectKind
	Ref       vulnfinding.SubjectRef
	Ecosystem string
	Package   string
	VulnID    string
	Reason    GapReason
}

// Withheld is a record that failed the D2/D5 validation; it is not sent.
// Err names the field, never the value.
type Withheld struct {
	Kind      vulnfinding.SubjectKind
	Ref       vulnfinding.SubjectRef
	Ecosystem string
	VulnID    string
	Err       error
}

// Result is the outcome of Match.
type Result struct {
	// MatcherVersion is the version every record carries.
	MatcherVersion string
	// Findings are sorted by (subject kind, subject ref, ecosystem,
	// package or model, vuln_id).
	Findings []Finding
	// Gaps are sorted like Findings, then by reason.
	Gaps []Gap
	// Withheld lists records that failed validation.
	Withheld []Withheld
	// FeedPartsCut counts feed-side parts cut or failed closed (A1.3:
	// invalid aliases, over-bound fixed versions, CVSS entries).
	FeedPartsCut int
}

// Anchor is one entry of NOS's primary anchor list (A1.3): the primary
// vuln_id NOS holds for an (ecosystem, package or model) pair.
type Anchor struct {
	Ecosystem string
	Package   string
	VulnID    string
}

// Options tune Match.
type Options struct {
	// Anchors is NOS's primary anchor list; nil means none.
	Anchors map[Anchor]struct{}
}
