// SPDX-License-Identifier: AGPL-3.0-or-later

package vulninventory

import (
	"regexp"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/osdebian"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnver"
)

// Reasons a stored read is partial, set by FromInstalled. They are fixed
// text and never carry host content (MaxReasonBytes applies).
const (
	// ReasonNoEcosystem: the host's release has no ecosystem NOS can map
	// packages to, so no run can cover the host (fail closed).
	ReasonNoEcosystem = "release not supported for package mapping"
	// ReasonNoBasis: a source package has no version basis (ADR 0011 D4).
	ReasonNoBasis = "source version basis unknown"
	// ReasonIncomplete: the package list was partial but gave no reason.
	ReasonIncomplete = "package list incomplete"
	// ReasonLookupFailed: the host's release could not be read, so the list
	// cannot be mapped (fail closed, see Failed).
	ReasonLookupFailed = "release lookup failed"
	// ReasonRefused: the store refused the list (a field or limit check on
	// host content). The list is not stored (see Failed).
	ReasonRefused = "list refused by the store"
)

// Failed returns the partial marker stored in place of a list that could not
// be read or stored (fail closed): an incomplete read of host from execution
// execID at time at, with reason (one of the Reason constants) and no
// components. Latest returns it, so an older complete read is no longer the
// host's current inventory, while LastComplete still finds that read.
func Failed(host, execID string, at time.Time, reason string) Read {
	return Read{HostID: host, ExecutionID: execID, ReadAt: at, Reason: reason}
}

// ecosystemRe is the shape of an ecosystem NOS stores for a Debian or Ubuntu
// host. It mirrors the debian and ubuntu alternatives of exportEcosystemRe
// (internal/web/api/vuln_export.go); the two must change together.
var ecosystemRe = regexp.MustCompile(`^(debian:[a-z]{2,32}|ubuntu:[0-9]{2}\.[0-9]{2})$`)

// Ecosystem returns the ecosystem of a host from its os-release values
// (executions.OSRelease) and the matching version distro: "debian:<codename>"
// for Debian and "ubuntu:<VERSION_ID>" for Ubuntu. Any other release, or a
// value that does not match the export pattern, gives "" and 0.
func Ecosystem(id, versionID, codename string) (string, vulnver.Distro) {
	switch id {
	case "debian":
		if eco := "debian:" + codename; ecosystemRe.MatchString(eco) {
			return eco, vulnver.DistroDebian
		}
	case "ubuntu":
		if eco := "ubuntu:" + versionID; ecosystemRe.MatchString(eco) {
			return eco, vulnver.DistroUbuntu
		}
	}
	return "", 0
}

// ecosystemDistro returns the distro of a stored ecosystem, or 0 when the
// ecosystem is not one NOS maps packages to.
func ecosystemDistro(eco string) vulnver.Distro {
	if !ecosystemRe.MatchString(eco) {
		return 0
	}
	if strings.HasPrefix(eco, "debian:") {
		return vulnver.DistroDebian
	}
	return vulnver.DistroUbuntu
}

// FromInstalled turns a parsed package.list_installed inventory into a read
// of host, taken at time at for ecosystem eco (see Ecosystem).
//
// Every source package gets its version basis, the lowest source version
// among its installed binaries (vulnver.SourceVersionBasis, ADR 0011 D4);
// the binaries are kept as context. Signed and meta kernel sources are never
// components. The running kernel is copied from inv.RunningKernel.
//
// The read is complete only if inv is complete, eco is supported and every
// stored source has a basis. Otherwise it is partial with a reason. Without a
// supported ecosystem no components are stored, because no run could cover
// the host. FromInstalled never fails: the result is always a Read that Put
// can store.
func FromInstalled(host, execID string, at time.Time, eco string, inv osdebian.InstalledInventory) Read {
	r := Read{
		HostID:      host,
		ExecutionID: execID,
		ReadAt:      at,
		Dropped:     min(inv.Dropped, MaxDropped),
		Kernel: Kernel{
			Release: inv.RunningKernel.Release,
			State:   string(inv.RunningKernel.State),
			Source:  inv.RunningKernel.Source,
			Version: inv.RunningKernel.Version,
		},
	}
	reason := ""
	if !inv.Complete {
		reason = inv.Reason
		if reason == "" {
			reason = ReasonIncomplete
		}
	}
	distro := ecosystemDistro(eco)
	if distro == 0 {
		r.Reason = firstNonEmpty(reason, ReasonNoEcosystem)
		return r
	}
	r.Ecosystem = eco

	// Group the binaries by source package, in inventory order. Signed and
	// meta kernel sources are not components at all.
	var sources []string
	bySource := map[string][]osdebian.InstalledPackage{}
	for _, p := range inv.Packages {
		if vulnver.NeverVersionBasis(p.Source) {
			continue
		}
		if _, ok := bySource[p.Source]; !ok {
			sources = append(sources, p.Source)
		}
		bySource[p.Source] = append(bySource[p.Source], p)
	}
	for _, src := range sources {
		pkgs := bySource[src]
		bins := make([]vulnver.Binary, 0, len(pkgs))
		for _, p := range pkgs {
			bins = append(bins, vulnver.Binary{Name: p.Name, Version: p.Version, SourceName: p.Source, SourceVersion: p.SourceVersion, BuiltUsing: p.BuiltUsing})
		}
		basis, err := vulnver.SourceVersionBasis(vulnver.SchemeDpkg, src, bins)
		if err != nil {
			// The source is dropped, its binaries count as unused lines.
			reason = firstNonEmpty(reason, ReasonNoBasis)
			r.Dropped = min(r.Dropped+len(pkgs), MaxDropped)
			continue
		}
		c := Component{Source: src, SourceVersion: basis.Version}
		for _, p := range pkgs {
			c.Binaries = append(c.Binaries, Binary{Name: p.Name, Version: p.Version, Arch: p.Arch})
		}
		r.Components = append(r.Components, c)
	}
	r.Reason = reason
	r.Complete = reason == ""
	return r
}

// firstNonEmpty returns a if it is set, else b.
func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
