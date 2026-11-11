// SPDX-License-Identifier: AGPL-3.0-or-later

package schedgrant

import (
	"regexp"
	"time"
)

// RegistryReadProfile is the read-grant-v2 rate profile of a private
// registry read lease (ADR 0006, cu06 part 1, G13): typed metadata reads
// (a manifest digest or a tag list) of exact repositories of one exact
// private registry record and credential held in the executor vault. It
// binds no SSH actions, hosts, provider remotes or network devices, and it
// never authorizes a blob fetch, pull, push or login.
const RegistryReadProfile = "registry"

// Registry read lease limits. The ordinary floor and budgets apply; the
// budget counts reads per registry per rolling hour across all leases, the
// floor applies per registry, repository and method.
const (
	// RegistryMinInterval is the 15-minute floor between two reads of one
	// method on one repository of one registry.
	RegistryMinInterval = MinInterval
	// RegistryDefaultRunBudget is the default per-registry rolling-hour budget.
	RegistryDefaultRunBudget = 24
	// RegistryMaxRunBudget bounds the per-registry rolling-hour budget.
	RegistryMaxRunBudget = 240
	// RegistryReadMaxLifetime bounds a registry read lease's lifetime: a
	// lease that reaches a credential lives at most 7 days.
	RegistryReadMaxLifetime = 7 * 24 * time.Hour
	// maxRegistryRepositoryLen bounds a repository path.
	maxRegistryRepositoryLen = 255
)

// Typed private registry reads. The names equal the executor's
// RegistryMethod constants, one to one.
const (
	// RegistryReadTagDigest is a manifest HEAD of one tag or digest.
	RegistryReadTagDigest = "tag_digest"
	// RegistryReadListTags is a bounded tag list of one repository.
	RegistryReadListTags = "list_tags"
)

var registryReadMethods = []string{RegistryReadTagDigest, RegistryReadListTags}

// RegistryReadMethods returns a copy of the closed list of typed registry
// reads.
func RegistryReadMethods() []string {
	return append([]string(nil), registryReadMethods...)
}

// IsRegistryReadMethod reports whether name is one of the typed registry
// reads.
func IsRegistryReadMethod(name string) bool {
	for _, m := range registryReadMethods {
		if m == name {
			return true
		}
	}
	return false
}

var (
	registryIDRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	registryRepoRe = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$`)
)

// ValidRegistryID reports whether id has the executor's private registry
// id form.
func ValidRegistryID(id string) bool { return registryIDRe.MatchString(id) }

// ValidRegistryRepository reports whether repo is a bounded OCI repository
// path (no host, tag or digest).
func ValidRegistryRepository(repo string) bool {
	return len(repo) <= maxRegistryRepositoryLen && registryRepoRe.MatchString(repo)
}
