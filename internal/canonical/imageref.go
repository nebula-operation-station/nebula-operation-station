// SPDX-License-Identifier: AGPL-3.0-or-later

package canonical

import (
	"errors"
	"regexp"
	"strings"
)

// Image reference limits, enforced by ParseImageReference.
const (
	// maxImageReferenceSize bounds a whole reference such as Config.Image.
	maxImageReferenceSize = 512
	// maxRepositorySize is Docker's own limit for a repository name.
	maxRepositorySize = 255
)

// ErrImageReference means a reference is not in a form NOS can compare.
var ErrImageReference = errors.New("image reference is not comparable")

var (
	registryHostRe  = regexp.MustCompile(`^(localhost|[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*)(:[0-9]{1,5})?$`)
	pathComponentRe = regexp.MustCompile(`^[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*$`)
	imageTagRe      = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
)

// ImageReference is a parsed image reference in canonical form. Repository
// always keeps its registry host (docker.io for Docker Hub), Tag is never
// empty, and Digest is empty or "sha256:<64 hex>".
type ImageReference struct {
	Repository string
	Tag        string
	Digest     string
}

// ParseImageReference is the single normalization rule for image references
// (container update plan, cu01). "nginx", "library/nginx" and
// "docker.io/nginx" all give the repository docker.io/library/nginx;
// index.docker.io gives docker.io; a first path part with "." or ":", or
// "localhost", is a registry host. A reference without a tag has the implicit
// tag "latest". "repo:tag@digest" keeps repository, tag and digest. A digest
// without a tag, a bare image ID, uppercase repository parts and every other
// form are refused with ErrImageReference.
func ParseImageReference(ref string) (ImageReference, error) {
	if ref == "" || len(ref) > maxImageReferenceSize || strings.HasPrefix(ref, "-") {
		return ImageReference{}, ErrImageReference
	}
	for _, r := range ref {
		if r <= ' ' || r > '~' {
			return ImageReference{}, ErrImageReference
		}
	}
	if strings.HasPrefix(ref, "sha256:") || hex64.MatchString(ref) {
		return ImageReference{}, ErrImageReference // a bare image ID
	}
	name, digest, hasDigest := strings.Cut(ref, "@")
	if hasDigest && !validImageDigest(digest) {
		return ImageReference{}, ErrImageReference
	}
	tag := ""
	if i := strings.LastIndex(name, ":"); i > strings.LastIndex(name, "/") {
		name, tag = name[:i], name[i+1:]
		if !imageTagRe.MatchString(tag) {
			return ImageReference{}, ErrImageReference
		}
	} else if hasDigest {
		return ImageReference{}, ErrImageReference // repo@digest has no comparable tag
	} else {
		tag = "latest"
	}
	host, path := "docker.io", name
	if first, rest, ok := strings.Cut(name, "/"); ok && (strings.ContainsAny(first, ".:") || first == "localhost") {
		host, path = first, rest
		if !registryHostRe.MatchString(host) {
			return ImageReference{}, ErrImageReference
		}
		if host == "index.docker.io" {
			host = "docker.io"
		}
	}
	if host == "docker.io" && !strings.Contains(path, "/") {
		path = "library/" + path
	}
	for _, part := range strings.Split(path, "/") {
		if !pathComponentRe.MatchString(part) {
			return ImageReference{}, ErrImageReference
		}
	}
	repo := host + "/" + path
	if len(repo) > maxRepositorySize {
		return ImageReference{}, ErrImageReference
	}
	return ImageReference{Repository: repo, Tag: tag, Digest: digest}, nil
}

// validCanonicalRepository reports whether repo is already in the canonical
// form ParseImageReference produces.
func validCanonicalRepository(repo string) bool {
	r, err := ParseImageReference(repo + ":latest")
	return err == nil && r.Repository == repo
}
