// SPDX-License-Identifier: AGPL-3.0-or-later

package registrymeta

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
)

// This file is the server side of private registry reads (ADR 0006, cu06
// part 1, G13). The server never holds a registry credential: it lists the
// executor's private registry metadata (ListPrivateRegistries, server role)
// and asks the executor for typed reads (ReadPrivateRegistry, server role),
// which the executor authorizes against an approved registry read lease
// (BuildRegistryReadLease). Everything the executor returns is checked
// before use; the executor's error text never reaches a caller.

// Sentinel errors of server-side private registry reads.
var (
	// ErrNotPrivate: the image's registry is not an executor private
	// registry; the host's anonymous read is the only source.
	ErrNotPrivate = errors.New("registrymeta: the image is not on an executor private registry")
	// ErrPrivateReadRefused: the executor refused the read (no covering
	// lease, lease stale or expired, budget, interval, read pause, locked
	// vault, credential rejected).
	ErrPrivateReadRefused = errors.New("registrymeta: the executor refused the private registry read")
	// ErrPrivateReadFailed: the executor or registry could not answer, or
	// the answer did not validate.
	ErrPrivateReadFailed = errors.New("registrymeta: the private registry read failed")
	// ErrPrivateListFailed: the executor's private registry metadata could
	// not be listed.
	ErrPrivateListFailed = errors.New("registrymeta: the executor's private registries could not be listed")
)

// Limits of server-side private registry reads.
const (
	// MaxPrivateDigestImages bounds the images resolved in one
	// PrivateDigests call; it equals the docker.check_updates image limit.
	MaxPrivateDigestImages = 50
	// maxListedRegistries bounds the registries taken from one list answer.
	maxListedRegistries = 64
	// maxRegistryOriginLen bounds a listed registry origin.
	maxRegistryOriginLen = 512
	// defaultTag is the tag of a reference that names none (Docker's rule,
	// as docker.check_updates applies it).
	defaultTag = "latest"
)

var (
	configDigestRe   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	credentialIDRe   = regexp.MustCompile(`^[0-9a-f]{32}$`)
	manifestDigestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	privateRefHostRe = regexp.MustCompile(`^[A-Za-z0-9.-]+(:[0-9]{1,5})?$`)
)

// ExecutorRegistry is the server-role subset of the executor API for
// private registries. Neither method carries a credential.
type ExecutorRegistry interface {
	ListPrivateRegistries(ctx context.Context, in *pb.ListPrivateRegistriesRequest, opts ...grpc.CallOption) (*pb.ListPrivateRegistriesResponse, error)
	ReadPrivateRegistry(ctx context.Context, in *pb.ReadPrivateRegistryRequest, opts ...grpc.CallOption) (*pb.ReadPrivateRegistryResponse, error)
}

// PrivateIdentity is one executor private registry as the server may know
// it: the approved scope and the identity a registry read lease binds. It
// holds no credential, user name or token.
type PrivateIdentity struct {
	ID                string
	Origin            string
	Repositories      []string
	ConfigDigest      string
	ConfigVersion     int64
	CredentialID      string
	CredentialVersion int64
	// CredentialExpires is when the executor stops reading with the
	// credential; zero when it does not expire.
	CredentialExpires time.Time
}

// identityFromInfo validates one listed registry.
func identityFromInfo(in *pb.PrivateRegistryInfo) (PrivateIdentity, bool) {
	id := PrivateIdentity{
		ID: in.GetRegistryId(), Origin: in.GetRegistryOrigin(), ConfigDigest: in.GetConfigDigest(),
		ConfigVersion: in.GetConfigVersion(), CredentialID: in.GetCredentialId(), CredentialVersion: in.GetCredentialVersion(),
	}
	if e := in.GetCredentialExpiresUnix(); e > 0 {
		id.CredentialExpires = time.Unix(e, 0).UTC()
	}
	if !schedgrant.ValidRegistryID(id.ID) || !configDigestRe.MatchString(id.ConfigDigest) ||
		!credentialIDRe.MatchString(id.CredentialID) || id.ConfigVersion < 1 || id.CredentialVersion < 1 ||
		len(id.Origin) > maxRegistryOriginLen {
		return PrivateIdentity{}, false
	}
	u, err := parseOrigin(id.Origin)
	if err != nil || u.Scheme != "https" || u.User != nil {
		return PrivateIdentity{}, false
	}
	repos := in.GetRepositories()
	if len(repos) == 0 || len(repos) > MaxPrivateRepositories {
		return PrivateIdentity{}, false
	}
	for _, r := range repos {
		if !schedgrant.ValidRegistryRepository(r) || slices.Contains(id.Repositories, r) {
			return PrivateIdentity{}, false
		}
		id.Repositories = append(id.Repositories, r)
	}
	return id, true
}

// ListPrivateIdentities lists the executor's private registries. An entry
// that does not validate is left out (it cannot be leased or read), so one
// bad record never hides the others; a duplicate registry ID or origin
// leaves out every entry carrying it, because neither could be told apart.
func ListPrivateIdentities(ctx context.Context, exec ExecutorRegistry) ([]PrivateIdentity, error) {
	resp, err := exec.ListPrivateRegistries(ctx, &pb.ListPrivateRegistriesRequest{})
	if err != nil {
		return nil, ErrPrivateListFailed
	}
	infos := resp.GetRegistries()
	if len(infos) > maxListedRegistries {
		return nil, ErrPrivateListFailed
	}
	var out []PrivateIdentity
	ids, origins := map[string]int{}, map[string]int{}
	for _, in := range infos {
		id, ok := identityFromInfo(in)
		if !ok {
			continue
		}
		ids[id.ID]++
		origins[id.Origin]++
		out = append(out, id)
	}
	return slices.DeleteFunc(out, func(id PrivateIdentity) bool { return ids[id.ID] > 1 || origins[id.Origin] > 1 }), nil
}

// privateRef is an image reference on a private registry.
type privateRef struct {
	registry   PrivateIdentity
	repository string
	tag        string
}

// matchPrivateImage maps a running image reference
// ("host[:port]/repository[:tag]") to its private registry by exact origin.
// A reference without a registry host, with a scheme, or pinned by digest
// is not a private tag reference. A repository outside the record's
// approved scope is ErrOutOfScope (no read is attempted).
func matchPrivateImage(image string, regs []PrivateIdentity) (privateRef, error) {
	if image == "" || len(image) > MaxImageLen || strings.Contains(image, "://") || strings.Contains(image, "@") {
		return privateRef{}, ErrNotPrivate
	}
	host, rest, ok := strings.Cut(image, "/")
	if !ok || !privateRefHostRe.MatchString(host) || (!strings.ContainsAny(host, ".:") && host != "localhost") {
		return privateRef{}, ErrNotPrivate
	}
	origin := "https://" + strings.ToLower(host)
	k := slices.IndexFunc(regs, func(r PrivateIdentity) bool { return strings.EqualFold(r.Origin, origin) })
	if k < 0 {
		return privateRef{}, ErrNotPrivate
	}
	tag := defaultTag
	if i := strings.LastIndex(rest, ":"); i >= 0 && !strings.Contains(rest[i:], "/") {
		rest, tag = rest[:i], rest[i+1:]
	}
	if len(tag) > MaxTagLen || !tagRe.MatchString(tag) || !schedgrant.ValidRegistryRepository(rest) {
		return privateRef{}, fmt.Errorf("%w: invalid reference", ErrBadRef)
	}
	if !slices.Contains(regs[k].Repositories, rest) {
		return privateRef{}, ErrOutOfScope
	}
	return privateRef{registry: regs[k], repository: rest, tag: tag}, nil
}

// PrivateDigest is the registry's current manifest digest of one private
// image tag, read by the executor with the vault credential.
type PrivateDigest struct {
	RegistryID string
	Repository string
	Tag        string
	// Digest is the validated manifest digest ("sha256:<64 hex>").
	Digest     string
	ObservedAt time.Time
}

// PrivateDigests resolves the current registry digest of each private
// image among images (running references as docker.check_updates reports
// them) through the executor, one ReadPrivateRegistry tag_digest read per
// distinct repository and tag. The map holds the images that resolved;
// errs holds, per image on a private registry that did not resolve, the
// reason (ErrOutOfScope, ErrPrivateReadRefused, ErrPrivateReadFailed or
// ErrBadRef). Images on no private registry appear in neither. An error is
// returned only when the registries cannot be listed.
func PrivateDigests(ctx context.Context, exec ExecutorRegistry, images []string) (map[string]PrivateDigest, map[string]error, error) {
	if len(images) > MaxPrivateDigestImages {
		images = images[:MaxPrivateDigestImages]
	}
	regs, err := ListPrivateIdentities(ctx, exec)
	if err != nil {
		return nil, nil, err
	}
	out, errs := map[string]PrivateDigest{}, map[string]error{}
	if len(regs) == 0 {
		return out, errs, nil
	}
	type key struct{ reg, repo, tag string }
	type answer struct {
		d   PrivateDigest
		err error
	}
	done := map[key]answer{}
	for _, img := range images {
		pi, err := matchPrivateImage(img, regs)
		if errors.Is(err, ErrNotPrivate) {
			continue
		}
		if err != nil {
			errs[img] = err
			continue
		}
		k := key{pi.registry.ID, pi.repository, pi.tag}
		a, ok := done[k]
		if !ok {
			a.d, a.err = readPrivateDigest(ctx, exec, pi)
			done[k] = a
		}
		if a.err != nil {
			errs[img] = a.err
			continue
		}
		out[img] = a.d
	}
	return out, errs, nil
}

// readPrivateDigest asks the executor for one tag_digest read and checks
// the answer echoes the request and carries a valid digest.
func readPrivateDigest(ctx context.Context, exec ExecutorRegistry, pi privateRef) (PrivateDigest, error) {
	resp, err := exec.ReadPrivateRegistry(ctx, &pb.ReadPrivateRegistryRequest{
		RegistryId: pi.registry.ID, Method: pb.PrivateRegistryReadMethod_PRIVATE_REGISTRY_READ_METHOD_TAG_DIGEST,
		Repository: pi.repository, Tag: pi.tag,
	})
	if err != nil {
		switch status.Code(err) {
		case codes.PermissionDenied, codes.FailedPrecondition, codes.ResourceExhausted, codes.Unauthenticated:
			return PrivateDigest{}, ErrPrivateReadRefused
		}
		return PrivateDigest{}, ErrPrivateReadFailed
	}
	if resp.GetRegistryId() != pi.registry.ID || resp.GetRepository() != pi.repository ||
		!manifestDigestRe.MatchString(resp.GetDigest()) || len(resp.GetTags()) != 0 {
		return PrivateDigest{}, ErrPrivateReadFailed
	}
	return PrivateDigest{RegistryID: pi.registry.ID, Repository: pi.repository, Tag: pi.tag, Digest: resp.GetDigest(),
		ObservedAt: time.Unix(resp.GetObservedAtUnix(), 0).UTC()}, nil
}
