// SPDX-License-Identifier: AGPL-3.0-or-later

// Package registrypull fetches one approved, digest-pinned image from an
// administrator-approved private registry and writes it as a `docker load`
// compatible archive stream (ADR 0006, private pulls are executor-mediated,
// cu06 transfer/load profile).
//
// The executor opens the registry credential from its vault and passes it
// in for one pull; the package never stores, logs or returns it, and the
// bearer token obtained with it stays inside the pull. Every manifest and
// blob is verified against the digest and size that bind it (the approved
// digest for the top-level manifest, descriptors for everything below).
// Layers are spooled one at a time to an unlinked temporary file, verified,
// and only then copied to the output, so no unverified byte is ever
// written and memory stays bounded. manifest.json, which `docker load`
// needs, is written last: an error leaves a truncated archive without it
// and without a tar trailer, which the caller must discard.
//
// The package is the only place that fetches blobs; internal/registrymeta
// stays metadata-only.
package registrypull

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/registrymeta"
)

// Sentinel errors of a pull.
var (
	// ErrInvalidOptions: the Puller options are invalid.
	ErrInvalidOptions = errors.New("registrypull: invalid options")
	// ErrInvalidRequest: the pull request is malformed.
	ErrInvalidRequest = errors.New("registrypull: invalid pull request")
	// ErrOutOfScope: the repository is not in the approved scope.
	ErrOutOfScope = errors.New("registrypull: repository is outside the approved scope")
	// ErrCredentialRejected: the credential is malformed or the registry or
	// token realm refused it.
	ErrCredentialRejected = errors.New("registrypull: registry credential rejected or invalid")
	// ErrRealmNotApproved: an auth challenge names another realm or service.
	ErrRealmNotApproved = errors.New("registrypull: authentication challenge names an unapproved realm")
	// ErrRequestNotAllowed: a request outside the pull allowlist was refused
	// before it was sent.
	ErrRequestNotAllowed = errors.New("registrypull: request is not allowed")
	// ErrRedirectNotAllowed: a redirect leaves the approved hosts or is not
	// allowed for this request.
	ErrRedirectNotAllowed = errors.New("registrypull: redirect is not allowed")
	// ErrPrivateAddress: the target resolved to a refused address.
	ErrPrivateAddress = errors.New("registrypull: refused private, loopback or link-local address")
	// ErrDigestMismatch: content does not match its digest.
	ErrDigestMismatch = errors.New("registrypull: content does not match its digest")
	// ErrSizeMismatch: content length differs from its descriptor size or
	// the stream ended early.
	ErrSizeMismatch = errors.New("registrypull: content size differs from its descriptor")
	// ErrTooLarge: a manifest, config, blob or the image exceeds a limit.
	ErrTooLarge = errors.New("registrypull: content exceeds the size limit")
	// ErrBadResponse: a registry response is malformed or out of schema.
	ErrBadResponse = errors.New("registrypull: malformed registry response")
	// ErrUnsupported: a media type or manifest feature is not supported.
	ErrUnsupported = errors.New("registrypull: unsupported manifest content")
	// ErrPlatform: the requested platform is missing, ambiguous or differs
	// from the image configuration.
	ErrPlatform = errors.New("registrypull: platform not found or ambiguous")
	// ErrNotFound: the registry reports the manifest or blob as missing.
	ErrNotFound = errors.New("registrypull: manifest or blob not found")
	// ErrRateLimited: the registry answered 429.
	ErrRateLimited = errors.New("registrypull: registry rate limit")
)

const (
	registryAuthBasic = registrymeta.AuthBasic
	registryAuthToken = registrymeta.AuthToken
)

var platformRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

// Options configures New.
type Options struct {
	// Registry is the administrator-approved registry record; its
	// Repositories are the pull scope.
	Registry registrymeta.PrivateRegistry
	// BlobHosts are exact lower-case HTTPS origins the registry may
	// redirect blob downloads to (for example an object storage
	// endpoint). No Authorization header is ever sent to them.
	BlobHosts []string
	// RootCAs, when non-nil, replaces the system roots. TLS is always
	// verified.
	RootCAs *x509.CertPool
	// TempDir holds the unlinked spool file of the layer being verified.
	// Empty means os.TempDir().
	TempDir string
	// Limits lowers the size ceilings.
	Limits Limits
	// BlobTimeout bounds one blob transfer. Zero means DefaultBlobTimeout.
	BlobTimeout time.Duration
	// AllowLoopback permits dialling loopback addresses. Test-only; HTTPS
	// stays required.
	AllowLoopback bool
}

// Puller pulls approved images from one registry. It is safe for
// concurrent use; each Pull has its own auth state.
type Puller struct {
	reg           registrymeta.PrivateRegistry
	registry      string // lower-case origin
	host          string // registry host[:port] for RepoTags
	realm         *url.URL
	blobHosts     []string
	roots         *x509.CertPool
	tempDir       string
	limits        Limits
	blobTimeout   time.Duration
	allowLoopback bool
	http          *http.Client
}

// New validates o and returns a Puller.
func New(o Options) (*Puller, error) {
	realm, err := o.Registry.Validate()
	if err != nil {
		return nil, fmt.Errorf("%w: registry record: %w", ErrInvalidOptions, err)
	}
	reg, err := parseOrigin(o.Registry.Registry)
	if err != nil {
		return nil, err
	}
	limits, err := o.Limits.resolve()
	if err != nil {
		return nil, err
	}
	if len(o.BlobHosts) > MaxBlobHosts {
		return nil, fmt.Errorf("%w: at most %d blob hosts", ErrInvalidOptions, MaxBlobHosts)
	}
	var hosts []string
	for _, h := range o.BlobHosts {
		if _, err := parseOrigin(h); err != nil {
			return nil, err
		}
		if h == o.Registry.Registry || slices.Contains(hosts, h) {
			return nil, fmt.Errorf("%w: duplicate blob host %q", ErrInvalidOptions, h)
		}
		if realm != nil && h == originOf(realm) {
			return nil, fmt.Errorf("%w: the token realm cannot be a blob host", ErrInvalidOptions)
		}
		hosts = append(hosts, h)
	}
	if o.BlobTimeout < 0 {
		return nil, fmt.Errorf("%w: negative blob timeout", ErrInvalidOptions)
	}
	timeout := o.BlobTimeout
	if timeout == 0 {
		timeout = DefaultBlobTimeout
	}
	tempDir := o.TempDir
	if tempDir == "" {
		tempDir = os.TempDir()
	}
	r := o.Registry
	r.Repositories = slices.Clone(r.Repositories)
	p := &Puller{
		reg:           r,
		registry:      o.Registry.Registry,
		host:          reg.Host,
		realm:         realm,
		blobHosts:     hosts,
		roots:         o.RootCAs,
		tempDir:       tempDir,
		limits:        limits,
		blobTimeout:   timeout,
		allowLoopback: o.AllowLoopback,
	}
	p.http = p.newHTTPClient()
	return p, nil
}

// Platform is the exact platform of the approved image.
type Platform struct {
	// OS is the operating system, for example "linux".
	OS string
	// Architecture is the CPU architecture, for example "amd64".
	Architecture string
	// Variant is the CPU variant, for example "v8"; it must match exactly,
	// including being empty.
	Variant string
}

// Request names the approved image of one pull.
type Request struct {
	// Repository is the repository path; it must be in the approved scope.
	Repository string
	// Digest is the approved immutable digest: an image index or an image
	// manifest.
	Digest string
	// Tag is the tag recorded in the archive's RepoTags and repositories.
	Tag string
	// Platform selects the manifest from an index and must match the image
	// configuration.
	Platform Platform
}

// Result describes a completed pull. It holds no credential or token.
type Result struct {
	// IndexDigest is the approved digest when it named an index, else empty.
	IndexDigest string
	// ManifestDigest is the platform image manifest digest.
	ManifestDigest string
	// ImageID is the image configuration digest.
	ImageID string
	// RepoTag is the reference recorded in the archive.
	RepoTag string
	// Layers is the number of layers in the manifest.
	Layers int
	// BlobBytes is the number of verified config and layer bytes written.
	BlobBytes int64
}

func (r Request) validate(p *Puller) (digest, error) {
	if !slices.Contains(p.reg.Repositories, r.Repository) {
		return digest{}, ErrOutOfScope
	}
	d, err := parseDigest(r.Digest)
	if err != nil {
		return digest{}, fmt.Errorf("%w: approved digest: %w", ErrInvalidRequest, err)
	}
	if !registrymeta.ValidTag(r.Tag) {
		return digest{}, fmt.Errorf("%w: invalid tag", ErrInvalidRequest)
	}
	for _, f := range []string{r.Platform.OS, r.Platform.Architecture, r.Platform.Variant} {
		if len(f) > MaxPlatformFieldLen || (f != "" && !platformRe.MatchString(f)) {
			return digest{}, fmt.Errorf("%w: invalid platform", ErrInvalidRequest)
		}
	}
	if r.Platform.OS == "" || r.Platform.Architecture == "" {
		return digest{}, fmt.Errorf("%w: platform needs os and architecture", ErrInvalidRequest)
	}
	return d, nil
}

// Pull fetches the approved image req with cred, verifies it and writes a
// docker-archive tar stream to w. On error the stream written so far lacks
// manifest.json and the tar trailer and must be discarded by the caller;
// it never contains unverified blob bytes.
func (p *Puller) Pull(ctx context.Context, cred registrymeta.Credential, req Request, w io.Writer) (Result, error) {
	top, err := req.validate(p)
	if err != nil {
		return Result{}, err
	}
	if err := cred.Validate(); err != nil {
		return Result{}, fmt.Errorf("%w: invalid credential shape", ErrCredentialRejected)
	}
	s := &session{p: p, repo: req.Repository, basic: basicAuth(cred.Username, cred.Secret)}
	defer s.clear()

	res := Result{RepoTag: p.host + "/" + req.Repository + ":" + req.Tag}
	man, err := p.resolveManifest(ctx, s, top, req.Platform, &res)
	if err != nil {
		return Result{}, err
	}
	res.Layers = len(man.Layers)
	cfgBytes, err := p.fetchConfig(ctx, s, *man.Config, req.Platform, len(man.Layers))
	if err != nil {
		return Result{}, err
	}
	cfgDigest, _ := parseDigest(man.Config.Digest)
	res.ImageID = cfgDigest.String()

	aw := newArchiveWriter(w)
	written := map[string]bool{}
	var layerPaths []string
	for i, l := range man.Layers {
		d, _ := parseDigest(l.Digest)
		layerPaths = append(layerPaths, d.path())
		if written[d.String()] {
			continue
		}
		if err := p.copyLayer(ctx, s, aw, d, l.Size, i); err != nil {
			return Result{}, err
		}
		written[d.String()] = true
		res.BlobBytes += l.Size
	}
	if err := aw.file(cfgDigest.path(), int64(len(cfgBytes)), bytes.NewReader(cfgBytes)); err != nil {
		return Result{}, err
	}
	res.BlobBytes += int64(len(cfgBytes))
	if err := aw.finish(cfgDigest, res.RepoTag, p.host+"/"+req.Repository, req.Tag, layerPaths); err != nil {
		return Result{}, err
	}
	return res, nil
}

// copyLayer spools layer i, verifies it and appends it to the archive.
func (p *Puller) copyLayer(ctx context.Context, s *session, aw *archiveWriter, d digest, size int64, i int) error {
	f, err := os.CreateTemp(p.tempDir, "nos-registrypull-*")
	if err != nil {
		return fmt.Errorf("registrypull: spool layer %d: %w", i, err)
	}
	// Unlink at once: the spool disappears with the descriptor, even on a
	// crash.
	rmErr := os.Remove(f.Name())
	defer f.Close()
	if rmErr != nil {
		return fmt.Errorf("registrypull: spool layer %d: %w", i, rmErr)
	}
	if err := p.fetchBlob(ctx, s, d, size, f, fmt.Sprintf("layer %d (%s)", i, d)); err != nil {
		return err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("registrypull: spool layer %d: %w", i, err)
	}
	return aw.file(d.path(), size, f)
}
