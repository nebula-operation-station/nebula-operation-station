// SPDX-License-Identifier: AGPL-3.0-or-later

package registrypull

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"mime"
	"strings"
	"unicode/utf8"
)

// Media types.
const (
	mtOCIIndex       = "application/vnd.oci.image.index.v1+json"
	mtOCIManifest    = "application/vnd.oci.image.manifest.v1+json"
	mtDockerList     = "application/vnd.docker.distribution.manifest.list.v2+json"
	mtDockerManifest = "application/vnd.docker.distribution.manifest.v2+json"
	mtOCIConfig      = "application/vnd.oci.image.config.v1+json"
	mtDockerConfig   = "application/vnd.docker.container.image.v1+json"
)

// manifestAccept is the Accept header of manifest requests.
var manifestAccept = strings.Join([]string{mtOCIIndex, mtOCIManifest, mtDockerList, mtDockerManifest}, ", ")

// layerMediaTypes are the layer media types `docker load` can import.
// Non-distributable ("foreign") layers are refused.
var layerMediaTypes = map[string]bool{
	"application/vnd.oci.image.layer.v1.tar":            true,
	"application/vnd.oci.image.layer.v1.tar+gzip":       true,
	"application/vnd.oci.image.layer.v1.tar+zstd":       true,
	"application/vnd.docker.image.rootfs.diff.tar.gzip": true,
}

// digest is a validated sha256 or sha512 content digest.
type digest struct {
	alg string
	hex string
}

// parseDigest accepts "sha256:<64 lower hex>" or "sha512:<128 lower hex>".
func parseDigest(s string) (digest, error) {
	alg, h, ok := strings.Cut(s, ":")
	want := map[string]int{"sha256": 64, "sha512": 128}[alg]
	if !ok || want == 0 || len(h) != want {
		return digest{}, errors.New("unsupported or malformed digest")
	}
	for i := 0; i < len(h); i++ {
		if (h[i] < '0' || h[i] > '9') && (h[i] < 'a' || h[i] > 'f') {
			return digest{}, errors.New("malformed digest")
		}
	}
	return digest{alg: alg, hex: h}, nil
}

// String returns "alg:hex".
func (d digest) String() string { return d.alg + ":" + d.hex }

// path is the archive path of the blob.
func (d digest) path() string { return "blobs/" + d.alg + "/" + d.hex }

func (d digest) hasher() hash.Hash {
	if d.alg == "sha512" {
		return sha512.New()
	}
	return sha256.New()
}

// matches reports whether b has digest d.
func (d digest) matches(b []byte) bool {
	h := d.hasher()
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil)) == d.hex
}

// descriptor is an OCI content descriptor.
type descriptor struct {
	MediaType string    `json:"mediaType"`
	Digest    string    `json:"digest"`
	Size      int64     `json:"size"`
	URLs      []string  `json:"urls"`
	Platform  *platform `json:"platform"`
}

type platform struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Variant      string `json:"variant"`
}

func (pl platform) equal(want Platform) bool {
	return pl.OS == want.OS && pl.Architecture == want.Architecture && pl.Variant == want.Variant
}

// manifestDoc is an image index or image manifest.
type manifestDoc struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Config        *descriptor  `json:"config"`
	Layers        []descriptor `json:"layers"`
	Manifests     []descriptor `json:"manifests"`

	// verified is set by resolveManifest on the platform image manifest:
	// its body exactly as served (digest-verified), its media type and
	// digest. It feeds the archive's OCI layout byte for byte.
	verified ociManifest
}

// ociManifest is a verified image manifest as the archive's OCI layout
// stores it.
type ociManifest struct {
	body      []byte
	mediaType string
	digest    digest
}

// isIndexType and isManifestType classify media types.
func isIndexType(mt string) bool    { return mt == mtOCIIndex || mt == mtDockerList }
func isManifestType(mt string) bool { return mt == mtOCIManifest || mt == mtDockerManifest }

// fetchManifest fetches manifest d, bounded by the manifest limit and, when
// wantSize >= 0, required to be exactly wantSize bytes, and verifies its
// digest. It returns the body and the response media type.
func (p *Puller) fetchManifest(ctx context.Context, s *session, d digest, wantSize int64, what string) ([]byte, string, error) {
	resp, err := s.get(ctx, "manifests", d.String(), manifestAccept, what)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	max := p.limits.ManifestBytes
	if resp.ContentLength > max {
		return nil, "", fmt.Errorf("%w: %s is larger than %d bytes", ErrTooLarge, what, max)
	}
	if wantSize >= 0 && resp.ContentLength >= 0 && resp.ContentLength != wantSize {
		return nil, "", fmt.Errorf("%w: %s", ErrSizeMismatch, what)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, "", fmt.Errorf("%w: %s: %w", ErrSizeMismatch, what, cleanErr(err))
	}
	if int64(len(body)) > max {
		return nil, "", fmt.Errorf("%w: %s is larger than %d bytes", ErrTooLarge, what, max)
	}
	if wantSize >= 0 && int64(len(body)) != wantSize {
		return nil, "", fmt.Errorf("%w: %s", ErrSizeMismatch, what)
	}
	if !d.matches(body) {
		return nil, "", fmt.Errorf("%w: %s", ErrDigestMismatch, what)
	}
	ct, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	return body, ct, nil
}

// parseManifest decodes an index or manifest body and returns its media
// type. The body's mediaType wins; the Content-Type header is used only
// when the body has none (allowed for OCI).
func parseManifest(body []byte, ct, what string) (*manifestDoc, string, error) {
	if !utf8.Valid(body) {
		return nil, "", fmt.Errorf("%w: %s is not UTF-8", ErrBadResponse, what)
	}
	var doc manifestDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, "", fmt.Errorf("%w: %s is not valid JSON", ErrBadResponse, what)
	}
	if doc.SchemaVersion != 2 {
		return nil, "", fmt.Errorf("%w: %s: schema version %d", ErrUnsupported, what, doc.SchemaVersion)
	}
	mt := doc.MediaType
	if mt == "" {
		mt = ct
	}
	switch {
	case isIndexType(mt):
		if doc.Config != nil || len(doc.Layers) > 0 {
			return nil, "", fmt.Errorf("%w: %s is both index and manifest", ErrBadResponse, what)
		}
		if len(doc.Manifests) == 0 || len(doc.Manifests) > MaxIndexEntries {
			return nil, "", fmt.Errorf("%w: %s has 0 or more than %d entries", ErrBadResponse, what, MaxIndexEntries)
		}
	case isManifestType(mt):
		if doc.Config == nil || len(doc.Manifests) > 0 {
			return nil, "", fmt.Errorf("%w: %s is not an image manifest", ErrBadResponse, what)
		}
	default:
		return nil, "", fmt.Errorf("%w: %s has an unsupported media type", ErrUnsupported, what)
	}
	return &doc, mt, nil
}

// resolveManifest fetches the approved digest and, for an index, the one
// manifest of the requested platform, and validates the image manifest.
func (p *Puller) resolveManifest(ctx context.Context, s *session, top digest, want Platform, res *Result) (*manifestDoc, error) {
	body, ct, err := p.fetchManifest(ctx, s, top, -1, "approved manifest")
	if err != nil {
		return nil, err
	}
	doc, mt, err := parseManifest(body, ct, "approved manifest")
	if err != nil {
		return nil, err
	}
	res.ManifestDigest = top.String()
	md := top
	if isIndexType(mt) {
		entry, err := selectPlatform(doc.Manifests, want, p.limits.ManifestBytes)
		if err != nil {
			return nil, err
		}
		d, _ := parseDigest(entry.Digest)
		body, ct, err = p.fetchManifest(ctx, s, d, entry.Size, "platform manifest")
		if err != nil {
			return nil, err
		}
		doc, mt, err = parseManifest(body, ct, "platform manifest")
		if err != nil {
			return nil, err
		}
		if !isManifestType(mt) || mt != entry.MediaType {
			return nil, fmt.Errorf("%w: platform manifest media type differs from its index entry", ErrBadResponse)
		}
		res.IndexDigest = top.String()
		res.ManifestDigest = d.String()
		md = d
	}
	if err := p.validateImageManifest(doc); err != nil {
		return nil, err
	}
	doc.verified = ociManifest{body: body, mediaType: mt, digest: md}
	return doc, nil
}

// selectPlatform returns the single index entry of the requested platform.
func selectPlatform(entries []descriptor, want Platform, maxSize int64) (descriptor, error) {
	var found []descriptor
	for _, e := range entries {
		if e.Platform == nil || !e.Platform.equal(want) {
			continue
		}
		if !isManifestType(e.MediaType) {
			return descriptor{}, fmt.Errorf("%w: platform entry is not an image manifest", ErrUnsupported)
		}
		if _, err := parseDigest(e.Digest); err != nil {
			return descriptor{}, fmt.Errorf("%w: platform entry: %w", ErrBadResponse, err)
		}
		if e.Size <= 0 || e.Size > maxSize {
			return descriptor{}, fmt.Errorf("%w: platform manifest size %d", ErrTooLarge, e.Size)
		}
		if len(e.URLs) > 0 {
			return descriptor{}, fmt.Errorf("%w: platform entry has external URLs", ErrUnsupported)
		}
		found = append(found, e)
	}
	switch {
	case len(found) == 0:
		return descriptor{}, fmt.Errorf("%w: no manifest for the requested platform", ErrPlatform)
	case len(found) > 1:
		for _, e := range found[1:] {
			if e.Digest != found[0].Digest || e.Size != found[0].Size || e.MediaType != found[0].MediaType {
				return descriptor{}, fmt.Errorf("%w: several manifests for the requested platform", ErrPlatform)
			}
		}
	}
	return found[0], nil
}

// validateImageManifest checks the config and layer descriptors against
// the supported media types and size limits before any blob is fetched.
func (p *Puller) validateImageManifest(doc *manifestDoc) error {
	c := doc.Config
	if c.MediaType != mtOCIConfig && c.MediaType != mtDockerConfig {
		return fmt.Errorf("%w: config media type", ErrUnsupported)
	}
	if _, err := parseDigest(c.Digest); err != nil {
		return fmt.Errorf("%w: config: %w", ErrBadResponse, err)
	}
	if c.Size <= 0 || c.Size > p.limits.ConfigBytes {
		return fmt.Errorf("%w: config size %d", ErrTooLarge, c.Size)
	}
	if len(c.URLs) > 0 {
		return fmt.Errorf("%w: config has external URLs", ErrUnsupported)
	}
	if len(doc.Layers) > p.limits.Layers {
		return fmt.Errorf("%w: %d layers, at most %d", ErrTooLarge, len(doc.Layers), p.limits.Layers)
	}
	total := c.Size
	for i, l := range doc.Layers {
		if !layerMediaTypes[l.MediaType] {
			return fmt.Errorf("%w: layer %d media type", ErrUnsupported, i)
		}
		if len(l.URLs) > 0 {
			return fmt.Errorf("%w: layer %d has external URLs", ErrUnsupported, i)
		}
		if _, err := parseDigest(l.Digest); err != nil {
			return fmt.Errorf("%w: layer %d: %w", ErrBadResponse, i, err)
		}
		if l.Size <= 0 || l.Size > p.limits.BlobBytes {
			return fmt.Errorf("%w: layer %d size %d", ErrTooLarge, i, l.Size)
		}
		total += l.Size
		if total > p.limits.TotalBytes {
			return fmt.Errorf("%w: image is larger than %d bytes", ErrTooLarge, p.limits.TotalBytes)
		}
	}
	return nil
}

// fetchConfig fetches and verifies the image configuration and checks its
// platform and layer count.
func (p *Puller) fetchConfig(ctx context.Context, s *session, desc descriptor, want Platform, layers int) ([]byte, error) {
	d, _ := parseDigest(desc.Digest)
	var buf bytes.Buffer
	if err := p.fetchBlob(ctx, s, d, desc.Size, &buf, "image config"); err != nil {
		return nil, err
	}
	b := buf.Bytes()
	if !utf8.Valid(b) {
		return nil, fmt.Errorf("%w: image config is not UTF-8", ErrBadResponse)
	}
	var cfg struct {
		platform
		RootFS struct {
			Type    string   `json:"type"`
			DiffIDs []string `json:"diff_ids"`
		} `json:"rootfs"`
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("%w: image config is not valid JSON", ErrBadResponse)
	}
	if !cfg.platform.equal(want) {
		return nil, fmt.Errorf("%w: image config platform differs from the requested platform", ErrPlatform)
	}
	if cfg.RootFS.Type != "layers" || len(cfg.RootFS.DiffIDs) != layers {
		return nil, fmt.Errorf("%w: image config rootfs does not match the manifest layers", ErrBadResponse)
	}
	for _, id := range cfg.RootFS.DiffIDs {
		if _, err := parseDigest(id); err != nil {
			return nil, fmt.Errorf("%w: image config diff_id: %w", ErrBadResponse, err)
		}
	}
	return b, nil
}

// trackWriter records whether a write to the destination failed, so read
// and write failures are reported apart.
type trackWriter struct {
	w   io.Writer
	err error
}

func (t *trackWriter) Write(b []byte) (int, error) {
	n, err := t.w.Write(b)
	if err != nil {
		t.err = err
	}
	return n, err
}

// fetchBlob streams blob d of exactly size bytes into dst and verifies its
// digest. Memory use is the copy buffer; the caller bounds dst.
func (p *Puller) fetchBlob(ctx context.Context, s *session, d digest, size int64, dst io.Writer, what string) error {
	ctx, cancel := context.WithTimeout(ctx, p.blobTimeout)
	defer cancel()
	resp, err := s.get(ctx, "blobs", d.String(), "", what)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.ContentLength > size {
		return fmt.Errorf("%w: %s is larger than its descriptor", ErrSizeMismatch, what)
	}
	if resp.ContentLength >= 0 && resp.ContentLength != size {
		return fmt.Errorf("%w: %s length differs from its descriptor", ErrSizeMismatch, what)
	}
	h := d.hasher()
	tw := &trackWriter{w: dst}
	n, err := io.Copy(io.MultiWriter(tw, h), io.LimitReader(resp.Body, size+1))
	if tw.err != nil {
		return fmt.Errorf("registrypull: spool %s: %w", what, tw.err)
	}
	if err != nil {
		return fmt.Errorf("%w: %s: stream ended after %d of %d bytes: %w", ErrSizeMismatch, what, n, size, cleanErr(err))
	}
	if n != size {
		return fmt.Errorf("%w: %s: got %d bytes, want %d", ErrSizeMismatch, what, n, size)
	}
	if hex.EncodeToString(h.Sum(nil)) != d.hex {
		return fmt.Errorf("%w: %s", ErrDigestMismatch, what)
	}
	return nil
}
