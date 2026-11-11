// SPDX-License-Identifier: AGPL-3.0-or-later

package registrypull

import (
	"fmt"
	"time"
)

// Hard ceilings of one pull. Limits may lower them, never raise them.
const (
	// MaxManifestBytes bounds an image index or image manifest body
	// (1 MiB, the ADR 0006 registry response limit).
	MaxManifestBytes = 1 << 20
	// MaxConfigBytes bounds the image configuration blob.
	MaxConfigBytes = 4 << 20
	// MaxBlobBytes bounds one layer blob. It is also the temporary disk
	// bound of a pull: one layer is spooled at a time.
	MaxBlobBytes int64 = 8 << 30
	// MaxTotalBytes bounds the sum of all blob sizes of one image.
	MaxTotalBytes int64 = 16 << 30
	// MaxLayers bounds the number of layers of one image manifest.
	MaxLayers = 128
)

// Fixed limits.
const (
	// MaxIndexEntries bounds the number of manifests in an image index.
	MaxIndexEntries = 256
	// MaxRedirects is the maximum number of redirects followed for one blob.
	MaxRedirects = 3
	// MaxBlobHosts bounds the configured blob redirect host allowlist.
	MaxBlobHosts = 8
	// MaxTokenResponseBytes bounds a token endpoint response body.
	MaxTokenResponseBytes = 64 << 10
	// MaxTokenLen bounds a bearer token.
	MaxTokenLen = 16 << 10
	// MaxChallengeLen bounds a WWW-Authenticate header.
	MaxChallengeLen = 4096
	// MaxPlatformFieldLen bounds the os, architecture and variant fields.
	MaxPlatformFieldLen = 64
	// DefaultBlobTimeout bounds the transfer of one blob when Options does
	// not set BlobTimeout.
	DefaultBlobTimeout = 30 * time.Minute
	// responseHeaderTimeout bounds the wait for response headers.
	responseHeaderTimeout = 30 * time.Second
	// tlsHandshakeTimeout bounds one TLS handshake.
	tlsHandshakeTimeout = 15 * time.Second
	// idleConnTimeout bounds how long an idle connection is kept.
	idleConnTimeout = 30 * time.Second
)

// Limits lowers the hard ceilings for one Puller. A zero field means the
// ceiling.
type Limits struct {
	// ManifestBytes bounds index and manifest bodies.
	ManifestBytes int64
	// ConfigBytes bounds the image configuration blob.
	ConfigBytes int64
	// BlobBytes bounds one layer blob.
	BlobBytes int64
	// TotalBytes bounds the sum of all blob sizes.
	TotalBytes int64
	// Layers bounds the layer count.
	Layers int
}

// resolve fills defaults and refuses values above the ceilings.
func (l Limits) resolve() (Limits, error) {
	set := func(v *int64, ceiling int64, name string) error {
		switch {
		case *v == 0:
			*v = ceiling
		case *v < 0 || *v > ceiling:
			return fmt.Errorf("%w: %s must be between 1 and %d", ErrInvalidOptions, name, ceiling)
		}
		return nil
	}
	if err := set(&l.ManifestBytes, MaxManifestBytes, "manifest limit"); err != nil {
		return Limits{}, err
	}
	if err := set(&l.ConfigBytes, MaxConfigBytes, "config limit"); err != nil {
		return Limits{}, err
	}
	if err := set(&l.BlobBytes, MaxBlobBytes, "blob limit"); err != nil {
		return Limits{}, err
	}
	if err := set(&l.TotalBytes, MaxTotalBytes, "total limit"); err != nil {
		return Limits{}, err
	}
	layers := int64(l.Layers)
	if err := set(&layers, MaxLayers, "layer limit"); err != nil {
		return Limits{}, err
	}
	l.Layers = int(layers)
	return l, nil
}
