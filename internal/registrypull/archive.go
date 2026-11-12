// SPDX-License-Identifier: AGPL-3.0-or-later

package registrypull

import (
	"archive/tar"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"time"
)

// archiveWriter writes the image tar stream: verified blobs under
// blobs/<alg>/<hex>, then the verified platform manifest blob,
// manifest.json, repositories, oci-layout and index.json, then the trailer.
type archiveWriter struct {
	tw   *tar.Writer
	dirs map[string]bool
}

func newArchiveWriter(w io.Writer) *archiveWriter {
	return &archiveWriter{tw: tar.NewWriter(w), dirs: map[string]bool{}}
}

// epoch is the fixed modification time of every entry.
var epoch = time.Unix(0, 0).UTC()

// dir writes the parent directories of name once.
func (a *archiveWriter) dir(name string) error {
	d := path.Dir(name)
	if d == "." || a.dirs[d] {
		return nil
	}
	if err := a.dir(d); err != nil {
		return err
	}
	a.dirs[d] = true
	if err := a.tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: d + "/", Mode: 0o755, ModTime: epoch}); err != nil {
		return fmt.Errorf("registrypull: write archive: %w", err)
	}
	return nil
}

// file writes one regular file of exactly size bytes from r.
func (a *archiveWriter) file(name string, size int64, r io.Reader) error {
	if err := a.dir(name); err != nil {
		return err
	}
	if err := a.tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: name, Size: size, Mode: 0o644, ModTime: epoch}); err != nil {
		return fmt.Errorf("registrypull: write archive: %w", err)
	}
	if _, err := io.CopyN(a.tw, r, size); err != nil {
		return fmt.Errorf("registrypull: write archive %s: %w", name, err)
	}
	return nil
}

// archiveManifest is one entry of docker-archive manifest.json.
type archiveManifest struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

// OCI image layout entries (image-spec v1.1 image-layout).
const (
	ociLayoutVersion = "1.0.0"
	// annotationImageName is containerd's image name annotation; a
	// containerd-store `docker load` names the image after it.
	annotationImageName = "io.containerd.image.name"
	// annotationRefName is the OCI reference name annotation (the tag).
	annotationRefName = "org.opencontainers.image.ref.name"
)

// ociIndexEntry is the one index.json descriptor: the verified platform
// manifest with its platform and names.
type ociIndexEntry struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Platform    ociPlatform       `json:"platform"`
	Annotations map[string]string `json:"annotations"`
}

type ociPlatform struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Variant      string `json:"variant,omitempty"`
}

type ociIndex struct {
	SchemaVersion int             `json:"schemaVersion"`
	MediaType     string          `json:"mediaType"`
	Manifests     []ociIndexEntry `json:"manifests"`
}

// finish writes the verified platform manifest blob, manifest.json,
// repositories, oci-layout and index.json, and closes the tar stream.
//
// The archive is both a docker-archive (manifest.json, read by the classic
// image store) and an OCI image layout (oci-layout and index.json, read by
// the containerd image store), as `docker save` writes it. The layout
// names the registry's own manifest bytes, so a containerd import keeps
// the registry manifest digest as the image target; from manifest.json
// alone it would generate a manifest with another digest.
func (a *archiveWriter) finish(cfg digest, repoTag, repoName, tag string, layers []string, om ociManifest, pl Platform, written map[string]bool) error {
	if layers == nil {
		layers = []string{}
	}
	// The manifest blob is written once, like a duplicate layer.
	if !written[om.digest.String()] {
		if err := a.dir(om.digest.path()); err != nil {
			return err
		}
		if err := a.bytes(om.digest.path(), om.body); err != nil {
			return err
		}
	}
	idx, err := json.Marshal(ociIndex{SchemaVersion: 2, MediaType: mtOCIIndex, Manifests: []ociIndexEntry{{
		MediaType: om.mediaType, Digest: om.digest.String(), Size: int64(len(om.body)),
		Platform:    ociPlatform{Architecture: pl.Architecture, OS: pl.OS, Variant: pl.Variant},
		Annotations: map[string]string{annotationImageName: repoTag, annotationRefName: tag},
	}}})
	if err != nil {
		return fmt.Errorf("registrypull: encode index.json: %w", err)
	}
	man, err := json.Marshal([]archiveManifest{{Config: cfg.path(), RepoTags: []string{repoTag}, Layers: layers}})
	if err != nil {
		return fmt.Errorf("registrypull: encode manifest.json: %w", err)
	}
	repos, err := json.Marshal(map[string]map[string]string{repoName: {tag: cfg.hex}})
	if err != nil {
		return fmt.Errorf("registrypull: encode repositories: %w", err)
	}
	if err := a.bytes("manifest.json", man); err != nil {
		return err
	}
	if err := a.bytes("repositories", repos); err != nil {
		return err
	}
	if err := a.bytes("oci-layout", []byte(`{"imageLayoutVersion":"`+ociLayoutVersion+`"}`)); err != nil {
		return err
	}
	if err := a.bytes("index.json", idx); err != nil {
		return err
	}
	if err := a.tw.Close(); err != nil {
		return fmt.Errorf("registrypull: write archive: %w", err)
	}
	return nil
}

func (a *archiveWriter) bytes(name string, b []byte) error {
	if err := a.tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: name, Size: int64(len(b)), Mode: 0o644, ModTime: epoch}); err != nil {
		return fmt.Errorf("registrypull: write archive: %w", err)
	}
	if _, err := a.tw.Write(b); err != nil {
		return fmt.Errorf("registrypull: write archive %s: %w", name, err)
	}
	return nil
}
