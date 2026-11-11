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

// archiveWriter writes the docker-archive tar stream: verified blobs under
// blobs/<alg>/<hex>, then manifest.json and repositories, then the trailer.
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

// finish writes manifest.json and repositories and closes the tar stream.
func (a *archiveWriter) finish(cfg digest, repoTag, repoName, tag string, layers []string) error {
	if layers == nil {
		layers = []string{}
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
