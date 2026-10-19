// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/modulelock"
	"github.com/nebula-operation-station/nebula-operation-station/internal/prelude"
)

// Module authoring (spec 10): module.yaml is the author's file; `nebula
// module pack DIR` turns it into the canonical lock (module.lock.json),
// which the author signs with
//
//	ssh-keygen -Y sign -f KEY -n nebula-module DIR/module.lock.json
//
// and `nebula module pack --archive OUT.tar.gz DIR` puts lock, signature
// and scripts into the archive the web UI imports. The executor only ever
// reads the lock, never YAML.

type yamlParam struct {
	Type    string   `yaml:"type"`
	Label   string   `yaml:"label"`
	Choices []string `yaml:"choices"`
}

type yamlAction struct {
	Title       string               `yaml:"title"`
	Description string               `yaml:"description"`
	Script      string               `yaml:"script"`
	Risk        string               `yaml:"risk"`
	Durable     bool                 `yaml:"durable"`
	Timeout     string               `yaml:"timeout"`
	Params      map[string]yamlParam `yaml:"params"`
	Secrets     []string             `yaml:"secrets"`
	Declares    []string             `yaml:"declares"`
}

type yamlModule struct {
	Name        string                `yaml:"name"`
	Version     string                `yaml:"version"`
	Title       string                `yaml:"title"`
	Description string                `yaml:"description"`
	Actions     map[string]yamlAction `yaml:"actions"`
	UI          *yamlUI               `yaml:"ui"`
}

type yamlUI struct {
	HostTab *struct {
		Title string `yaml:"title"`
		Cards []struct {
			Title  string `yaml:"title"`
			Action string `yaml:"action"`
			Fields []struct {
				Label string `yaml:"label"`
				Path  string `yaml:"path"`
			} `yaml:"fields"`
		} `yaml:"cards"`
	} `yaml:"host_tab"`
}

const maxYAML = 256 << 10

// packLock reads DIR/module.yaml and the scripts and returns the lock's
// canonical bytes.
func packLock(dir string) ([]byte, error) {
	b, err := readModuleFile(dir, "module.yaml", maxYAML)
	if err != nil {
		return nil, err
	}
	var m yamlModule
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("module.yaml: %w", err)
	}
	l := modulelock.Lock{Format: modulelock.Format, Name: m.Name, Version: m.Version, Title: m.Title, Description: m.Description,
		Actions: map[string]modulelock.Action{}}
	for name, a := range m.Actions {
		t, err := time.ParseDuration(a.Timeout)
		if err != nil || t%time.Second != 0 {
			return nil, fmt.Errorf("action %s: timeout must be whole seconds such as 300s", name)
		}
		script, err := readScript(dir, a.Script)
		if err != nil {
			return nil, fmt.Errorf("action %s: %w", name, err)
		}
		sum := sha256.Sum256(script)
		la := modulelock.Action{Title: a.Title, Description: a.Description, Script: a.Script, SHA256: hex.EncodeToString(sum[:]),
			Risk: strings.ToUpper(a.Risk), Durable: a.Durable, TimeoutS: int(t / time.Second),
			Params: []prelude.Param{}, Secrets: nonNil(a.Secrets), Declares: nonNil(a.Declares)}
		names := make([]string, 0, len(a.Params))
		for n := range a.Params {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			p := a.Params[n]
			la.Params = append(la.Params, prelude.Param{Name: n, Label: p.Label, Type: p.Type, Choices: p.Choices})
		}
		l.Actions[name] = la
	}
	if m.UI != nil && m.UI.HostTab != nil {
		t := &modulelock.HostTab{Title: m.UI.HostTab.Title, Cards: []modulelock.Card{}}
		for _, c := range m.UI.HostTab.Cards {
			card := modulelock.Card{Title: c.Title, Action: c.Action, Fields: []modulelock.Field{}}
			for _, f := range c.Fields {
				card.Fields = append(card.Fields, modulelock.Field{Label: f.Label, Path: f.Path})
			}
			t.Cards = append(t.Cards, card)
		}
		l.UI = &modulelock.UI{HostTab: t}
	}
	raw, err := json.Marshal(l)
	if err != nil {
		return nil, err
	}
	c, _, err := canonical.CanonicalParameters(raw)
	if err != nil {
		return nil, err
	}
	if _, _, err := modulelock.Parse(c); err != nil {
		return nil, err
	}
	return c, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// readModuleFile reads DIR/rel, at most limit bytes, refusing anything
// that is not a regular file inside DIR: no symlink (also not in a parent
// directory) may lead the author to pack and sign a file from elsewhere.
func readModuleFile(dir, rel string, limit int64) ([]byte, error) {
	if rel == "" || filepath.IsAbs(rel) || strings.Contains(rel, "..") {
		return nil, fmt.Errorf("%q must be a relative path inside the module", rel)
	}
	root, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, err
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	p := filepath.Join(root, filepath.FromSlash(rel))
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return nil, err
	}
	if real != p {
		return nil, fmt.Errorf("%s is or passes through a symbolic link; module files must be regular files inside the module", rel)
	}
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", rel)
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is larger than %d KiB", rel, limit>>10)
	}
	return b, nil
}

func readScript(dir, rel string) ([]byte, error) {
	return readModuleFile(dir, rel, modulelock.MaxScript)
}

func modulePack(args []string, w io.Writer) error {
	archive := ""
	if len(args) == 3 && args[0] == "--archive" {
		archive, args = args[1], args[2:]
	}
	if len(args) != 1 {
		return errors.New("usage: nebula module pack [--archive OUT.tar.gz] DIR")
	}
	dir := args[0]
	if archive == "" {
		lock, err := packLock(dir)
		if err != nil {
			return err
		}
		p := filepath.Join(dir, "module.lock.json")
		if err := os.WriteFile(p, lock, 0o644); err != nil {
			return err
		}
		fmt.Fprintf(w, "wrote %s\nsign it with:\n  ssh-keygen -Y sign -f KEY -n %s %s\nthen run: nebula module pack --archive OUT.tar.gz %s\n",
			p, modulelock.Namespace, p, dir)
		return nil
	}
	lock, err := readModuleFile(dir, "module.lock.json", maxYAML)
	if err != nil {
		return err
	}
	l, _, err := modulelock.Parse(lock)
	if err != nil {
		return err
	}
	// The lock must still be what module.yaml and the scripts give.
	if again, err := packLock(dir); err != nil || !bytes.Equal(again, lock) {
		return errors.New("module.lock.json is out of date: run nebula module pack DIR and sign again")
	}
	files := map[string][]byte{"module.lock.json": lock}
	if sig, err := readModuleFile(dir, "module.lock.json.sig", 8<<10); err == nil {
		files["module.lock.json.sig"] = sig
	} else {
		fmt.Fprintln(w, "note: no module.lock.json.sig; the module will be unverified (its actions run at least HIGH)")
	}
	for _, name := range l.Names() {
		a := l.Actions[name]
		b, err := readScript(dir, a.Script)
		if err != nil {
			return err
		}
		files[a.Script] = b
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if err := tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(files[n])), Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		if _, err := tw.Write(files[n]); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	if err := os.WriteFile(archive, buf.Bytes(), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(w, "wrote %s (%s %s, %d actions)\n", archive, l.Name, l.Version, len(l.Actions))
	return nil
}
