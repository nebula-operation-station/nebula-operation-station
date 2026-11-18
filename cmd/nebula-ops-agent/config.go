// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// MaxConfigBytes bounds the agent's config file.
const MaxConfigBytes = 16 << 10

// Config is the agent's own configuration, written by the admin and read
// only by the agent's user. It holds paths and the NOS address; the LLM
// settings come from the NOS server (ADR 0016 D12).
type Config struct {
	// NOSBaseURL is the NOS API base, https, or http to a loopback address.
	NOSBaseURL string `json:"nos_base_url"`
	// NOSTokenFile holds the agent's exclusive API token.
	NOSTokenFile string `json:"nos_token_file"`
	// NOSCAFile is an optional pinned CA for the NOS server certificate.
	NOSCAFile string `json:"nos_ca_file,omitempty"`
	// StateDir holds the run-state file. It must be an absolute path.
	StateDir string `json:"state_dir"`
	// LLMCredentialFile is the optional bearer token of the LLM endpoint.
	LLMCredentialFile string `json:"llm_credential_file,omitempty"`
}

// LoadConfig reads and checks the config file. Unknown fields and trailing
// data are refused. Errors name the file, never its content.
func LoadConfig(path string) (Config, error) {
	if path == "" || !filepath.IsAbs(path) {
		return Config{}, errors.New("config: an absolute -config path is required")
	}
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("config %s: %w", path, err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, MaxConfigBytes+1))
	if err != nil {
		return Config{}, fmt.Errorf("config %s: %w", path, err)
	}
	if len(raw) > MaxConfigBytes {
		return Config{}, fmt.Errorf("config %s: too large", path)
	}
	var c Config
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("config %s: invalid", path)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("config %s: trailing data", path)
	}
	if err := c.check(); err != nil {
		return Config{}, fmt.Errorf("config %s: %w", path, err)
	}
	return c, nil
}

func (c Config) check() error {
	for name, p := range map[string]string{
		"nos_token_file": c.NOSTokenFile, "state_dir": c.StateDir,
	} {
		if !filepath.IsAbs(p) {
			return fmt.Errorf("%s must be an absolute path", name)
		}
	}
	for name, p := range map[string]string{"nos_ca_file": c.NOSCAFile, "llm_credential_file": c.LLMCredentialFile} {
		if p != "" && !filepath.IsAbs(p) {
			return fmt.Errorf("%s must be an absolute path", name)
		}
	}
	if c.NOSBaseURL == "" {
		return errors.New("nos_base_url is required")
	}
	return nil
}
