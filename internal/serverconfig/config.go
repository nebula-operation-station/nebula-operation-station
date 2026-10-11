// SPDX-License-Identifier: AGPL-3.0-or-later

// Package serverconfig loads and validates the nebula-server configuration
// from a JSON file, and provides a structured JSON logger that never logs
// secrets.
package serverconfig

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
)

// DefaultListen is the default listen address.
const DefaultListen = "127.0.0.1:8080"

// Config is the nebula-server configuration.
type Config struct {
	// Listen is the address to listen on. Default "127.0.0.1:8080".
	Listen string `json:"listen"`
	// AllowRemoteListen permits a non-loopback listen address.
	AllowRemoteListen bool `json:"allow_remote_listen"`
	// PublicOrigin is the https URL the browser uses, e.g.
	// "https://nebula.example.org".
	PublicOrigin string `json:"public_origin"`
	// DataDir is where the server stores its data.
	DataDir string `json:"data_dir"`
	// ExecutorSocket is the path to the executor's unix socket.
	ExecutorSocket string `json:"executor_socket"`
	// ExecutorUser is the OS user the executor runs as.
	ExecutorUser string `json:"executor_user"`
	// Token is a secret. It must never be logged; use LogAttrs or
	// NewLogger to log the configuration.
	Token string `json:"token"`
}

// Load reads the config from path, applies defaults, and validates it.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("serverconfig: read %s: %w", path, err)
	}
	return Parse(data)
}

// Parse parses the JSON config, applies defaults, and validates it.
// Unknown keys are an error.
func Parse(data []byte) (Config, error) {
	var cfg Config
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("serverconfig: parse: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Listen == "" {
		c.Listen = DefaultListen
	}
}

// Validate checks the configuration and returns a single error listing
// every problem found, or nil if the config is valid.
func (c Config) Validate() error {
	var problems []string

	if c.Listen == "" {
		problems = append(problems, "listen: required")
	} else {
		host, _, err := net.SplitHostPort(c.Listen)
		if err != nil {
			problems = append(problems, fmt.Sprintf("listen: %q is not a valid host:port: %v", c.Listen, err))
		} else if !isLoopback(host) && !c.AllowRemoteListen {
			problems = append(problems, fmt.Sprintf("listen: non-loopback address %q requires allow_remote_listen", host))
		}
	}

	if !isValidHTTPSOrigin(c.PublicOrigin) {
		problems = append(problems, fmt.Sprintf("public_origin: %q must be an https URL", c.PublicOrigin))
	}

	if c.DataDir == "" {
		problems = append(problems, "data_dir: required")
	}
	if c.ExecutorSocket == "" {
		problems = append(problems, "executor_socket: required")
	}
	if c.ExecutorUser == "" {
		problems = append(problems, "executor_user: required")
	}

	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("serverconfig: invalid config: %s", strings.Join(problems, "; "))
}

// isLoopback reports whether host names a loopback address. Only explicit
// loopback IPs and the literal "localhost" are treated as loopback; any
// other hostname is treated as non-loopback (no DNS resolution).
func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// isValidHTTPSOrigin reports whether s is a well-formed https URL with a
// host.
func isValidHTTPSOrigin(s string) bool {
	if s == "" {
		return false
	}
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	return u.Scheme == "https" && u.Host != ""
}
