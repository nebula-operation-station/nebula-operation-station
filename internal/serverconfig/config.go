// SPDX-License-Identifier: AGPL-3.0-or-later

// Package serverconfig loads and validates the nebula-server configuration
// from a JSON file, with command-line flags that override the file, and
// provides a structured JSON logger that never logs secrets.
package serverconfig

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// redacted is what a Token prints in every formatting, logging, and
// serialization context.
const redacted = "[redacted]"

// Token is the server's secret token. It is a dedicated type so that no
// formatting, logging, or serialization path can print the value: String,
// GoString, Format, MarshalJSON, and slog's LogValue all print
// "[redacted]".
type Token string

// String always redacts the token.
func (t Token) String() string { return redacted }

// GoString always redacts the token.
func (t Token) GoString() string { return redacted }

// Format always redacts the token, for every verb.
func (t Token) Format(s fmt.State, verb rune) {
	switch verb {
	case 'v':
		if s.Flag('#') {
			fmt.Fprint(s, "serverconfig.Token("+redacted+")")
			return
		}
		fmt.Fprint(s, redacted)
	case 's':
		fmt.Fprint(s, redacted)
	case 'q':
		fmt.Fprint(s, `"`+redacted+`"`)
	default:
		fmt.Fprintf(s, "%%!%c(serverconfig.Token)", verb)
	}
}

// MarshalJSON redacts the token so it never appears in serialized output.
func (t Token) MarshalJSON() ([]byte, error) {
	return []byte(`"` + redacted + `"`), nil
}

// LogValue implements slog.LogValuer and always redacts the token.
func (t Token) LogValue() slog.Value {
	return slog.StringValue(redacted)
}

// DefaultListen is the default listen address.
const DefaultListen = "127.0.0.1:8080"

// Config is the nebula-server configuration.
type Config struct {
	// Listen is the address to listen on. Default "127.0.0.1:8080".
	Listen string `json:"listen"`
	// AllowRemoteListen permits a non-loopback listen address.
	AllowRemoteListen bool `json:"allow_remote_listen"`
	// PublicOrigin is the https origin the browser uses, e.g.
	// "https://nebula.example.org". It must be lowercase: browsers send
	// the Origin header lowercased and the middleware compares exactly.
	PublicOrigin string `json:"public_origin"`
	// DataDir is where the server stores its data.
	DataDir string `json:"data_dir"`
	// ExecutorSocket is the path to the executor's unix socket.
	ExecutorSocket string `json:"executor_socket"`
	// ExecutorUser is the OS user the executor runs as.
	ExecutorUser string `json:"executor_user"`
	// Token is the server's secret token. The Token type redacts the
	// value in every formatting, logging, and serialization path.
	Token Token `json:"token"`
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
// Unknown keys and trailing data after the JSON object are errors.
func Parse(data []byte) (Config, error) {
	cfg, err := decode(data)
	if err != nil {
		return Config{}, err
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// decode parses the JSON config. Unknown keys and any trailing data after
// the JSON object are errors.
func decode(data []byte) (Config, error) {
	var cfg Config
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("serverconfig: parse: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return Config{}, fmt.Errorf("serverconfig: parse: trailing data after JSON object")
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
		if strings.ToLower(c.PublicOrigin) != c.PublicOrigin {
			problems = append(problems, fmt.Sprintf("public_origin: %q must be lowercase (browsers send the Origin header lowercased and the middleware compares exactly)", c.PublicOrigin))
		} else {
			problems = append(problems, fmt.Sprintf("public_origin: %q must be a bare https origin (scheme, host, optional port)", c.PublicOrigin))
		}
	}

	if c.DataDir == "" {
		problems = append(problems, "data_dir: required")
	} else if !filepath.IsAbs(c.DataDir) {
		problems = append(problems, fmt.Sprintf("data_dir: %q must be an absolute path", c.DataDir))
	}
	if c.ExecutorSocket == "" {
		problems = append(problems, "executor_socket: required")
	} else if !filepath.IsAbs(c.ExecutorSocket) {
		problems = append(problems, fmt.Sprintf("executor_socket: %q must be an absolute path", c.ExecutorSocket))
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

// isValidHTTPSOrigin reports whether s is a bare https origin: scheme
// https, a host, and an optional port — with no path (not even "/"),
// query, fragment, userinfo, or uppercase character (browsers send the
// Origin header with a lowercase scheme and host and the middleware
// compares exactly).
func isValidHTTPSOrigin(s string) bool {
	if s == "" {
		return false
	}
	// A bare origin never contains a query or fragment delimiter, not
	// even with an empty query or fragment ("https://n.example?").
	if strings.ContainsAny(s, "?#") {
		return false
	}
	// url.Parse lowercases the scheme, so "HTTPS://..." would pass a
	// u.Scheme check; require the literal lowercase prefix.
	if !strings.HasPrefix(s, "https://") {
		return false
	}
	// Browsers send the Origin header lowercased and the middleware
	// compares exactly, so any uppercase character is invalid.
	if strings.ToLower(s) != s {
		return false
	}
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	return u.Scheme == "https" && u.Host != "" && u.User == nil && u.Path == ""
}
