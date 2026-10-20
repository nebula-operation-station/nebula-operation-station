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
	"regexp"
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

// DefaultDiscoveryDir is the default discovery spool.
const DefaultDiscoveryDir = "/var/lib/nebula/discovery"

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
	// DiscoveryDir is the discovery spool (jobs/ and results/) shared
	// with nebula-discovery. Default "/var/lib/nebula/discovery"; without
	// it discovery shows as not installed.
	DiscoveryDir string `json:"discovery_dir"`
	// AuditHashChain links each stored server audit line to the one
	// before by hash (M10-1); off by default. The executor's own events are
	// always signed and chained.
	AuditHashChain bool `json:"audit_hash_chain"`
	// Notifications configures the providers (spec 13). Their tokens are
	// low-privilege and live here, not in the executor vault; a config
	// with any of them must not be readable by others.
	Notifications Notifications `json:"notifications"`
	// API configures the read-only API (spec 13); disabled by default.
	API APIConfig `json:"api"`
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
	cfg, err := Parse(data)
	if err != nil {
		return Config{}, err
	}
	if err := checkSecretFileMode(path, cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
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
	if c.DiscoveryDir == "" {
		c.DiscoveryDir = DefaultDiscoveryDir
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
	if c.DiscoveryDir != "" && !filepath.IsAbs(c.DiscoveryDir) {
		problems = append(problems, fmt.Sprintf("discovery_dir: %q must be an absolute path", c.DiscoveryDir))
	}

	problems = append(problems, c.Notifications.problems()...)
	problems = append(problems, c.API.Problems()...)

	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("serverconfig: invalid config: %s", strings.Join(problems, "; "))
}

// isLoopback reports whether host names a loopback address. Only explicit
// loopback IPs and the literal "localhost" are treated as loopback; any
// other hostname is treated as non-loopback (no DNS resolution).
// Notifications are the notification providers. Each is optional.
type Notifications struct {
	Webhook  *WebhookConfig  `json:"webhook,omitempty"`
	Ntfy     *NtfyConfig     `json:"ntfy,omitempty"`
	Telegram *TelegramConfig `json:"telegram,omitempty"`
}

// WebhookConfig sends JSON, HMAC-SHA256 signed with Secret.
type WebhookConfig struct {
	URL    string `json:"url"`
	Secret Token  `json:"secret"`
}

// NtfyConfig publishes to Topic on the ntfy server URL, with an optional
// access token.
type NtfyConfig struct {
	URL   string `json:"url"`
	Topic string `json:"topic"`
	Token Token  `json:"token,omitempty"`
}

// TelegramConfig sends through a bot to one chat.
type TelegramConfig struct {
	BotToken Token  `json:"bot_token"`
	ChatID   string `json:"chat_id"`
}

// HasSecrets reports whether any provider carries a token or secret.
func (n Notifications) HasSecrets() bool {
	return (n.Webhook != nil && n.Webhook.Secret != "") || (n.Ntfy != nil && n.Ntfy.Token != "") ||
		(n.Telegram != nil && n.Telegram.BotToken != "")
}

var (
	ntfyTopicRe  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	chatIDRe     = regexp.MustCompile(`^(-?[0-9]{1,20}|@[A-Za-z0-9_]{5,32})$`)
	botTokenRe   = regexp.MustCompile(`^[0-9]{1,20}:[A-Za-z0-9_-]{20,64}$`)
	minSecretLen = 32
)

func (n Notifications) problems() []string {
	var p []string
	if w := n.Webhook; w != nil {
		if !isHTTPURL(w.URL) {
			p = append(p, "notifications.webhook.url: must be an absolute http(s) URL without credentials")
		}
		if len(w.Secret) < minSecretLen {
			p = append(p, fmt.Sprintf("notifications.webhook.secret: at least %d characters", minSecretLen))
		}
	}
	if t := n.Ntfy; t != nil {
		if !isHTTPURL(t.URL) {
			p = append(p, "notifications.ntfy.url: must be an absolute http(s) URL without credentials")
		}
		if !ntfyTopicRe.MatchString(t.Topic) {
			p = append(p, "notifications.ntfy.topic: 1-64 characters A-Z, a-z, 0-9, '_' or '-'")
		}
	}
	if t := n.Telegram; t != nil {
		if !botTokenRe.MatchString(string(t.BotToken)) {
			p = append(p, "notifications.telegram.bot_token: not a bot token (digits:characters)")
		}
		if !chatIDRe.MatchString(t.ChatID) {
			p = append(p, "notifications.telegram.chat_id: a numeric chat ID or @channelname")
		}
	}
	return p
}

func isHTTPURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.User == nil && u.Fragment == ""
}

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

// API scopes (spec 13).
const (
	ScopeInventoryRead     = "inventory.read"
	ScopeOperationsRead    = "operations.read"
	ScopeExecutionLogsRead = "execution_logs.read"
)

// APIConfig configures the read-only API under /api/v1 (spec 13). It is
// disabled by default; when enabled, every request needs a token.
type APIConfig struct {
	Enabled bool       `json:"enabled"`
	Tokens  []APIToken `json:"tokens,omitempty"`
}

// APIToken is one API token. Only the SHA-256 of the token is stored, so
// the configuration does not contain the token itself.
type APIToken struct {
	// Name identifies the token in the audit log.
	Name string `json:"name"`
	// SHA256 is the lowercase hex SHA-256 of the token string.
	SHA256 string   `json:"sha256"`
	Scopes []string `json:"scopes"`
}

var (
	apiTokenNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	apiHashRe      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	apiScopes      = map[string]bool{ScopeInventoryRead: true, ScopeOperationsRead: true, ScopeExecutionLogsRead: true}
)

// ValidAPIScope reports whether s is a known API scope.
func ValidAPIScope(s string) bool { return apiScopes[s] }

// Problems lists what is wrong with the API configuration.
func (a APIConfig) Problems() []string {
	var out []string
	if a.Enabled && len(a.Tokens) == 0 {
		out = append(out, "api: enabled needs at least one token")
	}
	names, hashes := map[string]bool{}, map[string]bool{}
	for i, t := range a.Tokens {
		if !apiTokenNameRe.MatchString(t.Name) {
			out = append(out, fmt.Sprintf("api.tokens[%d].name: %q must match %s", i, t.Name, apiTokenNameRe))
		} else if names[t.Name] {
			out = append(out, fmt.Sprintf("api.tokens[%d].name: %q is used twice", i, t.Name))
		}
		names[t.Name] = true
		if !apiHashRe.MatchString(t.SHA256) {
			out = append(out, fmt.Sprintf("api.tokens[%d].sha256: must be 64 lowercase hex digits (nebula-server -api-token prints it)", i))
		} else if hashes[t.SHA256] {
			out = append(out, fmt.Sprintf("api.tokens[%d].sha256: the same token is listed twice", i))
		}
		hashes[t.SHA256] = true
		if len(t.Scopes) == 0 {
			out = append(out, fmt.Sprintf("api.tokens[%d].scopes: at least one scope", i))
		}
		seen := map[string]bool{}
		for _, s := range t.Scopes {
			if !apiScopes[s] {
				out = append(out, fmt.Sprintf("api.tokens[%d].scopes: unknown scope %q", i, s))
			} else if seen[s] {
				out = append(out, fmt.Sprintf("api.tokens[%d].scopes: %q listed twice", i, s))
			}
			seen[s] = true
		}
	}
	return out
}
