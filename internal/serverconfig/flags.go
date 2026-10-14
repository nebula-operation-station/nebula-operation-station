// SPDX-License-Identifier: AGPL-3.0-or-later

package serverconfig

import (
	"flag"
	"fmt"
	"os"
)

// RegisterFlags registers a flag on fs for every Config field except
// Token, using the field's zero value as the default. Call it before
// fs.Parse.
//
// The token has no flag on purpose: a secret on the command line is
// visible in ps and /proc. It comes from the config file only.
//
// The flags override the file: LoadWithFlags applies only the flags the
// user explicitly set, so an unset flag leaves the file value (or the
// built-in default) in place.
//
// Note: allow_remote_listen is a bool flag. A bare bool flag does not
// consume a value argument, so callers must use the -allow_remote_listen
// or -allow_remote_listen=true form, not "-allow_remote_listen true"
// (the "true" would be a positional argument and stop flag parsing).
func RegisterFlags(fs *flag.FlagSet) {
	var zero Config
	fs.StringVar(&zero.Listen, "listen", zero.Listen, "listen address (host:port)")
	fs.BoolVar(&zero.AllowRemoteListen, "allow_remote_listen", zero.AllowRemoteListen, "permit a non-loopback listen address")
	fs.StringVar(&zero.PublicOrigin, "public_origin", zero.PublicOrigin, "public origin (bare lowercase https origin, e.g. https://nebula.example.org)")
	fs.StringVar(&zero.DataDir, "data_dir", zero.DataDir, "data directory (absolute path)")
	fs.StringVar(&zero.ExecutorSocket, "executor_socket", zero.ExecutorSocket, "executor unix socket path (absolute path)")
	fs.StringVar(&zero.ExecutorUser, "executor_user", zero.ExecutorUser, "executor OS user")
}

// LoadWithFlags reads the config from path, applies every flag that was
// explicitly set on fs, applies the built-in defaults, and validates once.
// Unknown JSON keys and trailing data after the JSON object are errors.
// A file value that fails validation can be fixed by a flag, because
// validation runs only after the flags are applied.
//
// RegisterFlags must have been called on fs before fs.Parse.
func LoadWithFlags(path string, fs *flag.FlagSet) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("serverconfig: read %s: %w", path, err)
	}
	cfg, err := decode(data)
	if err != nil {
		return Config{}, err
	}
	if err := checkSecretFileMode(path, cfg); err != nil {
		return Config{}, err
	}
	applyFlags(&cfg, fs)
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// applyFlags copies every flag explicitly set on fs onto cfg. Flags the
// user did not set are left alone.
func applyFlags(cfg *Config, fs *flag.FlagSet) {
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "listen":
			cfg.Listen = f.Value.String()
		case "allow_remote_listen":
			cfg.AllowRemoteListen = f.Value.String() == "true"
		case "public_origin":
			cfg.PublicOrigin = f.Value.String()
		case "data_dir":
			cfg.DataDir = f.Value.String()
		case "executor_socket":
			cfg.ExecutorSocket = f.Value.String()
		case "executor_user":
			cfg.ExecutorUser = f.Value.String()
		}
	})
}

// checkSecretFileMode refuses a config with notification secrets that
// others can read (spec 13: owner nebula-server, not world-readable; the
// installer's 0640 root:nebula-server is fine).
func checkSecretFileMode(path string, cfg Config) error {
	if !cfg.Notifications.HasSecrets() {
		return nil
	}
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("serverconfig: stat %s: %w", path, err)
	}
	if fi.Mode().Perm()&0o007 != 0 {
		return fmt.Errorf("serverconfig: %s contains notification secrets and is readable or writable by others (mode %04o); chmod o-rwx it", path, fi.Mode().Perm())
	}
	return nil
}
