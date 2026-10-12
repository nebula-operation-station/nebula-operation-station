// SPDX-License-Identifier: AGPL-3.0-or-later

package serverconfig

import (
	"flag"
	"fmt"
	"os"
)

// RegisterFlags registers a flag on fs for every Config field, using the
// field's zero value as the default. Call it before fs.Parse.
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
	fs.StringVar(&zero.PublicOrigin, "public_origin", zero.PublicOrigin, "public origin (bare https origin, e.g. https://nebula.example.org)")
	fs.StringVar(&zero.DataDir, "data_dir", zero.DataDir, "data directory (absolute path)")
	fs.StringVar(&zero.ExecutorSocket, "executor_socket", zero.ExecutorSocket, "executor unix socket path (absolute path)")
	fs.StringVar(&zero.ExecutorUser, "executor_user", zero.ExecutorUser, "executor OS user")
	var token string
	fs.StringVar(&token, "token", token, "server token (secret; never logged)")
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
		case "token":
			cfg.Token = Token(f.Value.String())
		}
	})
}
