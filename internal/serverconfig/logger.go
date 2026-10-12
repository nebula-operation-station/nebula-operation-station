// SPDX-License-Identifier: AGPL-3.0-or-later

package serverconfig

import (
	"io"
	"log/slog"
)

// LogAttrs returns slog attributes for the non-secret configuration fields.
// The Token is never included, so logging via these attributes cannot leak
// the secret.
func (c Config) LogAttrs() []slog.Attr {
	return []slog.Attr{
		slog.String("listen", c.Listen),
		slog.Bool("allow_remote_listen", c.AllowRemoteListen),
		slog.String("public_origin", c.PublicOrigin),
		slog.String("data_dir", c.DataDir),
		slog.String("executor_socket", c.ExecutorSocket),
		slog.String("executor_user", c.ExecutorUser),
	}
}

// NewLogger builds a JSON slog logger with the safe configuration
// attributes (see LogAttrs) bound, so every record carries the
// non-secret config. The Token is never included.
func NewLogger(w io.Writer, cfg Config) *slog.Logger {
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo})
	attrs := cfg.LogAttrs()
	log := slog.New(h)
	for i := range attrs {
		log = log.With(attrs[i])
	}
	return log
}
