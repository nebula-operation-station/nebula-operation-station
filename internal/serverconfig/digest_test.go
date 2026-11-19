// SPDX-License-Identifier: AGPL-3.0-or-later

package serverconfig

import (
	"errors"
	"strings"
	"testing"
)

// digestBase is a valid config with one provider, into which a
// notifications.daily_digest block is spliced.
func digestBase(digest string) string {
	return `{
  "public_origin": "https://nebula.example.org",
  "data_dir": "/var/lib/nebula/server",
  "executor_socket": "/run/nebula/executor.sock",
  "executor_user": "nebula-executor",
  "notifications": {
    "ntfy": {"url": "http://ntfy.lan", "topic": "nebula-ops"}` + digest + `
  }
}`
}

func TestDailyDigestDefaultsOffAt0700(t *testing.T) {
	cfg, err := Parse([]byte(digestBase("")))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	d := cfg.Notifications.DailyDigest
	if d.Enabled {
		t.Errorf("digest enabled by default, want off")
	}
	if d.SkipEmpty {
		t.Errorf("skip_empty set by default")
	}
	h, m, err := d.SendTime()
	if err != nil || h != 7 || m != 0 {
		t.Errorf("SendTime = %d:%d, %v; want 07:00", h, m, err)
	}
}

func TestDailyDigestSendTimeAndFlags(t *testing.T) {
	cfg, err := Parse([]byte(digestBase(`, "daily_digest": {"enabled": true, "time": "18:45", "skip_empty": true}`)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	d := cfg.Notifications.DailyDigest
	if !d.Enabled || !d.SkipEmpty {
		t.Errorf("flags = enabled %v skip_empty %v; want both true", d.Enabled, d.SkipEmpty)
	}
	h, m, err := d.SendTime()
	if err != nil || h != 18 || m != 45 {
		t.Errorf("SendTime = %d:%d, %v; want 18:45", h, m, err)
	}
}

func TestDailyDigestRejectsBadTimeAndUnknownKeys(t *testing.T) {
	tests := []struct {
		name   string
		digest string
	}{
		{"single digit hour", `, "daily_digest": {"enabled": true, "time": "7:00"}`},
		{"hour 24", `, "daily_digest": {"enabled": true, "time": "24:00"}`},
		{"minute 60", `, "daily_digest": {"enabled": true, "time": "07:60"}`},
		{"seconds", `, "daily_digest": {"enabled": true, "time": "07:00:00"}`},
		{"text", `, "daily_digest": {"enabled": true, "time": "morning"}`},
		{"unknown key", `, "daily_digest": {"enabled": true, "send_at": "07:00"}`},
		{"string enabled", `, "daily_digest": {"enabled": "yes"}`},
		{"bad time while off", `, "daily_digest": {"enabled": false, "time": "25:00"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Parse([]byte(digestBase(tt.digest))); err == nil {
				t.Fatalf("Parse accepted %s", tt.digest)
			}
		})
	}
}

func TestDailyDigestNeedsAProvider(t *testing.T) {
	cfg := `{
  "public_origin": "https://nebula.example.org",
  "data_dir": "/var/lib/nebula/server",
  "executor_socket": "/run/nebula/executor.sock",
  "executor_user": "nebula-executor",
  "notifications": {"daily_digest": {"enabled": true}}
}`
	_, err := Parse([]byte(cfg))
	if err == nil || !strings.Contains(err.Error(), "daily_digest") {
		t.Fatalf("Parse = %v; want a daily_digest problem without any provider", err)
	}
}

func TestDailyDigestSendTimeRejectsUnvalidated(t *testing.T) {
	_, _, err := DailyDigest{Time: "7:00"}.SendTime()
	if !errors.Is(err, ErrDigestTime) {
		t.Fatalf("SendTime error = %v; want ErrDigestTime", err)
	}
}
