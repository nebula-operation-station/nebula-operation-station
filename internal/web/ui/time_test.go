// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"testing"
	"time"
)

func TestTimeTag(t *testing.T) {
	tests := []struct {
		name string
		in   time.Time
		want string
	}{
		{"zero renders nothing", time.Time{}, ""},
		{"nonzero renders RFC3339 datetime and UTC text",
			time.Date(2026, 10, 20, 12, 34, 56, 0, time.UTC),
			`<time datetime="2026-10-20T12:34:56Z">2026-10-20 12:34:56 UTC</time>`},
		{"non-UTC is converted to UTC",
			time.Date(2026, 10, 20, 14, 34, 56, 0, time.FixedZone("UTC+2", 7200)),
			`<time datetime="2026-10-20T12:34:56Z">2026-10-20 12:34:56 UTC</time>`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(timeTag(tt.in)); got != tt.want {
				t.Errorf("timeTag(%v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
