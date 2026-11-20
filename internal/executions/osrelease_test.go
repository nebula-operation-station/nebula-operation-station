// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

// factsWithOSRelease wraps text in a core.facts document as the executor
// reports it: os_release is base64, the other members are ignored here.
func factsWithOSRelease(text string) []byte {
	return []byte(fmt.Sprintf(`{"os_release":%q,"uname":"","hostname":"","uptime":"","proxmox":false}`,
		base64.StdEncoding.EncodeToString([]byte(text))))
}

func TestOSReleaseReadsDebian12(t *testing.T) {
	text := "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"12\"\n" +
		"VERSION=\"12 (bookworm)\"\nVERSION_CODENAME=bookworm\nID=debian\n"
	id, ver, code, ok := OSRelease(factsWithOSRelease(text))
	if !ok || id != "debian" || ver != "12" || code != "bookworm" {
		t.Fatalf("OSRelease = %q %q %q %v, want debian 12 bookworm true", id, ver, code, ok)
	}
}

func TestOSReleaseReadsUbuntu2404(t *testing.T) {
	text := "NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nVERSION_CODENAME=noble\nID=ubuntu\nID_LIKE=debian\n"
	id, ver, code, ok := OSRelease(factsWithOSRelease(text))
	if !ok || id != "ubuntu" || ver != "24.04" || code != "noble" {
		t.Fatalf("OSRelease = %q %q %q %v, want ubuntu 24.04 noble true", id, ver, code, ok)
	}
}

func TestOSReleaseMissingKeysGiveEmptyFields(t *testing.T) {
	tests := []struct {
		name, text, id, ver, code string
	}{
		{"no version codename", "ID=debian\nVERSION_ID=\"12\"\n", "debian", "12", ""},
		{"no id", "VERSION_ID=\"12\"\nVERSION_CODENAME=bookworm\n", "", "12", "bookworm"},
		{"empty file", "", "", "", ""},
		{"only comments", "# nothing here\n", "", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id, ver, code, ok := OSRelease(factsWithOSRelease(tc.text))
			if !ok {
				t.Fatalf("ok = false for a readable document")
			}
			if id != tc.id || ver != tc.ver || code != tc.code {
				t.Fatalf("OSRelease = %q %q %q, want %q %q %q", id, ver, code, tc.id, tc.ver, tc.code)
			}
		})
	}
}

func TestOSReleaseRejectsBrokenInput(t *testing.T) {
	tests := []struct {
		name   string
		result []byte
	}{
		{"not JSON", []byte("not json")},
		{"JSON array", []byte(`["x"]`)},
		{"os_release not base64", []byte(`{"os_release":"!!!not base64!!!"}`)},
		{"os_release wrong type", []byte(`{"os_release":42}`)},
		{"empty result", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id, ver, code, ok := OSRelease(tc.result)
			if ok || id != "" || ver != "" || code != "" {
				t.Fatalf("OSRelease = %q %q %q %v, want nothing and ok=false", id, ver, code, ok)
			}
		})
	}
}

func TestOSReleaseRejectsOverlongValues(t *testing.T) {
	long := strings.Repeat("a", 33)
	text := "ID=" + long + "\nVERSION_ID=" + strings.Repeat("1", 32) + "\nVERSION_CODENAME=" + strings.Repeat("b", 33) + "\n"
	id, ver, code, ok := OSRelease(factsWithOSRelease(text))
	if !ok {
		t.Fatalf("ok = false for a readable document")
	}
	if id != "" || code != "" {
		t.Fatalf("overlong id/codename kept: %q %q", id, code)
	}
	if ver != strings.Repeat("1", 32) {
		t.Fatalf("32-byte version dropped: %q", ver)
	}
}

func TestOSReleaseRejectsControlAndOddCharacters(t *testing.T) {
	tests := []struct {
		name, text string
	}{
		{"escape sequence", "ID=\"deb\\x1b[31mian\"\nVERSION_ID=12\nVERSION_CODENAME=bookworm\n"},
		{"uppercase", "ID=Debian\nVERSION_ID=12\nVERSION_CODENAME=bookworm\n"},
		{"space in value", "ID=debian gnu\nVERSION_ID=12\nVERSION_CODENAME=book worm\n"},
		{"slash", "ID=debian\nVERSION_ID=12/../x\nVERSION_CODENAME=bookworm\n"},
		{"bidi override", "ID=debian\nVERSION_ID=12\nVERSION_CODENAME=book‮worm\n"},
		{"newline inside quotes", "ID=\"debian\nVERSION_ID=12\nVERSION_CODENAME=bookworm\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id, ver, code, ok := OSRelease(factsWithOSRelease(tc.text))
			if !ok {
				t.Fatalf("ok = false for a readable document")
			}
			if strings.ContainsAny(id+ver+code, "\x1b‮ /\n") {
				t.Fatalf("control or odd characters kept: %q %q %q", id, ver, code)
			}
			if id != "" && id != "debian" {
				t.Fatalf("unexpected id %q", id)
			}
		})
	}
}

func TestOSReleaseStopsAfterOneHundredLines(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 100; i++ {
		b.WriteString("# filler\n")
	}
	b.WriteString("ID=debian\nVERSION_ID=12\nVERSION_CODENAME=bookworm\n")
	id, ver, code, ok := OSRelease(factsWithOSRelease(b.String()))
	if !ok || id != "" || ver != "" || code != "" {
		t.Fatalf("keys after line 100 were read: %q %q %q %v", id, ver, code, ok)
	}
}
