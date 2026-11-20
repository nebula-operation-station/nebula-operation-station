// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

// hostileFactsResult builds a core.facts result the way core_facts.sh prints
// it: every value is the base64 of the raw bytes the host command wrote.
func hostileFactsResult(t *testing.T, uname, hostname []byte) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"os_release": "",
		"uname":      base64.StdEncoding.EncodeToString(uname),
		"hostname":   base64.StdEncoding.EncodeToString(hostname),
		"uptime":     "",
		"proxmox":    false,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// factValue returns the displayed value of the named fact, if any.
func factValue(facts []Fact, name string) (string, bool) {
	for _, f := range facts {
		if f.Name == name {
			return f.Value, true
		}
	}
	return "", false
}

// TestCoreFactsHostileKernelAndHostnameDisplay: a host controls uname and
// hostname. Quotes and backslashes are printable and shown as they are; a tab,
// a control byte and a bidi control are replaced by U+FFFD; invalid UTF-8 is
// replaced byte by byte. Surrounding whitespace is trimmed.
func TestCoreFactsHostileKernelAndHostnameDisplay(t *testing.T) {
	for name, tc := range map[string]struct {
		uname, hostname []byte
		wantKernel      string
		wantHostname    string
	}{
		"quote and backslash": {
			uname:        []byte(`Linux "k"\ 6.1` + "\n"),
			hostname:     []byte(`h"o\s` + "\n"),
			wantKernel:   `Linux "k"\ 6.1`,
			wantHostname: `h"o\s`,
		},
		"tab and control byte": {
			uname:        []byte("Linux\t6.1\x01\n"),
			hostname:     []byte("web\x1b[31m\n"),
			wantKernel:   "Linux�6.1�",
			wantHostname: "web�[31m",
		},
		"invalid UTF-8": {
			uname:        []byte("Linux \xff\xfe 6.1\n"),
			hostname:     []byte("h\xc3(st\n"),
			wantKernel:   "Linux �� 6.1",
			wantHostname: "h�(st",
		},
		"bidi override": {
			uname:        []byte("Linux ‮6.1\n"),
			hostname:     []byte("web⁦\n"),
			wantKernel:   "Linux �6.1",
			wantHostname: "web�",
		},
		"empty values": {
			uname:        []byte("\n"),
			hostname:     nil,
			wantKernel:   "",
			wantHostname: "",
		},
	} {
		t.Run(name, func(t *testing.T) {
			facts := DecodeFacts(hostileFactsResult(t, tc.uname, tc.hostname))
			if got, _ := factValue(facts, "Kernel"); got != tc.wantKernel {
				t.Errorf("Kernel = %q, want %q", got, tc.wantKernel)
			}
			if got, _ := factValue(facts, "Hostname"); got != tc.wantHostname {
				t.Errorf("Hostname = %q, want %q", got, tc.wantHostname)
			}
			for _, f := range facts {
				checkDisplayText(t, f.Value)
			}
		})
	}
}

// TestCoreFactsMalformedDocumentShowsNothing: a document that is not JSON or
// has base64 values that do not decode yields no hostile text.
func TestCoreFactsMalformedDocumentShowsNothing(t *testing.T) {
	for name, doc := range map[string]string{
		"not JSON":        `not json`,
		"bad base64 name": `{"uname":"!!!not base64","hostname":"%%%"}`,
		"wrong types":     `{"uname":12,"hostname":true}`,
	} {
		t.Run(name, func(t *testing.T) {
			facts := DecodeFacts([]byte(doc))
			for _, f := range facts {
				if f.Name == "Kernel" || f.Name == "Hostname" {
					t.Errorf("%s shows %s = %q", name, f.Name, f.Value)
				}
			}
		})
	}
}
