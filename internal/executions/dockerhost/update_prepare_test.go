// SPDX-License-Identifier: AGPL-3.0-or-later

package dockerhost

import (
	"errors"
	"strings"
	"testing"
)

func TestParseUpdatePrepareAcceptsEveryStatus(t *testing.T) {
	for st := range prepareStatuses {
		for _, nl := range []string{"", "\n"} {
			p, err := ParseUpdatePrepare([]byte(`{"format":"docker-update-prepare-v1","status":"` + st + `"}` + nl))
			if err != nil {
				t.Fatalf("%s: %v", st, err)
			}
			if p.Status != st || p.Prepared() != (st == PrepareCreated || st == PreparePresent) {
				t.Fatalf("%s: %+v", st, p)
			}
		}
	}
}

// A hostile host cannot smuggle anything (a salt, a path, a log) through
// the prepare result: only the two known members with known values parse.
func TestParseUpdatePrepareRefusesHostileResult(t *testing.T) {
	salt := strings.Repeat("ab", 32)
	for name, in := range map[string]string{
		"empty":           ``,
		"not json":        `created`,
		"no format":       `{"status":"created"}`,
		"other format":    `{"format":"docker-update-preview-v1","status":"created"}`,
		"no status":       `{"format":"docker-update-prepare-v1"}`,
		"unknown status":  `{"format":"docker-update-prepare-v1","status":"prepared"}`,
		"salt member":     `{"format":"docker-update-prepare-v1","status":"created","salt":"` + salt + `"}`,
		"salt as status":  `{"format":"docker-update-prepare-v1","status":"` + salt + `"}`,
		"null status":     `{"format":"docker-update-prepare-v1","status":null}`,
		"number status":   `{"format":"docker-update-prepare-v1","status":1}`,
		"duplicate value": `{"format":"docker-update-prepare-v1","status":"created"}{"status":"present"}`,
		"two lines":       "{\"format\":\"docker-update-prepare-v1\",\n\"status\":\"created\"}",
		"array":           `[]`,
		"oversize":        `{"format":"docker-update-prepare-v1","status":"created"}` + strings.Repeat(" ", MaxPrepareResultBytes),
		"bad utf8":        "{\"format\":\"docker-update-prepare-v1\",\"status\":\"created\xff\"}",
	} {
		if _, err := ParseUpdatePrepare([]byte(in)); !errors.Is(err, ErrPrepareFormat) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestPreviewPrepareRequired(t *testing.T) {
	p, err := ParseUpdatePreview([]byte(`{"format":"docker-update-preview-v1","status":"prepare_required","units":[]}`))
	if err != nil || !p.PrepareRequired() {
		t.Fatalf("%+v %v", p, err)
	}
	p, err = ParseUpdatePreview([]byte(`{"format":"docker-update-preview-v1","status":"ok","units":[]}`))
	if err != nil || p.PrepareRequired() {
		t.Fatalf("%+v %v", p, err)
	}
}

func FuzzParseUpdatePrepare(f *testing.F) {
	f.Add([]byte(`{"format":"docker-update-prepare-v1","status":"created"}` + "\n"))
	f.Add([]byte(`{"format":"docker-update-prepare-v1","status":"present"}`))
	f.Add([]byte(`{"format":"docker-update-prepare-v1","status":"salt_unsafe","x":1}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := ParseUpdatePrepare(b)
		if err != nil {
			if !errors.Is(err, ErrPrepareFormat) {
				t.Fatalf("unwrapped error %v", err)
			}
			return
		}
		if !prepareStatuses[p.Status] || len(b) > MaxPrepareResultBytes {
			t.Fatalf("accepted %q as %+v", b, p)
		}
	})
}
