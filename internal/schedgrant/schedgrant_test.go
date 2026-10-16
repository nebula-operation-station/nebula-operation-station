// SPDX-License-Identifier: AGPL-3.0-or-later

package schedgrant

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
)

var now = time.Unix(1792000000, 0)

func valid() Doc {
	return Doc{Grant: Format, ID: "00000000-0000-4000-8000-000000000001",
		Actions:      []Action{{ActionID: "package.list_updates", ModuleVersion: "1.0.0", ArtifactSHA256: strings.Repeat("a", 64), ParametersHash: strings.Repeat("b", 64)}},
		Targets:      []canonical.Target{{HostID: "web", HostKeyFingerprint: "SHA256:" + strings.Repeat("A", 43)}},
		MinIntervalS: 3600, ExpiryUnix: now.Add(30 * 24 * time.Hour).Unix()}
}

func raw(t *testing.T, d Doc) []byte {
	t.Helper()
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseAcceptsAValidGrant(t *testing.T) {
	d, canon, hash, err := Parse(raw(t, valid()), now)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := canonical.HashParameters(canon)
	if hash != want || len(d.Actions) != 1 {
		t.Fatalf("%+v %s", d, hash)
	}
	if _, ok := d.Action("package.list_updates", "1.0.0"); !ok {
		t.Fatal("action not found")
	}
	if _, ok := d.Action("package.list_updates", "2.0.0"); ok {
		t.Fatal("other version found")
	}
	if _, ok := d.Target("web"); !ok {
		t.Fatal("target not found")
	}
}

func TestParseRefusesGrantsOutsideTheLimits(t *testing.T) {
	cases := map[string]func(*Doc){
		"format":         func(d *Doc) { d.Grant = "other" },
		"id":             func(d *Doc) { d.ID = "x" },
		"no actions":     func(d *Doc) { d.Actions = nil },
		"no targets":     func(d *Doc) { d.Targets = nil },
		"interval short": func(d *Doc) { d.MinIntervalS = 60 },
		"interval long":  func(d *Doc) { d.MinIntervalS = 8 * 24 * 3600 },
		"interval wraps": func(d *Doc) { d.MinIntervalS = -9223372036854774908 }, // times 1s wraps to 15 min; also beyond the I-JSON number range
		"expiry soon":    func(d *Doc) { d.ExpiryUnix = now.Add(time.Minute).Unix() },
		"expiry far":     func(d *Doc) { d.ExpiryUnix = now.Add(91 * 24 * time.Hour).Unix() },
		"bad action":     func(d *Doc) { d.Actions[0].ActionID = "-x" },
		"bad hash":       func(d *Doc) { d.Actions[0].ParametersHash = "x" },
		"dup action":     func(d *Doc) { d.Actions = append(d.Actions, d.Actions[0]) },
		"dup host":       func(d *Doc) { d.Targets = append(d.Targets, d.Targets[0]) },
		"bad host":       func(d *Doc) { d.Targets[0].HostID = "-web" },
		"bad fp":         func(d *Doc) { d.Targets[0].HostKeyFingerprint = "md5" },
		"many actions": func(d *Doc) {
			for i := 0; i < MaxActions; i++ {
				d.Actions = append(d.Actions, Action{ActionID: "a" + strings.Repeat("x", i+1), ModuleVersion: "1.0.0",
					ArtifactSHA256: strings.Repeat("a", 64), ParametersHash: strings.Repeat("b", 64)})
			}
		},
	}
	for name, mutate := range cases {
		d := valid()
		mutate(&d)
		if _, _, _, err := Parse(raw(t, d), now); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, s := range map[string]string{
		"unknown member": strings.Replace(string(raw(t, valid())), `"id":`, `"extra":1,"id":`, 1),
		"upper case":     strings.Replace(string(raw(t, valid())), `"min_interval_s":3600`, `"min_interval_s":3600,"MIN_INTERVAL_S":900`, 1),
		"member missing": strings.Replace(string(raw(t, valid())), `"min_interval_s":3600,`, ``, 1),
		"not an object":  `[]`,
	} {
		if _, _, _, err := Parse([]byte(s), now); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
