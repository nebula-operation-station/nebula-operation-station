// SPDX-License-Identifier: AGPL-3.0-or-later

package containerdef

import (
	"errors"
	"strings"
	"testing"
)

const planted = "s3cr3t-planted-value"

func good() Definition {
	return Definition{
		Format:        Format,
		ContainerName: "web",
		Options: []string{"--name=web", "--restart=unless-stopped", "--publish=8080:80", "--publish=127.0.0.1:8443:443/tcp",
			"--publish=[::1]:9000-9001:9000-9001/udp", "--volume=/srv/web:/data", "--label=tier=front", "--init=true"},
		Command: []string{"serve", "--port", "80"},
		Env:     []EnvVar{{Name: "DB_PASSWORD", Value: planted}, {Name: "EMPTY", Value: ""}},
	}
}

func TestDefinitionGoodShapeRoundTrips(t *testing.T) {
	raw, err := Encode(good(), "web")
	if err != nil {
		t.Fatal(err)
	}
	d, err := Decode(raw, "web")
	if err != nil {
		t.Fatal(err)
	}
	if d.Env[0].Value != planted || len(d.Options) != len(good().Options) {
		t.Fatalf("round trip %+v", d)
	}
	if _, err := Decode(raw, "other"); !errors.Is(err, ErrShape) {
		t.Fatalf("decoded for another container: %v", err)
	}
	if _, err := Decode(append(raw[:len(raw)-1:len(raw)-1], []byte(`,"extra":1}`)...), "web"); !errors.Is(err, ErrShape) {
		t.Fatalf("unknown field: %v", err)
	}
}

// refused asserts a shape rejection whose message holds no planted value.
func refused(t *testing.T, d Definition, secret string) {
	t.Helper()
	_, err := Encode(d, "web")
	if !errors.Is(err, ErrShape) {
		t.Fatalf("accepted: %v", err)
	}
	if secret != "" && strings.Contains(err.Error(), secret) {
		t.Fatalf("error echoes the value: %v", err)
	}
}

func TestDefinitionNewlineEnvRefused(t *testing.T) {
	for _, v := range []string{"a\nb", "\n", "tail\n", planted + "\nmore"} {
		d := good()
		d.Env[0].Value = v
		refused(t, d, planted)
	}
	// A stored value with a newline is refused again when read back (the
	// check before dispatch), not split or changed.
	if _, err := Decode([]byte(`{"format":"`+Format+`","container_name":"web","options":["--name=web"],"command":[],"env":[{"name":"A","value":"x\nb"}]}`), "web"); !errors.Is(err, ErrShape) {
		t.Fatalf("stored newline decoded: %v", err)
	}
}

func TestDefinitionCarriageReturnEnvRefused(t *testing.T) {
	for name, v := range map[string]string{
		"trailing CR": planted + "\r",
		"inner CR":    "s3cr3t\rplanted-value",
		"leading CR":  "\r" + planted,
		"NUL":         "s3cr3t\x00planted-value",
	} {
		t.Run(name, func(t *testing.T) {
			d := good()
			d.Env[0].Value = v
			refused(t, d, "s3cr3t")
		})
	}
}

func TestDefinitionEnvNotOnCommandLine(t *testing.T) {
	for _, o := range []string{"--env=DB_PASSWORD=" + planted, "--env-file=/tmp/x", "-e", "-eA=" + planted} {
		d := good()
		d.Options = append(d.Options, o)
		refused(t, d, planted)
	}
}

func TestDefinitionRejectedShapes(t *testing.T) {
	cases := map[string]func(*Definition){
		"wrong format":            func(d *Definition) { d.Format = "v0" },
		"other container":         func(d *Definition) { d.ContainerName = "db" },
		"no name option":          func(d *Definition) { d.Options = d.Options[1:] },
		"two name options":        func(d *Definition) { d.Options = append(d.Options, "--name=web") },
		"name of another":         func(d *Definition) { d.Options[0] = "--name=db" },
		"split name flag":         func(d *Definition) { d.Options[0] = "--name"; d.Options = append(d.Options, "web") },
		"short flag":              func(d *Definition) { d.Options = append(d.Options, "-p=80:80") },
		"bare long flag":          func(d *Definition) { d.Options = append(d.Options, "--privileged") },
		"image in options":        func(d *Definition) { d.Options = append(d.Options, "nginx:1.27") },
		"end of options":          func(d *Definition) { d.Options = append(d.Options, "--") },
		"pull policy":             func(d *Definition) { d.Options = append(d.Options, "--pull=always") },
		"platform":                func(d *Definition) { d.Options = append(d.Options, "--platform=linux/arm64") },
		"publish all":             func(d *Definition) { d.Options = append(d.Options, "--publish-all=true") },
		"container port only":     func(d *Definition) { d.Options = append(d.Options, "--publish=80") },
		"empty host port":         func(d *Definition) { d.Options = append(d.Options, "--publish=127.0.0.1::80") },
		"zero host port":          func(d *Definition) { d.Options = append(d.Options, "--publish=0:80") },
		"host range single ctr":   func(d *Definition) { d.Options = append(d.Options, "--publish=8000-8010:80") },
		"empty host before ctr":   func(d *Definition) { d.Options = append(d.Options, "--publish=:80") },
		"ipv6 container only":     func(d *Definition) { d.Options = append(d.Options, "--publish=[::1]:80") },
		"bad protocol":            func(d *Definition) { d.Options = append(d.Options, "--publish=80:80/icmp") },
		"port out of range":       func(d *Definition) { d.Options = append(d.Options, "--publish=70000:80") },
		"newline in option":       func(d *Definition) { d.Options = append(d.Options, "--label=a\nb") },
		"NUL in command":          func(d *Definition) { d.Command = append(d.Command, "a\x00b") },
		"malformed env name":      func(d *Definition) { d.Env[1].Name = "1BAD" },
		"env name with equals":    func(d *Definition) { d.Env[1].Name = "A=B" },
		"duplicate env":           func(d *Definition) { d.Env[1].Name = d.Env[0].Name },
		"oversized env value":     func(d *Definition) { d.Env[0].Value = strings.Repeat("x", MaxEnvValueBytes+1) },
		"too many options":        func(d *Definition) { d.Options = append(d.Options, make([]string, MaxOptions)...) },
		"invalid utf-8 env value": func(d *Definition) { d.Env[0].Value = "\xff" + planted },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			d := good()
			mutate(&d)
			refused(t, d, planted)
		})
	}
}

func TestDefinitionOversizedEncodingRefused(t *testing.T) {
	d := good()
	for i := range 3 {
		d.Env = append(d.Env, EnvVar{Name: "BIG" + string(rune('A'+i)), Value: strings.Repeat("x", MaxEnvValueBytes)})
	}
	refused(t, d, "")
}
