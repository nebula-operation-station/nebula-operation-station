// SPDX-License-Identifier: AGPL-3.0-or-later

// Package containerdef is the format and shape check of a standalone
// container definition (ADR 0006 P2-03, container update plan cu05, Q7).
//
// A definition is the operator's exact `docker create` argument list for
// one container, which NOS completes only with the image:
//
//	docker create <Options...> --env-file=<tmpfs file> <image> <Command...>
//
// Env values travel apart from the argument list (Env), because the script
// writes them to a file in the run's tmpfs and passes that as --env-file,
// so no env value reaches a process command line. Options stay on the
// command line and must hold no secret.
//
// The shape is checked when the definition is stored and again before
// dispatch. Errors never contain an env value, an option value or a
// command argument; they name the position and, for options, the flag.
package containerdef

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Format names the stored encoding.
const Format = "nebula-container-definition-v1"

// Limits of one definition. MaxEncodedBytes stays below the vault's value
// limit and the host run secret channel (both 64 KiB).
const (
	MaxOptions        = 256
	MaxOptionBytes    = 4096
	MaxCommandArgs    = 256
	MaxCommandBytes   = 4096
	MaxEnv            = 256
	MaxEnvNameBytes   = 255
	MaxEnvValueBytes  = 32 << 10
	MaxEncodedBytes   = 60 << 10
	maxContainerName  = 128
	maxPortNumber     = 65535
	maxPortRangeWidth = 65535
)

// ErrShape is wrapped by every shape rejection.
var ErrShape = errors.New("containerdef: rejected definition shape")

var (
	containerNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)
	// optionRe is the only option form accepted: a long flag with its value
	// in the same token. Docker's flag parser accepts it for every flag
	// type, and it leaves no token whose meaning depends on the flag table
	// (no positional argument, so no image, and no short flag).
	optionRe  = regexp.MustCompile(`^--([a-z][a-z0-9-]{0,63})=`)
	envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	portRe    = regexp.MustCompile(`^([0-9]{1,5})(?:-([0-9]{1,5}))?$`)
)

// imageFlags are flags that would choose or fetch the image, which is
// NOS's alone.
var imageFlags = map[string]bool{"pull": true, "platform": true, "disable-content-trust": true}

// EnvVar is one environment variable. Value is secret.
type EnvVar struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Definition is one stored definition.
type Definition struct {
	Format        string   `json:"format"`
	ContainerName string   `json:"container_name"`
	Options       []string `json:"options"`
	Command       []string `json:"command"`
	Env           []EnvVar `json:"env"`
}

func shapeErr(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrShape}, args...)...)
}

// Validate checks the shape of d for the container containerName.
func (d Definition) Validate(containerName string) error {
	if d.Format != Format {
		return shapeErr("unknown format")
	}
	if !containerNameRe.MatchString(containerName) || len(containerName) > maxContainerName {
		return shapeErr("malformed container name")
	}
	if d.ContainerName != containerName {
		return shapeErr("definition is for another container")
	}
	if err := checkOptions(d.Options, containerName); err != nil {
		return err
	}
	if len(d.Command) > MaxCommandArgs {
		return shapeErr("more than %d command arguments", MaxCommandArgs)
	}
	for i, a := range d.Command {
		if len(a) > MaxCommandBytes || !utf8.ValidString(a) || strings.ContainsRune(a, 0) {
			return shapeErr("command argument %d is over %d bytes, not UTF-8 or holds a NUL byte", i, MaxCommandBytes)
		}
	}
	return checkEnv(d.Env)
}

func checkOptions(opts []string, containerName string) error {
	if len(opts) > MaxOptions {
		return shapeErr("more than %d options", MaxOptions)
	}
	names := 0
	for i, o := range opts {
		if len(o) > MaxOptionBytes || !utf8.ValidString(o) || hasControl(o) {
			return shapeErr("option %d is over %d bytes, not UTF-8 or holds a control character", i, MaxOptionBytes)
		}
		m := optionRe.FindStringSubmatch(o)
		if m == nil {
			return shapeErr("option %d is not of the form --flag=value (no short flags, no image, no positional argument)", i)
		}
		flag, value := m[1], o[len(m[0]):]
		switch {
		case flag == "name":
			names++
			if value != containerName {
				return shapeErr("option %d (--name) does not name the container", i)
			}
		case flag == "env" || flag == "env-file":
			return shapeErr("option %d (--%s): env values belong in the env list, not on the command line", i, flag)
		case flag == "publish-all":
			return shapeErr("option %d (--publish-all): Docker would choose the host ports", i)
		case flag == "publish":
			if err := checkPublish(value); err != nil {
				return shapeErr("option %d (--publish): %s", i, err)
			}
		case imageFlags[flag]:
			return shapeErr("option %d (--%s): the image is chosen by NOS", i, flag)
		}
	}
	if names != 1 {
		return shapeErr("the options must name the container exactly once with --name")
	}
	return nil
}

func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// checkPublish accepts only a published port whose host port the
// definition fixes: [ip:]host:container[/proto], host and container a
// port or a range of the same width. A container port alone, an empty or
// zero host port, or a host range against a single container port lets
// Docker choose the host port and is refused. The error never echoes the
// value.
func checkPublish(v string) error {
	if v == "" {
		return errors.New("empty value")
	}
	if i := strings.LastIndexByte(v, '/'); i >= 0 {
		switch v[i+1:] {
		case "tcp", "udp", "sctp":
		default:
			return errors.New("unknown protocol")
		}
		v = v[:i]
	}
	var parts []string
	if rest, ok := strings.CutPrefix(v, "["); ok {
		ip, ports, ok := strings.Cut(rest, "]:")
		if !ok {
			return errors.New("malformed address")
		}
		if a, err := netip.ParseAddr(ip); err != nil || !a.Is6() {
			return errors.New("malformed address")
		}
		parts = strings.Split(ports, ":")
		if len(parts) != 2 {
			return errors.New("Docker would choose the host port")
		}
	} else {
		parts = strings.Split(v, ":")
		switch len(parts) {
		case 2:
		case 3:
			if a, err := netip.ParseAddr(parts[0]); err != nil || !a.Is4() {
				return errors.New("malformed address")
			}
			parts = parts[1:]
		case 1:
			return errors.New("Docker would choose the host port")
		default:
			return errors.New("malformed value")
		}
	}
	if parts[0] == "" {
		return errors.New("Docker would choose the host port")
	}
	hostLo, hostHi, err := portRange(parts[0])
	if err != nil {
		return err
	}
	if hostLo == 0 {
		return errors.New("Docker would choose the host port")
	}
	ctrLo, ctrHi, err := portRange(parts[1])
	if err != nil || ctrLo == 0 {
		return errors.New("malformed container port")
	}
	if hostHi-hostLo != ctrHi-ctrLo {
		return errors.New("Docker would choose the host port inside the range")
	}
	return nil
}

func portRange(s string) (int, int, error) {
	m := portRe.FindStringSubmatch(s)
	if m == nil {
		return 0, 0, errors.New("malformed port")
	}
	lo, _ := strconv.Atoi(m[1])
	hi := lo
	if m[2] != "" {
		hi, _ = strconv.Atoi(m[2])
	}
	if lo > maxPortNumber || hi > maxPortNumber || hi < lo || hi-lo > maxPortRangeWidth {
		return 0, 0, errors.New("malformed port")
	}
	return lo, hi, nil
}

func checkEnv(env []EnvVar) error {
	if len(env) > MaxEnv {
		return shapeErr("more than %d env entries", MaxEnv)
	}
	seen := make(map[string]bool, len(env))
	for i, e := range env {
		if len(e.Name) > MaxEnvNameBytes || !envNameRe.MatchString(e.Name) {
			return shapeErr("env entry %d has a malformed name", i)
		}
		if seen[e.Name] {
			return shapeErr("env %s is listed twice", e.Name)
		}
		seen[e.Name] = true
		if len(e.Value) > MaxEnvValueBytes || !utf8.ValidString(e.Value) {
			return shapeErr("env %s: value is over %d bytes or not UTF-8", e.Name, MaxEnvValueBytes)
		}
		// --env-file is line based: a newline cannot be represented, a
		// trailing carriage return is stripped and a NUL cannot be carried.
		// NOS neither splits nor changes the value; it refuses it.
		if strings.ContainsAny(e.Value, "\n\r\x00") {
			return shapeErr("env %s: value contains a newline, carriage return or NUL byte, which the env file cannot carry", e.Name)
		}
	}
	return nil
}

// Encode validates d for containerName and returns its stored encoding.
func Encode(d Definition, containerName string) ([]byte, error) {
	if d.Options == nil {
		d.Options = []string{}
	}
	if d.Command == nil {
		d.Command = []string{}
	}
	if d.Env == nil {
		d.Env = []EnvVar{}
	}
	if err := d.Validate(containerName); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return nil, shapeErr("cannot encode")
	}
	if len(raw) > MaxEncodedBytes {
		clear(raw)
		return nil, shapeErr("definition is over %d bytes", MaxEncodedBytes)
	}
	return raw, nil
}

// Decode parses a stored definition strictly and validates it for
// containerName, so a definition read before dispatch passes the same
// check as at storage.
func Decode(raw []byte, containerName string) (Definition, error) {
	if len(raw) > MaxEncodedBytes {
		return Definition{}, shapeErr("definition is over %d bytes", MaxEncodedBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var d Definition
	if err := dec.Decode(&d); err != nil || dec.More() {
		return Definition{}, shapeErr("malformed encoding")
	}
	if err := d.Validate(containerName); err != nil {
		return Definition{}, err
	}
	return d, nil
}
