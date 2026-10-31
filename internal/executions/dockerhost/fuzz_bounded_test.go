// SPDX-License-Identifier: AGPL-3.0-or-later

package dockerhost

import (
	"regexp"
	"strings"
	"testing"
	"time"
)

var hexRe = regexp.MustCompile(`^[0-9a-f]+$`)

// healthSet holds the health values the parsers may produce.
var healthSet = map[string]bool{"": true, "healthy": true, "unhealthy": true, "starting": true}

// FuzzParseListBounds feeds arbitrary bytes to the docker.list parser and
// asserts the snapshot stays within its bounds: no panic, bounded
// container count, and every kept field inside its pattern or length.
func FuzzParseListBounds(f *testing.F) {
	for _, s := range fuzzSeedFiles("docker29.json") {
		f.Add(s)
	}
	f.Add([]byte(`{"format":"docker-ps-v1","phase":"precheck","reason":"no docker"}`))
	f.Add([]byte(`{"format":"docker-ps-v1","phase":"done","present":false}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		l, err := ParseList(b)
		if err != nil {
			return
		}
		if len(l.Containers) > maxContainers {
			t.Fatalf("list has %d containers, bound is %d", len(l.Containers), maxContainers)
		}
		for _, c := range l.Containers {
			if !idRe.MatchString(c.ID) {
				t.Fatalf("container ID %q is not 12-64 hex digits", c.ID)
			}
			if c.FullID != "" && !fullIDRe.MatchString(c.FullID) {
				t.Fatalf("full ID %q is not 64 hex digits", c.FullID)
			}
			if !nameRe.MatchString(c.Name) {
				t.Fatalf("container name %q does not match the name pattern", c.Name)
			}
			if !states[c.State] {
				t.Fatalf("unknown state %q", c.State)
			}
			if len(c.Image) > 300 || len(c.Status) > 200 || len(c.Ports) > 1000 {
				t.Fatalf("image/status/ports lengths %d/%d/%d exceed their bounds", len(c.Image), len(c.Status), len(c.Ports))
			}
			if !healthSet[c.Health] {
				t.Fatalf("unknown health %q", c.Health)
			}
			if c.Project != "" && !projectRe.MatchString(c.Project) {
				t.Fatalf("project %q does not match the project pattern", c.Project)
			}
			if len(c.Service) > 100 || len(c.Dir) > 500 {
				t.Fatalf("service/dir lengths %d/%d exceed their bounds", len(c.Service), len(c.Dir))
			}
			if c.Created != "" {
				if _, err := time.Parse(time.RFC3339, c.Created); err != nil {
					t.Fatalf("created %q is not RFC 3339", c.Created)
				}
			}
		}
	})
}

// FuzzParseLogsBounds feeds arbitrary bytes to the docker.logs parser and
// asserts the log stays within its bounds: at most maxLogLines lines of at
// most maxLogLineLen bytes each.
func FuzzParseLogsBounds(f *testing.F) {
	for _, s := range fuzzSeedFiles("docker29-logs.json") {
		f.Add(s)
	}
	f.Add([]byte(`{"format":"docker-logs-v1","phase":"precheck","reason":"no docker"}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		l, err := ParseLogs(b)
		if err != nil {
			return
		}
		if len(l.Lines) > maxLogLines {
			t.Fatalf("logs have %d lines, bound is %d", len(l.Lines), maxLogLines)
		}
		for _, line := range l.Lines {
			if len(line) > maxLogLineLen {
				t.Fatalf("log line is %d bytes, bound is %d", len(line), maxLogLineLen)
			}
		}
		if l.Container != "" && !containerRe.MatchString(l.Container) {
			t.Fatalf("container %q does not match the container pattern", l.Container)
		}
		if l.State != "" && !states[l.State] {
			t.Fatalf("unknown state %q", l.State)
		}
	})
}

// FuzzParseInspectBounds feeds arbitrary bytes to the docker.inspect
// parser and asserts the result stays within its bounds: no panic,
// bounded mounts/ports/networks/digests, and every kept field inside its
// pattern or length.
func FuzzParseInspectBounds(f *testing.F) {
	for _, s := range fuzzSeedFiles("docker29-inspect.json", "docker29-inspect-created.json") {
		f.Add(s)
	}
	f.Add([]byte(`{"format":"docker-inspect-v1","phase":"precheck","reason":"no docker"}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		in, err := ParseInspect(b)
		if err != nil {
			return
		}
		if len(in.Mounts) > maxMounts || len(in.Ports) > maxPorts || len(in.Networks) > maxNetworks || len(in.Digests) > maxDigests {
			t.Fatalf("mounts/ports/networks/digests %d/%d/%d/%d exceed their bounds",
				len(in.Mounts), len(in.Ports), len(in.Networks), len(in.Digests))
		}
		if in.ID != "" && (len(in.ID) != 12 || !hexRe.MatchString(in.ID)) {
			t.Fatalf("ID %q is not 12 hex digits", in.ID)
		}
		if in.FullID != "" && !fullIDRe.MatchString(in.FullID) {
			t.Fatalf("full ID %q is not 64 hex digits", in.FullID)
		}
		if in.Name != "" && !nameRe.MatchString(in.Name) {
			t.Fatalf("name %q does not match the name pattern", in.Name)
		}
		if in.Image != "" && len(in.Image) > 300 {
			t.Fatalf("image %q exceeds 300 bytes", in.Image)
		}
		if in.ImageID != "" && !imageIDRe.MatchString(in.ImageID) {
			t.Fatalf("image ID %q is not a sha256 digest", in.ImageID)
		}
		if in.Status != "" && !states[in.Status] {
			t.Fatalf("unknown status %q", in.Status)
		}
		if in.ExitCode < -1 || in.ExitCode > 1<<16 {
			t.Fatalf("exit code %d outside [-1, %d]", in.ExitCode, 1<<16)
		}
		if in.Restarts < 0 || in.FailingStreak < 0 {
			t.Fatalf("restarts %d / failing streak %d negative", in.Restarts, in.FailingStreak)
		}
		if in.RestartPolicy != "" && !restartPolicy[in.RestartPolicy] {
			t.Fatalf("unknown restart policy %q", in.RestartPolicy)
		}
		if in.Health != "" && !healthStates[in.Health] {
			t.Fatalf("unknown health %q", in.Health)
		}
		if in.Platform != "" && !platformBounded(in.Platform) {
			t.Fatalf("platform %q exceeds its component bounds", in.Platform)
		}
		if in.ImageDigestPlatform != "" && !imageIDRe.MatchString(in.ImageDigestPlatform) {
			t.Fatalf("platform digest %q is not a sha256 digest", in.ImageDigestPlatform)
		}
		if in.ImageDigestIndex != "" && !imageIDRe.MatchString(in.ImageDigestIndex) {
			t.Fatalf("index digest %q is not a sha256 digest", in.ImageDigestIndex)
		}
		for _, d := range in.Digests {
			if !digestRe.MatchString(d) {
				t.Fatalf("digest %q does not match the digest pattern", d)
			}
		}
		for _, m := range in.Mounts {
			if !mountTypes[m.Type] || len(m.Destination) > 500 || !strings.HasPrefix(m.Destination, "/") {
				t.Fatalf("mount %+v violates its bounds", m)
			}
		}
	})
}

// platformBounded reports whether p is "os/arch" or "os/arch/variant"
// with every component within its bound.
func platformBounded(p string) bool {
	parts := strings.Split(p, "/")
	if len(parts) != 2 && len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if !platformComponent(part) {
			return false
		}
	}
	return true
}

// FuzzParseControlBounds feeds arbitrary bytes to the docker control
// parser and asserts the result stays within its bounds: no panic, a
// known verb, a bounded exit code and at most 20 output lines of bounded
// length.
func FuzzParseControlBounds(f *testing.F) {
	for _, s := range fuzzSeedFiles("docker29-start.json") {
		f.Add(s)
	}
	f.Add([]byte(`{"format":"docker-control-v1","phase":"precheck","reason":"no docker"}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := ParseControl(b)
		if err != nil {
			return
		}
		switch c.Verb {
		case "", "start", "stop", "restart":
		default:
			t.Fatalf("unknown verb %q", c.Verb)
		}
		if c.Container != "" && !containerRe.MatchString(c.Container) {
			t.Fatalf("container %q does not match the container pattern", c.Container)
		}
		if c.Exit < 0 || c.Exit > 255 {
			t.Fatalf("exit %d outside [0, 255]", c.Exit)
		}
		if c.Before != "" && !states[c.Before] {
			t.Fatalf("unknown before state %q", c.Before)
		}
		if c.After != "" && !states[c.After] {
			t.Fatalf("unknown after state %q", c.After)
		}
		if len(c.Output) > 20 {
			t.Fatalf("output has %d lines, bound is 20", len(c.Output))
		}
		for _, line := range c.Output {
			if len(line) > maxLogLineLen {
				t.Fatalf("output line is %d bytes, bound is %d", len(line), maxLogLineLen)
			}
		}
	})
}

// FuzzParseComposeUpdateBounds feeds arbitrary bytes to the
// compose.update parser and asserts the result stays within its bounds:
// no panic, at most 200 containers per side with bounded fields, and a
// verdict from the known set.
func FuzzParseComposeUpdateBounds(f *testing.F) {
	for _, s := range fuzzSeedFiles("docker29-compose.json") {
		f.Add(s)
	}
	f.Add([]byte(`{"format":"compose-update-v1","phase":"precheck","reason":"no compose"}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := ParseComposeUpdate(b)
		if err != nil {
			return
		}
		if c.Project != "" && !projectRe.MatchString(c.Project) {
			t.Fatalf("project %q does not match the project pattern", c.Project)
		}
		switch c.Verdict {
		case "OK", "WARNING", "FAILED":
		default:
			t.Fatalf("unknown verdict %q", c.Verdict)
		}
		for _, side := range [][]ComposeContainer{c.Before, c.After} {
			if len(side) > 200 {
				t.Fatalf("compose side has %d containers, bound is 200", len(side))
			}
			for _, x := range side {
				if !nameRe.MatchString(x.Name) || !states[x.State] {
					t.Fatalf("compose container %+v violates its bounds", x)
				}
				if len(x.Status) > 200 || len(x.Ports) > 1000 || len(x.Image) > 300 {
					t.Fatalf("compose container fields %d/%d/%d exceed their bounds", len(x.Status), len(x.Ports), len(x.Image))
				}
				if x.Service != "" && !composeServiceRe.MatchString(x.Service) {
					t.Fatalf("service %q does not match the service pattern", x.Service)
				}
				if !healthSet[x.Health] {
					t.Fatalf("unknown health %q", x.Health)
				}
			}
		}
	})
}

// FuzzParseImageUpdatesBounds feeds arbitrary bytes to the
// check_updates parser and asserts the result stays within its bounds:
// no panic, at most maxImages rows, every row inside its patterns, and
// the update count equal to the number of rows with status update.
func FuzzParseImageUpdatesBounds(f *testing.F) {
	f.Add([]byte(`{"format":"docker-updates-v1","phase":"precheck","reason":"no docker"}`))
	f.Add([]byte(`{"format":"docker-updates-v1","phase":"done","lines":"bW9raW5nOjIJY3VycmVudAlzaGEyNTY6MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZjAJCm1va2luZzoyCXVwZGF0ZQlzaGEyNTY6MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZjAJCg=="}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		u, err := ParseImageUpdates(b)
		if err != nil {
			return
		}
		if len(u.Images) > maxImages {
			t.Fatalf("updates have %d images, bound is %d", len(u.Images), maxImages)
		}
		updates := 0
		for _, x := range u.Images {
			if !imageRefRe.MatchString(x.Image) {
				t.Fatalf("image %q does not match the image reference pattern", x.Image)
			}
			if !updateStates[x.Status] {
				t.Fatalf("unknown status %q", x.Status)
			}
			if x.Remote != "" && !digestOnlyRe.MatchString(x.Remote) {
				t.Fatalf("remote %q is not a sha256 digest", x.Remote)
			}
			if len(x.Note) > 200 {
				t.Fatalf("note exceeds 200 bytes: %d", len(x.Note))
			}
			if x.Status == "update" {
				updates++
			}
		}
		if u.Updates != updates {
			t.Fatalf("update count %d is not the %d rows with status update", u.Updates, updates)
		}
	})
}
