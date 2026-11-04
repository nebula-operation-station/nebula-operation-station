// SPDX-License-Identifier: AGPL-3.0-or-later

package softwarecat

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/dockerhost"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/gpuhost"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/osdebian"
)

// Ingest limits for untrusted action results.
const (
	// MaxResultSize bounds an action result handed to an Ingest
	// function (docker.list carries up to 4 MiB of base64 text).
	MaxResultSize = 8 << 20
	// maxOSReleaseSize bounds the decoded /etc/os-release text.
	maxOSReleaseSize = 64 << 10
	// maxOSReleaseLines bounds how many os-release lines are read.
	maxOSReleaseLines = 200
)

// The ingest functions turn the results of read actions NOS already
// runs into observations (ADR 0009 D5). They take the managed host and
// target from the server's own records and the observation time from
// the server's execution record; only the identifiers and versions come
// from the result, which is untrusted. They never create placements,
// assets or hosts.

func checkIngest(target Target, result []byte, hostOnly bool) error {
	if err := target.validate(); err != nil {
		return err
	}
	if hostOnly && target.Kind == TargetContainer {
		return fmt.Errorf("container target for a host-level result: %w", ErrInvalidInput)
	}
	if len(result) > MaxResultSize {
		return fmt.Errorf("result of %d bytes: %w", len(result), ErrInvalidResult)
	}
	return nil
}

// IngestCoreFacts records the operating system of a core.facts result:
// the os-release ID (with VERSION_ID), or Proxmox VE when the result
// says the host is a Proxmox VE node.
func (s *Store) IngestCoreFacts(ctx context.Context, target Target, result []byte, at time.Time) (IngestReport, error) {
	if err := checkIngest(target, result, true); err != nil {
		return IngestReport{}, fmt.Errorf("ingest core.facts: %w", err)
	}
	var doc struct {
		OSRelease string `json:"os_release"`
		Proxmox   bool   `json:"proxmox"`
	}
	if err := json.Unmarshal(result, &doc); err != nil {
		return IngestReport{}, fmt.Errorf("ingest core.facts: %w", ErrInvalidResult)
	}
	if base64.StdEncoding.DecodedLen(len(doc.OSRelease)) > maxOSReleaseSize+3 {
		return IngestReport{}, fmt.Errorf("ingest core.facts: os-release too large: %w", ErrInvalidResult)
	}
	raw, err := base64.StdEncoding.DecodeString(doc.OSRelease)
	if err != nil || !utf8.Valid(raw) {
		return IngestReport{}, fmt.Errorf("ingest core.facts: os-release encoding: %w", ErrInvalidResult)
	}
	osr := parseOSRelease(string(raw))
	id, version := osr["ID"], osr["VERSION_ID"]
	if doc.Proxmox {
		// VERSION_ID is Debian's on a Proxmox VE node, not Proxmox's.
		id, version = "proxmox-ve", ""
	}
	if id == "" {
		return IngestReport{}, nil
	}
	return s.observe(ctx, []item{{
		target: target, res: FromOSRelease(id, doc.Proxmox),
		identifier: id, version: version, source: SourceCoreFacts,
	}}, at)
}

// parseOSRelease reads KEY=value lines of an os-release file (bounded
// line count; values unquoted).
func parseOSRelease(text string) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 0, 4096), maxOSReleaseSize)
	for n := 0; n < maxOSReleaseLines && sc.Scan(); n++ {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok || (k != "ID" && k != "VERSION_ID") {
			continue
		}
		if uq, err := strconv.Unquote(v); err == nil {
			v = uq
		} else {
			v = strings.Trim(v, `"'`)
		}
		out[k] = strings.TrimSpace(v)
	}
	return out
}

// IngestDockerList records a docker.list result: Docker itself (with
// the daemon version) on the target, and every container's image as an
// observation of that container (keyed by its full ID) with the image
// tag as version. A host without Docker or a precheck result records
// nothing.
func (s *Store) IngestDockerList(ctx context.Context, target Target, result []byte, at time.Time) (IngestReport, error) {
	if err := checkIngest(target, result, true); err != nil {
		return IngestReport{}, fmt.Errorf("ingest docker.list: %w", err)
	}
	l, err := dockerhost.ParseList(result)
	if err != nil {
		return IngestReport{}, fmt.Errorf("ingest docker.list: %w", ErrInvalidResult)
	}
	if l.Phase != "done" || !l.Present {
		return IngestReport{}, nil
	}
	items := []item{{
		target: target, res: FromPackage("docker"),
		identifier: "docker", version: l.Version, source: SourceDockerList,
	}}
	var skipped int
	for _, c := range l.Containers {
		ct := Target{Kind: TargetContainer, HostID: target.HostID, Ref: c.FullID}
		if ct.validate() != nil || c.Image == "" {
			skipped++
			continue
		}
		items = append(items, item{
			target: ct, res: FromImage(c.Image),
			identifier: c.Image, version: imageTag(c.Image), source: SourceDockerList,
		})
	}
	rep, err := s.observe(ctx, items, at)
	if err != nil {
		return IngestReport{}, fmt.Errorf("ingest docker.list: %w", err)
	}
	rep.Skipped += skipped
	return rep, nil
}

// imageTag returns the tag of an image reference: the part after the
// last ':' that follows the last '/', before any digest; "" if none.
func imageTag(ref string) string {
	if i := strings.IndexByte(ref, '@'); i >= 0 {
		ref = ref[:i]
	}
	j := strings.LastIndexByte(ref, ':')
	if j < 0 || j < strings.LastIndexByte(ref, '/') {
		return ""
	}
	return ref[j+1:]
}

// IngestGPUStatus records NVIDIA when a gpu.status result (the GPU
// reader) lists at least one GPU; the GPU model is kept as the
// identifier. A host without nvidia-smi or a precheck result records
// nothing.
func (s *Store) IngestGPUStatus(ctx context.Context, target Target, result []byte, at time.Time) (IngestReport, error) {
	if err := checkIngest(target, result, true); err != nil {
		return IngestReport{}, fmt.Errorf("ingest gpu.status: %w", err)
	}
	st, err := gpuhost.ParseGPUStatus(result)
	if err != nil {
		return IngestReport{}, fmt.Errorf("ingest gpu.status: %w", ErrInvalidResult)
	}
	if st.Phase != "done" || !st.Present || len(st.GPUs) == 0 {
		return IngestReport{}, nil
	}
	return s.observe(ctx, []item{{
		target: target, res: FromPackage("nvidia"),
		identifier: st.GPUs[0].Name, source: SourceGPUStatus,
	}}, at)
}

// IngestServiceList records the loaded systemd service units of a
// service.list result, normalized by FromUnit. Units that are not
// loaded (not-found, masked, error) say nothing about installed
// software and are skipped.
func (s *Store) IngestServiceList(ctx context.Context, target Target, result []byte, at time.Time) (IngestReport, error) {
	if err := checkIngest(target, result, true); err != nil {
		return IngestReport{}, fmt.Errorf("ingest service.list: %w", err)
	}
	units, err := osdebian.ParseUnits(result)
	if err != nil {
		return IngestReport{}, fmt.Errorf("ingest service.list: %w", ErrInvalidResult)
	}
	var items []item
	var skipped int
	for _, u := range units {
		if u.Load != "loaded" {
			skipped++
			continue
		}
		items = append(items, item{
			target: target, res: FromUnit(u.Name),
			identifier: u.Name, source: SourceServiceList,
		})
	}
	rep, err := s.observe(ctx, items, at)
	if err != nil {
		return IngestReport{}, fmt.Errorf("ingest service.list: %w", err)
	}
	rep.Skipped += skipped
	return rep, nil
}
