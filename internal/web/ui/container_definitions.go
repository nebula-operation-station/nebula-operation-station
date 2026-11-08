// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"context"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/dockerhost"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Standalone containers in the container tree (ADR 0006 P2-03/P2-05,
// container update plan cu05).
//
// A standalone container is updated from the definition an administrator
// stored in the executor vault. The definition holds environment values,
// so it enters the vault only through `nebula container definition put`
// on the executor host (admin role, read from a file or stdin) and never
// passes the web server: this page has no form, route or field that
// carries one, and it never shows one. It shows only the metadata of the
// newest version (version, author, time) when the server may read it, and
// the commands an administrator runs to store or remove a definition.
//
// A container without a definition shows the update as unavailable with
// that reason when the server can read the definitions. In production it
// cannot (see ctrNoteNotRead), so the tree shows the definition status as
// unknown and points to the CLI. One with a definition is still unavailable until the batch
// planner binds docker.update members.

// ContainerDefinitionLister reads definition metadata (the executor's
// ListContainerDefinitions). Its answers carry no content and no digest.
type ContainerDefinitionLister interface {
	ListContainerDefinitions(ctx context.Context, in *pb.ListContainerDefinitionsRequest, opts ...grpc.CallOption) (*pb.ListContainerDefinitionsResponse, error)
}

// Limits of the definition lookup.
const (
	// ctrMaxDefinitions bounds the definition rows read for one host.
	ctrMaxDefinitions = 1000
	// ctrMaxShownText bounds a shown author name.
	ctrMaxShownText = 200
)

// Unavailable reasons of a standalone container.
const (
	ctrNoDefinition = "no container definition is stored for this container; an administrator stores one on the executor host (see below)"
	ctrNoPlanner    = "standalone containers are not offered here yet (no batch planner for docker.update)"
)

// ctrDefinitionView is the metadata of the newest definition version. It
// has no field for content or a digest, so the page cannot show one.
type ctrDefinitionView struct {
	Version   uint64
	CreatedBy string
	CreatedAt string
}

// ctrDefinitions is the definition status of one host's containers.
type ctrDefinitions struct {
	// Note is why the status is unknown ("" when it was read).
	Note string
	// Latest is the newest version per container name.
	Latest map[string]ctrDefinitionView
}

// Notes shown when the definition status is unknown.
const (
	// ctrNoteNotRead is the production state: cmd/nebula-server sets no
	// ContainerDefinitions reader, because the executor lets only the
	// admin role call ListContainerDefinitions and the server role gets no
	// new permission for it (docs/implementation/m0.md, known gaps).
	ctrNoteNotRead      = "this server does not read container definitions (the executor lets only an administrator list them); an administrator checks them with nebula container definition list"
	ctrNoteDenied       = "the executor lets only an administrator read container definitions; check them with nebula container definition list"
	ctrNoteFailed       = "the executor's container definitions could not be read"
	ctrNoteTooMany      = "too many container definitions to show here; an administrator checks them with nebula container definition list"
	ctrNoteInconsistent = "the executor's answer about container definitions is inconsistent; an administrator checks them with nebula container definition list"
)

// ctrLoadDefinitions reads the definition metadata of hostID. An answer
// over ctrMaxDefinitions rows, or with two newest versions of one
// container, leaves the status unknown instead of showing a partial or
// wrong one.
func (h *Handler) ctrLoadDefinitions(ctx context.Context, hostID string) ctrDefinitions {
	if h.containerDefinitions == nil {
		return ctrDefinitions{Note: ctrNoteNotRead}
	}
	resp, err := h.containerDefinitions.ListContainerDefinitions(ctx, &pb.ListContainerDefinitionsRequest{HostId: hostID})
	switch {
	case status.Code(err) == codes.PermissionDenied:
		return ctrDefinitions{Note: ctrNoteDenied}
	case err != nil:
		h.log.Warn("container definitions", "host", hostID, "error", err)
		return ctrDefinitions{Note: ctrNoteFailed}
	}
	rows := resp.GetDefinitions()
	if len(rows) > ctrMaxDefinitions {
		h.log.Warn("container definitions over the limit", "host", hostID, "rows", len(rows), "limit", ctrMaxDefinitions)
		return ctrDefinitions{Note: ctrNoteTooMany}
	}
	d := ctrDefinitions{Latest: map[string]ctrDefinitionView{}}
	for _, info := range rows {
		// Only the newest version of this host's containers is shown.
		if !info.GetLatest() || info.GetHostId() != hostID || info.GetVersion() == 0 {
			continue
		}
		if _, dup := d.Latest[info.GetContainerName()]; dup {
			h.log.Warn("container definitions with two newest versions", "host", hostID)
			return ctrDefinitions{Note: ctrNoteInconsistent}
		}
		v := ctrDefinitionView{Version: info.GetVersion(), CreatedBy: ctrShownText(info.GetCreatedBy())}
		if at := info.GetCreatedAtUnix(); at > 0 {
			v.CreatedAt = time.Unix(at, 0).UTC().Format(time.RFC3339)
		}
		d.Latest[info.GetContainerName()] = v
	}
	return d
}

// ctrShownText bounds a string from the executor for display; the
// template escapes it.
func ctrShownText(s string) string {
	r := []rune(s)
	if len(r) > ctrMaxShownText {
		return string(r[:ctrMaxShownText]) + "…"
	}
	return s
}

// ctrStandaloneUnit builds the tree entry of a standalone container. defs
// is loaded on first use, once per host.
func (h *Handler) ctrStandaloneUnit(ctx context.Context, hostID string, u dockerhost.PreviewUnit, defs *ctrDefinitions, loaded *bool) ctrUnitView {
	name := ""
	if len(u.Targets) == 1 {
		name = u.Targets[0].ContainerName
	}
	v := ctrUnitView{Standalone: true, Label: u.ContainerID, ContainerName: name}
	if u.Reason != "" {
		v.Unavailable = ctrReason(u.Reason)
	}
	if name == "" {
		// The preview parser gives an available unit exactly one target;
		// without it there is no name to look a definition up by.
		if v.Unavailable == "" {
			v.Unavailable = ctrNoPlanner
		}
		return v
	}
	v.PutCommand = "nebula container definition put " + hostID + " " + name + " DEFINITION.json"
	v.RemoveCommand = "nebula container definition remove " + hostID + " " + name
	if !*loaded {
		*defs, *loaded = h.ctrLoadDefinitions(ctx, hostID), true
	}
	switch d, ok := defs.Latest[name]; {
	case defs.Note != "":
		v.DefinitionNote = defs.Note
	case ok:
		v.Definition = &d
	default:
		v.DefinitionNote = "none stored"
		if v.Unavailable == "" {
			v.Unavailable = ctrNoDefinition
		}
	}
	if v.Unavailable == "" {
		v.Unavailable = ctrNoPlanner
	}
	return v
}
