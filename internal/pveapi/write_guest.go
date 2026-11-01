// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
)

// Guest write limits, named next to the code that enforces them.
const (
	// MaxDiskGiB bounds a resized disk (64 TiB).
	MaxDiskGiB = 64 << 10
	// MaxGuestNameBytes bounds a guest name (a DNS name, RFC 1035).
	MaxGuestNameBytes = 253
)

// guestPath returns the escaped API path of one QEMU guest after validating
// node and VMID.
func guestPath(op, node string, vmid int64) (string, error) {
	if validNodeName(node) != nil {
		return "", invalid(op, "node")
	}
	if validVMID(vmid) != nil {
		return "", invalid(op, "vmid")
	}
	return "/nodes/" + url.PathEscape(node) + "/qemu/" + strconv.FormatInt(vmid, 10), nil
}

// CloneRequest is a full clone of a QEMU template or guest on the same node
// (POST /nodes/{node}/qemu/{vmid}/clone). Linked clones are not offered.
type CloneRequest struct {
	// Node is the node that holds the source and receives the clone.
	Node string
	// SourceVMID is the template or guest to clone.
	SourceVMID int64
	// NewVMID is the VMID of the new guest; it must differ from SourceVMID.
	NewVMID int64
	// Name is the new guest name (a DNS name). Empty keeps the PVE default.
	Name string
	// Storage is the target storage for the full clone. Empty keeps the
	// source storage.
	Storage string
}

// CloneVM starts a full clone and returns the UPID of the qmclone task.
func (w *Writer) CloneVM(ctx context.Context, r CloneRequest) (string, error) {
	const op = "clone"
	path, err := guestPath(op, r.Node, r.SourceVMID)
	if err != nil {
		return "", err
	}
	if validVMID(r.NewVMID) != nil || r.NewVMID == r.SourceVMID {
		return "", invalid(op, "newid")
	}
	form := url.Values{
		"newid": {strconv.FormatInt(r.NewVMID, 10)},
		"full":  {"1"},
	}
	if r.Name != "" {
		if !validDNSName(r.Name) {
			return "", invalid(op, "name")
		}
		form.Set("name", r.Name)
	}
	if r.Storage != "" {
		if validStorageID(r.Storage) != nil {
			return "", invalid(op, "storage")
		}
		form.Set("storage", r.Storage)
	}
	return w.dispatch(ctx, writeRequest{op: op, method: http.MethodPost, path: path + "/clone", form: form},
		r.Node, "qmclone", strconv.FormatInt(r.SourceVMID, 10))
}

// diskRe allowlists QEMU disk slots that may be resized.
var diskRe = regexp.MustCompile(`^(scsi([0-9]|[12][0-9]|30)|virtio([0-9]|1[0-5])|sata[0-5]|ide[0-3])$`)

// ResizeRequest sets a guest disk to an absolute size
// (PUT /nodes/{node}/qemu/{vmid}/resize). PVE refuses to shrink a disk.
type ResizeRequest struct {
	// Node is the node holding the guest.
	Node string
	// VMID is the guest.
	VMID int64
	// Disk is the disk slot, e.g. "scsi0" or "virtio0".
	Disk string
	// SizeGiB is the new absolute size in GiB, 1..MaxDiskGiB.
	SizeGiB int64
}

// ResizeDisk starts a disk resize and returns the UPID of the resize task.
// It requires a PVE version whose resize call runs as a task (PVE 8+).
func (w *Writer) ResizeDisk(ctx context.Context, r ResizeRequest) (string, error) {
	const op = "resize"
	path, err := guestPath(op, r.Node, r.VMID)
	if err != nil {
		return "", err
	}
	if !diskRe.MatchString(r.Disk) {
		return "", invalid(op, "disk")
	}
	if r.SizeGiB < 1 || r.SizeGiB > MaxDiskGiB {
		return "", invalid(op, "size")
	}
	form := url.Values{"disk": {r.Disk}, "size": {strconv.FormatInt(r.SizeGiB, 10) + "G"}}
	return w.dispatch(ctx, writeRequest{op: op, method: http.MethodPut, path: path + "/resize", form: form},
		r.Node, "resize", strconv.FormatInt(r.VMID, 10))
}

// StartVM starts a QEMU guest (POST /nodes/{node}/qemu/{vmid}/status/start)
// and returns the UPID of the qmstart task.
func (w *Writer) StartVM(ctx context.Context, node string, vmid int64) (string, error) {
	const op = "start"
	path, err := guestPath(op, node, vmid)
	if err != nil {
		return "", err
	}
	return w.dispatch(ctx, writeRequest{op: op, method: http.MethodPost, path: path + "/status/start", form: url.Values{}},
		node, "qmstart", strconv.FormatInt(vmid, 10))
}

// ConvertToTemplate converts a stopped QEMU guest into a template
// (POST /nodes/{node}/qemu/{vmid}/template) and returns the UPID of the
// qmtemplate task.
func (w *Writer) ConvertToTemplate(ctx context.Context, node string, vmid int64) (string, error) {
	const op = "template"
	path, err := guestPath(op, node, vmid)
	if err != nil {
		return "", err
	}
	return w.dispatch(ctx, writeRequest{op: op, method: http.MethodPost, path: path + "/template", form: url.Values{}},
		node, "qmtemplate", strconv.FormatInt(vmid, 10))
}

// validDNSName reports whether s is a lowercase DNS name: dot-separated
// labels of [a-z0-9-], 1..63 bytes each, not starting or ending with '-',
// at most MaxGuestNameBytes in total.
func validDNSName(s string) bool {
	if s == "" || len(s) > MaxGuestNameBytes {
		return false
	}
	label := 0
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch == '.':
			if label == 0 || s[i-1] == '-' {
				return false
			}
			label = 0
		case ch >= 'a' && ch <= 'z', ch >= '0' && ch <= '9', ch == '-':
			if ch == '-' && label == 0 {
				return false
			}
			label++
			if label > 63 {
				return false
			}
		default:
			return false
		}
	}
	return label > 0 && s[len(s)-1] != '-'
}
