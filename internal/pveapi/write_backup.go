// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
)

// Backup write limits, named next to the code that enforces them.
const (
	// MaxBackupBandwidthKiB bounds the vzdump bwlimit we send, in KiB/s
	// (ADR 0006 P2-01: bandwidth is optional; above this a limit is
	// meaningless for a homelab link).
	MaxBackupBandwidthKiB = 10_000_000
)

// backupModes is the closed set of vzdump modes BackupNow may send
// (ADR 0006 P2-01: exact guest, storage, mode and bandwidth).
var backupModes = map[string]bool{
	"snapshot": true,
	"suspend":  true,
	"stop":     true,
}

// backupCompress is the closed set of vzdump compression values BackupNow
// may send. "0" means no compression; an empty request field defaults to
// zstd.
var backupCompress = map[string]bool{
	"zstd": true,
	"lzo":  true,
	"gzip": true,
	"0":    true,
}

// BackupRequest is the checked input of BackupNow
// (POST /nodes/{node}/vzdump). It describes a backup of exactly one guest.
type BackupRequest struct {
	// Node is the node on which vzdump runs.
	Node string
	// VMID is the single guest to back up.
	VMID int64
	// Storage is the target storage (a validated storage id).
	Storage string
	// Mode is the vzdump mode: "snapshot", "suspend" or "stop".
	Mode string
	// BandwidthKiB is the optional bandwidth limit in KiB/s. Zero sends no
	// bwlimit; 1..MaxBackupBandwidthKiB is sent.
	BandwidthKiB int
	// Compress is the vzdump compression: "zstd" (the default when empty),
	// "lzo", "gzip" or "0" (no compression).
	Compress string
}

// BackupNow starts a vzdump backup of exactly one guest and returns the UPID
// of the vzdump task (ADR 0006 P2-01). The request always carries a single
// vmid, the storage, the mode, the compression and remove=0; it never sends
// the pruning or deletion flags (all, exclude, prune-backups, mailto,
// script, dumpdir, stdout).
func (w *Writer) BackupNow(ctx context.Context, r BackupRequest) (string, error) {
	const op = "backup-now"
	if validNodeName(r.Node) != nil {
		return "", invalid(op, "node")
	}
	if validVMID(r.VMID) != nil {
		return "", invalid(op, "vmid")
	}
	if validStorageID(r.Storage) != nil {
		return "", invalid(op, "storage")
	}
	if !backupModes[r.Mode] {
		return "", invalid(op, "mode")
	}
	if r.BandwidthKiB < 0 || r.BandwidthKiB > MaxBackupBandwidthKiB {
		return "", invalid(op, "bwlimit")
	}
	compress := r.Compress
	if compress == "" {
		compress = "zstd"
	}
	if !backupCompress[compress] {
		return "", invalid(op, "compress")
	}
	form := url.Values{
		"vmid":     {strconv.FormatInt(r.VMID, 10)},
		"storage":  {r.Storage},
		"mode":     {r.Mode},
		"compress": {compress},
		"remove":   {"0"},
	}
	if r.BandwidthKiB > 0 {
		form.Set("bwlimit", strconv.Itoa(r.BandwidthKiB))
	}
	path := "/nodes/" + url.PathEscape(r.Node) + "/vzdump"
	return w.dispatch(ctx, writeRequest{op: op, method: http.MethodPost, path: path, form: form},
		r.Node, "vzdump", strconv.FormatInt(r.VMID, 10))
}
