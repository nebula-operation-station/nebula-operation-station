// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Migration request limits. targetstorage is sent verbatim, so a single
// storage id is bounded by MaxRefBytes (via validStorageID) and a complete
// "src:dst[,src:dst]" mapping is bounded in total length and pair count.
const (
	// MaxStorageTargetBytes is the largest targetstorage value accepted.
	MaxStorageTargetBytes = 512
	// MaxStorageMappingPairs is the largest number of "src:dst" pairs in a
	// targetstorage mapping.
	MaxStorageMappingPairs = 16
)

// MigrateRequest describes an intra-cluster guest migration (ADR 0006, phase
// 2: "intra-cluster migration"). The source and destination nodes are exact
// and must differ. The migration mode is explicit per kind: QEMU uses Online
// (live vs. stop-and-migrate), LXC uses Restart (live vs. stop-migrate-
// restart). WithLocalDisks and TargetStorage are optional and sent only when
// set.
type MigrateRequest struct {
	// Kind is the guest kind (qemu or lxc).
	Kind GuestKind
	// Node is the exact source node.
	Node string
	// VMID is the guest to migrate.
	VMID int64
	// Target is the exact destination node; it must differ from Node.
	Target string
	// Online selects a live (online) QEMU migration. It must be false for
	// LXC, which chooses its mode via Restart.
	Online bool
	// Restart selects an LXC restart migration (stop, migrate, start). It
	// must be false for QEMU.
	Restart bool
	// TimeoutSec is the LXC restart-migration shutdown timeout in seconds
	// (MinPowerTimeoutSec..MaxPowerTimeoutSec). It is required for an LXC
	// restart migration and must be zero otherwise.
	TimeoutSec int
	// TargetStorage is an optional complete storage target: a single storage
	// id or a "src:dst[,src:dst]" mapping. Empty keeps the PVE default.
	TargetStorage string
	// WithLocalDisks moves local disks too; sent only when true.
	WithLocalDisks bool
}

// MigrateGuest migrates a QEMU guest or LXC container to another node in the
// same cluster and returns the UPID of the qmigrate (QEMU) or vzmigrate (LXC)
// task. The source (r.Node) and destination (r.Target) nodes must be exact
// and different. The mode is explicit per kind: QEMU uses r.Online (live vs.
// stop-and-migrate), LXC uses r.Restart (live vs. stop-migrate-restart). NOS
// never sends force or migration_network, and it sends with-local-disks and
// targetstorage only when explicitly requested (ADR 0006, phase 2:
// "intra-cluster migration").
func (w *Writer) MigrateGuest(ctx context.Context, r MigrateRequest) (string, error) {
	const op = "migrate"
	path, err := guestKindPath(op, r.Kind, r.Node, r.VMID)
	if err != nil {
		return "", err
	}
	if validNodeName(r.Target) != nil || r.Target == r.Node {
		return "", invalid(op, "target")
	}
	if r.TargetStorage != "" && !validStorageTarget(r.TargetStorage) {
		return "", invalid(op, "targetstorage")
	}

	wantType := "qmigrate"
	form := url.Values{"target": {r.Target}}
	if r.Kind == GuestLXC {
		wantType = "vzmigrate"
		if r.Online {
			return "", invalid(op, "online")
		}
		if r.WithLocalDisks {
			// with-local-disks exists only on the QEMU migrate endpoint.
			return "", invalid(op, "with_local_disks")
		}
		if r.Restart {
			if !validPowerTimeout(r.TimeoutSec) {
				return "", invalid(op, "timeout")
			}
			form.Set("restart", "1")
			form.Set("timeout", strconv.Itoa(r.TimeoutSec))
		} else {
			if r.TimeoutSec != 0 {
				return "", invalid(op, "timeout")
			}
			form.Set("restart", "0")
		}
	} else {
		if r.Restart {
			return "", invalid(op, "restart")
		}
		if r.TimeoutSec != 0 {
			return "", invalid(op, "timeout")
		}
		if r.Online {
			form.Set("online", "1")
		} else {
			form.Set("online", "0")
		}
	}
	if r.WithLocalDisks {
		form.Set("with-local-disks", "1")
	}
	if r.TargetStorage != "" {
		// The QEMU endpoint names it targetstorage, pct migrate target-storage.
		key := "targetstorage"
		if r.Kind == GuestLXC {
			key = "target-storage"
		}
		form.Set(key, r.TargetStorage)
	}
	return w.dispatch(ctx, writeRequest{op: op, method: http.MethodPost, path: path + "/migrate", form: form},
		r.Node, wantType, strconv.FormatInt(r.VMID, 10))
}

// validStorageTarget reports whether target is a valid PVE migration
// targetstorage value: either a single storage id or a complete
// "src:dst[,src:dst]" mapping. It is sent verbatim, so every component is
// checked.
func validStorageTarget(target string) bool {
	if target == "" {
		return true
	}
	if len(target) > MaxStorageTargetBytes {
		return false
	}
	if strings.Contains(target, ":") {
		pairs := strings.Split(target, ",")
		if len(pairs) > MaxStorageMappingPairs {
			return false
		}
		for _, pair := range pairs {
			src, dst, ok := strings.Cut(pair, ":")
			if !ok {
				return false
			}
			if validStorageID(src) != nil || validStorageID(dst) != nil {
				return false
			}
		}
		return true
	}
	if strings.Contains(target, ",") {
		return false
	}
	return validStorageID(target) == nil
}
