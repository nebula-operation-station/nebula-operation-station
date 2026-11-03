// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
)

// Power-operation timeout limits, named next to the code that enforces them.
const (
	// MinPowerTimeoutSec is the smallest guest power-operation timeout in
	// seconds.
	MinPowerTimeoutSec = 1
	// MaxPowerTimeoutSec is the largest guest power-operation timeout in
	// seconds (one hour).
	MaxPowerTimeoutSec = 3600
)

// validPowerTimeout reports whether timeoutSec is a valid guest
// power-operation timeout in seconds.
func validPowerTimeout(timeoutSec int) bool {
	return timeoutSec >= MinPowerTimeoutSec && timeoutSec <= MaxPowerTimeoutSec
}

// ShutdownGuest performs a graceful shutdown of a QEMU guest or LXC container
// (POST /nodes/{node}/{kind}/{vmid}/status/shutdown) and returns the UPID of
// the qmshutdown (QEMU) or vzshutdown (LXC) task. timeoutSec is bounded to
// 1..MaxPowerTimeoutSec seconds. forceStop is always sent as 0: NOS never
// falls back to a force stop (ADR 0006, phase 2: "no automatic force-stop
// fallback").
func (w *Writer) ShutdownGuest(ctx context.Context, kind GuestKind, node string, vmid int64, timeoutSec int) (string, error) {
	const op = "shutdown"
	path, err := guestKindPath(op, kind, node, vmid)
	if err != nil {
		return "", err
	}
	if !validPowerTimeout(timeoutSec) {
		return "", invalid(op, "timeout")
	}
	wantType := "qmshutdown"
	if kind == GuestLXC {
		wantType = "vzshutdown"
	}
	form := url.Values{"timeout": {strconv.Itoa(timeoutSec)}, "forceStop": {"0"}}
	return w.dispatch(ctx, writeRequest{op: op, method: http.MethodPost, path: path + "/status/shutdown", form: form},
		node, wantType, strconv.FormatInt(vmid, 10))
}

// RebootGuest performs a graceful reboot of a QEMU guest or LXC container
// (POST /nodes/{node}/{kind}/{vmid}/status/reboot) and returns the UPID of
// the qmreboot (QEMU) or vzreboot (LXC) task. timeoutSec is bounded to
// 1..MaxPowerTimeoutSec seconds.
func (w *Writer) RebootGuest(ctx context.Context, kind GuestKind, node string, vmid int64, timeoutSec int) (string, error) {
	const op = "reboot"
	path, err := guestKindPath(op, kind, node, vmid)
	if err != nil {
		return "", err
	}
	if !validPowerTimeout(timeoutSec) {
		return "", invalid(op, "timeout")
	}
	wantType := "qmreboot"
	if kind == GuestLXC {
		wantType = "vzreboot"
	}
	form := url.Values{"timeout": {strconv.Itoa(timeoutSec)}}
	return w.dispatch(ctx, writeRequest{op: op, method: http.MethodPost, path: path + "/status/reboot", form: form},
		node, wantType, strconv.FormatInt(vmid, 10))
}

// StopGuest performs a hard stop of a QEMU guest or LXC container
// (POST /nodes/{node}/{kind}/{vmid}/status/stop) and returns the UPID of the
// qmstop (QEMU) or vzstop (LXC) task. It is an explicit destructive verb
// (ADR 0006, phase 2: "Hard stop / reset: explicit destructive verb").
// No parameters are sent, in particular no skiplock or overrude-shutdown:
// NOS never overrides PVE's lock or shutdown state for a hard stop.
func (w *Writer) StopGuest(ctx context.Context, kind GuestKind, node string, vmid int64) (string, error) {
	const op = "stop"
	path, err := guestKindPath(op, kind, node, vmid)
	if err != nil {
		return "", err
	}
	wantType := "qmstop"
	if kind == GuestLXC {
		wantType = "vzstop"
	}
	return w.dispatch(ctx, writeRequest{op: op, method: http.MethodPost, path: path + "/status/stop", form: url.Values{}},
		node, wantType, strconv.FormatInt(vmid, 10))
}

// ResetGuest performs a hard reset of a QEMU guest
// (POST /nodes/{node}/qemu/{vmid}/status/reset) and returns the UPID of the
// qmreset task. It is an explicit destructive verb (ADR 0006, phase 2:
// "Hard stop / reset: explicit destructive verb"). Reset is QEMU-only: there
// is no kind parameter and the path is fixed to /qemu/, so an LXC reset is
// refused before anything is sent (ADR 0006, phase 2: "LXC reset
// unsupported"). No parameters are sent.
func (w *Writer) ResetGuest(ctx context.Context, node string, vmid int64) (string, error) {
	const op = "reset"
	path, err := guestPath(op, node, vmid)
	if err != nil {
		return "", err
	}
	return w.dispatch(ctx, writeRequest{op: op, method: http.MethodPost, path: path + "/status/reset", form: url.Values{}},
		node, "qmreset", strconv.FormatInt(vmid, 10))
}
