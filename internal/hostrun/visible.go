// SPDX-License-Identifier: AGPL-3.0-or-later

package hostrun

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// visibleScript looks for a process of the attached run %[1]s that the
// SSH user owns: the bootstrap shell carries the execution ID on its
// command line, and the script and its children inherit it in their
// environment.
//
// It fails closed: only a complete scan that read every owned process
// (and found its own command line, which proves the listing and tr
// work) ends with visibleNone on stdout and exit 0. A marker found is
// exit 1; anything else (no /proc, tr missing or failing, a process file
// that cannot be read while the process still exists, a shell without
// test -O or 64-bit arithmetic) is exit 3 or another status, which
// callers treat as "cannot tell". The /proc entries are walked by the
// shell itself, so no argument list grows with the number of processes,
// and the only external tool is tr; grep is not used.
//
// Only processes whose /proc/<pid>/environ the SSH user owns count
// (test -O), so another local user cannot keep the target held by
// starting a process that carries the ID. The kernel reports a
// non-dumpable process as owned by root, so such a process of the run is
// not seen. The kernel also refuses the environment of an own process
// that holds capabilities the check lacks (systemd --user with
// CAP_WAKE_ALARM, for one); for such a process only the command line is
// checked, and any other unreadable environment is "cannot tell". The
// marker is assembled at run time, so the check's own command line does
// not contain it.
const visibleScript = `m=NEBULA_EXECUTION
m="${m}_ID=%[1]s"
[ -r /proc/self/environ ] || exit 3
command -v tr >/dev/null 2>&1 || exit 3
capprm() {
  while read -r k v; do
    [ "$k" = CapPrm: ] && { echo "$v"; return 0; }
  done < "$1/status"
  return 1
}
own=$(capprm /proc/$$) || exit 3
self=0
for p in /proc/[0-9]*; do
  [ -O "$p/environ" ] || continue
  if c=$(tr '\0' '\n' < "$p/cmdline"); then :; else
    [ -e "$p" ] && exit 3
    continue
  fi
  case $c in *"$m"*) exit 1;; esac
  if [ "$p" = "/proc/$$" ]; then
    case $c in *"m=NEBULA_EXECUTION"*) self=1;; esac
    continue
  fi
  if e=$(tr '\0' '\n' < "$p/environ"); then
    case $e in *"$m"*) exit 1;; esac
    continue
  fi
  [ -e "$p" ] || continue
  t=$(capprm "$p") || { [ -e "$p" ] && exit 3; continue; }
  [ $((0x$t & ~0x$own)) -ne 0 ] || exit 3
done
[ "$self" = 1 ] || exit 3
echo '` + visibleNone + `'
`

// visibleNone is what visibleScript prints after a complete scan found no
// process of the run.
const visibleNone = "nebula-visible: none"

// ErrVisibilityUnknown means the host could not tell whether a process of
// the run is still running.
var ErrVisibilityUnknown = errors.New("hostrun: cannot tell whether the run is still running")

// RunVisible reports whether a process of the attached run executionID is
// still running on the host, as far as the SSH user can see: processes
// owned by the SSH user whose command line or environment carries the
// execution ID. A process that switched to another user, became
// non-dumpable or dropped the execution ID from its environment is not
// seen. Absence is reported only on a positive confirmation from a
// complete scan; every other outcome is ErrVisibilityUnknown, and callers
// that need the target idle treat an error as running.
func RunVisible(ctx context.Context, client *ssh.Client, executionID string) (bool, error) {
	cmd, err := visibleCommand(executionID)
	if err != nil {
		return false, err
	}
	s, err := client.NewSession()
	if err != nil {
		return false, fmt.Errorf("%w: open session: %w", ErrVisibilityUnknown, err)
	}
	return runVisible(ctx, s, cmd)
}

func visibleCommand(executionID string) (string, error) {
	if !uuidRe.MatchString(executionID) {
		return "", errors.New("hostrun: execution ID is not a lowercase UUID")
	}
	return "exec /bin/sh -c " + shellQuote(fmt.Sprintf(visibleScript, executionID)), nil
}

// outputSession is the part of *ssh.Session runVisible uses.
type outputSession interface {
	Output(cmd string) ([]byte, error)
	Close() error
}

// runVisible runs the check command cmd and maps its outcome: exit 0 with
// exactly visibleNone on stdout is "not running", a plain exit 1 is
// "running", everything else (other statuses, signals, no exit status,
// other output, cancellation) is ErrVisibilityUnknown.
func runVisible(ctx context.Context, s outputSession, cmd string) (bool, error) {
	type result struct {
		out []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, err := s.Output(cmd)
		done <- result{out, err}
	}()
	var r result
	select {
	case r = <-done:
		_ = s.Close()
	case <-ctx.Done():
		_ = s.Close()
		return false, fmt.Errorf("%w: %w", ErrVisibilityUnknown, ctx.Err())
	}
	var ee *ssh.ExitError
	switch {
	case r.err == nil && string(r.out) == visibleNone+"\n":
		return false, nil
	case r.err == nil:
		return false, fmt.Errorf("%w: the check ended without confirming the run gone", ErrVisibilityUnknown)
	case errors.As(r.err, &ee) && ee.Signal() == "" && ee.ExitStatus() == 1:
		return true, nil
	}
	return false, fmt.Errorf("%w: %w", ErrVisibilityUnknown, r.err)
}
