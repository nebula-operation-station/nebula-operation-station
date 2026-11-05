// SPDX-License-Identifier: AGPL-3.0-or-later

package hostrun

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/ssh"
)

// visibleScript looks for a process of the attached run %[1]s that the
// SSH user owns: the bootstrap shell carries the execution ID on its
// command line, and the script and its children inherit it in their
// environment. %[2]s is the shell-quoted process root (procRoot in
// production; tests pass a fake tree), %[3]d the most processes it reads
// (visibleMaxProcs) and %[4]d the deepest parent chain it follows
// (visibleMaxDepth).
//
// It fails closed: only a complete scan that read every owned process
// (and found its own command line, which proves the listing and tr
// work) ends with visibleNone on stdout and exit 0. A marker found is
// exit 1; anything else (no /proc, tr missing or failing, a process file
// that cannot be read while the process still exists, a shell without
// test -O or 64-bit arithmetic, more owned processes than the limit) is
// exit 3 or another status, which callers treat as "cannot tell". The
// process entries are walked by the shell itself, so no argument list
// grows with the number of processes, and the only external tool is tr;
// grep is not used. Kernel threads (PF_KTHREAD in the stat flags, set
// only by the kernel) are skipped before anything is forked for them and
// do not count against the limit.
//
// Only processes whose /proc/<pid>/environ the SSH user owns count
// (test -O), so another local user cannot keep the target held by
// starting a process that carries the ID. The kernel reports a
// non-dumpable process as owned by root, so such a process of the run is
// not seen. The kernel also refuses the environment of an own process
// that holds capabilities the check lacks. Such a process is skipped only
// when it is the user's service manager: comm "systemd", command line
// exactly "<dir>/systemd --user" for <dir> in /lib/systemd or
// /usr/lib/systemd, and a parent chain up to init (at most %[4]d steps,
// every link readable) whose command lines do not carry the ID. Any
// other unreadable environment is "cannot tell". A process of the run
// that deliberately imitates systemd --user (comm, command line, and a
// parent chain without the ID, for example after being orphaned) is not
// seen; that needs intent, not just a capability binary in the script.
// The marker is assembled at run time, so the check's own command line
// does not contain it.
const visibleScript = `m=NEBULA_EXECUTION
m="${m}_ID=%[1]s"
r=%[2]s
[ -r /proc/self/environ ] || exit 3
command -v tr >/dev/null 2>&1 || exit 3
sfield() {
  while read -r k v; do
    [ "$k" = "$2" ] && { sv=$v; return 0; }
  done 2>/dev/null < "$1/status"
  return 1
}
pstat() {
  IFS= read -r l 2>/dev/null < "$1/stat" || return 1
  set -- ${l##*) }
  [ $# -ge 7 ] || return 1
  case $2$7 in ''|*[!0-9]*) return 1;; esac
  pp=$2; fl=$7
}
walk() {
  q=$1; i=0
  while :; do
    pstat "$q" || exit 3
    [ "$pp" -le 1 ] && return 0
    i=$((i + 1))
    [ "$i" -gt %[4]d ] && exit 3
    q=$r/$pp
    a=$(tr '\0' '\n' 2>/dev/null < "$q/cmdline") || exit 3
    case $a in *"$m"*) exit 1;; esac
  done
}
sfield "$r/$$" CapPrm: || exit 3
own=$sv
self=0
n=0
for p in "$r"/[0-9]*; do
  [ -O "$p/environ" ] || continue
  if pstat "$p"; then :; else
    [ -e "$p" ] && exit 3
    continue
  fi
  [ $((fl & 0x200000)) -ne 0 ] && continue
  n=$((n + 1))
  [ "$n" -gt %[3]d ] && exit 3
  if c=$(tr '\0' '\n' 2>/dev/null < "$p/cmdline"); then :; else
    [ -e "$p" ] && exit 3
    continue
  fi
  case $c in *"$m"*) exit 1;; esac
  if [ "$p" = "$r/$$" ]; then
    case $c in *"m=NEBULA_EXECUTION"*) self=1;; esac
    continue
  fi
  if e=$(tr '\0' '\n' 2>/dev/null < "$p/environ"); then
    case $e in *"$m"*) exit 1;; esac
    continue
  fi
  [ -e "$p" ] || continue
  sfield "$p" CapPrm: || { [ -e "$p" ] && exit 3; continue; }
  [ $((0x$sv & ~0x$own)) -ne 0 ] || exit 3
  sfield "$p" Name: || exit 3
  [ "$sv" = systemd ] || exit 3
  case $c in
    /lib/systemd/systemd"
"--user|/usr/lib/systemd/systemd"
"--user) ;;
    *) exit 3;;
  esac
  walk "$p"
done
[ "$self" = 1 ] || exit 3
echo '` + visibleNone + `'
`

// procRoot is the process root the check scans on a managed host.
const procRoot = "/proc"

// visibleMaxProcs bounds the processes one check reads, so that it ends
// within the executor's recheck window on a large host; a host with more
// owned processes (kernel threads excluded) is "cannot tell".
const visibleMaxProcs = 4096

// visibleMaxDepth bounds the parent chain followed for a skipped
// process.
const visibleMaxDepth = 64

// visibleMaxOutput bounds what the check may print on stdout and on
// stderr. The only accepted output is visibleNone and a newline; more on
// either stream is "cannot tell".
const visibleMaxOutput = 256

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
	return runVisible(ctx, sshSession{s}, cmd)
}

func visibleCommand(executionID string) (string, error) {
	script, err := visibleCheck(executionID, procRoot, visibleMaxProcs)
	if err != nil {
		return "", err
	}
	return "exec /bin/sh -c " + shellQuote(script), nil
}

// visibleCheck returns the check script for executionID scanning root,
// reading at most maxProcs processes. Production always passes procRoot
// and visibleMaxProcs; only tests pass anything else.
func visibleCheck(executionID, root string, maxProcs int) (string, error) {
	if !uuidRe.MatchString(executionID) {
		return "", errors.New("hostrun: execution ID is not a lowercase UUID")
	}
	return fmt.Sprintf(visibleScript, executionID, shellQuote(root), maxProcs, visibleMaxDepth), nil
}

// visibleSession is the part of an SSH session runVisible uses.
type visibleSession interface {
	// RunWith runs cmd with its stdout and stderr going to the writers.
	RunWith(cmd string, stdout, stderr io.Writer) error
	Close() error
}

type sshSession struct{ s *ssh.Session }

func (s sshSession) RunWith(cmd string, stdout, stderr io.Writer) error {
	s.s.Stdout, s.s.Stderr = stdout, stderr
	return s.s.Run(cmd)
}

func (s sshSession) Close() error { return s.s.Close() }

// cappedWriter keeps the first max bytes written to it. Past that it
// keeps accepting (and dropping) data, so the session's copy loop never
// stalls, and closes over once.
type cappedWriter struct {
	mu   sync.Mutex
	max  int
	buf  []byte
	over chan struct{}
	once sync.Once
}

func newCappedWriter(limit int, over chan struct{}) *cappedWriter {
	return &cappedWriter{max: limit, over: over}
}

func (w *cappedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if room := w.max - len(w.buf); len(p) <= room {
		w.buf = append(w.buf, p...)
	} else {
		w.buf = append(w.buf, p[:max(room, 0)]...)
		w.once.Do(func() { close(w.over) })
	}
	return len(p), nil
}

func (w *cappedWriter) bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return bytes.Clone(w.buf)
}

// runVisible runs the check command cmd and maps its outcome: exit 0 with
// exactly visibleNone on stdout is "not running", a plain exit 1 is
// "running", everything else (other statuses, signals, no exit status,
// other output, more than visibleMaxOutput bytes on stdout or stderr,
// cancellation) is ErrVisibilityUnknown. On too much output the session
// is closed at once, so the host stops sending; the writers keep
// draining (and dropping) until the session has ended.
func runVisible(ctx context.Context, s visibleSession, cmd string) (bool, error) {
	over := make(chan struct{})
	stdout := newCappedWriter(visibleMaxOutput, over)
	stderr := newCappedWriter(visibleMaxOutput, over)
	done := make(chan error, 1)
	go func() { done <- s.RunWith(cmd, stdout, stderr) }()
	var err error
	select {
	case err = <-done:
	case <-over:
		// Stop the host from sending more; the session ends at once.
		_ = s.Close()
		select {
		case err = <-done:
		case <-ctx.Done():
			return false, fmt.Errorf("%w: %w", ErrVisibilityUnknown, ctx.Err())
		}
	case <-ctx.Done():
		_ = s.Close()
		return false, fmt.Errorf("%w: %w", ErrVisibilityUnknown, ctx.Err())
	}
	_ = s.Close()
	select {
	case <-over:
		return false, fmt.Errorf("%w: the check printed more than %d bytes", ErrVisibilityUnknown, visibleMaxOutput)
	default:
	}
	var ee *ssh.ExitError
	switch {
	case err == nil && string(stdout.bytes()) == visibleNone+"\n":
		return false, nil
	case err == nil:
		return false, fmt.Errorf("%w: the check ended without confirming the run gone", ErrVisibilityUnknown)
	case errors.As(err, &ee) && ee.Signal() == "" && ee.ExitStatus() == 1:
		return true, nil
	}
	return false, fmt.Errorf("%w: %w", ErrVisibilityUnknown, err)
}
