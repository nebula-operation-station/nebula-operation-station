// SPDX-License-Identifier: AGPL-3.0-or-later

// Package hostrun runs an approved action on a managed host over an
// established SSH connection (spec 07, attached runs). Only the executor
// uses it, after permit.AuthorizeGrant.
//
// The remote command is fixed and contains no request data except the
// execution ID (a validated lowercase UUID). Parameters and script travel
// on stdin: first one line with the base64 of the canonical parameters,
// then the script bytes. A POSIX sh bootstrap writes both into a private
// temporary directory (umask 077, removed on exit), runs the script with
// /bin/sh as the SSH user (a script that needs root calls `sudo -n`
// itself; NOPASSWD sudo is effectively root, spec 08) and with stdin from
// /dev/null. stdout is the result document, stderr the log.
//
// Host output is untrusted (spec 09): the result is bounded, must be valid
// UTF-8 and exactly one JSON document; the log is bounded with a visible
// truncation marker.
package hostrun

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// Limits (spec 09 defaults).
const (
	MaxResult = 1 << 20
	MaxLog    = 10 << 20
	// MaxTimeout bounds attached runs; longer work is a durable job.
	MaxTimeout     = 10 * time.Minute
	DefaultTimeout = time.Minute
)

// killGrace is how long a timed-out attached run has between SIGTERM and
// SIGKILL (a variable for tests).
var killGrace = 5 * time.Second

// TruncationMarker ends a log that hit MaxLog.
const TruncationMarker = "\n[nebula: log truncated at 10 MiB]\n"

// Classes of a finished attempt (spec 07 error classes).
const (
	ClassSuccess           = "success"
	ClassScriptFailed      = "script_failed"
	ClassScriptInterrupted = "script_interrupted"
	ClassExecutionTimeout  = "execution_timeout"
	ClassResultMissing     = "result_missing"
	ClassPrecheckFailed    = "precheck_failed"
	ClassPostcheckFailed   = "postcheck_failed"
)

// Exit statuses an action uses to report its own checks (adapter
// convention; the result document says why).
const (
	ExitPrecheckFailed  = 10
	ExitPostcheckFailed = 11
)

// Result of an attached run. Result and Log are untrusted host output.
type Result struct {
	Class        string
	Detail       string
	ExitCode     int
	Result       []byte
	Log          []byte
	LogTruncated bool
	Duration     time.Duration
}

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// bootstrapExit is the exit status range the bootstrap uses for its own
// failures; it also prints bootstrapTag on stderr so that a script's own
// exit status in this range is not mistaken for one.
const (
	bootstrapExitMin = 120
	bootstrapExitMax = 124
	bootstrapTag     = "nebula-bootstrap: "
)

// bootstrap is the fixed remote program. %[1]s is the execution ID, %[2]s
// the secrets block (empty without secrets).
const bootstrap = `umask 077
s=
d=$(mktemp -d "${TMPDIR:-/tmp}/nebula.XXXXXXXXXX") || { echo "nebula-bootstrap: mktemp failed" >&2; exit 120; }
trap 'rm -rf "$d" ${s:+"$s"}' EXIT
trap 'exit 129' HUP
trap 'exit 143' TERM
IFS= read -r p || { echo "nebula-bootstrap: no parameters" >&2; exit 121; }
printf '%%s' "$p" | base64 -d > "$d/params.json" || { echo "nebula-bootstrap: base64 failed" >&2; exit 122; }
%[2]scat > "$d/action.sh" || { echo "nebula-bootstrap: cannot write the script" >&2; exit 123; }
cd "$d" || { echo "nebula-bootstrap: cd failed" >&2; exit 124; }
NEBULA_EXECUTION_ID=%[1]s NEBULA_PARAMS="$d/params.json" NEBULA_SECRETS_DIR="$s" /bin/sh "$d/action.sh" </dev/null
`

// attachedSecrets puts the secrets of an attached run into a new private
// directory on the SSH user's runtime directory ($XDG_RUNTIME_DIR, a
// tmpfs under /run/user that systemd-logind removes when the user's last
// session ends), never on disk (spec 06). Without such a directory the run
// does not start.
const attachedSecrets = `t=${XDG_RUNTIME_DIR:-}
case $t in /*) ;; *) echo "nebula-bootstrap: the SSH user has no runtime directory (XDG_RUNTIME_DIR) for secrets; run this action as a durable job" >&2; exit 120;; esac
case $(stat -f -c %T "$t" 2>/dev/null) in tmpfs|ramfs) ;; *) echo "nebula-bootstrap: the runtime directory is not a tmpfs" >&2; exit 120;; esac
s=$(mktemp -d "$t/nebula-secrets.XXXXXXXXXX") || { echo "nebula-bootstrap: mktemp failed" >&2; exit 120; }
` + readSecrets

// readSecrets reads "N" and then N lines "slot base64" from stdin into
// "$s/<slot>". It is fixed text; slots are checked again here.
const readSecrets = `IFS= read -r n || { echo "nebula-bootstrap: no secrets" >&2; exit 121; }
case $n in [1-8]) ;; *) echo "nebula-bootstrap: bad secret count" >&2; exit 121;; esac
i=0
while [ "$i" -lt "$n" ]; do
  IFS=' ' read -r k v || { echo "nebula-bootstrap: secret missing" >&2; exit 121; }
  case $k in [a-z]*) ;; *) echo "nebula-bootstrap: bad secret slot" >&2; exit 121;; esac
  case $k in *[!a-z0-9_]*) echo "nebula-bootstrap: bad secret slot" >&2; exit 121;; esac
  printf '%s' "$v" | base64 -d > "$s/$k" || { echo "nebula-bootstrap: base64 failed" >&2; exit 122; }
  i=$((i + 1))
done
`

// Command returns the remote command line for executionID.
func Command(executionID string) (string, error) {
	return command(executionID, false)
}

func command(executionID string, withSecrets bool) (string, error) {
	if !uuidRe.MatchString(executionID) {
		return "", errors.New("hostrun: execution ID is not a lowercase UUID")
	}
	block := ""
	if withSecrets {
		block = attachedSecrets
	}
	script := fmt.Sprintf(bootstrap, executionID, block)
	return "exec /bin/sh -c " + shellQuote(script), nil
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// cappedBuffer keeps the first limit bytes and counts the rest.
type cappedBuffer struct {
	mu      sync.Mutex
	buf     bytes.Buffer
	limit   int
	dropped int64
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	room := c.limit - c.buf.Len()
	if room > len(p) {
		room = len(p)
	}
	if room > 0 {
		c.buf.Write(p[:room])
	}
	c.dropped += int64(len(p) - max(room, 0))
	return len(p), nil
}

func (c *cappedBuffer) bytes() ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Clone(c.buf.Bytes()), c.dropped > 0
}

// Session is the part of *ssh.Session Run needs (tests fake it).
type Session interface {
	Run(cmd string) error
	Signal(sig ssh.Signal) error
	Close() error
}

// Attached runs script with params as an attached run. timeout is bounded
// by MaxTimeout; zero means DefaultTimeout. Errors are returned only when
// nothing was started; everything after that is a Result class.
func Attached(ctx context.Context, client *ssh.Client, executionID string, params, script []byte, timeout time.Duration, secrets ...Secret) (Result, error) {
	if err := validSecrets(secrets); err != nil {
		return Result{}, err
	}
	cmd, err := command(executionID, len(secrets) > 0)
	if err != nil {
		return Result{}, err
	}
	s, err := client.NewSession()
	if err != nil {
		return Result{}, fmt.Errorf("hostrun: open session: %w", err)
	}
	var out, log cappedBuffer
	out.limit, log.limit = MaxResult, MaxLog
	s.Stdin = io.MultiReader(strings.NewReader(base64.StdEncoding.EncodeToString(params)+"\n"+secretLines(secrets)), bytes.NewReader(script))
	s.Stdout, s.Stderr = &out, &log
	return run(ctx, s, cmd, timeout, &out, &log), nil
}

func run(ctx context.Context, s Session, cmd string, timeout time.Duration, out, log *cappedBuffer) Result {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if timeout > MaxTimeout {
		timeout = MaxTimeout
	}
	start := time.Now()
	done := make(chan error, 1)
	go func() { done <- s.Run(cmd) }()
	var runErr error
	timedOut := false
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case runErr = <-done:
	case <-t.C:
		timedOut = true
	case <-ctx.Done():
		timedOut = true
	}
	if timedOut {
		// Best effort: OpenSSH may ignore the signal; closing the channel
		// ends our side. The remote process can outlive this (stated in
		// docs); long work belongs in a durable job. TERM first: the
		// bootstrap's trap turns it into an exit that removes the private
		// runtime directory with the run's secrets; KILL only if it is
		// still there after a grace period.
		_ = s.Signal(ssh.SIGTERM)
		select {
		case <-done:
		case <-time.After(killGrace):
			_ = s.Signal(ssh.SIGKILL)
		}
		_ = s.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	} else {
		_ = s.Close()
	}
	res := Result{Duration: time.Since(start), ExitCode: -1}
	res.Result, _ = out.bytes()
	logBytes, truncated := log.bytes()
	if truncated {
		logBytes = append(logBytes, TruncationMarker...)
	}
	res.Log, res.LogTruncated = logBytes, truncated
	_, resultTooLarge := out.bytes()

	switch {
	case timedOut:
		res.Class, res.Detail = ClassExecutionTimeout, fmt.Sprintf("no result within %s", timeout)
		return res
	case runErr == nil:
		res.ExitCode = 0
	default:
		var ee *ssh.ExitError
		var missing *ssh.ExitMissingError
		switch {
		case errors.As(runErr, &ee) && ee.Signal() != "":
			res.Class, res.Detail = ClassScriptInterrupted, "killed by signal "+ee.Signal()
			return res
		case errors.As(runErr, &ee):
			res.ExitCode = ee.ExitStatus()
		case errors.As(runErr, &missing):
			res.Class, res.Detail = ClassScriptInterrupted, "the connection ended without an exit status"
			return res
		default:
			res.Class, res.Detail = ClassScriptInterrupted, "session error: "+runErr.Error()
			return res
		}
	}
	if res.ExitCode >= bootstrapExitMin && res.ExitCode <= bootstrapExitMax && bytes.Contains(logBytes, []byte(bootstrapTag)) {
		res.Class, res.Detail = ClassPrecheckFailed, "the host could not prepare the run (needs /bin/sh, mktemp, base64 and a writable temp directory)"
		return res
	}
	classify(&res, resultTooLarge)
	return res
}

func oneJSONDocument(b []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(b))
	var v json.RawMessage
	if err := dec.Decode(&v); err != nil {
		return false
	}
	_, err := dec.Token()
	return err == io.EOF
}
