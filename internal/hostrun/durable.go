// SPDX-License-Identifier: AGPL-3.0-or-later

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
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
)

// Durable jobs (spec 07): mutating or long actions run detached from the
// SSH session in /var/lib/nebula/jobs/<execution-id>/, which holds only
// action.sh, state.json, result.json and execution.log. Parameters go to
// /run/nebula/<execution-id>/ (tmpfs) and are removed when the script
// ends. Results are written atomically (write .tmp, sync, rename).
//
// The executor dispatches once and afterwards only reads: Check never
// starts anything, so a run whose outcome is unknown is never repeated.

// JobConfig describes how jobs are started on hosts. Production uses
// DefaultJobConfig; tests use a launcher without sudo and systemd.
type JobConfig struct {
	// Sudo prefixes the remote programs with `sudo -n` (the job
	// directories are root's, spec 08 enrollment).
	Sudo bool
	// JobRoot and RunRoot are absolute directories on the host.
	JobRoot string
	RunRoot string
	// Systemd starts the job as a transient unit (systemd-run); otherwise
	// it is started with setsid in the background (tests).
	Systemd bool
	// BootIDFile is read to tell whether a host rebooted; empty means
	// /proc/sys/kernel/random/boot_id (tests point it elsewhere).
	BootIDFile string
}

// DefaultJobConfig is the Debian adapter's setup (spec 07).
var DefaultJobConfig = JobConfig{Sudo: true, JobRoot: "/var/lib/nebula/jobs", RunRoot: "/run/nebula", Systemd: true}

var safePathRe = regexp.MustCompile(`^/[A-Za-z0-9._/-]{1,200}$`)

func (c JobConfig) valid() error {
	if !safePathRe.MatchString(c.JobRoot) || !safePathRe.MatchString(c.RunRoot) || strings.Contains(c.JobRoot+c.RunRoot, "..") {
		return errors.New("hostrun: job directories must be simple absolute paths")
	}
	if c.BootIDFile != "" && (!safePathRe.MatchString(c.BootIDFile) || strings.Contains(c.BootIDFile, "..")) {
		return errors.New("hostrun: the boot ID file must be a simple absolute path")
	}
	return nil
}

var bootIDRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ValidBootID reports whether s looks like a Linux boot ID.
func ValidBootID(s string) bool { return bootIDRe.MatchString(s) }

// BootID reads the host's current boot ID (a fixed read-only command).
func BootID(ctx context.Context, client *ssh.Client, cfg JobConfig) (string, error) {
	if err := cfg.valid(); err != nil {
		return "", err
	}
	f := cfg.BootIDFile
	if f == "" {
		f = "/proc/sys/kernel/random/boot_id"
	}
	out, err := output(ctx, client, "exec head -c 64 "+f, 128)
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(out))
	if !ValidBootID(id) {
		return "", errors.New("hostrun: unreadable boot ID")
	}
	return id, nil
}

// AwaitReboot reads a result that asks the executor to wait for a reboot:
// {"await_reboot":true,"boot_id":"<id before>"}.
func AwaitReboot(result []byte) (string, bool) {
	var doc struct {
		Await  bool   `json:"await_reboot"`
		BootID string `json:"boot_id"`
	}
	if json.Unmarshal(result, &doc) != nil || !doc.Await || !ValidBootID(doc.BootID) {
		return "", false
	}
	return doc.BootID, true
}

// MaxDurableTimeout bounds a durable job.
const MaxDurableTimeout = 6 * time.Hour

// Exit status of the dispatch program when the job directory exists
// already: the job was dispatched before and must not start again.
const exitJobExists = 125

// wrapper runs on the host inside the unit (or setsid). $1 job dir, $2 run
// dir, $3 execution ID. It is fixed text; nothing is interpolated.
const wrapper = `j=$1; r=$2; cd "$j" || exit 1
b=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
printf '{"state":"running","pid":%d,"boot":"%s","started":%s}\n' "$$" "$b" "$(date +%s)" > state.json.tmp && mv state.json.tmp state.json
NEBULA_EXECUTION_ID=$3 NEBULA_PARAMS="$r/params.json" /bin/sh "$j/action.sh" </dev/null >"$j/result.json.tmp" 2>"$j/execution.log"
rc=$?
rm -rf "$r"
sync "$j/result.json.tmp" "$j/execution.log" 2>/dev/null
mv "$j/result.json.tmp" "$j/result.json"
printf '{"state":"finished","exit":%d,"finished":%s}\n' "$rc" "$(date +%s)" > state.json.tmp
sync state.json.tmp 2>/dev/null
mv state.json.tmp state.json
`

func (c JobConfig) program(body string) string {
	p := "/bin/sh -c " + shellQuote(body)
	if c.Sudo {
		p = "sudo -n " + p
	}
	return "exec " + p
}

// DispatchCommand returns the remote command that stores and starts the
// job. timeout bounds the job when systemd runs it.
func (c JobConfig) DispatchCommand(executionID string, timeout time.Duration) (string, error) {
	if !uuidRe.MatchString(executionID) {
		return "", errors.New("hostrun: execution ID is not a lowercase UUID")
	}
	if err := c.valid(); err != nil {
		return "", err
	}
	if timeout <= 0 || timeout > MaxDurableTimeout {
		return "", fmt.Errorf("hostrun: durable timeout must be 1s..%s", MaxDurableTimeout)
	}
	j, r := c.JobRoot+"/"+executionID, c.RunRoot+"/"+executionID
	launch := "setsid /bin/sh -c " + shellQuote(wrapper) + " nebula-job \"$j\" \"$r\" " + executionID + " </dev/null >/dev/null 2>&1 &"
	if c.Systemd {
		launch = "systemd-run --quiet --collect --unit=nebula-job-" + executionID +
			" --property=RuntimeMaxSec=" + strconv.Itoa(int(timeout/time.Second)) +
			" /bin/sh -c " + shellQuote(wrapper) + " nebula-job \"$j\" \"$r\" " + executionID +
			" || { echo 'nebula-bootstrap: systemd-run failed' >&2; rm -rf \"$j\" \"$r\"; exit 120; }"
	}
	body := `umask 077
j=` + j + `; r=` + r + `
mkdir -p -m 0700 ` + c.JobRoot + ` ` + c.RunRoot + ` || { echo "nebula-bootstrap: cannot create the job directories" >&2; exit 120; }
mkdir -m 0700 "$j" || { echo "nebula-bootstrap: job exists" >&2; exit 125; }
mkdir -m 0700 "$r" || { echo "nebula-bootstrap: cannot create the run directory" >&2; rm -rf "$j"; exit 120; }
IFS= read -r p || { echo "nebula-bootstrap: no parameters" >&2; rm -rf "$j" "$r"; exit 121; }
printf '%s' "$p" | base64 -d > "$r/params.json" || { echo "nebula-bootstrap: base64 failed" >&2; rm -rf "$j" "$r"; exit 122; }
cat > "$j/action.sh" || { echo "nebula-bootstrap: cannot write the script" >&2; rm -rf "$j" "$r"; exit 123; }
printf '{"state":"dispatched"}\n' > "$j/state.json"
` + launch + `
`
	return c.program(body), nil
}

// CheckCommand prints the job's state.json, or "missing".
func (c JobConfig) CheckCommand(executionID string) (string, error) {
	if !uuidRe.MatchString(executionID) {
		return "", errors.New("hostrun: execution ID is not a lowercase UUID")
	}
	if err := c.valid(); err != nil {
		return "", err
	}
	j := c.JobRoot + "/" + executionID
	body := `j=` + j + `
[ -d "$j" ] || { echo missing; exit 0; }
s=$(head -c 4096 "$j/state.json" 2>/dev/null)
case "$s" in *'"state":"running"'*)
  pid=$(printf '%s' "$s" | sed -n 's/.*"pid":\([0-9]*\).*/\1/p')
  boot=$(printf '%s' "$s" | sed -n 's/.*"boot":"\([0-9a-f-]*\)".*/\1/p')
  now=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
  if [ -n "$pid" ] && [ "$boot" = "$now" ] && kill -0 "$pid" 2>/dev/null; then printf '%s\nalive\n' "$s"; exit 0; fi
  # The job may have ended between the read above and kill -0; the wrapper
  # writes its final state before it exits, so a second read tells a
  # finished job from a dead one.
  s=$(head -c 4096 "$j/state.json" 2>/dev/null)
  case "$s" in *'"state":"running"'*) printf '%s\ndead\n' "$s"; exit 0;; esac;;
esac
printf '%s\n' "$s"
`
	return c.program(body), nil
}

// RemoveCommand deletes the job directory after the result is stored.
func (c JobConfig) RemoveCommand(executionID string) (string, error) {
	if !uuidRe.MatchString(executionID) {
		return "", errors.New("hostrun: execution ID is not a lowercase UUID")
	}
	if err := c.valid(); err != nil {
		return "", err
	}
	return c.program(`rm -rf ` + c.JobRoot + "/" + executionID + ` ` + c.RunRoot + "/" + executionID), nil
}

// DispatchOutcome of Dispatch.
type DispatchOutcome int

// Outcomes.
const (
	// Dispatched: the job was stored and started.
	Dispatched DispatchOutcome = iota
	// AlreadyThere: the job directory existed; nothing was started.
	AlreadyThere
	// NotStarted: the host refused before starting (precheck_failed).
	NotStarted
)

// Dispatch stores the job on the host and starts it.
func Dispatch(ctx context.Context, client *ssh.Client, cfg JobConfig, executionID string, params, script []byte, timeout time.Duration) (DispatchOutcome, string, error) {
	cmd, err := cfg.DispatchCommand(executionID, timeout)
	if err != nil {
		return NotStarted, "", err
	}
	s, err := client.NewSession()
	if err != nil {
		return NotStarted, "", fmt.Errorf("hostrun: open session: %w", err)
	}
	defer s.Close()
	var stderr cappedBuffer
	stderr.limit = 4096
	s.Stdin = io.MultiReader(strings.NewReader(base64.StdEncoding.EncodeToString(params)+"\n"), bytes.NewReader(script))
	s.Stderr = &stderr
	done := make(chan error, 1)
	go func() { done <- s.Run(cmd) }()
	select {
	case err = <-done:
	case <-ctx.Done():
		_ = s.Close()
		return NotStarted, "", ctx.Err()
	case <-time.After(2 * time.Minute):
		_ = s.Close()
		return NotStarted, "", errors.New("hostrun: dispatch did not finish within 2 minutes")
	}
	msg, _ := stderr.bytes()
	detail := strings.TrimSpace(clean(string(msg)))
	if err == nil {
		return Dispatched, "", nil
	}
	var ee *ssh.ExitError
	if errors.As(err, &ee) {
		switch {
		case ee.ExitStatus() == exitJobExists:
			return AlreadyThere, detail, nil
		case ee.ExitStatus() >= bootstrapExitMin && ee.ExitStatus() <= bootstrapExitMax:
			return NotStarted, detail, nil
		case ee.ExitStatus() == 1 && strings.Contains(detail, "sudo"):
			return NotStarted, "sudo -n refused: " + detail, nil
		}
		return NotStarted, fmt.Sprintf("dispatch exit status %d: %s", ee.ExitStatus(), detail), nil
	}
	// The connection broke while dispatching: the job may or may not have
	// been stored; only Check can tell.
	return AlreadyThere, "connection lost during dispatch", err
}

// JobState of a durable job on the host.
type JobState struct {
	// Phase: missing, dispatched, running, finished, dead.
	Phase    string
	ExitCode int
}

// stateDoc is state.json.
type stateDoc struct {
	State string `json:"state"`
	Exit  *int   `json:"exit"`
}

// Check reads the job's state without changing anything.
func Check(ctx context.Context, client *ssh.Client, cfg JobConfig, executionID string) (JobState, error) {
	cmd, err := cfg.CheckCommand(executionID)
	if err != nil {
		return JobState{}, err
	}
	out, err := output(ctx, client, cmd, 8192)
	if err != nil {
		return JobState{}, err
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 0 || lines[0] == "missing" {
		return JobState{Phase: "missing"}, nil
	}
	var st stateDoc
	if err := json.Unmarshal([]byte(lines[0]), &st); err != nil {
		return JobState{}, fmt.Errorf("hostrun: unreadable state.json")
	}
	switch st.State {
	case "finished":
		if st.Exit == nil {
			return JobState{}, errors.New("hostrun: state.json has no exit status")
		}
		return JobState{Phase: "finished", ExitCode: *st.Exit}, nil
	case "running":
		if len(lines) > 1 && lines[1] == "alive" {
			return JobState{Phase: "running"}, nil
		}
		return JobState{Phase: "dead"}, nil
	case "dispatched":
		return JobState{Phase: "dispatched"}, nil
	}
	return JobState{}, errors.New("hostrun: unknown job state")
}

// Collect reads the bounded result and log of a finished job and
// classifies them like an attached run.
func Collect(ctx context.Context, client *ssh.Client, cfg JobConfig, executionID string, exitCode int) (Result, error) {
	if !uuidRe.MatchString(executionID) {
		return Result{}, errors.New("hostrun: execution ID is not a lowercase UUID")
	}
	if err := cfg.valid(); err != nil {
		return Result{}, err
	}
	res, err := output(ctx, client, cfg.program(`head -c `+strconv.Itoa(MaxResult+1)+` `+cfg.JobRoot+"/"+executionID+`/result.json 2>/dev/null; true`), MaxResult+1)
	if err != nil {
		return Result{}, err
	}
	log, err := output(ctx, client, cfg.program(`head -c `+strconv.Itoa(MaxLog+1)+` `+cfg.JobRoot+"/"+executionID+`/execution.log 2>/dev/null; true`), MaxLog+1)
	if err != nil {
		return Result{}, err
	}
	out := Result{ExitCode: exitCode, Result: res, Log: log}
	if len(log) > MaxLog {
		out.Log, out.LogTruncated = append(log[:MaxLog:MaxLog], TruncationMarker...), true
	}
	classify(&out, len(res) > MaxResult)
	return out, nil
}

// Remove deletes the job's directories on the host.
func Remove(ctx context.Context, client *ssh.Client, cfg JobConfig, executionID string) error {
	cmd, err := cfg.RemoveCommand(executionID)
	if err != nil {
		return err
	}
	_, err = output(ctx, client, cmd, 1024)
	return err
}

// classify sets Class and Detail from the exit code and the result. A
// result that is not one bounded UTF-8 JSON document is dropped.
func classify(r *Result, resultTooLarge bool) {
	empty := len(bytes.TrimSpace(r.Result)) == 0
	validResult := !resultTooLarge && !empty && utf8.Valid(r.Result) && oneJSONDocument(r.Result)
	if !validResult {
		r.Result = nil
	}
	switch {
	case r.ExitCode == 129 || r.ExitCode == 143 || r.ExitCode == 137:
		r.Class, r.Detail = ClassScriptInterrupted, fmt.Sprintf("interrupted (exit %d)", r.ExitCode)
	case r.ExitCode == ExitPrecheckFailed:
		r.Class, r.Detail = ClassPrecheckFailed, "the action's precheck failed"
	case r.ExitCode == ExitPostcheckFailed:
		r.Class, r.Detail = ClassPostcheckFailed, "the action's postcheck failed"
	case r.ExitCode != 0:
		r.Class, r.Detail = ClassScriptFailed, fmt.Sprintf("exit status %d", r.ExitCode)
	case resultTooLarge:
		r.Class, r.Detail = ClassScriptFailed, "the result exceeds 1 MiB"
	case empty:
		r.Class, r.Detail = ClassResultMissing, "the script printed no result"
	case !validResult:
		r.Class, r.Detail = ClassScriptFailed, "stdout is not exactly one JSON document"
	default:
		r.Class = ClassSuccess
	}
}

// output runs cmd and returns at most limit bytes of stdout; a non-zero
// exit is an error.
func output(ctx context.Context, client *ssh.Client, cmd string, limit int) ([]byte, error) {
	s, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("hostrun: open session: %w", err)
	}
	defer s.Close()
	var out, errb cappedBuffer
	out.limit, errb.limit = limit, 4096
	s.Stdout, s.Stderr = &out, &errb
	done := make(chan error, 1)
	go func() { done <- s.Run(cmd) }()
	select {
	case err = <-done:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(2 * time.Minute):
		return nil, errors.New("hostrun: command did not finish within 2 minutes")
	}
	if err != nil {
		msg, _ := errb.bytes()
		return nil, fmt.Errorf("hostrun: %v: %s", err, clean(string(msg)))
	}
	b, _ := out.bytes()
	return b, nil
}

// clean keeps host messages printable and short.
func clean(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}
