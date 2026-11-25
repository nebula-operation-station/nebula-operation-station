// SPDX-License-Identifier: AGPL-3.0-or-later

package hostrun

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf16"
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
	// RequireTmpfs refuses to write secrets unless the run root is a
	// tmpfs (or ramfs), so a secret never lands on persistent disk.
	RequireTmpfs bool
}

// DefaultJobConfig is the Debian adapter's setup (spec 07).
var DefaultJobConfig = JobConfig{Sudo: true, JobRoot: "/var/lib/nebula/jobs", RunRoot: "/run/nebula", Systemd: true, RequireTmpfs: true}

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
NEBULA_EXECUTION_ID=$3 NEBULA_PARAMS="$r/params.json" NEBULA_SECRETS_DIR="$r/secrets" NEBULA_RUN_DIR="$r" /bin/sh "$j/action.sh" </dev/null >"$j/result.json.tmp" 2>"$j/execution.log"
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
	return c.dispatchCommand(executionID, timeout, false)
}

func (c JobConfig) dispatchCommand(executionID string, timeout time.Duration, withSecrets bool) (string, error) {
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
	// Secrets go to "$r/secrets" on the run root (tmpfs, removed with "$r"
	// when the script ends). From the first secret byte until the job is
	// handed to its launcher, the dispatch shell owns the cleanup: any
	// failure, and a hang-up or kill signal (a dropped connection), removes
	// the job, so no secret is left behind without a job to remove it.
	secretsBlock, handedOver := "", ""
	if withSecrets {
		tmpfs := ""
		if c.RequireTmpfs {
			tmpfs = `case $(stat -f -c %T "$r" 2>/dev/null) in tmpfs|ramfs) ;; *) echo "nebula-bootstrap: the run root is not a tmpfs" >&2; exit 120;; esac
`
		}
		secretsBlock = `trap 'rm -rf "$j" "$r"' EXIT
trap 'exit 129' HUP INT TERM
` + tmpfs + `mkdir -m 0700 "$r/secrets" || exit 120
s="$r/secrets"
` + readSecrets
		handedOver = `trap - EXIT HUP INT TERM
`
	}
	launch := "setsid /bin/sh -c " + shellQuote(wrapper) + " nebula-job \"$j\" \"$r\" " + executionID + " </dev/null >/dev/null 2>&1 &\n" + handedOver
	if c.Systemd {
		launch = "systemd-run --quiet --collect --unit=nebula-job-" + executionID +
			" --property=RuntimeMaxSec=" + strconv.Itoa(int(timeout/time.Second)) +
			" /bin/sh -c " + shellQuote(wrapper) + " nebula-job \"$j\" \"$r\" " + executionID +
			" || { echo 'nebula-bootstrap: systemd-run failed' >&2; rm -rf \"$j\" \"$r\"; exit 120; }\n" + handedOver
	}
	body := `umask 077
j=` + j + `; r=` + r + `
mkdir -p -m 0700 ` + c.JobRoot + ` ` + c.RunRoot + ` || { echo "nebula-bootstrap: cannot create the job directories" >&2; exit 120; }
mkdir -m 0700 "$j" || { echo "nebula-bootstrap: job exists" >&2; exit 125; }
mkdir -m 0700 "$r" || { echo "nebula-bootstrap: cannot create the run directory" >&2; rm -rf "$j"; exit 120; }
IFS= read -r p || { echo "nebula-bootstrap: no parameters" >&2; rm -rf "$j" "$r"; exit 121; }
printf '%s' "$p" | base64 -d > "$r/params.json" || { echo "nebula-bootstrap: base64 failed" >&2; rm -rf "$j" "$r"; exit 122; }
` + secretsBlock + `cat > "$j/action.sh" || { echo "nebula-bootstrap: cannot write the script" >&2; rm -rf "$j" "$r"; exit 123; }
printf '{"state":"dispatched"}\n' > "$j/state.json"
` + launch
	return c.program(body), nil
}

// CheckCommand prints the job's state.json, "missing", or "incomplete"
// for a job directory without state.json (a dispatch that was cut off).
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
[ -e "$j/state.json" ] || { echo incomplete; exit 0; }
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
func Dispatch(ctx context.Context, client *ssh.Client, cfg JobConfig, executionID string, params, script []byte, timeout time.Duration, secrets ...Secret) (DispatchOutcome, string, error) {
	if err := validSecrets(secrets); err != nil {
		return NotStarted, "", err
	}
	cmd, err := cfg.dispatchCommand(executionID, timeout, len(secrets) > 0)
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
	s.Stdin = io.MultiReader(strings.NewReader(base64.StdEncoding.EncodeToString(params)+"\n"+secretLines(secrets)), bytes.NewReader(script))
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
	// Phase: missing, incomplete, dispatched, running, finished, dead.
	// incomplete is a job directory without state.json: the dispatch was
	// cut off before the job was stored.
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
	if lines[0] == "incomplete" {
		return JobState{Phase: "incomplete"}, nil
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

// MaxDurableResultLimit is the highest result limit a caller of
// CollectStream may ask for: the raw fim-scan-v1 document limit
// (fimscan.MaxDocumentBytes, 128 MiB, ADR 0015 D6). Only fim.scan uses it;
// every other action keeps MaxResult.
const MaxDurableResultLimit = 128 << 20

// collectTimeout bounds a read of up to MaxResult bytes, like Collect's.
const collectTimeout = 2 * time.Minute

// minStreamRate (bytes per second) is the slowest a result above
// MaxResult may arrive: every byte above MaxResult adds 1/minStreamRate
// seconds to collectTimeout. A MaxDurableResultLimit document gets about
// 19 minutes.
const minStreamRate = 128 << 10

// streamReadTimeout bounds the streaming read of a result of at most limit
// bytes (limit already defaulted): collectTimeout for the 1 MiB default,
// growing with the limit above it.
func streamReadTimeout(limit int) time.Duration {
	if limit <= MaxResult {
		return collectTimeout
	}
	return collectTimeout + time.Duration(limit-MaxResult)*time.Second/minStreamRate
}

// ErrResultLimit is returned when a requested result limit is negative or
// above MaxDurableResultLimit.
var ErrResultLimit = errors.New("hostrun: result limit out of range")

// StreamedResult is the outcome of CollectStream. The result document
// itself went to the caller's writer; hostrun keeps none of it.
type StreamedResult struct {
	Class    string
	Detail   string
	ExitCode int
	// Bytes is the number of result bytes handed to the writer; never
	// more than the limit.
	Bytes int64
	// Truncated is set when result.json is larger than the limit. The bytes
	// written are then a cut document: the run is never complete, and
	// Class is never ClassSuccess.
	Truncated bool
	// Log is the bounded execution.log (untrusted host output).
	Log          []byte
	LogTruncated bool
}

// CollectStream reads the result of a finished job like Collect, but
// streams result.json to w instead of buffering it, and takes the result
// limit from the caller: 0 means MaxResult, anything above
// MaxDurableResultLimit (or below 0) is refused with ErrResultLimit. At
// most limit bytes reach w; a larger result is Truncated and the read
// stops there.
//
// The bytes are checked as they pass, exactly as Collect checks a buffered
// result: Class is ClassSuccess only for exit status 0 and a result within
// the limit that is valid UTF-8, not blank, exactly one JSON document and
// names no top-level member twice. Anything else gets the class Collect
// would give it. Because w sees the bytes before the verdict, the caller
// must discard what w received unless Class is ClassSuccess (and still
// validate the document's schema itself). The checks keep no document
// bytes: their memory is bounded by the JSON nesting limit and by
// maxTopLevelMembers.
//
// The read is bounded by ctx and by a timeout that grows with the limit
// (2 minutes for the default). If w returns an error, the read stops and
// the error is returned. w is never called while CollectStream holds a lock
// its return needs: when it returns ctx's error or the timeout error, one
// call to w already under way may still be running; no further call starts.
func CollectStream(ctx context.Context, client *ssh.Client, cfg JobConfig, executionID string, exitCode int, limit int, w io.Writer) (StreamedResult, error) {
	return collectStream(ctx, client, cfg, executionID, exitCode, limit, w, streamReadTimeout)
}

func collectStream(ctx context.Context, client *ssh.Client, cfg JobConfig, executionID string, exitCode int, limit int, w io.Writer, timeout func(int) time.Duration) (StreamedResult, error) {
	if limit < 0 || limit > MaxDurableResultLimit {
		return StreamedResult{}, fmt.Errorf("%w: %d (0..%d)", ErrResultLimit, limit, MaxDurableResultLimit)
	}
	if limit == 0 {
		limit = MaxResult
	}
	if w == nil {
		return StreamedResult{}, errors.New("hostrun: no result writer")
	}
	if !uuidRe.MatchString(executionID) {
		return StreamedResult{}, errors.New("hostrun: execution ID is not a lowercase UUID")
	}
	if err := cfg.valid(); err != nil {
		return StreamedResult{}, err
	}
	sw := newStreamWriter(w, int64(limit))
	err := streamOutput(ctx, client, cfg.program(`head -c `+strconv.Itoa(limit+1)+` `+cfg.JobRoot+"/"+executionID+`/result.json 2>/dev/null; true`), sw, timeout(limit))
	st := sw.finish()
	if st.err != nil {
		return StreamedResult{}, fmt.Errorf("hostrun: write result of %s: %w", executionID, st.err)
	}
	if err != nil {
		return StreamedResult{}, err
	}
	log, err := output(ctx, client, cfg.program(`head -c `+strconv.Itoa(MaxLog+1)+` `+cfg.JobRoot+"/"+executionID+`/execution.log 2>/dev/null; true`), MaxLog+1)
	if err != nil {
		return StreamedResult{}, err
	}
	out := StreamedResult{ExitCode: exitCode, Bytes: st.written, Truncated: st.total > int64(limit), Log: log}
	if len(log) > MaxLog {
		out.Log, out.LogTruncated = append(log[:MaxLog:MaxLog], TruncationMarker...), true
	}
	switch {
	case exitCode == 129 || exitCode == 143 || exitCode == 137:
		out.Class, out.Detail = ClassScriptInterrupted, fmt.Sprintf("interrupted (exit %d)", exitCode)
	case exitCode == ExitPrecheckFailed:
		out.Class, out.Detail = ClassPrecheckFailed, "the action's precheck failed"
	case exitCode == ExitPostcheckFailed:
		out.Class, out.Detail = ClassPostcheckFailed, "the action's postcheck failed"
	case exitCode != 0:
		out.Class, out.Detail = ClassScriptFailed, fmt.Sprintf("exit status %d", exitCode)
	case out.Truncated:
		out.Class, out.Detail = ClassScriptFailed, fmt.Sprintf("the result exceeds %d bytes", limit)
	case !st.nonBlank:
		out.Class, out.Detail = ClassResultMissing, "the script printed no result"
	case !st.valid:
		out.Class, out.Detail = ClassScriptFailed, "stdout is not exactly one JSON document"
	default:
		out.Class = ClassSuccess
	}
	return out, nil
}

// streamWriter forwards the first limit bytes to w, checks them with a
// jsonStream and counts the rest. It never holds mu while it calls w, so
// finish never waits for w. Once w failed, the limit was passed, or finish
// was called, nothing more reaches w; the first two also close stop, so the
// read ends early instead of draining a host that ignores `head -c`.
type streamWriter struct {
	w     io.Writer
	limit int64
	stop  chan struct{}

	mu        sync.Mutex
	forwarded int64 // bytes handed to w or about to be
	written   int64 // bytes w accepted
	total     int64 // bytes the host sent
	check     jsonStream
	err       error
	done      bool
	stopped   bool
}

func newStreamWriter(w io.Writer, limit int64) *streamWriter {
	return &streamWriter{w: w, limit: limit, stop: make(chan struct{})}
}

// Write is called by the session's stdout copy, one call at a time. It
// always reports success to the session; failures are kept for finish.
func (s *streamWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	s.total += int64(len(p))
	room := min(s.limit-s.forwarded, int64(len(p)))
	if s.done || s.err != nil || room <= 0 {
		s.stopIfOverLocked()
		s.mu.Unlock()
		return len(p), nil
	}
	chunk := p[:room]
	s.forwarded += room
	s.check.write(chunk)
	s.mu.Unlock()

	n, err := s.w.Write(chunk)
	// A writer may report any n; never count more than it was given.
	n = min(max(n, 0), len(chunk))
	if err == nil && n < len(chunk) {
		err = io.ErrShortWrite
	}

	s.mu.Lock()
	s.written += int64(n)
	if err != nil && s.err == nil {
		s.err = err
	}
	s.stopIfOverLocked()
	s.mu.Unlock()
	return len(p), nil
}

// stopIfOverLocked closes stop once w failed or the limit was passed.
func (s *streamWriter) stopIfOverLocked() {
	if !s.stopped && (s.err != nil || s.total > s.limit) {
		s.stopped = true
		close(s.stop)
	}
}

// streamState is what finish reports.
type streamState struct {
	written, total  int64
	nonBlank, valid bool
	err             error
}

// finish stops forwarding: no call to w starts after it returned. It does
// not wait for a call to w under way.
func (s *streamWriter) finish() streamState {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.done = true
	nonBlank, valid := s.check.finish()
	return streamState{written: s.written, total: s.total, nonBlank: nonBlank, valid: valid, err: s.err}
}

// maxTopLevelMembers bounds the top-level member names a jsonStream
// remembers (one SHA-256 sum each) to find duplicates. A document within
// MaxResult cannot reach it (a member takes at least 4 bytes), so up to the
// default limit the check is exactly Collect's; a larger document with more
// members is not one valid result.
const maxTopLevelMembers = MaxResult / 4

// maxJSONDepth is encoding/json's nesting limit, which Collect's check
// applies through json.Decoder.
const maxJSONDepth = 10000

// jsState is a jsonStream parser state.
type jsState uint8

const (
	jsBeginValue        jsState = iota // a value must follow
	jsBeginValueOrClose                // after '[': a value or ']'
	jsBeginKeyOrClose                  // after '{': a key or '}'
	jsBeginKey                         // after ',' in an object
	jsEndValue                         // a value ended
	jsEndTop                           // the document ended; only whitespace may follow
	jsString
	jsStringEsc
	jsStringU
	jsLiteral
	jsNeg
	jsZero // "0", or a number's integer part ended
	jsInt  // in the digits of a number's integer part
	jsDot
	jsFrac
	jsExp
	jsExpSign
	jsExpDigits
)

// jsonStream checks a document fed to it in pieces for what classify checks
// on a buffered one: valid UTF-8, not blank in the sense of bytes.TrimSpace,
// exactly one JSON document in the grammar of encoding/json (whitespace,
// nesting limit) and no top-level member named twice (names compared after
// unescaping, as json.Decoder.Token unescapes them). It keeps no document
// bytes: at most a partial UTF-8 sequence, one byte per open container and
// one SHA-256 sum per top-level member name. The zero value is ready.
type jsonStream struct {
	// UTF-8 and blank check.
	carry    [utf8.UTFMax]byte
	nCarry   int
	badUTF8  bool
	nonBlank bool

	// JSON grammar.
	state   jsState
	stack   []byte // 'k' object awaiting a key, 'v' object value, 'a' array
	bad     bool
	literal string // the rest of true/false/null
	uDigits int
	u       rune

	// Top-level member names.
	inKey   bool
	key     hash.Hash
	pending rune // a \u surrogate whose pair is not known yet, or -1
	keys    map[[sha256.Size]byte]struct{}
	members int
}

// write checks the next piece of the document.
func (j *jsonStream) write(p []byte) {
	j.checkUTF8(p)
	if j.bad {
		return
	}
	for i := 0; i < len(p) && !j.bad; i++ {
		if j.state == jsString {
			// Fast path: the run of plain string bytes.
			k := i
			for k < len(p) && p[k] != '"' && p[k] != '\\' && p[k] >= 0x20 {
				k++
			}
			if k > i && j.inKey {
				j.flushPending()
				j.key.Write(p[i:k])
			}
			if k == len(p) {
				return
			}
			i = k
		}
		j.step(p[i])
	}
}

// finish reports whether the document is not blank and whether it is one
// valid result document.
func (j *jsonStream) finish() (nonBlank, valid bool) {
	if j.nCarry > 0 {
		// A partial sequence at the end is invalid, and not a space.
		j.badUTF8, j.nonBlank = true, true
	}
	if !j.bad {
		switch j.state {
		case jsZero, jsInt, jsFrac, jsExpDigits:
			// A number at the end of the input ends there.
			j.step(' ')
		}
		if j.state == jsEndValue && len(j.stack) == 0 {
			j.state = jsEndTop
		}
	}
	return j.nonBlank, !j.badUTF8 && !j.bad && j.state == jsEndTop
}

func (j *jsonStream) checkUTF8(p []byte) {
	if j.badUTF8 {
		return
	}
	// Complete a sequence split by the previous piece.
	for j.nCarry > 0 && len(p) > 0 {
		j.carry[j.nCarry] = p[0]
		j.nCarry++
		p = p[1:]
		if !utf8.FullRune(j.carry[:j.nCarry]) {
			continue
		}
		r, size := utf8.DecodeRune(j.carry[:j.nCarry])
		if size != j.nCarry || (r == utf8.RuneError && size == 1) {
			j.badUTF8, j.nonBlank = true, true
			return
		}
		j.nCarry = 0
		if !j.nonBlank && !unicode.IsSpace(r) {
			j.nonBlank = true
		}
	}
	if len(p) == 0 {
		return
	}
	// Keep a sequence cut at the end of this piece for the next one.
	body := p
	for i := len(p) - 1; i >= 0 && i > len(p)-utf8.UTFMax; i-- {
		if utf8.RuneStart(p[i]) {
			if !utf8.FullRune(p[i:]) {
				body = p[:i]
				j.nCarry = copy(j.carry[:], p[i:])
			}
			break
		}
	}
	for b := body; !j.nonBlank && len(b) > 0; {
		r, size := utf8.DecodeRune(b)
		if (r == utf8.RuneError && size == 1) || !unicode.IsSpace(r) {
			j.nonBlank = true
		}
		b = b[size:]
	}
	if !utf8.Valid(body) {
		j.badUTF8, j.nonBlank = true, true
	}
}

func isJSONSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' }

// push opens a container; more than maxJSONDepth open ones is invalid.
func (j *jsonStream) push(kind byte) {
	j.stack = append(j.stack, kind)
	if len(j.stack) > maxJSONDepth {
		j.bad = true
	}
}

// step advances the grammar by one byte (outside the string fast path).
func (j *jsonStream) step(c byte) {
	for {
		switch j.state {
		case jsBeginValueOrClose:
			if isJSONSpace(c) {
				return
			}
			if c == ']' {
				j.stack = j.stack[:len(j.stack)-1]
				j.state = jsEndValue
				return
			}
			j.state = jsBeginValue
			continue
		case jsBeginValue:
			switch {
			case isJSONSpace(c):
			case c == '{':
				j.push('k')
				j.state = jsBeginKeyOrClose
			case c == '[':
				j.push('a')
				j.state = jsBeginValueOrClose
			case c == '"':
				j.state = jsString
			case c == '-':
				j.state = jsNeg
			case c == '0':
				j.state = jsZero
			case c >= '1' && c <= '9':
				j.state = jsInt
			case c == 't':
				j.state, j.literal = jsLiteral, "rue"
			case c == 'f':
				j.state, j.literal = jsLiteral, "alse"
			case c == 'n':
				j.state, j.literal = jsLiteral, "ull"
			default:
				j.bad = true
			}
			return
		case jsBeginKeyOrClose:
			if isJSONSpace(c) {
				return
			}
			if c == '}' {
				j.stack = j.stack[:len(j.stack)-1]
				j.state = jsEndValue
				return
			}
			j.state = jsBeginKey
			continue
		case jsBeginKey:
			switch {
			case isJSONSpace(c):
			case c == '"':
				j.state = jsString
				if len(j.stack) == 1 {
					j.startKey()
				}
			default:
				j.bad = true
			}
			return
		case jsEndValue:
			if len(j.stack) == 0 {
				j.state = jsEndTop
				continue
			}
			if isJSONSpace(c) {
				return
			}
			top := &j.stack[len(j.stack)-1]
			switch {
			case *top == 'k' && c == ':':
				*top = 'v'
				j.state = jsBeginValue
			case *top == 'v' && c == ',':
				*top = 'k'
				j.state = jsBeginKey
			case *top == 'a' && c == ',':
				j.state = jsBeginValue
			case (*top == 'v' && c == '}') || (*top == 'a' && c == ']'):
				j.stack = j.stack[:len(j.stack)-1]
			default:
				j.bad = true
			}
			return
		case jsEndTop:
			if !isJSONSpace(c) {
				j.bad = true
			}
			return
		case jsString:
			switch {
			case c == '"':
				if j.inKey {
					j.endKey()
				}
				j.state = jsEndValue
			case c == '\\':
				j.state = jsStringEsc
			case c < 0x20:
				j.bad = true
			default:
				j.keyBytes(c)
			}
			return
		case jsStringEsc:
			j.state = jsString
			switch c {
			case '"', '\\', '/':
				j.keyBytes(c)
			case 'b':
				j.keyBytes('\b')
			case 'f':
				j.keyBytes('\f')
			case 'n':
				j.keyBytes('\n')
			case 'r':
				j.keyBytes('\r')
			case 't':
				j.keyBytes('\t')
			case 'u':
				j.state, j.u, j.uDigits = jsStringU, 0, 0
			default:
				j.bad = true
			}
			return
		case jsStringU:
			var d rune
			switch {
			case c >= '0' && c <= '9':
				d = rune(c - '0')
			case c >= 'a' && c <= 'f':
				d = rune(c-'a') + 10
			case c >= 'A' && c <= 'F':
				d = rune(c-'A') + 10
			default:
				j.bad = true
				return
			}
			j.u = j.u<<4 | d
			if j.uDigits++; j.uDigits == 4 {
				j.state = jsString
				j.keyEscapeU(j.u)
			}
			return
		case jsLiteral:
			if c != j.literal[0] {
				j.bad = true
				return
			}
			if j.literal = j.literal[1:]; j.literal == "" {
				j.state = jsEndValue
			}
			return
		case jsNeg:
			switch {
			case c == '0':
				j.state = jsZero
			case c >= '1' && c <= '9':
				j.state = jsInt
			default:
				j.bad = true
			}
			return
		case jsInt:
			if c >= '0' && c <= '9' {
				return
			}
			j.state = jsZero
			continue
		case jsZero:
			switch c {
			case '.':
				j.state = jsDot
				return
			case 'e', 'E':
				j.state = jsExp
				return
			}
			j.state = jsEndValue
			continue
		case jsDot:
			if c >= '0' && c <= '9' {
				j.state = jsFrac
				return
			}
			j.bad = true
			return
		case jsFrac:
			if c >= '0' && c <= '9' {
				return
			}
			if c == 'e' || c == 'E' {
				j.state = jsExp
				return
			}
			j.state = jsEndValue
			continue
		case jsExp:
			if c == '+' || c == '-' {
				j.state = jsExpSign
				return
			}
			j.state = jsExpSign
			continue
		case jsExpSign:
			if c >= '0' && c <= '9' {
				j.state = jsExpDigits
				return
			}
			j.bad = true
			return
		case jsExpDigits:
			if c >= '0' && c <= '9' {
				return
			}
			j.state = jsEndValue
			continue
		}
		j.bad = true
		return
	}
}

// startKey begins a top-level member name.
func (j *jsonStream) startKey() {
	if j.members++; j.members > maxTopLevelMembers {
		j.bad = true
		return
	}
	if j.key == nil {
		j.key = sha256.New()
		j.keys = map[[sha256.Size]byte]struct{}{}
	}
	j.key.Reset()
	j.inKey, j.pending = true, -1
}

// endKey ends a top-level member name; a name seen before is invalid.
func (j *jsonStream) endKey() {
	j.flushPending()
	var sum [sha256.Size]byte
	j.key.Sum(sum[:0])
	if _, dup := j.keys[sum]; dup {
		j.bad = true
	}
	j.keys[sum] = struct{}{}
	j.inKey = false
}

// keyBytes adds one unescaped byte to the member name being read.
func (j *jsonStream) keyBytes(c byte) {
	if j.inKey {
		j.flushPending()
		j.key.Write([]byte{c})
	}
}

// keyEscapeU adds a \u escape to the member name the way encoding/json
// unescapes it: a surrogate pair is one rune, any other surrogate is
// U+FFFD.
func (j *jsonStream) keyEscapeU(r rune) {
	if !j.inKey {
		return
	}
	if j.pending >= 0 {
		pair := utf16.DecodeRune(j.pending, r)
		j.pending = -1
		if pair != unicode.ReplacementChar {
			j.keyRune(pair)
			return
		}
		j.keyRune(unicode.ReplacementChar)
	}
	if utf16.IsSurrogate(r) {
		j.pending = r
		return
	}
	j.keyRune(r)
}

// flushPending writes a surrogate that got no pair as U+FFFD.
func (j *jsonStream) flushPending() {
	if j.pending >= 0 {
		j.pending = -1
		j.keyRune(unicode.ReplacementChar)
	}
}

func (j *jsonStream) keyRune(r rune) {
	var b [utf8.UTFMax]byte
	j.key.Write(b[:utf8.EncodeRune(b[:], r)])
}

// streamOutput runs cmd with stdout going to w; a non-zero exit is an
// error. It returns early, without an error, once w's stop is closed.
func streamOutput(ctx context.Context, client *ssh.Client, cmd string, w *streamWriter, timeout time.Duration) error {
	s, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("hostrun: open session: %w", err)
	}
	defer s.Close()
	var errb cappedBuffer
	errb.limit = 4096
	s.Stdout, s.Stderr = w, &errb
	done := make(chan error, 1)
	go func() { done <- s.Run(cmd) }()
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case err = <-done:
	case <-w.stop:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return fmt.Errorf("hostrun: result read did not finish within %s", timeout)
	}
	if err != nil {
		msg, _ := errb.bytes()
		return fmt.Errorf("hostrun: %v: %s", err, clean(string(msg)))
	}
	return nil
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
