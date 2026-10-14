// SPDX-License-Identifier: AGPL-3.0-or-later

package hostrun_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
)

func jobConfig(t *testing.T) hostrun.JobConfig {
	t.Helper()
	d := t.TempDir()
	return hostrun.JobConfig{JobRoot: filepath.Join(d, "jobs"), RunRoot: filepath.Join(d, "run")}
}

func waitPhase(t *testing.T, check func() hostrun.JobState, want string) hostrun.JobState {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		st := check()
		if st.Phase == want {
			return st
		}
		if time.Now().After(deadline) {
			t.Fatalf("phase %q, want %q", st.Phase, want)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestDurableJobLifecycle(t *testing.T) {
	c := client(t)
	cfg := jobConfig(t)
	ctx := context.Background()
	counter := filepath.Join(t.TempDir(), "runs")
	script := "echo x >> " + counter + "\necho log line >&2\ncat \"$NEBULA_PARAMS\"\n"
	out, detail, err := hostrun.Dispatch(ctx, c, cfg, execID, []byte(`{"a":1}`), []byte(script), time.Minute)
	if err != nil || out != hostrun.Dispatched {
		t.Fatalf("dispatch: %v %s %v", out, detail, err)
	}
	check := func() hostrun.JobState {
		st, err := hostrun.Check(ctx, c, cfg, execID)
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	st := waitPhase(t, check, "finished")
	// A second dispatch of the same execution never starts it again.
	out, _, err = hostrun.Dispatch(ctx, c, cfg, execID, []byte(`{"a":1}`), []byte(script), time.Minute)
	if err != nil || out != hostrun.AlreadyThere {
		t.Fatalf("second dispatch: %v %v", out, err)
	}
	r, err := hostrun.Collect(ctx, c, cfg, execID, st.ExitCode)
	if err != nil || r.Class != hostrun.ClassSuccess || string(r.Result) != `{"a":1}` || string(r.Log) != "log line\n" {
		t.Fatalf("collect: %+v %v", r, err)
	}
	// Only the four spec files remain; the parameters are gone.
	entries, _ := os.ReadDir(filepath.Join(cfg.JobRoot, execID))
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	if strings.Join(names, ",") != "action.sh,execution.log,result.json,state.json" {
		t.Fatalf("job dir: %v", names)
	}
	if _, err := os.Stat(filepath.Join(cfg.RunRoot, execID)); !os.IsNotExist(err) {
		t.Fatalf("run dir left: %v", err)
	}
	if fi, _ := os.Stat(filepath.Join(cfg.JobRoot, execID)); fi.Mode().Perm() != 0o700 {
		t.Fatalf("job dir mode %v", fi.Mode())
	}
	if err := hostrun.Remove(ctx, c, cfg, execID); err != nil {
		t.Fatal(err)
	}
	if check().Phase != "missing" {
		t.Fatal("job not removed")
	}
	b, _ := os.ReadFile(counter)
	if strings.Count(string(b), "x") != 1 {
		t.Fatalf("script ran %d times", strings.Count(string(b), "x"))
	}
}

func TestDurableJobFailureAndDeath(t *testing.T) {
	c := client(t)
	cfg := jobConfig(t)
	ctx := context.Background()
	check := func(id string) func() hostrun.JobState {
		return func() hostrun.JobState {
			st, err := hostrun.Check(ctx, c, cfg, id)
			if err != nil {
				t.Fatal(err)
			}
			return st
		}
	}
	const failID = "0b9c2f7e-4a51-4c8e-9a51-6f0d3c2b1a01"
	if _, _, err := hostrun.Dispatch(ctx, c, cfg, failID, []byte(`{}`), []byte("exit 4\n"), time.Minute); err != nil {
		t.Fatal(err)
	}
	st := waitPhase(t, check(failID), "finished")
	r, err := hostrun.Collect(ctx, c, cfg, failID, st.ExitCode)
	if err != nil || r.Class != hostrun.ClassScriptFailed || r.ExitCode != 4 {
		t.Fatalf("%+v %v", r, err)
	}

	const deadID = "0b9c2f7e-4a51-4c8e-9a51-6f0d3c2b1a02"
	if _, _, err := hostrun.Dispatch(ctx, c, cfg, deadID, []byte(`{}`), []byte("sleep 30\n"), time.Minute); err != nil {
		t.Fatal(err)
	}
	waitPhase(t, check(deadID), "running")
	// The host "reboots": the wrapper dies without writing a final state.
	state, _ := os.ReadFile(filepath.Join(cfg.JobRoot, deadID, "state.json"))
	pid := strings.SplitN(strings.SplitN(string(state), `"pid":`, 2)[1], ",", 2)[0]
	n, _ := strconv.Atoi(pid)
	p, _ := os.FindProcess(n)
	_ = p.Kill()
	waitPhase(t, check(deadID), "dead")
}

func TestDurableCommandsAreFixed(t *testing.T) {
	cfg := hostrun.DefaultJobConfig
	for _, id := range []string{"", strings.ToUpper(execID), execID + ";reboot"} {
		if _, err := cfg.DispatchCommand(id, time.Minute); err == nil {
			t.Errorf("id %q accepted", id)
		}
	}
	bad := cfg
	bad.JobRoot = "/var/lib/nebula/jobs; reboot"
	if _, err := bad.DispatchCommand(execID, time.Minute); err == nil {
		t.Error("unsafe job root accepted")
	}
	if _, err := cfg.DispatchCommand(execID, 7*time.Hour); err == nil {
		t.Error("timeout above the maximum accepted")
	}
	cmd, err := cfg.DispatchCommand(execID, 5*time.Minute)
	if err != nil || !strings.HasPrefix(cmd, "exec sudo -n /bin/sh -c '") || !strings.Contains(cmd, "systemd-run --quiet --collect --unit=nebula-job-"+execID) ||
		!strings.Contains(cmd, "RuntimeMaxSec=300") {
		t.Fatalf("command %q %v", cmd, err)
	}
}

// The systemd variant, with a stand-in systemd-run that starts the unit's
// command like systemd would (minus the cgroup).
func TestDurableJobWithSystemdRun(t *testing.T) {
	bin := t.TempDir()
	fake := "#!/bin/sh\necho \"$@\" > " + filepath.Join(bin, "args") + "\nwhile [ $# -gt 0 ]; do case \"$1\" in --*) shift;; *) break;; esac; done\nsetsid \"$@\" </dev/null >/dev/null 2>&1 &\n"
	if err := os.WriteFile(filepath.Join(bin, "systemd-run"), []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	c := client(t)
	cfg := jobConfig(t)
	cfg.Systemd = true
	ctx := context.Background()
	if out, detail, err := hostrun.Dispatch(ctx, c, cfg, execID, []byte(`{"s":"d"}`), []byte("cat \"$NEBULA_PARAMS\"\n"), 90*time.Second); err != nil || out != hostrun.Dispatched {
		t.Fatalf("dispatch: %v %s %v", out, detail, err)
	}
	st := waitPhase(t, func() hostrun.JobState {
		st, err := hostrun.Check(ctx, c, cfg, execID)
		if err != nil {
			t.Fatal(err)
		}
		return st
	}, "finished")
	r, err := hostrun.Collect(ctx, c, cfg, execID, st.ExitCode)
	if err != nil || r.Class != hostrun.ClassSuccess || string(r.Result) != `{"s":"d"}` {
		t.Fatalf("%+v %v", r, err)
	}
	args, _ := os.ReadFile(filepath.Join(bin, "args"))
	if !strings.HasPrefix(string(args), "--quiet --collect --unit=nebula-job-"+execID+" --property=RuntimeMaxSec=90 /bin/sh -c ") {
		t.Fatalf("systemd-run args %q", args)
	}
}

// TestCheckRereadsAJobThatEndsDuringTheCheck covers the race between
// reading state.json and probing the wrapper's PID: a job that finishes in
// between must be reported finished (its result kept), not dead.
func TestCheckRereadsAJobThatEndsDuringTheCheck(t *testing.T) {
	realHead, err := exec.LookPath("head")
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	// head prints the state, then the job "finishes" before kill -0 runs.
	stub := "#!/bin/sh\nf=$3\n" + realHead + " \"$@\"\nif [ ! -e \"$f.done\" ]; then : > \"$f.done\"; printf '{\"state\":\"finished\",\"exit\":0,\"finished\":1}\\n' > \"$f\"; fi\n"
	if err := os.WriteFile(filepath.Join(bin, "head"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	c := client(t)
	cfg := jobConfig(t)
	// A wrapper PID that is gone, on the current boot.
	p := exec.Command("true")
	if err := p.Run(); err != nil {
		t.Fatal(err)
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	j := filepath.Join(cfg.JobRoot, execID)
	if err := os.MkdirAll(j, 0o700); err != nil {
		t.Fatal(err)
	}
	state := `{"state":"running","pid":` + strconv.Itoa(p.Process.Pid) + `,"boot":"` + strings.TrimSpace(string(boot)) + `","started":1}` + "\n"
	if err := os.WriteFile(filepath.Join(j, "state.json"), []byte(state), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := hostrun.Check(context.Background(), c, cfg, execID)
	if err != nil || st.Phase != "finished" || st.ExitCode != 0 {
		t.Fatalf("%+v %v", st, err)
	}
	// Without the race the same dead PID is reported dead.
	if err := os.WriteFile(filepath.Join(j, "state.json"), []byte(state), 0o600); err != nil {
		t.Fatal(err)
	}
	if st, err := hostrun.Check(context.Background(), c, cfg, execID); err != nil || st.Phase != "dead" {
		t.Fatalf("%+v %v", st, err)
	}
}
