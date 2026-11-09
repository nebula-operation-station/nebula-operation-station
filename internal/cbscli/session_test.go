// SPDX-License-Identifier: AGPL-3.0-or-later

package cbscli

import (
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/sshtransport"
)

func open(t *testing.T, d *testDriver, f *fakeCBS, opts Options) (*Session, error) {
	t.Helper()
	target, key := f.start(t)
	s, err := d.Open(context.Background(), target, key, opts)
	if err == nil {
		t.Cleanup(func() { s.Close() })
	}
	return s, err
}

func mustOpen(t *testing.T, d *testDriver, f *fakeCBS) *Session {
	t.Helper()
	s, err := open(t, d, f, Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}

func TestRunsAllowlistedCommandsInOneShellSession(t *testing.T) {
	for _, chunk := range []int{0, 3} {
		f := newFakeCBS()
		f.chunk = chunk
		s := mustOpen(t, newTestDriver(), f)
		if s.Prompt() != synthPrompt {
			t.Errorf("chunk %d: prompt %q", chunk, s.Prompt())
		}
		out, err := s.Run(context.Background(), ShowVersion())
		if err != nil {
			t.Fatalf("chunk %d: Run: %v", chunk, err)
		}
		if string(out) != synthVersion {
			t.Errorf("chunk %d: output %q, want %q", chunk, out, synthVersion)
		}
		out, err = s.Run(context.Background(), ShowVLAN())
		if err != nil || string(out) != synthVLAN {
			t.Errorf("chunk %d: show vlan = %q, %v", chunk, out, err)
		}
		s.Close()
		want := []string{"terminal datadump", "show version", "show vlan"}
		if got := f.got(); !slices.Equal(got, want) {
			t.Errorf("chunk %d: device received %q, want %q", chunk, got, want)
		}
		_, sessions, execs, shells, ptys := f.counts()
		if sessions != 1 || shells != 1 || ptys != 1 || execs != 0 {
			t.Errorf("chunk %d: sessions %d shells %d ptys %d execs %d", chunk, sessions, shells, ptys, execs)
		}
	}
}

func TestDatadumpRefusedFailsOpen(t *testing.T) {
	for name, reply := range map[string]string{
		"unrecognized": "% Unrecognized command\r\n" + synthPrompt,
		"other output": "paging stays on\r\n" + synthPrompt,
	} {
		f := newFakeCBS()
		f.replies["terminal datadump"] = reply
		_, err := open(t, newTestDriver(), f, Options{})
		if !errors.Is(err, ErrDatadump) {
			t.Errorf("%s: err = %v, want ErrDatadump", name, err)
		}
		if got := f.got(); !slices.Equal(got, []string{"terminal datadump"}) {
			t.Errorf("%s: device received %q", name, got)
		}
	}
}

func TestUnexpectedPromptsAbortAndAreNeverAnswered(t *testing.T) {
	cases := map[string]string{
		"more":           "line one\r\n--More--",
		"cbs pager":      "line one\r\nMore: <space>,  Quit: q or CTRL+Z, One line: <return> ",
		"yes/no":         "Overwrite file [startup-config].... (Y/N)[N] ?",
		"confirm":        "Proceed? [confirm]",
		"in-band login":  "\r\nUser Name:",
		"password":       "Password:",
		"config mode":    "\r\nsw-lab1(config)#",
		"other hostname": "\r\nother-switch#",
		"privilege drop": "\r\nsw-lab1>",
	}
	for name, reply := range cases {
		f := newFakeCBS()
		f.replies["show version"] = reply
		s := mustOpen(t, newTestDriver(), f)
		_, err := s.Run(context.Background(), ShowVersion())
		if !errors.Is(err, ErrUnexpectedPrompt) {
			t.Errorf("%s: err = %v, want ErrUnexpectedPrompt", name, err)
		}
		if _, err := s.Run(context.Background(), ShowVLAN()); !errors.Is(err, ErrSessionBroken) {
			t.Errorf("%s: second Run err = %v, want ErrSessionBroken", name, err)
		}
		s.Close()
		if got := f.got(); !slices.Equal(got, []string{"terminal datadump", "show version"}) {
			t.Errorf("%s: device received %q (an answer was sent)", name, got)
		}
	}
}

func TestUnexpectedPromptBeforeFirstPromptAbortsOpen(t *testing.T) {
	for name, banner := range map[string]string{
		"in-band login": "\r\nUser Name:",
		"press key":     "Welcome\r\nPress any key to continue",
		"config prompt": "\r\nsw-lab1(config)#",
	} {
		f := newFakeCBS()
		f.banner, f.prompt = banner, ""
		_, err := open(t, newTestDriver(), f, Options{})
		if !errors.Is(err, ErrUnexpectedPrompt) {
			t.Errorf("%s: err = %v, want ErrUnexpectedPrompt", name, err)
		}
		if got := f.got(); len(got) != 0 {
			t.Errorf("%s: device received %q", name, got)
		}
	}
}

func TestBannerChangeAbortsOpen(t *testing.T) {
	f := newFakeCBS()
	s := mustOpen(t, newTestDriver(), f)
	pinned := s.BannerDigest()
	want := sha256.Sum256([]byte(strings.ReplaceAll(synthBanner, "\r\n", "\n")))
	if pinned != want {
		t.Fatalf("banner digest %x, want %x", pinned, want)
	}
	s.Close()

	if _, err := open(t, newTestDriver(), f, Options{ExpectBanner: &pinned}); err != nil {
		t.Fatalf("same banner: %v", err)
	}

	g := newFakeCBS()
	g.banner = "\r\nSYNTHETIC BANNER - changed\r\n"
	if _, err := open(t, newTestDriver(), g, Options{ExpectBanner: &pinned}); !errors.Is(err, ErrBannerChanged) {
		t.Errorf("changed banner: err = %v, want ErrBannerChanged", err)
	}
	if got := g.got(); len(got) != 0 {
		t.Errorf("changed banner: device received %q", got)
	}
}

func TestOversizeBannerAbortsOpen(t *testing.T) {
	f := newFakeCBS()
	f.banner = strings.Repeat(strings.Repeat("b", 99)+"\r\n", MaxBannerBytes/100+1)
	if _, err := open(t, newTestDriver(), f, Options{}); !errors.Is(err, ErrOutputTooLarge) {
		t.Errorf("err = %v, want ErrOutputTooLarge", err)
	}
}

// body builds raw output of exactly n bytes (n >= 1000) from CRLF lines of
// about 1000 bytes, CR LF included, ending with CR LF.
func body(n int) string {
	line := func(l int) string { return strings.Repeat("x", l-2) + "\r\n" }
	k, r := n/1000, n%1000
	var b strings.Builder
	switch r {
	case 0:
		b.WriteString(strings.Repeat(line(1000), k))
	case 1:
		b.WriteString(strings.Repeat(line(1000), k-1) + line(1001))
	default:
		b.WriteString(strings.Repeat(line(1000), k) + line(r))
	}
	return b.String()
}

func TestOutputByteCaps(t *testing.T) {
	cases := []struct {
		name string
		cmd  Command
		cap  int
	}{
		{"show version", ShowVersion(), MaxCommandOutputBytes},
		{"show running-config", ShowRunningConfig(), MaxConfigOutputBytes},
	}
	for _, c := range cases {
		for _, over := range []bool{false, true} {
			n := c.cap
			if over {
				n++
			}
			raw := body(n)
			if len(raw) != n {
				t.Fatalf("body(%d) has %d bytes", n, len(raw))
			}
			f := newFakeCBS()
			f.replies[c.name] = raw + synthPrompt
			s := mustOpen(t, newTestDriver(), f)
			out, err := s.Run(context.Background(), c.cmd)
			switch {
			case over && !errors.Is(err, ErrOutputTooLarge):
				t.Errorf("%s at cap+1: err = %v, want ErrOutputTooLarge", c.name, err)
			case !over && err != nil:
				t.Errorf("%s at cap: %v", c.name, err)
			case !over && len(out) != n-strings.Count(raw, "\r"):
				t.Errorf("%s at cap: %d bytes out", c.name, len(out))
			}
			s.Close()
		}
	}
}

func TestOutputLineLengthLimit(t *testing.T) {
	for _, over := range []bool{false, true} {
		n := MaxLineBytes
		if over {
			n++
		}
		f := newFakeCBS()
		f.replies["show version"] = strings.Repeat("y", n) + "\r\nshort\r\n" + synthPrompt
		s := mustOpen(t, newTestDriver(), f)
		_, err := s.Run(context.Background(), ShowVersion())
		if over != errors.Is(err, ErrLineTooLong) || (!over && err != nil) {
			t.Errorf("line of %d bytes: err = %v", n, err)
		}
		s.Close()
	}
}

func TestOverlongUnterminatedLineAbortsEarly(t *testing.T) {
	f := newFakeCBS()
	f.replies["show version"] = strings.Repeat("z", 64<<10)
	s := mustOpen(t, newTestDriver(), f)
	if _, err := s.Run(context.Background(), ShowVersion()); !errors.Is(err, ErrLineTooLong) {
		t.Errorf("err = %v, want ErrLineTooLong", err)
	}
}

func TestConfigLineCountLimit(t *testing.T) {
	for _, over := range []bool{false, true} {
		n := MaxConfigLines
		if over {
			n++
		}
		f := newFakeCBS()
		f.replies["show running-config"] = strings.Repeat("!\r\n", n) + synthPrompt
		s := mustOpen(t, newTestDriver(), f)
		_, err := s.Run(context.Background(), ShowRunningConfig())
		if over != errors.Is(err, ErrTooManyLines) || (!over && err != nil) {
			t.Errorf("%d config lines: err = %v", n, err)
		}
		s.Close()
	}
}

func TestMalformedOutputIsRejected(t *testing.T) {
	for name, out := range map[string]string{
		"escape sequence": "\x1b[2Jcleared\r\n",
		"bare CR":         "over\rwrite\r\n",
		"backspace":       "abc\b\b\bxyz\r\n",
		"NUL":             "a\x00b\r\n",
		"invalid UTF-8":   "\xff\xfe\r\n",
		"bidi override":   "abc‮def\r\n",
	} {
		f := newFakeCBS()
		f.replies["show version"] = out + synthPrompt
		s := mustOpen(t, newTestDriver(), f)
		_, err := s.Run(context.Background(), ShowVersion())
		if !errors.Is(err, ErrMalformedOutput) {
			t.Errorf("%s: err = %v, want ErrMalformedOutput", name, err)
		}
		if err != nil && strings.Contains(err.Error(), out) {
			t.Errorf("%s: error echoes device output", name)
		}
		s.Close()
	}
}

func TestPromptLikeTextInsideStreamingOutputDoesNotEndTheRead(t *testing.T) {
	f := newFakeCBS()
	f.replies["show running-config"] = "banner line\r\nsw-lab1#" + pauseMark + " rest\r\n--More--" + pauseMark + " text\r\n" + synthPrompt
	s := mustOpen(t, newTestDriver(), f)
	out, err := s.Run(context.Background(), ShowRunningConfig())
	if err != nil {
		t.Fatal(err)
	}
	if want := "banner line\nsw-lab1# rest\n--More-- text\n"; string(out) != want {
		t.Errorf("output %q, want %q", out, want)
	}
}

func TestMissingEchoIsRejected(t *testing.T) {
	f := newFakeCBS()
	f.noEcho = true
	if _, err := open(t, newTestDriver(), f, Options{}); !errors.Is(err, ErrUnexpectedEcho) {
		t.Errorf("err = %v, want ErrUnexpectedEcho", err)
	}
}

func TestNoPromptTimesOut(t *testing.T) {
	d := newTestDriver()
	d.promptTimeout = 200 * time.Millisecond
	f := newFakeCBS()
	f.silent = true
	if _, err := open(t, d, f, Options{}); !errors.Is(err, ErrTimeout) {
		t.Errorf("Open: err = %v, want ErrTimeout", err)
	}

	d = newTestDriver()
	d.commandTimeout = 200 * time.Millisecond
	g := newFakeCBS()
	g.replies["show version"] = "partial output\r\n"
	s := mustOpen(t, d, g)
	start := time.Now()
	if _, err := s.Run(context.Background(), ShowVersion()); !errors.Is(err, ErrTimeout) {
		t.Errorf("Run: err = %v, want ErrTimeout", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("Run took %v", time.Since(start))
	}
}

func TestDeviceClosingMidOutputFails(t *testing.T) {
	f := newFakeCBS()
	f.replies["show version"] = "partial\r\n"
	s := mustOpen(t, newTestDriver(), f)
	// Close the device side by closing our transport underneath the read.
	go func() { time.Sleep(50 * time.Millisecond); s.client.Close() }()
	_, err := s.Run(context.Background(), ShowVersion())
	if !errors.Is(err, ErrSessionClosed) {
		t.Errorf("err = %v, want ErrSessionClosed", err)
	}
}

func TestNotAllowedCommandSendsNothing(t *testing.T) {
	f := newFakeCBS()
	s := mustOpen(t, newTestDriver(), f)
	for _, c := range []Command{{}, {text: "reload"}, {text: "configure terminal"}, {text: "terminal datadump"}} {
		if _, err := s.Run(context.Background(), c); !errors.Is(err, ErrNotAllowed) {
			t.Errorf("Run(%q) = %v, want ErrNotAllowed", c.text, err)
		}
	}
	if _, err := s.Run(context.Background(), ShowVersion()); err != nil {
		t.Errorf("session unusable after a refused command: %v", err)
	}
	s.Close()
	if got := f.got(); !slices.Equal(got, []string{"terminal datadump", "show version"}) {
		t.Errorf("device received %q", got)
	}
}

func TestOneSessionPerDevice(t *testing.T) {
	f := newFakeCBS()
	d := newTestDriver()
	target, key := f.start(t)
	s, err := d.Open(context.Background(), target, key, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Open(context.Background(), target, key, Options{}); !errors.Is(err, ErrDeviceBusy) {
		t.Errorf("second Open: err = %v, want ErrDeviceBusy", err)
	}
	if _, sessions, _, _, _ := f.counts(); sessions != 1 {
		t.Errorf("device saw %d sessions", sessions)
	}
	other := target
	other.HostID = "sw-lab2"
	s2, err := d.Open(context.Background(), other, key, Options{})
	if err != nil {
		t.Errorf("other device: %v", err)
	} else {
		s2.Close()
	}
	s.Close()
	s3, err := d.Open(context.Background(), target, key, Options{})
	if err != nil {
		t.Fatalf("Open after Close: %v", err)
	}
	s3.Close()
}

func TestFailedSessionReleasesTheDevice(t *testing.T) {
	f := newFakeCBS()
	f.replies["show version"] = "--More--"
	d := newTestDriver()
	target, key := f.start(t)
	s, err := d.Open(context.Background(), target, key, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Run(context.Background(), ShowVersion()); !errors.Is(err, ErrUnexpectedPrompt) {
		t.Fatalf("err = %v", err)
	}
	s.Close()
	s2, err := d.Open(context.Background(), target, key, Options{})
	if err != nil {
		t.Fatalf("Open after failed session: %v", err)
	}
	s2.Close()
}

func TestHostKeyMismatchHardStops(t *testing.T) {
	f := newFakeCBS()
	d := newTestDriver()
	target, key := f.start(t)
	target.HostKey = signer(t).PublicKey()
	for range 2 { // the device lock is released after the failure
		_, err := d.Open(context.Background(), target, key, Options{})
		if sshtransport.ClassOf(err) != sshtransport.ClassHostKeyMismatch {
			t.Errorf("class %q, err %v", sshtransport.ClassOf(err), err)
		}
	}
	if auths, sessions, _, _, _ := f.counts(); auths != 0 || sessions != 0 {
		t.Errorf("device saw %d auths, %d sessions", auths, sessions)
	}
}

func TestAuthFailureHardStops(t *testing.T) {
	f := newFakeCBS()
	d := newTestDriver()
	target, _ := f.start(t)
	_, err := d.Open(context.Background(), target, signer(t), Options{})
	if sshtransport.ClassOf(err) != sshtransport.ClassAuth {
		t.Errorf("class %q, err %v", sshtransport.ClassOf(err), err)
	}
	if _, sessions, _, _, _ := f.counts(); sessions != 0 {
		t.Errorf("device saw %d sessions", sessions)
	}
}

func TestCommandsAreRateLimited(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	d := newTestDriver()
	d.Now = func() time.Time { return now }
	f := newFakeCBS()
	s := mustOpen(t, d, f)
	for _, c := range []Command{ShowVersion(), ShowVLAN()} {
		if _, err := s.Run(context.Background(), c); err != nil {
			t.Fatal(err)
		}
	}
	want := []time.Duration{MinCommandInterval, MinCommandInterval}
	if !slices.Equal(d.sleeps, want) {
		t.Errorf("sleeps %v, want %v", d.sleeps, want)
	}

	// Enough time passed: no wait.
	now = now.Add(MinCommandInterval)
	if _, err := s.Run(context.Background(), ShowVersion()); err != nil {
		t.Fatal(err)
	}
	if len(d.sleeps) != 2 {
		t.Errorf("sleeps %v after an idle interval", d.sleeps)
	}
}

func TestCanceledContextStopsRun(t *testing.T) {
	f := newFakeCBS()
	f.replies["show version"] = "slow\r\n"
	s := mustOpen(t, newTestDriver(), f)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	if _, err := s.Run(ctx, ShowVersion()); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestOpenRejectsMissingHostID(t *testing.T) {
	f := newFakeCBS()
	target, key := f.start(t)
	target.HostID = ""
	if _, err := newTestDriver().Open(context.Background(), target, key, Options{}); err == nil {
		t.Error("Open without host ID succeeded")
	}
	if auths, _, _, _, _ := f.counts(); auths != 0 {
		t.Errorf("device saw %d auths", auths)
	}
}
