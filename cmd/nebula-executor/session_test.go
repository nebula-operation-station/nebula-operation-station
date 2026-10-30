// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"flag"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSessionMinutesValidatedBeforeConversion(t *testing.T) {
	for _, minutes := range []int{-1, 0, 14, 15, 60, 240, 241, int(^uint(0) >> 1)} {
		t.Run(strconv.Itoa(minutes), func(t *testing.T) {
			length, err := sessionLengthFromMinutes(minutes)
			if minutes < 15 || minutes > 240 {
				if err == nil {
					t.Fatal("invalid session duration accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if want := time.Duration(minutes) * time.Minute; length != want {
				t.Fatalf("length = %v, want %v", length, want)
			}
		})
	}
}

func TestStartupRejectsInvalidSessionMinutes(t *testing.T) {
	for _, minutes := range []string{"0", "-1", "14", "241", strconv.FormatUint(uint64(^uint(0)>>1), 10)} {
		t.Run(minutes, func(t *testing.T) {
			oldFlags, oldArgs := flag.CommandLine, os.Args
			t.Cleanup(func() { flag.CommandLine, os.Args = oldFlags, oldArgs })
			flag.CommandLine = flag.NewFlagSet("nebula-executor", flag.ContinueOnError)
			flag.CommandLine.SetOutput(io.Discard)
			os.Args = []string{"nebula-executor", "-session-minutes=" + minutes}
			err := run()
			if err == nil || !strings.Contains(err.Error(), "session-minutes must be between 15 and 240") {
				t.Fatalf("startup error = %v", err)
			}
		})
	}
}
