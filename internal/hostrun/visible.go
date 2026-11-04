// SPDX-License-Identifier: AGPL-3.0-or-later

package hostrun

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// visibleScript looks for a process of the attached run %[1]s that the
// SSH user can see: the bootstrap shell carries the execution ID on its
// command line, and the script and its children inherit it in their
// environment. The marker is assembled by printf and read by grep from
// stdin, so neither the check's own command lines nor its environment
// contain it. Exit 0: none visible; 1: still running; anything else
// (no /proc, ...): cannot tell.
const visibleScript = `[ -r /proc/self/environ ] || exit 3
m=$(printf '%%s_EXECUTION_ID=%%s\n' NEBULA %[1]s | grep -lsaF -f - /proc/[0-9]*/environ /proc/[0-9]*/cmdline)
[ -z "$m" ] || exit 1
exit 0
`

// ErrVisibilityUnknown means the host could not tell whether a process of
// the run is still running.
var ErrVisibilityUnknown = errors.New("hostrun: cannot tell whether the run is still running")

// RunVisible reports whether a process of the attached run executionID is
// still running on the host, as far as the SSH user can see (a process
// that switched to another user and dropped the execution ID is not
// seen). Callers that need the target idle treat an error as running.
func RunVisible(ctx context.Context, client *ssh.Client, executionID string) (bool, error) {
	if !uuidRe.MatchString(executionID) {
		return false, errors.New("hostrun: execution ID is not a lowercase UUID")
	}
	s, err := client.NewSession()
	if err != nil {
		return false, fmt.Errorf("hostrun: open session: %w", err)
	}
	return runVisible(ctx, s, executionID)
}

func runVisible(ctx context.Context, s Session, executionID string) (bool, error) {
	done := make(chan error, 1)
	go func() { done <- s.Run("exec /bin/sh -c " + shellQuote(fmt.Sprintf(visibleScript, executionID))) }()
	var err error
	select {
	case err = <-done:
		_ = s.Close()
	case <-ctx.Done():
		_ = s.Close()
		return false, fmt.Errorf("%w: %w", ErrVisibilityUnknown, ctx.Err())
	}
	var ee *ssh.ExitError
	switch {
	case err == nil:
		return false, nil
	case errors.As(err, &ee) && ee.Signal() == "" && ee.ExitStatus() == 1:
		return true, nil
	}
	return false, fmt.Errorf("%w: %w", ErrVisibilityUnknown, err)
}
