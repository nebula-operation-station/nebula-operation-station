// SPDX-License-Identifier: AGPL-3.0-or-later

package runbooks

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/prelude"
)

// ShellCheck parses a script with sh -n without running it. It is a
// variable so tests on machines without /bin/sh can replace it.
var ShellCheck = func(script []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-n")
	cmd.Stdin = bytes.NewReader(script)
	cmd.Env = []string{"LC_ALL=C", "PATH=/usr/bin:/bin"}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if i := strings.IndexByte(msg, '\n'); i >= 0 {
			msg = msg[:i]
		}
		if len(msg) > 200 {
			msg = msg[:200]
		}
		if msg == "" {
			return err
		}
		return errors.New(msg)
	}
	return nil
}

// Artifact is what runs on the host for a version (internal/prelude).
func Artifact(v Version) []byte {
	return prelude.Build("Nebula runbook "+v.Slug+" version "+strconv.Itoa(v.Version)+" (runbook-v1).", v.Params, v.Secrets, v.Body)
}
