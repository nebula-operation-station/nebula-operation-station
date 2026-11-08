// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executor/containerdef"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Standalone container definitions (ADR 0006 P2-03, container update plan
// cu05). A definition holds env values, so it enters the executor vault
// only here, on the executor host, as the admin: read from a file or
// stdin, never from an argument, and never printed back. The executor
// validates it again and answers with metadata only.

const containerUsage = `usage:
  nebula container definition put HOST CONTAINER [FILE|-]
      store a new version (JSON from FILE, or stdin if FILE is - or missing)
  nebula container definition remove [--version N] HOST CONTAINER
      remove every version, or one older version N
  nebula container definition list [HOST]
      metadata only (version, author, time; never content)`

// maxDefinitionInput bounds what put reads: the executor's encoded limit
// plus one line ending. More is refused without being sent.
const maxDefinitionInput = containerdef.MaxEncodedBytes + 2

// errDefinitionInput is a refused definition file; the message names the
// rule, never a value from the file.
var errDefinitionInput = errors.New("definition refused")

func containerCmd(ctx context.Context, c pb.ExecutorServiceClient, args []string, stdin io.Reader, openFile func(string) (io.ReadCloser, error), w io.Writer) error {
	if len(args) < 2 || args[0] != "definition" {
		return errors.New(containerUsage)
	}
	sub, rest := args[1], args[2:]
	switch sub {
	case "put":
		if len(rest) != 2 && len(rest) != 3 {
			return errors.New(containerUsage)
		}
		src := stdin
		if len(rest) == 3 && rest[2] != "-" {
			f, err := openFile(rest[2])
			if err != nil {
				return fmt.Errorf("open definition file: %w", err)
			}
			defer f.Close()
			src = f
		}
		return definitionPut(ctx, c, rest[0], rest[1], src, w)
	case "remove":
		var version uint64
		if len(rest) > 0 && rest[0] == "--version" {
			if len(rest) < 2 {
				return errors.New(containerUsage)
			}
			v, err := strconv.ParseUint(rest[1], 10, 64)
			if err != nil || v == 0 {
				return errors.New("--version needs a positive number")
			}
			version, rest = v, rest[2:]
		}
		if len(rest) != 2 {
			return errors.New(containerUsage)
		}
		return definitionRemove(ctx, c, rest[0], rest[1], version, stdin, w)
	case "list":
		if len(rest) > 1 {
			return errors.New(containerUsage)
		}
		host := ""
		if len(rest) == 1 {
			host = rest[0]
		}
		return definitionList(ctx, c, host, w)
	}
	return errors.New(containerUsage)
}

// checkDefinitionTarget validates the host ID and container name before
// anything is read or sent.
func checkDefinitionTarget(host, name string) error {
	if !canonical.ValidHostID(host) {
		return errors.New("invalid host ID")
	}
	if name == "" || len(name) > 128 || strings.ContainsFunc(name, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
		return errors.New("invalid container name")
	}
	return nil
}

// readDefinition reads and strictly parses one definition for name. The
// buffer is cleared before it returns; the parsed values live on only in
// the returned definition.
func readDefinition(r io.Reader, name string) (containerdef.Definition, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxDefinitionInput+1))
	defer clear(raw)
	if err != nil {
		return containerdef.Definition{}, fmt.Errorf("read definition: %w", err)
	}
	if len(raw) > maxDefinitionInput {
		return containerdef.Definition{}, fmt.Errorf("%w: over %d bytes", errDefinitionInput, containerdef.MaxEncodedBytes)
	}
	body := raw
	if c, ok := bytes.CutSuffix(body, []byte("\r\n")); ok {
		body = c
	} else {
		body = bytes.TrimSuffix(body, []byte("\n"))
	}
	// containerdef's errors name the rule and a position, never a value.
	d, err := containerdef.Decode(body, name)
	if err != nil {
		return containerdef.Definition{}, fmt.Errorf("%w: %v", errDefinitionInput, err)
	}
	return d, nil
}

func definitionPut(ctx context.Context, c pb.ExecutorServiceClient, host, name string, src io.Reader, w io.Writer) error {
	if err := checkDefinitionTarget(host, name); err != nil {
		return err
	}
	d, err := readDefinition(src, name)
	if err != nil {
		return err
	}
	req := &pb.PutContainerDefinitionRequest{HostId: host, ContainerName: name, Options: d.Options, Command: d.Command}
	for _, e := range d.Env {
		req.Env = append(req.Env, &pb.ContainerDefinitionEnv{Name: e.Name, Value: e.Value})
	}
	resp, err := c.PutContainerDefinition(ctx, req)
	if err != nil {
		return fmt.Errorf("put container definition %s/%s: %w", displaySafe([]byte(host), 64), displaySafe([]byte(name), 128), err)
	}
	info := resp.GetDefinition()
	fmt.Fprintf(w, "definition for %s on %s stored: version %d (definition %s)\n",
		displaySafe([]byte(info.GetContainerName()), 128), displaySafe([]byte(info.GetHostId()), 64),
		info.GetVersion(), displaySafe([]byte(info.GetDefinitionId()), 64))
	return nil
}

func definitionRemove(ctx context.Context, c pb.ExecutorServiceClient, host, name string, version uint64, stdin io.Reader, w io.Writer) error {
	if err := checkDefinitionTarget(host, name); err != nil {
		return err
	}
	what := "every version of the definition"
	if version != 0 {
		what = fmt.Sprintf("version %d of the definition", version)
	}
	fmt.Fprintf(w, "Type 'yes' to remove %s for %s on %s: ", what, displaySafe([]byte(name), 128), displaySafe([]byte(host), 64))
	line, _ := bufio.NewReader(stdin).ReadString('\n')
	if strings.TrimSpace(line) != "yes" {
		return errors.New("not removed")
	}
	resp, err := c.RemoveContainerDefinition(ctx, &pb.RemoveContainerDefinitionRequest{HostId: host, ContainerName: name, Version: version})
	if err != nil {
		return fmt.Errorf("remove container definition %s/%s: %w", displaySafe([]byte(host), 64), displaySafe([]byte(name), 128), err)
	}
	vs := make([]string, 0, len(resp.GetVersions()))
	for _, v := range resp.GetVersions() {
		vs = append(vs, strconv.FormatUint(v, 10))
	}
	fmt.Fprintf(w, "removed version(s) %s\n", strings.Join(vs, ", "))
	return nil
}

func definitionList(ctx context.Context, c pb.ExecutorServiceClient, host string, w io.Writer) error {
	if host != "" && !canonical.ValidHostID(host) {
		return errors.New("invalid host ID")
	}
	resp, err := c.ListContainerDefinitions(ctx, &pb.ListContainerDefinitionsRequest{HostId: host})
	if err != nil {
		return fmt.Errorf("list container definitions: %w", err)
	}
	if len(resp.GetDefinitions()) == 0 {
		fmt.Fprintln(w, "no container definitions")
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "HOST\tCONTAINER\tVERSION\tLATEST\tCREATED\tBY\tDEFINITION")
	for _, d := range resp.GetDefinitions() {
		latest := ""
		if d.GetLatest() {
			latest = "yes"
		}
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\t%s\t%s\n", displaySafe([]byte(d.GetHostId()), 64),
			displaySafe([]byte(d.GetContainerName()), 128), d.GetVersion(), latest,
			time.Unix(d.GetCreatedAtUnix(), 0).UTC().Format(time.RFC3339),
			displaySafe([]byte(d.GetCreatedBy()), 200), displaySafe([]byte(d.GetDefinitionId()), 64))
	}
	return tw.Flush()
}

// openDefinitionFile opens a definition file for put.
func openDefinitionFile(path string) (io.ReadCloser, error) { return os.Open(path) }
