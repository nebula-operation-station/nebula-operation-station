// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"text/tabwriter"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
)

// batchHoldsCommand is the offline operator view and recovery of held
// batch targets (ADR 0007 E11). It runs as the executor user with the
// executor stopped: it opens executor.db, whose data directory flock keeps
// a running executor out (and this command out of a running executor's
// directory), and changes the held-target file only through the
// executor's store (validated read, atomic write). Changes are audited in
// the signed event chain.
const batchHoldsCommand = "batch-holds"

const batchHoldsUsage = `usage (as the executor user, with nebula-executor stopped):
  nebula-executor batch-holds list [-data-dir DIR]
  nebula-executor batch-holds rearm [-data-dir DIR] -execution ID -by NAME -reason TEXT HOST
`

// runBatchHolds runs `nebula-executor batch-holds`.
func runBatchHolds(args []string, stdout, stderr io.Writer, now func() time.Time) error {
	if len(args) == 0 {
		fmt.Fprint(stderr, batchHoldsUsage)
		return errors.New("batch-holds: a subcommand is required")
	}
	if os.Geteuid() == 0 {
		return errors.New("batch-holds: refusing to run as root; run it as the nebula-executor user (sudo -u nebula-executor)")
	}
	fs := flag.NewFlagSet(batchHoldsCommand+" "+args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	dataDir := fs.String("data-dir", "/var/lib/nebula/executor", "private executor state")
	var execution, by, reason *string
	switch args[0] {
	case "list":
	case "rearm":
		execution = fs.String("execution", "", "execution ID of the held run (from `list`)")
		by = fs.String("by", "", "operator name (audited)")
		reason = fs.String("reason", "", "why the hold is rechecked again (audited)")
	default:
		fmt.Fprint(stderr, batchHoldsUsage)
		return fmt.Errorf("batch-holds: unknown subcommand %q", args[0])
	}
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if (args[0] == "list" && fs.NArg() != 0) || (args[0] == "rearm" && fs.NArg() != 1) {
		fmt.Fprint(stderr, batchHoldsUsage)
		return errors.New("batch-holds: wrong arguments")
	}

	// Fails while the executor runs: it holds the data directory.
	db, err := executordb.Open(*dataDir)
	if err != nil {
		return fmt.Errorf("batch-holds: stop nebula-executor first: %w", err)
	}
	defer db.Close()

	if args[0] == "list" {
		held, err := executor.OfflineHeldBatchTargets(db, *dataDir)
		if err != nil {
			return err
		}
		writeHeldTargets(stdout, held)
		return nil
	}
	log, _, err := signedLog(*dataDir, db, slog.New(slog.NewJSONHandler(stderr, nil)))
	if err != nil {
		return err
	}
	host := fs.Arg(0)
	if err := executor.RearmHeldBatchTarget(db, *dataDir, host, *execution, *by, *reason, now(), log); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "%s: the hold of execution %s is rechecked again; start nebula-executor, the target is freed once it shows the run gone\n",
		host, *execution)
	return nil
}

// writeHeldTargets prints the held targets as a table.
func writeHeldTargets(w io.Writer, held []executor.HeldBatchTarget) {
	if len(held) == 0 {
		fmt.Fprintln(w, "no held batch targets")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "HOST\tEXECUTION\tHELD SINCE\tSTATE")
	for _, h := range held {
		state := "held (rechecked)"
		if h.Expired {
			state = "expired (rearm to recheck)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", h.HostID, h.ExecutionID, h.HeldAt.UTC().Format(time.RFC3339), state)
	}
	tw.Flush()
}
