// SPDX-License-Identifier: AGPL-3.0-or-later

// Command nebula-discovery will run one-shot Nmap scans with CAP_NET_RAW and
// write results to staging (Milestone 9). It holds no credentials and has no
// database access.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "nebula-discovery: not implemented yet (Milestone 9)")
	os.Exit(2)
}
