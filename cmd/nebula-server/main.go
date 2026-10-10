// SPDX-License-Identifier: AGPL-3.0-or-later

// Command nebula-server will serve the web UI, inventory and planning
// (Milestone 1). In Milestone 0 it only checks that it can reach the
// executor with its own UID, which exercises the server role end to end.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/version"
)

func main() {
	sock := flag.String("executor-socket", "/run/nebula/executor.sock", "executor Unix socket")
	execUser := flag.String("executor-user", "nebula-executor", "OS user that must serve the socket")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version.String())
		return
	}

	wantUID, err := peercred.LookupUID(*execUser)
	if err != nil {
		fmt.Fprintln(os.Stderr, "nebula-server:", err)
		os.Exit(1)
	}
	conn, err := grpc.NewClient("passthrough:///executor",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return peercred.DialVerified(ctx, *sock, wantUID)
		}))
	if err != nil {
		fmt.Fprintln(os.Stderr, "nebula-server:", err)
		os.Exit(1)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := pb.NewExecutorServiceClient(conn).GetStatus(ctx, &pb.GetStatusRequest{})
	if err != nil {
		fmt.Fprintln(os.Stderr, "nebula-server: executor check failed:", err)
		os.Exit(1)
	}
	fmt.Printf("executor reachable as server role; unlocked=%v hardened=%v\n", s.GetUnlocked(), s.GetHardenedMode())
	fmt.Println("web UI is not implemented yet (Milestone 1)")
}
