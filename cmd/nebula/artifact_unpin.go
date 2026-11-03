// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// maxUnpinVersionRef bounds the name@version argument of `artifact unpin`
// (the executor enforces the same bound).
const maxUnpinVersionRef = 256

const unpinUsage = "usage: nebula artifact unpin MODULE@VERSION (see `nebula artifact trust-builtins` for saved pins)"

// builtinUnpinClient is the part of the executor client `artifact unpin`
// uses.
type builtinUnpinClient interface {
	UnpinBuiltinVersion(ctx context.Context, in *pb.UnpinBuiltinVersionRequest, opts ...grpc.CallOption) (*pb.UnpinBuiltinVersionResponse, error)
}

// artifactUnpin implements `nebula artifact unpin MODULE@VERSION`: it
// clears a pin saved by `nebula artifact trust-builtins --pin`. Like
// trust-builtins it runs as the local admin user and the executor commits
// it, records the admin UID from the socket's peer credentials and audits
// it (builtin_trust_unpinned). It deletes and revokes nothing.
func artifactUnpin(ctx context.Context, c builtinUnpinClient, args []string) error {
	if os.Geteuid() == 0 {
		return errors.New("run `nebula artifact unpin` as your admin user, not as root or with sudo: the executor commits it and records your UID")
	}
	return artifactUnpinIO(ctx, c, args, os.Stdout)
}

// artifactUnpinIO is the testable core of artifactUnpin.
func artifactUnpinIO(ctx context.Context, c builtinUnpinClient, args []string, out io.Writer) error {
	if len(args) != 1 {
		return errors.New(unpinUsage)
	}
	v := args[0]
	name, version, ok := strings.Cut(v, "@")
	if !ok || name == "" || version == "" || len(v) > maxUnpinVersionRef || !utf8.ValidString(v) {
		return errors.New(unpinUsage)
	}
	res, err := c.UnpinBuiltinVersion(ctx, &pb.UnpinBuiltinVersionRequest{Version: v})
	if err != nil {
		if grpcstatus.Code(err) == codes.NotFound {
			return fmt.Errorf("%s is not pinned in the built-in trust store; nothing changed", safe(v))
		}
		return fmt.Errorf("unpin %s: %w", safe(v), err)
	}
	fmt.Fprintln(out, "unpinned:")
	fmt.Fprintf(out, "  version:    %s\n", safe(res.GetVersion()))
	fmt.Fprintf(out, "  admin uid:  %d\n", res.GetAdminUid())
	fmt.Fprintf(out, "  generation: %d\n", res.GetGeneration())
	if len(res.GetRemainingPins()) == 0 {
		fmt.Fprintln(out, "  still pinned: none")
	} else {
		fmt.Fprintf(out, "  still pinned: %s\n", safe(strings.Join(res.GetRemainingPins(), ", ")))
	}
	fmt.Fprintln(out, "Nothing was deleted or revoked; normal retention applies again, so a later trust-builtins commit may collect this version.")
	return nil
}
