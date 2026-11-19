// SPDX-License-Identifier: AGPL-3.0-or-later

package executorclient

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// executorServiceMethodPrefix is the gRPC prefix of every ExecutorService
// method. checkPVEAdminRPC takes the short method name and rebuilds the full
// name from this prefix, so the expected names below come from the generated
// *_FullMethodName constants and are only shortened, never retyped.
const executorServiceMethodPrefix = "/nebula.executor.v1.ExecutorService/"

func shortMethodName(t *testing.T, fullMethod string) string {
	t.Helper()
	short, ok := strings.CutPrefix(fullMethod, executorServiceMethodPrefix)
	if !ok {
		t.Fatalf("generated method name %q lacks prefix %q", fullMethod, executorServiceMethodPrefix)
	}
	return short
}

func TestContainerDefinitionRPCsForwardWithTimeoutAndMapErrors(t *testing.T) {
	t.Run("PutContainerDefinition", func(t *testing.T) {
		checkPVEAdminRPC(t, shortMethodName(t, pb.ExecutorService_PutContainerDefinition_FullMethodName), (*Client).PutContainerDefinition)
	})
	t.Run("RemoveContainerDefinition", func(t *testing.T) {
		checkPVEAdminRPC(t, shortMethodName(t, pb.ExecutorService_RemoveContainerDefinition_FullMethodName), (*Client).RemoveContainerDefinition)
	})
	t.Run("ListContainerDefinitions", func(t *testing.T) {
		checkPVEAdminRPC(t, shortMethodName(t, pb.ExecutorService_ListContainerDefinitions_FullMethodName), (*Client).ListContainerDefinitions)
	})
}

func TestContainerRecreationRPCsForwardWithTimeoutAndMapErrors(t *testing.T) {
	t.Run("ListContainerRecreations", func(t *testing.T) {
		checkPVEAdminRPC(t, shortMethodName(t, pb.ExecutorService_ListContainerRecreations_FullMethodName), (*Client).ListContainerRecreations)
	})
	t.Run("SetContainerRecoveryPlan", func(t *testing.T) {
		checkPVEAdminRPC(t, shortMethodName(t, pb.ExecutorService_SetContainerRecoveryPlan_FullMethodName), (*Client).SetContainerRecoveryPlan)
	})
	t.Run("ClearContainerRecoveryPlan", func(t *testing.T) {
		checkPVEAdminRPC(t, shortMethodName(t, pb.ExecutorService_ClearContainerRecoveryPlan_FullMethodName), (*Client).ClearContainerRecoveryPlan)
	})
	t.Run("ResolveContainerRecreation", func(t *testing.T) {
		checkPVEAdminRPC(t, shortMethodName(t, pb.ExecutorService_ResolveContainerRecreation_FullMethodName), (*Client).ResolveContainerRecreation)
	})
}

func TestPrivateRegistryRPCsForwardWithTimeoutAndMapErrors(t *testing.T) {
	t.Run("AddPrivateRegistry", func(t *testing.T) {
		checkPVEAdminRPC(t, shortMethodName(t, pb.ExecutorService_AddPrivateRegistry_FullMethodName), (*Client).AddPrivateRegistry)
	})
	t.Run("RotatePrivateRegistryCredential", func(t *testing.T) {
		checkPVEAdminRPC(t, shortMethodName(t, pb.ExecutorService_RotatePrivateRegistryCredential_FullMethodName), (*Client).RotatePrivateRegistryCredential)
	})
	t.Run("RemovePrivateRegistry", func(t *testing.T) {
		checkPVEAdminRPC(t, shortMethodName(t, pb.ExecutorService_RemovePrivateRegistry_FullMethodName), (*Client).RemovePrivateRegistry)
	})
	t.Run("ListPrivateRegistries", func(t *testing.T) {
		checkPVEAdminRPC(t, shortMethodName(t, pb.ExecutorService_ListPrivateRegistries_FullMethodName), (*Client).ListPrivateRegistries)
	})
	t.Run("ReadPrivateRegistry", func(t *testing.T) {
		checkPVEAdminRPC(t, shortMethodName(t, pb.ExecutorService_ReadPrivateRegistry_FullMethodName), (*Client).ReadPrivateRegistry)
	})
}

// TestContainerRegistryRPCMethodNamesArePairwiseDistinct guards against two
// of the twelve wrappers being wired to the same generated method.
func TestContainerRegistryRPCMethodNamesArePairwiseDistinct(t *testing.T) {
	names := []string{
		pb.ExecutorService_PutContainerDefinition_FullMethodName,
		pb.ExecutorService_RemoveContainerDefinition_FullMethodName,
		pb.ExecutorService_ListContainerDefinitions_FullMethodName,
		pb.ExecutorService_ListContainerRecreations_FullMethodName,
		pb.ExecutorService_SetContainerRecoveryPlan_FullMethodName,
		pb.ExecutorService_ClearContainerRecoveryPlan_FullMethodName,
		pb.ExecutorService_ResolveContainerRecreation_FullMethodName,
		pb.ExecutorService_AddPrivateRegistry_FullMethodName,
		pb.ExecutorService_RotatePrivateRegistryCredential_FullMethodName,
		pb.ExecutorService_RemovePrivateRegistry_FullMethodName,
		pb.ExecutorService_ListPrivateRegistries_FullMethodName,
		pb.ExecutorService_ReadPrivateRegistry_FullMethodName,
	}
	seen := make(map[string]int, len(names))
	for i, name := range names {
		if j, ok := seen[name]; ok {
			t.Fatalf("method %q is used by entries %d and %d", name, j, i)
		}
		seen[name] = i
	}
}

// TestCredentialRPCsDoNotEchoSecretInMappedErrors checks that an error
// returned for a credential-carrying call does not contain the secret that
// was sent. The placeholder values are not real credentials.
func TestCredentialRPCsDoNotEchoSecretInMappedErrors(t *testing.T) {
	const secret = "placeholder-registry-secret"
	rpcErr := status.Error(codes.PermissionDenied, "denied")

	t.Run("AddPrivateRegistry", func(t *testing.T) {
		req := &pb.AddPrivateRegistryRequest{
			RegistryId: "registry-example",
			Username:   "placeholder-user",
			Secret:     []byte(secret),
		}
		checkSecretNotEchoed(t, pb.ExecutorService_AddPrivateRegistry_FullMethodName, secret, req, rpcErr,
			(*Client).AddPrivateRegistry)
	})
	t.Run("RotatePrivateRegistryCredential", func(t *testing.T) {
		req := &pb.RotatePrivateRegistryCredentialRequest{
			RegistryId: "registry-example",
			Username:   "placeholder-user",
			Secret:     []byte(secret),
		}
		checkSecretNotEchoed(t, pb.ExecutorService_RotatePrivateRegistryCredential_FullMethodName, secret, req, rpcErr,
			(*Client).RotatePrivateRegistryCredential)
	})
}

func checkSecretNotEchoed[Request, Response any](
	t *testing.T,
	fullMethod string,
	secret string,
	request *Request,
	rpcErr error,
	call func(*Client, context.Context, *Request, ...grpc.CallOption) (*Response, error),
) {
	t.Helper()
	calls := 0
	c := &Client{defaultTimeout: time.Second, rpc: pb.NewExecutorServiceClient(pveAdminConn{
		invoke: func(_ context.Context, method string, in, _ any, _ ...grpc.CallOption) error {
			calls++
			if method != fullMethod {
				t.Errorf("method = %q, want RPC %s", method, fullMethod)
			}
			if in != request {
				t.Error("request was not forwarded")
			}
			return rpcErr
		},
	})}
	_, err := call(c, context.Background(), request)
	if calls != 1 {
		t.Fatalf("RPC calls = %d, want 1", calls)
	}
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("error = %v, want %v", err, ErrPermissionDenied)
	}
	if strings.Contains(err.Error(), secret) {
		t.Error("mapped error contains the sent secret")
	}
}
