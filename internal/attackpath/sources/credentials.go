// SPDX-License-Identifier: AGPL-3.0-or-later

package sources

import (
	"context"
	"fmt"

	"github.com/nebula-operation-station/nebula-operation-station/internal/attackpath"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
)

// HostLister reads the managed hosts of the inventory. *inventory.Store
// implements it.
type HostLister interface {
	List(ctx context.Context) ([]inventory.Host, error)
}

var _ HostLister = (*inventory.Store)(nil)

// CredentialConfig configures the executor credential adapter.
type CredentialConfig struct {
	// Hosts reads the inventory.
	Hosts HostLister
	// ExecutorHostID is the inventory ID of the host the executor runs on
	// (the crown-jewel role "NOS executor host"); empty when not assigned.
	ExecutorHostID string
}

// Credentials returns the credential edges of ADR 0011 D10: the executor
// host holds SSH keys to every managed host, so owning it owns each of
// them. It adds every managed host as a node (coverage unit: managed host)
// and an edge from the executor host to every other one. Without an
// assigned executor host, or one missing from the inventory, the source is
// unknown: the edges exist in reality, NOS only cannot place them.
//
// A read error yields StatusUnknown and an error wrapping
// ErrSourceUnavailable; the Result is still meant to be merged.
func Credentials(ctx context.Context, cfg CredentialConfig) (Result, error) {
	c := newCollector(SourceCredentials)
	if cfg.Hosts == nil {
		c.unavailable()
		return c.result(), fmt.Errorf("credential source: no host lister: %w", ErrSourceUnavailable)
	}
	hosts, err := cfg.Hosts.List(ctx)
	if err != nil {
		c.unavailable()
		return c.result(), fmt.Errorf("credential source: list hosts: %w: %w", ErrSourceUnavailable, err)
	}
	executor := ""
	var ids []string
	for _, h := range hosts {
		id, ok := nodeID("host:", h.ID)
		if !ok {
			c.uncertain(UncertainInvalidRecord, "")
			c.partial()
			continue
		}
		c.r.Coverage.Total++
		if !c.node(attackpath.Node{ID: id, Kind: attackpath.NodeHost, Label: label(h.DisplayName)}) {
			continue
		}
		ids = append(ids, id)
		if cfg.ExecutorHostID != "" && h.ID == cfg.ExecutorHostID {
			executor = id
		}
	}
	if executor == "" {
		c.r.Status = StatusUnknown
		c.uncertain(UncertainExecutorUnassigned, "")
		return c.result(), nil
	}
	for _, id := range ids {
		if id != executor {
			c.edge(attackpath.Edge{From: executor, To: id, Kind: attackpath.EdgeCredential})
		}
	}
	c.r.Coverage.Covered = len(ids)
	return c.result(), nil
}
