// SPDX-License-Identifier: AGPL-3.0-or-later

package run

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/nebula-operation-station/nebula-operation-station/internal/llmclient"
)

// LLM egress (ADR 0011 A1.4, ADR 0016 D6): the lab-only dialer lives in
// internal/llmclient. This file maps its errors to the names and texts of
// this package and builds its options from the run's configuration.

// LLMNetwork overrides resolver, dialer and TLS roots of the LLM endpoint
// (see llmclient.Network); the lab-address check applies regardless.
type LLMNetwork = llmclient.Network

// ErrNotLabAddress: the LLM endpoint is (or resolves to) an address
// outside the lab ranges; no connection was made.
var ErrNotLabAddress = errors.New("vulnagent/run: llm endpoint is not a lab address")

// ParseAllowedNetworks parses llm.allowed_networks (see
// llmclient.ParseNetworks); a refused entry matches ErrConfig.
func ParseAllowedNetworks(ss []string) ([]netip.Prefix, error) {
	nets, err := llmclient.ParseNetworks(ss)
	if err != nil {
		return nil, configErr(err)
	}
	return nets, nil
}

// configErr keeps the text of a shared-client configuration error and
// appends this package's ErrConfig.
func configErr(err error) error {
	var ce *llmclient.Error
	if errors.As(err, &ce) && errors.Is(err, llmclient.ErrConfig) {
		return fmt.Errorf("%s: %w", ce.Error(), ErrConfig)
	}
	return err
}

// llmOptions are the client options of one run: always the lab-only
// dialer, with the configured lab networks, Unix socket and test seams.
func (r *Runner) llmOptions(eff LLMConfig) llmclient.Options {
	return llmclient.Options{
		BaseURL:        eff.BaseURL,
		Model:          eff.Model,
		CredentialFile: eff.APIKeyFile,
		AllowPlainHTTP: eff.AllowPlainHTTP,
		Timeout:        eff.Limits.LLMCallTimeout,
		LabOnly:        true,
		LabNetworks:    r.labNets,
		UnixSocket:     r.cfg.LLM.UnixSocket,
		Network:        r.cfg.LLMNet,
	}
}

// checkEndpoint resolves the effective endpoint once before the assessor
// starts and refuses it unless every address is a lab address (or the
// Unix socket is configured). The dialer repeats the check on every
// connection, so a later DNS change is refused too.
func (r *Runner) checkEndpoint(ctx context.Context, eff LLMConfig) error {
	err := llmclient.CheckEndpoint(ctx, r.llmOptions(eff))
	if errors.Is(err, llmclient.ErrNotLabAddress) {
		return ErrNotLabAddress
	}
	return err
}
