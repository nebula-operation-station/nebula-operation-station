// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import "github.com/nebula-operation-station/nebula-operation-station/internal/executor"

// registryReadSetter is the part of *executor.Service that wires private
// registry read authorization.
type registryReadSetter interface {
	RegistryReadGrants() executor.RegistryReadAuthorizer
	SetRegistryReadAuthorizer(executor.RegistryReadAuthorizer)
}

// setupRegistryReads wires the production read-grant profile for private
// registry metadata reads (ADR 0006, cu06 part 1, G13; Q6 answered
// 2026-11-11, recommended profile): every ReadPrivateRegistry needs an
// approved registry read lease (rate profile "registry") bound to the
// exact registry record, credential identity and version, repository and
// method, and spends its durable budget. Without this call every private
// read is refused (fail closed). The credential never leaves the executor:
// the lease names no credential value and reads return sanitized values.
func setupRegistryReads(svc registryReadSetter) {
	svc.SetRegistryReadAuthorizer(svc.RegistryReadGrants())
}
