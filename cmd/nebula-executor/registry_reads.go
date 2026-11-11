// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/ed25519"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
)

// servedService is the part of *executor.Service that main wires right
// after construction.
type servedService interface {
	registryReadSetter
	SetPveGuestPowerBindings(*executor.PveGuestPowerBindings)
	SetEventKey(ed25519.PublicKey)
	SetBackupDirs(dataDir, keysDir string)
}

// wireServedService is main's wiring of the service it serves: the guest
// power bindings shared with the risk policy, the event chain key, the
// backup directories and, through setupRegistryReads, the lease-backed
// private registry read authorizer (ADR 0006, cu06 part 1, G13).
func wireServedService(svc servedService, power *executor.PveGuestPowerBindings, eventKey ed25519.PublicKey, dataDir, keysDir string) {
	svc.SetPveGuestPowerBindings(power)
	svc.SetEventKey(eventKey)
	svc.SetBackupDirs(dataDir, keysDir)
	setupRegistryReads(svc)
}

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
