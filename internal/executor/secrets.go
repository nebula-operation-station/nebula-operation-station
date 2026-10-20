// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"errors"
	"sort"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vault"
)

// runSecrets opens the vault secrets a run's parameters name (M7-3,
// spec 06). It runs before the permit's host is used, so a locked vault or
// a missing secret refuses the run without using it up. The values go only
// to the host, over the SSH channel; they are never logged.
func (s *Service) runSecrets(parametersJSON []byte) ([]hostrun.Secret, error) {
	refs, err := permit.SecretRefs(parametersJSON)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "parameters: "+err.Error())
	}
	return s.openSecrets(refs)
}

// openSecrets opens the vault secrets of a slot -> secret ID mapping.
func (s *Service) openSecrets(refs map[string]string) ([]hostrun.Secret, error) {
	if len(refs) == 0 {
		return nil, nil
	}
	slots := make([]string, 0, len(refs))
	for slot := range refs {
		slots = append(slots, slot)
	}
	sort.Strings(slots)
	out := make([]hostrun.Secret, 0, len(slots))
	for _, slot := range slots {
		v, err := s.vault.Open(refs[slot])
		switch {
		case errors.Is(err, vault.ErrLocked):
			return nil, status.Error(codes.FailedPrecondition, "vault_locked: the run uses vault secrets; run `nebula unlock` on the executor host")
		case errors.Is(err, vault.ErrNotFound):
			return nil, status.Errorf(codes.FailedPrecondition, "secret_unavailable: no vault secret %q (slot %s)", refs[slot], slot)
		case err != nil:
			s.log.Error("audit", "kind", "store_error", "op", "open_secret", "secret", refs[slot], "detail", err.Error())
			return nil, status.Error(codes.Unavailable, "storage_error: a vault secret could not be read")
		}
		out = append(out, hostrun.Secret{Slot: slot, Value: v})
	}
	return out, nil
}

// errSecretsUnavailable: a durable run's secrets could not be opened to
// redact its output (the vault is locked or a secret was removed).
var errSecretsUnavailable = errors.New("secrets unavailable")

// redactDurable removes a durable run's secret values from its collected
// result and log (review m73, finding 1). With the vault locked it returns
// errSecretsUnavailable, and the caller leaves the job on the host until
// the next pass. A secret that no longer exists cannot be used to redact,
// so the output is withheld instead of stored unredacted.
func (s *Service) redactDurable(run executordb.Run, r *hostrun.Result) error {
	if len(run.SecretRefs) == 0 {
		return nil
	}
	secrets, err := s.openSecrets(run.SecretRefs)
	switch {
	case status.Code(err) == codes.FailedPrecondition && strings.HasPrefix(status.Convert(err).Message(), "vault_locked"):
		return errSecretsUnavailable
	case err != nil:
		r.Result = nil
		r.Log = []byte(withheldLog)
		r.LogTruncated = false
		return nil
	}
	redact(r, secrets)
	return nil
}

// withheldLog replaces the output of a durable run whose secrets could not
// be opened for redaction.
const withheldLog = "[nebula: the result and log of this run were withheld: a vault secret it used could not be opened to redact them]\n"

// redact removes the run's secret values from host output.
func redact(r *hostrun.Result, secrets []hostrun.Secret) {
	if len(secrets) == 0 {
		return
	}
	r.Result = hostrun.Redact(r.Result, secrets)
	r.Log = hostrun.Redact(r.Log, secrets)
}
