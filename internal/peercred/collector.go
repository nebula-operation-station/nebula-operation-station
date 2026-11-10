// SPDX-License-Identifier: AGPL-3.0-or-later

package peercred

import (
	"errors"
	"fmt"
	"os/user"
	"strings"
)

// CollectorConfig is the configuration of one collector role: the
// executor flag that names the collector's OS user and the user name that
// install.sh, the Debian package and the container image create.
type CollectorConfig struct {
	Flag        string
	DefaultUser string
}

// collectorConfigs lists every collector role. A collector role always
// runs as its own dedicated UID; AssignCollectorUser refuses any other.
var collectorConfigs = map[Role]CollectorConfig{
	RolePVECollector:    {Flag: "pve-collector-user", DefaultUser: "nebula-pve-collector"},
	RoleNetDevCollector: {Flag: "netdev-collector-user", DefaultUser: "nebula-netdev-collector"},
}

// CollectorConfigFor returns the configuration of a collector role and
// false for any role that is not a collector.
func CollectorConfigFor(r Role) (CollectorConfig, bool) {
	c, ok := collectorConfigs[r]
	return c, ok
}

// Role user assignment errors. They are the single set of refusals for
// every role user of the executor start (server, admin and the collector
// roles); callers wrap them with the role and the user name and branch on
// them with errors.Is.
var (
	// ErrNotCollectorRole means AssignCollectorUser was asked to assign a
	// role that is not a collector role.
	ErrNotCollectorRole = errors.New("peercred: not a collector role")
	// ErrRoleUserRoot means a role user resolved to root.
	ErrRoleUserRoot = errors.New("must not be root")
	// ErrRoleUserExecutor means a role user resolved to the executor's own
	// UID.
	ErrRoleUserExecutor = errors.New("must not be the executor user")
	// ErrRoleUserShared means a role user's UID already holds a role
	// (server, admin or another collector).
	ErrRoleUserShared = errors.New("must be a dedicated user, not shared with another role")
	// ErrCollectorUserMissing means an explicitly configured collector
	// user (not the default name) does not exist.
	ErrCollectorUserMissing = errors.New("configured collector user does not exist")
)

// CollectorAssignment is the outcome of AssignCollectorUser.
type CollectorAssignment int

const (
	// CollectorNotAssigned is returned together with an error.
	CollectorNotAssigned CollectorAssignment = iota
	// CollectorAssigned means the user's UID now holds the role.
	CollectorAssigned
	// CollectorDisabled means the configured user name is empty, so the
	// role is switched off on purpose.
	CollectorDisabled
	// CollectorDefaultUserMissing means the role's default user does not
	// exist (an install that predates the collector); the role is not
	// assigned and the caller must log a warning, because the collector
	// cannot run.
	CollectorDefaultUserMissing
)

// String names the outcome for logs and test failures.
func (a CollectorAssignment) String() string {
	switch a {
	case CollectorAssigned:
		return "assigned"
	case CollectorDisabled:
		return "disabled"
	case CollectorDefaultUserMissing:
		return "default user missing"
	default:
		return "not assigned"
	}
}

// AssignCollectorUser maps the configured OS user of a collector role to
// that role in roles. It is the one assignment path of every collector
// role at executor start: an empty name disables the role
// (CollectorDisabled); a missing user with the role's default name leaves
// the role unassigned (CollectorDefaultUserMissing, the caller warns); a
// missing user that was configured explicitly, any other lookup failure,
// or a UID that is root, the executor itself (self) or already holds any
// role stops the start with an error. On error roles is unchanged.
func AssignCollectorUser(roles map[uint32][]Role, lookup func(string) (uint32, error), self uint32, role Role, name string) (CollectorAssignment, error) {
	cfg, ok := collectorConfigs[role]
	if !ok {
		return CollectorNotAssigned, fmt.Errorf("assign %q: %w", role, ErrNotCollectorRole)
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return CollectorDisabled, nil
	}
	uid, err := lookup(name)
	var unknown user.UnknownUserError
	if errors.As(err, &unknown) {
		if name != cfg.DefaultUser {
			return CollectorNotAssigned, fmt.Errorf("%s user %q: %w: %w", role, name, ErrCollectorUserMissing, err)
		}
		return CollectorDefaultUserMissing, nil
	}
	if err != nil {
		return CollectorNotAssigned, fmt.Errorf("%s user %q: %w", role, name, err)
	}
	switch {
	case uid == 0:
		return CollectorNotAssigned, fmt.Errorf("%s user %q %w", role, name, ErrRoleUserRoot)
	case uid == self:
		return CollectorNotAssigned, fmt.Errorf("%s user %q %w", role, name, ErrRoleUserExecutor)
	case len(roles[uid]) > 0:
		return CollectorNotAssigned, fmt.Errorf("%s user %q %w: it holds the %v role", role, name, ErrRoleUserShared, roles[uid])
	}
	roles[uid] = []Role{role}
	return CollectorAssigned, nil
}
