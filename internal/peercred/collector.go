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

// Collector role assignment errors; AssignCollectorUser wraps them with
// the role and the user name.
var (
	// ErrNotCollectorRole means AssignCollectorUser was asked to assign a
	// role that is not a collector role.
	ErrNotCollectorRole = errors.New("peercred: not a collector role")
	// ErrCollectorUIDRoot means a collector user resolved to root.
	ErrCollectorUIDRoot = errors.New("must not be root")
	// ErrCollectorUIDExecutor means a collector user resolved to the
	// executor's own UID.
	ErrCollectorUIDExecutor = errors.New("must not be the executor user")
	// ErrCollectorUIDShared means a collector UID already holds a role
	// (server, admin or another collector).
	ErrCollectorUIDShared = errors.New("must be a dedicated user, not shared with another role")
	// ErrCollectorUserMissing means an explicitly configured collector
	// user (not the default name) does not exist.
	ErrCollectorUserMissing = errors.New("configured collector user does not exist")
)

// AssignCollectorUser maps the configured OS user of a collector role to
// that role in roles, exactly like the pve-collector assignment of the
// executor start: an empty name disables the role; a missing user with the
// role's default name (an install that predates the collector) leaves the
// role unassigned; a missing user that was configured explicitly, any
// other lookup failure, or a UID that is root, the executor itself (self)
// or already holds any role stops the start. It reports whether the role
// was assigned. On error roles is unchanged.
func AssignCollectorUser(roles map[uint32][]Role, lookup func(string) (uint32, error), self uint32, role Role, name string) (bool, error) {
	cfg, ok := collectorConfigs[role]
	if !ok {
		return false, fmt.Errorf("assign %q: %w", role, ErrNotCollectorRole)
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return false, nil
	}
	uid, err := lookup(name)
	var unknown user.UnknownUserError
	if errors.As(err, &unknown) {
		if name != cfg.DefaultUser {
			return false, fmt.Errorf("%s user %q: %w: %w", role, name, ErrCollectorUserMissing, err)
		}
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("%s user %q: %w", role, name, err)
	}
	switch {
	case uid == 0:
		return false, fmt.Errorf("%s user %q %w", role, name, ErrCollectorUIDRoot)
	case uid == self:
		return false, fmt.Errorf("%s user %q %w", role, name, ErrCollectorUIDExecutor)
	case len(roles[uid]) > 0:
		return false, fmt.Errorf("%s user %q %w: it holds the %v role", role, name, ErrCollectorUIDShared, roles[uid])
	}
	roles[uid] = []Role{role}
	return true, nil
}
