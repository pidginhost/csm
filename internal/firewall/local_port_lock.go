package firewall

import (
	"fmt"
	"os"
	"os/user"
	"regexp"
	"strconv"
	"strings"
)

// LocalPortLock lets only Users, and root, open new connections to Port on
// this host.
type LocalPortLock struct {
	Port  int
	Users []string
}

var lockUserName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}$`)

// ParseLocalPortLocks reads firewall.local_port_locks entries of the form
// "PORT:user[,user...]". A port may appear once.
func ParseLocalPortLocks(entries []string) ([]LocalPortLock, error) {
	locks := make([]LocalPortLock, 0, len(entries))
	seen := map[int]bool{}
	for i, entry := range entries {
		portText, usersText, ok := strings.Cut(entry, ":")
		if !ok {
			return nil, fmt.Errorf("entry %d %q: want PORT:user[,user...]", i, entry)
		}
		port, err := strconv.Atoi(strings.TrimSpace(portText))
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("entry %d %q: port must be 1-65535", i, entry)
		}
		if seen[port] {
			return nil, fmt.Errorf("entry %d %q: port %d is listed twice", i, entry, port)
		}
		seen[port] = true
		var users []string
		for _, name := range strings.Split(usersText, ",") {
			name = strings.TrimSpace(name)
			if !lockUserName.MatchString(name) {
				return nil, fmt.Errorf("entry %d %q: %q is not a user name", i, entry, name)
			}
			users = append(users, name)
		}
		locks = append(locks, LocalPortLock{Port: port, Users: users})
	}
	return locks, nil
}

// localPortLockLookupUser resolves lock user names; tests swap a fixture.
var localPortLockLookupUser = user.Lookup

// resolveLockUIDs returns root plus each listed user's UID. Unknown users are
// reported and skipped: the lock still applies, so a typo denies that user
// rather than opening the port.
func resolveLockUIDs(port int, users []string) []uint32 {
	out := []uint32{0}
	seen := map[uint32]bool{0: true}
	for _, name := range users {
		u, err := localPortLockLookupUser(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "firewall: local_port_locks: port %d: unknown user %q\n", port, name)
			continue
		}
		uid, err := strconv.ParseUint(u.Uid, 10, 32)
		if err != nil {
			fmt.Fprintf(os.Stderr, "firewall: local_port_locks: port %d: invalid uid for %s: %v\n", port, name, err)
			continue
		}
		if !seen[uint32(uid)] {
			seen[uint32(uid)] = true
			out = append(out, uint32(uid))
		}
	}
	return out
}
