package firewall

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
)

// smtpAllowlistLookupUser is the user-database accessor that
// resolveSMTPAllowedUIDs goes through. Production binds it to
// user.Lookup; tests can swap a fixture so unit tests do not depend on
// /etc/passwd of the host they run on.
var smtpAllowlistLookupUser = user.Lookup

// resolveSMTPAllowedUIDs returns the deduplicated list of UIDs that are
// allowed to open outbound SMTP connections when smtp_block is on.
//
// Two UIDs are unconditional:
//   - 0 (root): operator commands, csm itself, system tools.
//   - mailnull: exim's queue-runner runs as this user on cPanel; if it
//     is dropped, queued mail never leaves the host even though cPanel
//     thinks it released the hold. Silently breaking outbound mail is
//     the worst possible failure mode for a security firewall, so we
//     allow it unconditionally rather than rely on the operator
//     remembering to list it under smtp_allow_users.
//
// `allowUsers` is the operator-supplied set; each entry is resolved
// through smtpAllowlistLookupUser. Unknown or unparseable entries are
// reported to stderr (matching the legacy behavior in createOutputChain)
// and skipped, so a typo in the YAML does not crash the firewall engine.
func resolveSMTPAllowedUIDs(allowUsers []string) []uint32 {
	seen := make(map[uint32]struct{}, len(allowUsers)+2)
	out := make([]uint32, 0, len(allowUsers)+2)
	add := func(uid uint32) {
		if _, ok := seen[uid]; ok {
			return
		}
		seen[uid] = struct{}{}
		out = append(out, uid)
	}

	add(0)

	if u, err := smtpAllowlistLookupUser("mailnull"); err == nil {
		if uid, parseErr := strconv.ParseUint(u.Uid, 10, 32); parseErr == nil {
			add(uint32(uid))
		}
	}

	for _, name := range allowUsers {
		u, err := smtpAllowlistLookupUser(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "firewall: smtp_allow_users: unknown user %q\n", name)
			continue
		}
		uid, err := strconv.ParseUint(u.Uid, 10, 32)
		if err != nil {
			fmt.Fprintf(os.Stderr, "firewall: smtp_allow_users: invalid uid for %s: %v\n", name, err)
			continue
		}
		add(uint32(uid))
	}

	return out
}
