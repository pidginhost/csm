package maillog

import (
	"os/user"
	"strconv"
	"strings"
)

// SenderRule names the units a service runs in and the uids its log lines
// come from. journald records both from the sending process, never from the
// message, so a program cannot claim them by naming itself after a service.
// The unit alone is not enough: a service can run a user's command inside
// its unit, a mail pipe or an SSH shell, under that user's uid.
type SenderRule struct {
	Units []string
	UIDs  []uint32
}

// TrustedLine reports whether line is a journal entry one of rules' services
// wrote. A line read from a file is never trusted: any local user can write
// one under any program name. Only the syslog socket and the native journal
// API give journald the sender's credentials with each message; an output
// stream keeps those of the process that opened it, and a child that
// inherits the stream writes under them.
func TrustedLine(line Line, rules []SenderRule) bool {
	if line.Source != "journal" || line.Unit == "" || (line.Transport != "syslog" && line.Transport != "journal") {
		return false
	}
	uid, err := strconv.ParseUint(line.UID, 10, 32)
	if err != nil {
		return false
	}
	for _, r := range rules {
		for _, u := range r.Units {
			if journalUnitName(u) != line.Unit {
				continue
			}
			for _, want := range r.UIDs {
				if uint32(uid) == want {
					return true
				}
			}
		}
	}
	return false
}

// journalUnitName is the full unit name journald records for unit.
func journalUnitName(unit string) string {
	unit = strings.TrimSpace(unit)
	if strings.Contains(unit, ".") {
		return unit
	}
	return unit + ".service"
}

// lookupServiceUID resolves a service account's uid.
var lookupServiceUID = func(name string) (uint32, bool) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, false
	}
	id, err := strconv.ParseUint(u.Uid, 10, 32)
	return uint32(id), err == nil
}

// MailSenderRules trusts root in every configured mail unit, which covers
// Dovecot's log process, and the postfix user in Postfix units.
func MailSenderRules(units []string) []SenderRule {
	var rules []SenderRule
	for _, u := range units {
		uids := []uint32{0}
		if name := strings.TrimSuffix(journalUnitName(u), ".service"); name == "postfix" || strings.HasPrefix(name, "postfix@") {
			if id, ok := lookupServiceUID("postfix"); ok && id != 0 {
				uids = append(uids, id)
			}
		}
		rules = append(rules, SenderRule{Units: []string{u}, UIDs: uids})
	}
	return rules
}
