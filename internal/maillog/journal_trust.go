package maillog

import (
	"os/user"
	"path/filepath"
	"slices"
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
	// Executables are program names trusted at any uid in the rule's units:
	// for a service that drops to a user's uid but runs no user code.
	Executables []string
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
			if !unitMatches(u, line.Unit) {
				continue
			}
			for _, want := range r.UIDs {
				if uint32(uid) == want {
					return true
				}
			}
			if line.Exe != "" && slices.Contains(r.Executables, filepath.Base(line.Exe)) {
				return true
			}
		}
	}
	return false
}

// unitMatches reports whether journald's unit is rule: a unit name, or a
// template ending in @ whose service instances all match.
func unitMatches(rule, unit string) bool {
	if strings.HasSuffix(rule, "@") {
		return strings.HasPrefix(unit, rule) && len(unit) > len(rule)+len(".service") && strings.HasSuffix(unit, ".service")
	}
	return journalUnitName(rule) == unit
}

// journalMatches selects a source's entries: each unit exactly, and each
// program identifier its lines carry. A template has no exact unit name; its
// instances arrive through the identifiers, and the sender rule decides
// whether a selected entry is trusted.
func journalMatches(units, identifiers []string) []string {
	var out []string
	for _, u := range units {
		if !strings.HasSuffix(u, "@") {
			out = append(out, "_SYSTEMD_UNIT="+journalUnitName(u))
		}
	}
	for _, id := range identifiers {
		out = append(out, "SYSLOG_IDENTIFIER="+id)
	}
	return out
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
		if postfixJournalUnit(u) {
			if id, ok := lookupServiceUID("postfix"); ok && id != 0 {
				uids = append(uids, id)
			}
		}
		rules = append(rules, SenderRule{Units: []string{u}, UIDs: uids})
	}
	return rules
}

func postfixJournalUnit(unit string) bool {
	name := strings.TrimSuffix(journalUnitName(unit), ".service")
	return name == "postfix" || strings.HasPrefix(name, "postfix@")
}
