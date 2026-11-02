package hostfacts

import (
	"errors"
	"slices"
	"strings"
)

// localAccounts maps the users in /etc/passwd to their uids, the first
// entry of a name winning as with NSS. A record that does not parse may
// hide a user, so the whole file must parse.
func (c collector) localAccounts() (map[string]int, error) {
	passwd, err := c.readPasswd()
	if err != nil {
		return nil, err
	}
	users := make(map[string]int)
	for line := range strings.SplitSeq(string(passwd), "\n") {
		line = strings.Trim(line, " \t\r\v\f")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.SplitN(line, ":", 8)
		if len(fields) != 7 || !accountName(fields[0]) {
			return nil, errors.New("local account database is not readable")
		}
		uid, ok := accountID(fields[2])
		if !ok {
			return nil, errors.New("local account uid is not readable")
		}
		if _, ok := accountID(fields[3]); !ok {
			return nil, errors.New("local account gid is not readable")
		}
		if _, seen := users[fields[0]]; !seen {
			users[fields[0]] = uid
		}
	}
	return users, nil
}

// postfixServiceUsers run no tenant code on a Postfix host. The mail uid
// user (vmail) is not one of them: tenants' sieve scripts and Dovecot's mail
// processes run as it. Being pinned grants no access: Redis trusts only
// root, redis and rspamd's user, the controller only root and rspamd's user.
var postfixServiceUsers = []string{"root", "redis", "dovecot", "dovenull", "postfix"}

// untrustedLocalUsers lists the users that may run tenant code on a Postfix
// host, which has no account registry: every user in /etc/passwd but
// rspamd's service user and postfixServiceUsers. A name whose uid Dovecot
// stores mail as stays untrusted even when pinned.
func (c collector) untrustedLocalUsers(rspamdUser string, mailUIDs []int) (map[string]bool, error) {
	users, err := c.localAccounts()
	if err != nil {
		return nil, err
	}
	names := make(map[string]bool, len(users))
	for name, uid := range users {
		if slices.Contains(mailUIDs, uid) || !slices.Contains(postfixServiceUsers, name) && name != rspamdUser {
			names[name] = true
		}
	}
	return names, nil
}
