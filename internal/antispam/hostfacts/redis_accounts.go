package hostfacts

import (
	"errors"
	"strings"
)

// localAccountNames lists the users in /etc/passwd. A record that does not
// parse may hide a user, so the whole file must parse.
func (c collector) localAccountNames() (map[string]bool, error) {
	passwd, err := c.readPasswd()
	if err != nil {
		return nil, err
	}
	names := make(map[string]bool)
	for line := range strings.SplitSeq(string(passwd), "\n") {
		line = strings.Trim(line, " \t\r\v\f")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.SplitN(line, ":", 8)
		if len(fields) != 7 || !accountName(fields[0]) {
			return nil, errors.New("local account database is not readable")
		}
		if _, ok := accountID(fields[2]); !ok {
			return nil, errors.New("local account uid is not readable")
		}
		if _, ok := accountID(fields[3]); !ok {
			return nil, errors.New("local account gid is not readable")
		}
		names[fields[0]] = true
	}
	return names, nil
}

// postfixServiceUsers run no tenant code on a Postfix host. The mail uid
// user (vmail) is not one of them: tenants' sieve scripts and Dovecot's mail
// processes run as it. Being pinned grants no access: Redis trusts only
// root, redis and rspamd's user, the controller only root and rspamd's user.
var postfixServiceUsers = []string{"root", "redis", "dovecot", "dovenull", "postfix"}

// untrustedLocalUsers lists the users that may run tenant code on a Postfix
// host, which has no account registry: every user in /etc/passwd but
// rspamd's service user and postfixServiceUsers.
func (c collector) untrustedLocalUsers(rspamdUser string) (map[string]bool, error) {
	names, err := c.localAccountNames()
	if err != nil {
		return nil, err
	}
	for _, name := range postfixServiceUsers {
		delete(names, name)
	}
	delete(names, rspamdUser)
	return names, nil
}
