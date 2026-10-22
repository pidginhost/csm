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
