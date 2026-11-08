package checks

import (
	"strings"

	"github.com/pidginhost/csm/internal/netutil"
)

// DovecotRemoteIP returns the connection's address from a Dovecot login
// line, or "" when the line has none. Dovecot logs the login name
// (user=<...>) as the client sent it, ahead of rip=, so only the last rip=
// field can be the server's.
func DovecotRemoteIP(line string) string {
	i := strings.LastIndex(line, "rip=")
	if i < 0 || (i > 0 && line[i-1] != ' ') {
		return ""
	}
	value := line[i+len("rip="):]
	if end := strings.IndexAny(value, ", \t"); end >= 0 {
		value = value[:end]
	}
	ip, _ := netutil.ParseIPToken(value)
	return ip
}
