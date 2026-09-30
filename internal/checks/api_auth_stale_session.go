package checks

import (
	"net"
	"strings"
	"time"
)

// apiAuthSessionLogTailLines is how much of session_log the counted check
// reads for token denials. session_log is far quieter than access_log, so
// this covers the span of the access_log tail with a wide margin. A shorter
// read only leaves more 401s counted, never fewer.
const apiAuthSessionLogTailLines = 1000

// recentSessionTokenDenials returns the token denials in the session_log tail.
func recentSessionTokenDenials() []SessionTokenDenial {
	var denials []SessionTokenDenial
	for _, line := range tailFile(sessionLogPath, apiAuthSessionLogTailLines) {
		if d, ok := ParseSessionTokenDenial(line); ok {
			denials = append(denials, d)
		}
	}
	return denials
}

// StaleSessionMatchWindow bounds how far apart, in log time, a 401 and the
// token denial that explains it may be. cpsrvd writes both during one page
// load: the parallel requests of a stale tab fail, the third failure purges
// the session, and the requests still in flight fail with a dead cookie.
// Measured bursts spread at most 4 s from the first failure to the purge.
const StaleSessionMatchWindow = 5 * time.Second

// SessionTokenDenial is cpsrvd's session_log record that a client presented
// a live session cookie with the wrong URL security token often enough that
// cPanel ended the session ("PURGE <account>:<session> tokendenied").
type SessionTokenDenial struct {
	IP      string
	Account string
	At      time.Time
}

// tokenDenialServices are the session daemons that enforce the URL security
// token for a browser session. Admin API lines ([xml-api], [security]) carry
// the caller's address, not the browser's.
var tokenDenialServices = map[string]bool{
	"[cpaneld]":   true,
	"[webmaild]":  true,
	"[whostmgrd]": true,
}

// ParseSessionTokenDenial reads a session_log line of the form
// "[<time>] info [cpaneld] <ip> PURGE <account>:<session> tokendenied ...".
// The fields are matched by position so a reason text that mentions
// tokendenied inside another purge line is not accepted.
func ParseSessionTokenDenial(line string) (SessionTokenDenial, bool) {
	if !strings.HasPrefix(line, "[") {
		return SessionTokenDenial{}, false
	}
	end := strings.IndexByte(line, ']')
	if end < 0 {
		return SessionTokenDenial{}, false
	}
	at, ok := parseCPanelLogTime(line[:end+1])
	if !ok {
		return SessionTokenDenial{}, false
	}
	fields := strings.Fields(line[end+1:])
	if len(fields) < 6 || fields[0] != "info" || !tokenDenialServices[fields[1]] ||
		fields[3] != "PURGE" || fields[5] != "tokendenied" {
		return SessionTokenDenial{}, false
	}
	ip := net.ParseIP(fields[2])
	if ip == nil {
		return SessionTokenDenial{}, false
	}
	account, session, ok := strings.Cut(fields[4], ":")
	if !ok || account == "" || session == "" {
		return SessionTokenDenial{}, false
	}
	return SessionTokenDenial{IP: ip.String(), Account: account, At: at}, true
}

// StaleSessionRequest is a 401 on a cPanel session URL
// (/cpsess<token>/...) as cpsrvd logged it in access_log.
type StaleSessionRequest struct {
	IP    string
	User  string
	Token string
	At    time.Time
}

// ParseStaleSessionRequest reads a cpsrvd access_log line of the form
// `<ip> - <user> [01/02/2006:15:04:05 -0700] "<method> /cpsess<token>/... <proto>" 401`.
// A line of any other shape is rejected, which keeps it counted as an
// authentication failure. Token and password API calls use no session URL,
// so they never parse here.
func ParseStaleSessionRequest(line string) (StaleSessionRequest, bool) {
	f := strings.Fields(line)
	if len(f) < 9 || f[8] != "401" || !strings.HasPrefix(f[3], "[") || !strings.HasSuffix(f[4], "]") ||
		!strings.HasPrefix(f[5], `"`) || !strings.HasSuffix(f[7], `"`) {
		return StaleSessionRequest{}, false
	}
	ip := net.ParseIP(f[0])
	if ip == nil {
		return StaleSessionRequest{}, false
	}
	token, ok := cpsessToken(f[6])
	if !ok {
		return StaleSessionRequest{}, false
	}
	at, err := time.Parse("01/02/2006:15:04:05 -0700", f[3][1:]+" "+strings.TrimSuffix(f[4], "]"))
	if err != nil {
		return StaleSessionRequest{}, false
	}
	return StaleSessionRequest{IP: ip.String(), User: f[2], Token: token, At: at}, true
}

// cpsessToken returns the digits of a leading "/cpsess<digits>/" segment.
func cpsessToken(path string) (string, bool) {
	rest, ok := strings.CutPrefix(path, "/cpsess")
	if !ok {
		return "", false
	}
	digits := 0
	for digits < len(rest) && rest[digits] >= '0' && rest[digits] <= '9' {
		digits++
	}
	if digits == 0 || digits >= len(rest) || rest[digits] != '/' {
		return "", false
	}
	return rest[:digits], true
}

// StaleSessionEvidence is what cPanel logged about stale browser sessions:
// its token denials and the session-URL 401s that named a user.
type StaleSessionEvidence struct {
	Denials  []SessionTokenDenial
	Rejected []StaleSessionRequest
}

// Explains reports whether r is a 401 from a stale browser tab rather than
// a failed credential.
//
// A request that names a user is explained by a token denial for that
// account from the same address within StaleSessionMatchWindow: cPanel only
// writes one after that address presented the account's live session cookie
// with the wrong URL token.
//
// A request logged as "-" carried no usable session; once cPanel purges the
// session, the tab's remaining requests look like that. It is explained
// only when it reuses the URL token of a request the denial explains. The
// token is private to that browser tab, so another client behind the same
// address cannot borrow the explanation. The account holder can, for their
// own purged session, which gives them nothing they did not already have
// unless the session daemons check other credentials on session URLs.
func (e StaleSessionEvidence) Explains(r StaleSessionRequest) bool {
	for _, d := range e.Denials {
		if d.IP != r.IP || !withinStaleSessionWindow(r.At, d.At) {
			continue
		}
		if r.User != "-" {
			if r.User == d.Account {
				return true
			}
			continue
		}
		for _, rej := range e.Rejected {
			if rej.IP == r.IP && rej.Token == r.Token && rej.User == d.Account && withinStaleSessionWindow(rej.At, d.At) {
				return true
			}
		}
	}
	return false
}

func withinStaleSessionWindow(a, b time.Time) bool {
	gap := a.Sub(b)
	if gap < 0 {
		gap = -gap
	}
	return gap <= StaleSessionMatchWindow
}
