package checks

import (
	"net/netip"
	"strings"
	"time"
)

// SessionRecord is one cpsrvd session_log record:
// "[<time>] info [<service>] <origin> <event> <account>:<session> <detail>...".
// Every field is matched by position, so text a client controls later in
// the line (a login name, the address= list) cannot supply the service,
// the origin, the event or the account.
type SessionRecord struct {
	At      time.Time // zero when the timestamp does not parse
	Level   string
	Service string // without brackets: cpaneld, webmaild, whostmgrd, whostmgr, security, xml-api
	Origin  string // the client address, or "internal" for a server-side event
	Event   string // NEW, PURGE, ...
	Account string
	Session string
	Detail  []string // the fields after <account>:<session>
}

// ParseSessionRecord reads one info-level session_log line. Records without
// a bracketed service or an <account>:<session> pair are rejected.
func ParseSessionRecord(line string) (SessionRecord, bool) {
	if !strings.HasPrefix(line, "[") || strings.ContainsAny(line, "\r\n") {
		return SessionRecord{}, false
	}
	end := strings.IndexByte(line, ']')
	if end < 0 || end+1 >= len(line) || (line[end+1] != ' ' && line[end+1] != '\t') {
		return SessionRecord{}, false
	}
	fields := strings.Fields(line[end+1:])
	if len(fields) < 5 || fields[0] != "info" {
		return SessionRecord{}, false
	}
	service, opened := strings.CutPrefix(fields[1], "[")
	service, closed := strings.CutSuffix(service, "]")
	if !opened || !closed || service == "" || strings.ContainsAny(service, "[]") {
		return SessionRecord{}, false
	}
	account, session, found := strings.Cut(fields[4], ":")
	if !found || account == "" || session == "" {
		return SessionRecord{}, false
	}
	at, _ := CPanelLogTime(line[:end+1])
	return SessionRecord{
		At:      at,
		Level:   fields[0],
		Service: service,
		Origin:  fields[2],
		Event:   fields[3],
		Account: account,
		Session: session,
		Detail:  fields[5:],
	}, true
}

// ClientAddr is the record's origin as an address. "internal" and any other
// text that is not an address report false.
func (r SessionRecord) ClientAddr() (netip.Addr, bool) {
	addr, err := netip.ParseAddr(r.Origin)
	if err != nil || addr.Zone() != "" {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

// Reason is the first detail field, which names why a PURGE ended the
// session (password_change, tokendenied, logout, ...).
func (r SessionRecord) Reason() string {
	if len(r.Detail) == 0 {
		return ""
	}
	return r.Detail[0]
}

// Attr is the value of key in the comma-separated key=value detail of a NEW
// record ("address=...,app=cpaneld,method=handle_form_login"). Duplicate keys
// yield no value: client-controlled detail must not override server metadata.
func (r SessionRecord) Attr(key string) string {
	var value string
	found := false
	for _, field := range r.Detail {
		for _, pair := range strings.Split(field, ",") {
			if k, v, ok := strings.Cut(pair, "="); ok && k == key {
				if found {
					return ""
				}
				value, found = v, true
			}
		}
	}
	return value
}

// CreatedByAPI reports a session an API call opened for the account (the
// portal's create_user_session), not a login the user made.
func (r SessionRecord) CreatedByAPI() bool {
	method := r.Attr("method")
	return method == "create_user_session" || method == "create_session"
}

// CPanelLogTime reads the leading "[<timestamp>]" of a cPanel session_log
// or api_tokens_log line. Both the timezone-qualified form
// ("2006-01-02 15:04:05 -0700") and the older bare form ("2006-01-02 15:04:05",
// interpreted in the host's local zone) are accepted. Returns ok=false when no
// bracketed timestamp is present or it does not parse.
func CPanelLogTime(line string) (time.Time, bool) {
	open := strings.IndexByte(line, '[')
	if open < 0 {
		return time.Time{}, false
	}
	end := strings.IndexByte(line[open:], ']')
	if end < 0 {
		return time.Time{}, false
	}
	stamp := strings.TrimSpace(line[open+1 : open+end])
	for _, layout := range []string{"2006-01-02 15:04:05 -0700", "2006-01-02 15:04:05"} {
		if t, err := time.ParseInLocation(layout, stamp, time.Local); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}
