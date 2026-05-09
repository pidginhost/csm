package incident

import (
	"strings"

	"github.com/pidginhost/csm/internal/alert"
)

// Key is the correlation key derived from a Finding. Empty fields mean
// "not provided"; the correlator uses the most specific non-empty fields.
type Key struct {
	Account  string `json:"account,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Mailbox  string `json:"mailbox,omitempty"`
	UID      int    `json:"uid,omitempty"`
	PID      int    `json:"pid,omitempty"`
	RemoteIP string `json:"remote_ip,omitempty"`
}

// IsEmpty reports whether the key has nothing to correlate on. Such
// findings are emitted normally but do not join an incident.
func (k Key) IsEmpty() bool {
	return k.Account == "" && k.Domain == "" && k.Mailbox == "" && k.UID == 0 && k.PID == 0 && k.RemoteIP == ""
}

// KeyFor extracts a correlation key from a Finding. Sources, in priority
// order: TenantID, Process.Account, CPUser (php-relay attribution), and a
// /home[N]/<account>/ heuristic for fanotify findings. Domain and Mailbox
// are taken verbatim from the finding. SourceIP is only a fallback identity:
// it should not split a mailbox/account/process incident by attacker IP.
func KeyFor(f alert.Finding) Key {
	k := Key{
		Account: f.TenantID,
		Domain:  f.Domain,
		Mailbox: f.Mailbox,
	}
	if f.Process != nil {
		if f.Process.Account != "" && k.Account == "" {
			k.Account = f.Process.Account
		}
		k.UID = f.Process.UID
		k.PID = f.Process.PID
	}
	if k.Account == "" && f.CPUser != "" {
		k.Account = f.CPUser
	}
	if k.Account == "" {
		k.Account = accountFromHomePath(f.FilePath)
	}
	if k.Account == "" && k.Domain == "" && k.Mailbox == "" && k.UID == 0 && k.PID == 0 {
		k.RemoteIP = f.SourceIP
	}
	return k
}

// accountFromHomePath parses /home[N]/<account>/... paths. Returns the
// account segment or "" if the path does not match the cPanel-style home
// layout. Pure string parsing; does not walk the filesystem.
func accountFromHomePath(p string) string {
	if p == "" {
		return ""
	}
	parts := strings.SplitN(p, "/", 4)
	if len(parts) < 3 {
		return ""
	}
	if parts[0] != "" {
		return ""
	}
	if !strings.HasPrefix(parts[1], "home") {
		return ""
	}
	for _, ch := range parts[1][len("home"):] {
		if ch < '0' || ch > '9' {
			return ""
		}
	}
	return parts[2]
}
