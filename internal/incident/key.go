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
// order: TenantID, Process.Account/UID, CPUser (php-relay attribution), and
// a /home[N]/<account>/ heuristic for fanotify findings. Domain and Mailbox
// are taken verbatim from the finding. SourceIP and process PID are fallback
// identities: they should not split mailbox/account/UID incidents.
//
// Mailbox + Domain are canonicalised so emitters that set either the
// full local@domain form or the split (Mailbox=local, Domain=site)
// form land on the same key. Without that, two findings about the
// same mailbox split into two incidents whenever the emitters use
// different conventions.
func KeyFor(f alert.Finding) Key {
	mailbox, domain := canonicalizeMailboxDomain(f.Mailbox, f.Domain)
	k := Key{
		Account: f.TenantID,
		Domain:  domain,
		Mailbox: mailbox,
	}
	if f.Process != nil {
		if f.Process.Account != "" && k.Account == "" {
			k.Account = f.Process.Account
		}
		if f.Process.UID != 0 {
			k.UID = f.Process.UID
		}
		if k.Account == "" && k.UID == 0 {
			k.PID = f.Process.PID
		}
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

// canonicalizeMailboxDomain merges Mailbox+Domain into a stable
// (Mailbox, Domain) pair regardless of which emit convention the
// caller used. Rules:
//
//   - If Mailbox already contains "@", treat it as authoritative;
//     drop Domain to avoid double-keying on conflicting site.
//   - If Mailbox lacks "@" and Domain is set, splice them into the
//     full form. Domain is then dropped from the key (it's already
//     encoded in Mailbox).
//   - Domain-only findings (no Mailbox) pass through unchanged.
//
// Pure string ops; no validation of email syntax beyond the @-marker.
func canonicalizeMailboxDomain(mailbox, domain string) (string, string) {
	mailbox = strings.TrimSpace(mailbox)
	domain = strings.TrimSpace(domain)
	if mailbox == "" {
		return "", domain
	}
	if strings.Contains(mailbox, "@") {
		return mailbox, ""
	}
	if domain == "" {
		return mailbox, ""
	}
	return mailbox + "@" + domain, ""
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
