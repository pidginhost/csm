package incident

import (
	"strings"

	"github.com/pidginhost/csm/internal/alert"
)

// Key is the correlation key derived from a Finding. Empty fields mean
// "not provided"; the correlator uses the most specific non-empty fields.
// Host is the synthetic local-host actor for findings whose blast radius
// is the machine itself rather than one tenant, process, or remote IP.
type Key struct {
	Host     string `json:"host,omitempty"`
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
	return k.Host == "" && k.Account == "" && k.Domain == "" && k.Mailbox == "" && k.UID == 0 && k.PID == 0 && k.RemoteIP == ""
}

// KeyFor extracts a correlation key from a Finding. Host-integrity
// findings are keyed to the local host so unattributed root/system events
// still become incidents. TenantID, Process.Account, CPUser, and a
// /home[N]/<account>/ heuristic provide account attribution. Domain and
// Mailbox come directly from the finding. Process UID/PID and SourceIP are
// fallback identities: they should not split account/domain/mailbox
// incidents.
//
// Mailbox + Domain are canonicalised so emitters that set either the
// full local@domain form or the split (Mailbox=local, Domain=site)
// form land on the same key. Without that, two findings about the
// same mailbox split into two incidents whenever the emitters use
// different conventions.
func KeyFor(f alert.Finding) Key {
	switch ClassifyKind(f) {
	case KindHostIntegrityRisk:
		return Key{Host: "host"}
	case KindWebAttack, KindMailboxBruteforce:
		// Inbound attacks correlate on the attacker IP; the victim
		// domain/account/mailbox is the target, not the key. This
		// collapses one attacker's hits across many victims into a single
		// incident. ClassifyKind only returns these kinds when a source IP
		// is present.
		return Key{RemoteIP: f.SourceIP}
	}

	mailbox, domain := canonicalizeMailboxDomain(f.Mailbox, f.Domain)
	k := Key{
		Account: f.TenantID,
		Domain:  domain,
		Mailbox: mailbox,
	}
	if f.Process != nil && f.Process.Account != "" && k.Account == "" {
		k.Account = f.Process.Account
	}
	if k.Account == "" && f.CPUser != "" {
		k.Account = f.CPUser
	}
	if k.Account == "" {
		k.Account = accountFromHomePath(f.FilePath)
	}
	if f.Process != nil && !hasStableActor(k) {
		if f.Process.UID != 0 {
			k.UID = f.Process.UID
		}
		if k.UID == 0 {
			k.PID = f.Process.PID
		}
	}
	if k.Account == "" && k.Domain == "" && k.Mailbox == "" && k.UID == 0 && k.PID == 0 {
		k.RemoteIP = f.SourceIP
	}
	return k
}

func hasStableActor(k Key) bool {
	return k.Account != "" || k.Domain != "" || k.Mailbox != ""
}

// canonicalizeMailboxDomain merges Mailbox+Domain into a stable
// (Mailbox, Domain) key pair regardless of which emit convention the
// caller used. Rules:
//
//   - If Mailbox already contains "@", treat it as authoritative;
//     drop Domain to avoid double-keying on conflicting site.
//   - If Mailbox lacks "@" and Domain is set, splice them into the
//     full form. Domain is then dropped from the key (it's already
//     encoded in Mailbox).
//   - Domain-only findings (no Mailbox) keep the domain as the key.
//
// Domain names are case-insensitive, so only the domain component is
// lower-cased. The local part is left intact.
func canonicalizeMailboxDomain(mailbox, domain string) (string, string) {
	mailbox = strings.TrimSpace(mailbox)
	domain = normalizeDomainForKey(domain)
	if mailbox == "" {
		return "", domain
	}
	if local, mailboxDomain := splitMailboxForKey(mailbox); mailboxDomain != "" {
		return local + "@" + mailboxDomain, ""
	}
	if strings.Contains(mailbox, "@") {
		return mailbox, ""
	}
	if domain == "" {
		return mailbox, ""
	}
	return mailbox + "@" + domain, ""
}

func canonicalizeKey(k Key) Key {
	k.Mailbox, k.Domain = canonicalizeMailboxDomain(k.Mailbox, k.Domain)
	return k
}

func displayMailboxDomain(mailbox, domain string) (string, string) {
	mailbox = strings.TrimSpace(mailbox)
	domain = strings.TrimSpace(domain)
	if mailbox == "" {
		return "", domain
	}
	if local, mailboxDomain := splitMailboxForKey(mailbox); mailboxDomain != "" {
		return local + "@" + mailboxDomain, mailboxDomain
	}
	if domain == "" {
		return mailbox, ""
	}
	if strings.Contains(mailbox, "@") {
		return mailbox, domain
	}
	normalizedDomain := normalizeDomainForKey(domain)
	return mailbox + "@" + normalizedDomain, normalizedDomain
}

func splitMailboxForKey(mailbox string) (string, string) {
	at := strings.LastIndexByte(mailbox, '@')
	if at <= 0 || at == len(mailbox)-1 {
		return "", ""
	}
	return mailbox[:at], normalizeDomainForKey(mailbox[at+1:])
}

func normalizeDomainForKey(domain string) string {
	return strings.ToLower(strings.TrimSpace(domain))
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
