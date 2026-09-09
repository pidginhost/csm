package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/processctx"
)

// Anonymizer rewrites a finding stream so it can leave the host: every
// identity is replaced by a pseudonym derived from an HMAC of the value under
// a private salt. The same salt gives the same pseudonym on every host, so
// streams can be joined on accounts and addresses without knowing either.
// Everything else that calibration needs (timestamps, check names,
// severities, path structure, plugin names, process names) is kept.
type Anonymizer struct {
	salt     []byte
	accounts map[string]struct{}
	hosts    map[string]string // lower-cased name or alias -> canonical hostname
	domains  map[string]struct{}
	emails   map[string]struct{}
	counts   map[string]int
}

// NewAnonymizer returns an anonymizer keyed on salt.
func NewAnonymizer(salt []byte) *Anonymizer {
	return &Anonymizer{
		salt:     append([]byte(nil), salt...),
		accounts: make(map[string]struct{}),
		hosts:    make(map[string]string),
		domains:  make(map[string]struct{}),
		emails:   make(map[string]struct{}),
		counts:   make(map[string]int),
	}
}

// systemUsers never identify a customer; replacing them would destroy the
// meaning of a finding that says "root" or "nobody".
var systemUsers = map[string]bool{
	"root": true, "nobody": true, "mailnull": true, "cpanel": true, "apache": true, "nginx": true,
	"www-data": true, "daemon": true, "mysql": true, "mail": true, "exim": true, "dovecot": true,
	"cpanelsolr": true, "cpanelphpmyadmin": true, "cpanelroundcube": true, "lsadm": true,
}

// None of these carry \b: an underscore is a word character to a regexp, and
// LiteSpeed vhost tokens (APVH_<ip>:443_<ip>:443_<account>_<domain>) glue
// identities together with underscores. Boundaries are checked by hand.
var (
	emailRe     = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	ipv6Re      = regexp.MustCompile(`[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}`)
	homePathRe  = regexp.MustCompile(`(/home\d*/)([^/\s"',;:]+)`)
	accountRe   = regexp.MustCompile(`Account: ([A-Za-z0-9._-]+)`)
	secretRe    = regexp.MustCompile(`(?i)(passw(?:or)?d|secret|token|api[_-]?key)\s*[:=]\s*\S+`)
	pseudonymRe = regexp.MustCompile(`(?:acct|host|dom|user)-[0-9a-f]{6}`)
)

// fileExtensions keeps dotted file names out of the domain replacement.
var fileExtensions = map[string]bool{
	"php": true, "phtml": true, "inc": true, "js": true, "html": true, "htm": true, "txt": true, "log": true,
	"gz": true, "zip": true, "tar": true, "tgz": true, "bz2": true, "xz": true, "css": true, "json": true,
	"xml": true, "yml": true, "yaml": true, "sh": true, "pl": true, "py": true, "ini": true, "conf": true,
	"so": true, "md": true, "sql": true, "png": true, "jpg": true, "jpeg": true, "gif": true, "svg": true,
	"ico": true, "pdf": true, "bak": true, "old": true, "tmp": true, "cgi": true, "lock": true, "key": true,
	"pem": true, "crt": true, "csv": true, "map": true, "min": true, "phar": true, "jsonl": true, "mmdb": true,
	"service": true, "timer": true, "socket": true, "cnf": true, "htaccess": true, "orig": true, "dist": true,
	"woff": true, "woff2": true, "ttf": true, "eot": true, "mp4": true, "mp3": true, "webp": true, "swp": true,
}

func (a *Anonymizer) label(kind, value string) string {
	mac := hmac.New(sha256.New, a.salt)
	mac.Write([]byte(kind))
	mac.Write([]byte{0})
	mac.Write([]byte(strings.ToLower(value)))
	return hex.EncodeToString(mac.Sum(nil)[:3])
}

// Account maps a hosting account name; system users and bare uids (a
// process whose owner has no name) pass through.
func (a *Anonymizer) Account(raw string) string {
	if systemUsers[raw] || raw == "" || strings.Trim(raw, "0123456789") == "" {
		return raw
	}
	return "acct-" + a.label("account", raw)
}

// Host maps a server hostname. A learned alias (the first label of a
// hostname) maps to the pseudonym of the full name.
func (a *Anonymizer) Host(raw string) string {
	if raw == "" {
		return raw
	}
	if canonical, ok := a.hosts[strings.ToLower(raw)]; ok {
		raw = canonical
	}
	return "host-" + a.label("host", raw)
}

// Domain maps a domain name; the pseudonym is a reserved name that can
// never resolve.
func (a *Anonymizer) Domain(raw string) string {
	if raw == "" {
		return raw
	}
	return "dom-" + a.label("domain", raw) + ".example"
}

// Email maps a mailbox, keeping the mapped domain so a mailbox and its
// domain agree across fields.
func (a *Anonymizer) Email(raw string) string {
	at := strings.LastIndexByte(raw, '@')
	if at <= 0 {
		return raw
	}
	return "user-" + a.label("mailbox", raw[:at]) + "@" + a.Domain(raw[at+1:])
}

// IPv4 maps an address into 198.18.0.0/15 (RFC 2544 benchmarking space,
// never routed), one address per raw value under a salt.
func (a *Anonymizer) IPv4(raw string) string {
	mac := hmac.New(sha256.New, a.salt)
	mac.Write([]byte("ipv4\x00" + raw))
	sum := mac.Sum(nil)
	n := binary.BigEndian.Uint32(sum[:4]) & 0x1ffff // 17 bits: 198.18.0.0/15
	return fmt.Sprintf("198.%d.%d.%d", 18+(n>>16), (n>>8)&0xff, n&0xff)
}

// IPv6 maps an address into 2001:db8::/32 (RFC 3849 documentation prefix).
func (a *Anonymizer) IPv6(raw string) string {
	mac := hmac.New(sha256.New, a.salt)
	mac.Write([]byte("ipv6\x00" + strings.ToLower(raw)))
	sum := mac.Sum(nil)
	return fmt.Sprintf("2001:db8:%x:%x::%x:%x",
		binary.BigEndian.Uint16(sum[0:2]), binary.BigEndian.Uint16(sum[2:4]),
		binary.BigEndian.Uint16(sum[4:6]), binary.BigEndian.Uint16(sum[6:8]))
}

// Learn collects the identities the events carry in structured fields and
// in the account-shaped parts of paths and details, so free text can be
// scrubbed of them and Verify can prove they are gone.
func (a *Anonymizer) Learn(events []alert.AuditEvent) {
	for i := range events {
		e := &events[i]
		a.learnAccount(e.TenantID)
		a.learnHost(e.Hostname)
		a.learnDomain(e.Domain)
		a.learnEmail(e.Mailbox)
		for _, text := range []string{e.Message, e.Details, e.FilePath} {
			for _, m := range homePathRe.FindAllStringSubmatch(text, -1) {
				a.learnAccount(m[2])
			}
			for _, m := range accountRe.FindAllStringSubmatch(text, -1) {
				a.learnAccount(m[1])
			}
			for _, m := range emailRe.FindAllString(text, -1) {
				a.learnEmail(m)
			}
		}
		for p := e.Process; p != nil; p = p.Parent {
			a.learnAccount(p.Account)
			a.learnAccount(p.User)
		}
	}
}

// learnAccount keeps names that can be a hosting account: not a system
// user, not a number (a uid or pid would then scrub every count in the
// stream) and not a file name that happened to sit under a /home/ segment.
func (a *Anonymizer) learnAccount(name string) {
	lower := strings.ToLower(name)
	if lower == "" || systemUsers[lower] || strings.ContainsAny(lower, "/\\") || strings.Trim(lower, "0123456789") == "" {
		return
	}
	if i := strings.LastIndexByte(lower, '.'); i >= 0 && fileExtensions[lower[i+1:]] {
		return
	}
	a.accounts[lower] = struct{}{}
}

// learnHost records the full hostname and, when its first label looks like
// a machine name rather than a word (it carries a digit), that label as an
// alias: "cp1" identifies the host as much as its full name does.
func (a *Anonymizer) learnHost(name string) {
	if name == "" {
		return
	}
	lower := strings.ToLower(name)
	a.hosts[lower] = name
	if short, _, ok := strings.Cut(lower, "."); ok && strings.ContainsAny(short, "0123456789") {
		a.hosts[short] = name
	}
}

func (a *Anonymizer) learnDomain(name string) {
	if name != "" {
		a.domains[strings.ToLower(name)] = struct{}{}
	}
}

func (a *Anonymizer) learnEmail(addr string) {
	if at := strings.LastIndexByte(addr, '@'); at > 0 {
		a.emails[strings.ToLower(addr)] = struct{}{}
		a.learnDomain(addr[at+1:])
	}
}

// Event returns the anonymized copy of e.
func (a *Anonymizer) Event(e alert.AuditEvent) alert.AuditEvent {
	out := e
	out.Hostname = a.Host(e.Hostname)
	out.TenantID = a.Account(e.TenantID)
	out.Domain = a.Domain(e.Domain)
	out.Mailbox = a.Email(e.Mailbox)
	out.FilePath = a.Text(e.FilePath)
	out.Message = a.Text(e.Message)
	if e.Check == "email_credential_leak" {
		// The subject line is the leaked credential itself.
		out.Details = "[redacted]"
	} else {
		out.Details = a.Text(e.Details)
	}
	out.Process = a.process(e.Process)
	return out
}

func (a *Anonymizer) process(p *processctx.ProcessContext) *processctx.ProcessContext {
	if p == nil {
		return nil
	}
	out := *p
	out.User = a.Account(p.User)
	out.Account = a.Account(p.Account)
	out.Exe = a.Text(p.Exe)
	if p.Cmdline != nil {
		out.Cmdline = make([]string, len(p.Cmdline))
		for i, arg := range p.Cmdline {
			out.Cmdline[i] = a.Text(arg)
		}
	}
	out.Parent = a.process(p.Parent)
	return &out
}

// Text scrubs free text in a fixed order: mail addresses, IPv6 addresses,
// home paths, then every name-shaped token (IPv4 addresses, learned hosts,
// learned and domain-shaped names, account labels), then secrets.
func (a *Anonymizer) Text(s string) string {
	if s == "" {
		return s
	}
	s = emailRe.ReplaceAllStringFunc(s, func(m string) string { a.counts["emails"]++; return a.Email(m) })
	s = replaceBounded(s, ipv6Re, func(m string) (string, bool) {
		if !looksLikeIPv6(m) {
			return m, false
		}
		a.counts["ipv6"]++
		return a.IPv6(m), true
	})
	s = homePathRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := homePathRe.FindStringSubmatch(m)
		a.counts["accounts"]++
		return sub[1] + a.Account(sub[2])
	})
	s = scrubTokens(s, a.token)
	s = secretRe.ReplaceAllString(s, "$1=[redacted]")
	return s
}

// token rewrites one name-shaped token (letters, digits, dots, hyphens).
func (a *Anonymizer) token(core string) string {
	lower := strings.ToLower(core)
	if isPseudonym(lower) {
		return core
	}
	if ip := parseIPv4(core); ip != nil {
		if ip.IsLoopback() {
			return core
		}
		a.counts["ipv4"]++
		return a.IPv4(core)
	}
	if _, ok := a.hosts[lower]; ok {
		a.counts["hosts"]++
		return a.Host(core)
	}
	if _, ok := a.domains[lower]; ok {
		a.counts["domains"]++
		return a.Domain(core)
	}
	if domainShaped(lower) {
		a.counts["domains"]++
		return a.Domain(core)
	}
	return a.accountLabels(a.embedded(core))
}

// labelBounds returns the offsets at which a label of tok starts or ends:
// the token edges and every dot or hyphen. A learned name inside a longer
// token ("example.com-ssl", "cluster6.log", "1.2.3.4-5.6.7.8") spans two of
// them.
func labelBounds(tok string) []int {
	bounds := []int{0}
	for i := 0; i < len(tok); i++ {
		if tok[i] == '.' || tok[i] == '-' {
			bounds = append(bounds, i, i+1)
		}
	}
	return append(bounds, len(tok))
}

// embedded replaces learned hosts, learned domains and addresses that sit
// between label boundaries of a longer token, longest span first.
func (a *Anonymizer) embedded(core string) string {
	if !strings.ContainsAny(core, ".-") {
		return core
	}
	lower := strings.ToLower(core)
	bounds := labelBounds(lower)
	var b strings.Builder
	last := 0
	for i := 0; i < len(bounds)-1; i++ {
		if bounds[i] < last {
			continue
		}
		for j := len(bounds) - 1; j > i; j-- {
			sub := lower[bounds[i]:bounds[j]]
			r, ok := a.embeddedName(sub, core[bounds[i]:bounds[j]], edge(lower, bounds[i]-1), edge(lower, bounds[j]))
			if !ok {
				continue
			}
			b.WriteString(core[last:bounds[i]])
			b.WriteString(r)
			last = bounds[j]
			break
		}
	}
	if last == 0 {
		return core
	}
	b.WriteString(core[last:])
	return b.String()
}

func edge(s string, i int) byte {
	if i < 0 || i >= len(s) {
		return 0
	}
	return s[i]
}

func (a *Anonymizer) embeddedName(lower, raw string, before, after byte) (string, bool) {
	if _, ok := a.hosts[lower]; ok {
		a.counts["hosts"]++
		return a.Host(raw), true
	}
	if _, ok := a.domains[lower]; ok {
		a.counts["domains"]++
		return a.Domain(raw), true
	}
	if before != '.' && after != '.' {
		if ip := parseIPv4(lower); ip != nil && !ip.IsLoopback() && !isPseudonym(lower) {
			a.counts["ipv4"]++
			return a.IPv4(raw), true
		}
	}
	return "", false
}

// accountLabels replaces the dot- or hyphen-separated labels of a token that
// name a learned account, so "alice.bak" and "backup-alice" lose the name
// while keeping their shape.
func (a *Anonymizer) accountLabels(core string) string {
	if len(a.accounts) == 0 {
		return core
	}
	var b strings.Builder
	last, changed := 0, false
	for i := 0; i <= len(core); i++ {
		if i < len(core) && core[i] != '.' && core[i] != '-' {
			continue
		}
		lab := core[last:i]
		if _, ok := a.accounts[strings.ToLower(lab)]; ok {
			if !changed {
				b.WriteString(core[:last])
				changed = true
			}
			a.counts["accounts"]++
			b.WriteString(a.Account(lab))
		} else if changed {
			b.WriteString(lab)
		}
		if changed && i < len(core) {
			b.WriteByte(core[i])
		}
		last = i + 1
	}
	if !changed {
		return core
	}
	return b.String()
}

func isPseudonym(lower string) bool {
	for _, p := range []string{"acct-", "host-", "dom-", "user-"} {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return strings.HasPrefix(lower, "198.18.") || strings.HasPrefix(lower, "198.19.")
}

func parseIPv4(s string) net.IP {
	if strings.Count(s, ".") != 3 {
		return nil
	}
	for i := 0; i < len(s); i++ {
		if s[i] != '.' && (s[i] < '0' || s[i] > '9') {
			return nil
		}
	}
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() == nil {
		return nil
	}
	return ip
}

func isAlnum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func isNameByte(c byte) bool { return isAlnum(c) || c == '.' || c == '-' }

// scrubTokens passes every maximal run of name bytes through fn, without
// the dots and hyphens at its edges (sentence punctuation, ranges), and
// splices the replacement back in place.
func scrubTokens(s string, fn func(core string) string) string {
	var b strings.Builder
	last := 0
	for i := 0; i < len(s); {
		if !isNameByte(s[i]) {
			i++
			continue
		}
		j := i
		for j < len(s) && isNameByte(s[j]) {
			j++
		}
		start, end := i, j
		for start < end && !isAlnum(s[start]) {
			start++
		}
		for end > start && !isAlnum(s[end-1]) {
			end--
		}
		if start < end {
			if r := fn(s[start:end]); r != s[start:end] {
				b.WriteString(s[last:start])
				b.WriteString(r)
				last = end
			}
		}
		i = j
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// replaceBounded applies fn to every match of re that is not glued to
// letters or digits on either side.
func replaceBounded(s string, re *regexp.Regexp, fn func(m string) (string, bool)) string {
	var b strings.Builder
	last := 0
	for _, loc := range re.FindAllStringIndex(s, -1) {
		if !bounded(s, loc[0], loc[1]) {
			continue
		}
		r, ok := fn(s[loc[0]:loc[1]])
		if !ok {
			continue
		}
		b.WriteString(s[last:loc[0]])
		b.WriteString(r)
		last = loc[1]
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

func bounded(s string, start, end int) bool {
	return (start == 0 || !isAlnum(s[start-1])) && (end == len(s) || !isAlnum(s[end]))
}

func looksLikeIPv6(m string) bool {
	if net.ParseIP(m) == nil || !strings.Contains(m, ":") {
		return false
	}
	// Times and durations carry two colons and no hex letters; an address
	// has a double colon, a letter, or more groups than a clock reading.
	return strings.Contains(m, "::") || strings.ContainsAny(m, "abcdefABCDEF") || strings.Count(m, ":") >= 5
}

// domainShaped reports whether a lower-cased token reads as a host name
// rather than a file name or version: at least two well-formed labels and
// an alphabetic last label that is not a file extension.
func domainShaped(lower string) bool {
	labels := strings.Split(lower, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
	}
	last := labels[len(labels)-1]
	if fileExtensions[last] || len(last) < 2 {
		return false
	}
	for _, c := range last {
		if c < 'a' || c > 'z' {
			return false
		}
	}
	return true
}

// Verify scans anonymized events for anything that still identifies a host,
// account, domain, mailbox or address and returns one problem per event. It
// looks at every span between label boundaries of every token, so a name
// glued to underscores, file extensions or hyphens is still found, while a
// name inside a longer word ("me.ro" in "some.rock") is not.
func (a *Anonymizer) Verify(events []alert.AuditEvent) []string {
	var problems []string
	for i := range events {
		found := a.leaksIn(pseudonymRe.ReplaceAllString(eventText(events[i]), " "))
		if len(found) > 0 {
			sort.Strings(found)
			problems = append(problems, fmt.Sprintf("event %d (%s): %s", i, events[i].Check, strings.Join(found, ", ")))
		}
	}
	return problems
}

func (a *Anonymizer) leaksIn(text string) []string {
	found := map[string]struct{}{}
	lowerText := strings.ToLower(text)
	for name := range a.hosts {
		if strings.Contains(name, ".") && strings.Contains(lowerText, name) {
			found["host "+name] = struct{}{}
		}
	}
	scrubTokens(lowerText, func(core string) string {
		bounds := labelBounds(core)
		for i := 0; i < len(bounds)-1; i++ {
			for j := i + 1; j < len(bounds); j++ {
				sub := core[bounds[i]:bounds[j]]
				if _, ok := a.accounts[sub]; ok {
					found["account "+sub] = struct{}{}
				}
				if _, ok := a.hosts[sub]; ok {
					found["host "+sub] = struct{}{}
				}
				if _, ok := a.domains[sub]; ok {
					found["domain "+sub] = struct{}{}
				}
				if edge(core, bounds[i]-1) != '.' && edge(core, bounds[j]) != '.' {
					if ip := parseIPv4(sub); ip != nil && !ip.IsLoopback() && !isPseudonym(sub) {
						found["ipv4 "+sub] = struct{}{}
					}
				}
			}
		}
		return core
	})
	for _, m := range emailRe.FindAllString(text, -1) {
		if !strings.HasPrefix(m, "user-") || !strings.HasSuffix(m, ".example") {
			found["mailbox "+m] = struct{}{}
		}
	}
	for _, loc := range ipv6Re.FindAllStringIndex(text, -1) {
		m := text[loc[0]:loc[1]]
		if bounded(text, loc[0], loc[1]) && looksLikeIPv6(m) && !strings.HasPrefix(strings.ToLower(m), "2001:db8:") {
			found["ipv6 "+m] = struct{}{}
		}
	}
	out := make([]string, 0, len(found))
	for f := range found {
		out = append(out, f)
	}
	return out
}

// eventText joins every free-text and identity field of an event, raw, so
// the leak check sees the same bytes the fields hold rather than their
// JSON escapes.
func eventText(e alert.AuditEvent) string {
	parts := []string{e.Message, e.Details, e.FilePath, e.Hostname, e.TenantID, e.Domain, e.Mailbox}
	for p := e.Process; p != nil; p = p.Parent {
		parts = append(parts, p.User, p.Account, p.Comm, p.Exe)
		parts = append(parts, p.Cmdline...)
	}
	return strings.Join(parts, "\n")
}

// Counts reports how many replacements of each kind Text performed.
func (a *Anonymizer) Counts() map[string]int {
	out := make(map[string]int, len(a.counts))
	for k, v := range a.counts {
		out[k] = v
	}
	return out
}
