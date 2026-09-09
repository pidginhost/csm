package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
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
	salt       []byte
	accounts   map[string]struct{}
	hosts      map[string]string // lower-cased name or alias -> canonical hostname
	domains    map[string]struct{}
	emails     map[string]struct{}
	counts     map[string]int
	pseudonyms map[string]struct{}
}

// NewAnonymizer returns an anonymizer keyed on salt.
func NewAnonymizer(salt []byte) *Anonymizer {
	return &Anonymizer{
		salt:       append([]byte(nil), salt...),
		accounts:   make(map[string]struct{}),
		hosts:      make(map[string]string),
		domains:    make(map[string]struct{}),
		emails:     make(map[string]struct{}),
		counts:     make(map[string]int),
		pseudonyms: make(map[string]struct{}),
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
	emailRe           = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	localPartRe       = regexp.MustCompile(`[A-Za-z0-9._%+-]+@`)
	ipv6Re            = regexp.MustCompile(`[0-9A-Fa-f]*:[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*`)
	homePathRe        = regexp.MustCompile(`(/home\d*/)([^/\s"',;:]+)`)
	accountRe         = regexp.MustCompile(`Account: ([A-Za-z0-9._-]+)`)
	secretRe          = regexp.MustCompile(`(?is)(["']?(?:passw(?:or)?d|secret|token|api[_-]?key)["']?\s*[:=]\s*)(?:"(?:\\.|[^"\\])*(?:"|\\?$)|'(?:\\.|[^'\\])*(?:'|\\?$)|\S+)`)
	domainCandidateRe = regexp.MustCompile(`(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}`)
	emittedNameRe     = regexp.MustCompile(`(?:acct|host|dom|user)-[0-9a-f]{6}(?:\.example)?`)
	ipv4Re            = regexp.MustCompile(`(?:[0-9]+\.){3}[0-9]+`)
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
	return a.remember("acct-" + a.label("account", raw))
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
	return a.remember("host-" + a.label("host", raw))
}

// Domain maps a domain name; the pseudonym is a reserved name that can
// never resolve.
func (a *Anonymizer) Domain(raw string) string {
	if raw == "" {
		return raw
	}
	return a.remember("dom-" + a.label("domain", raw) + ".example")
}

// Email maps a mailbox, keeping the mapped domain so a mailbox and its
// domain agree across fields.
func (a *Anonymizer) Email(raw string) string {
	at := strings.LastIndexByte(raw, '@')
	if at <= 0 {
		return raw
	}
	return a.remember("user-"+a.label("mailbox", raw[:at])) + "@" + a.Domain(raw[at+1:])
}

// IPv4 maps an address into 198.18.0.0/15 (RFC 2544 benchmarking space,
// never routed), one address per raw value under a salt.
func (a *Anonymizer) IPv4(raw string) string {
	mac := hmac.New(sha256.New, a.salt)
	mac.Write([]byte("ipv4\x00" + raw))
	sum := mac.Sum(nil)
	n := binary.BigEndian.Uint32(sum[:4]) & 0x1ffff // 17 bits: 198.18.0.0/15
	return a.remember(fmt.Sprintf("198.%d.%d.%d", 18+(n>>16), (n>>8)&0xff, n&0xff))
}

// IPv6 maps an address into 2001:db8::/32 (RFC 3849 documentation prefix).
func (a *Anonymizer) IPv6(raw string) string {
	mac := hmac.New(sha256.New, a.salt)
	mac.Write([]byte("ipv6\x00" + strings.ToLower(raw)))
	sum := mac.Sum(nil)
	return a.remember(fmt.Sprintf("2001:db8:%x:%x::%x:%x",
		binary.BigEndian.Uint16(sum[0:2]), binary.BigEndian.Uint16(sum[2:4]),
		binary.BigEndian.Uint16(sum[4:6]), binary.BigEndian.Uint16(sum[6:8])))
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
		a.learnText(eventText(*e))
		for p := e.Process; p != nil; p = p.Parent {
			a.learnAccount(p.Account)
			a.learnAccount(p.User)
		}
	}
}

func (a *Anonymizer) learnText(text string) {
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
	out.Comm = a.Text(p.Comm)
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

// Text removes secrets before identity substitutions can obscure their
// keys, then scrubs mail, IPv6, home paths and name-shaped tokens in order.
func (a *Anonymizer) Text(s string) string {
	if s == "" {
		return s
	}
	s = secretRe.ReplaceAllString(s, "${1}[redacted]")
	s = emailRe.ReplaceAllStringFunc(s, func(m string) string { a.counts["emails"]++; return a.Email(m) })
	// A mailbox truncated after the "@" still names a mailbox; map the local
	// part the way Email does so both forms agree.
	s = replaceLeftBounded(s, localPartRe, func(m string) (string, bool) {
		local := m[:len(m)-1]
		if systemUsers[local] || a.isPseudonym(local) {
			return m, false
		}
		a.counts["emails"]++
		return a.remember("user-"+a.label("mailbox", local)) + "@", true
	})
	s = a.scrubIPv6(s)
	s = homePathRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := homePathRe.FindStringSubmatch(m)
		a.counts["accounts"]++
		return sub[1] + a.Account(sub[2])
	})
	s = scrubTokens(s, a.token)
	return s
}

// A field separator or a hex letter at the end of its key can be part of
// the regex match, and so can a colon that belongs to the sentence after
// the address. Try every start after a colon and every end at a group
// boundary, longest first, before rejecting the match.
func (a *Anonymizer) scrubIPv6(s string) string {
	var b strings.Builder
	last := 0
	for _, loc := range ipv6Re.FindAllStringIndex(s, -1) {
		if loc[0] < last {
			continue
		}
		start, end, ok := longestIPv6(s, loc[0], loc[1])
		if !ok {
			continue
		}
		raw := s[start:end]
		if net.ParseIP(raw).IsLoopback() {
			continue
		}
		a.counts["ipv6"]++
		b.WriteString(s[last:start])
		b.WriteString(a.IPv6(raw))
		last = end
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

func longestIPv6(s string, lo, hi int) (int, int, bool) {
	for start := lo; start < hi; start++ {
		if start != lo && s[start-1] != ':' {
			continue
		}
		if start > 0 && isAlnum(s[start-1]) {
			continue
		}
		for end := hi; end > start; end-- {
			if end < len(s) && isAlnum(s[end]) {
				continue
			}
			if looksLikeIPv6(s[start:end]) {
				return start, end, true
			}
		}
	}
	return 0, 0, false
}

// token rewrites one name-shaped token (letters, digits, dots, hyphens).
func (a *Anonymizer) token(core string) string {
	lower := strings.ToLower(core)
	if a.isPseudonym(lower) {
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
	if _, ok := a.domains[lower]; ok || domainShaped(lower) {
		a.counts["domains"]++
		return a.Domain(core)
	}
	return a.embedded(core)
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

// embedded replaces hosts, domains, accounts and addresses that sit
// between label boundaries of a longer token, longest span first.
func (a *Anonymizer) embedded(core string) string {
	lower := strings.ToLower(core)
	bounds := labelBounds(lower)
	var b strings.Builder
	last := 0
	for i := 0; i < len(bounds)-1; i++ {
		if bounds[i] < last {
			continue
		}
		for j := len(bounds) - 1; j > i; j-- {
			if bounds[i] == bounds[j] {
				continue
			}
			sub := lower[bounds[i]:bounds[j]]
			r, ok := a.embeddedName(sub, core[bounds[i]:bounds[j]])
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

func (a *Anonymizer) embeddedName(lower, raw string) (string, bool) {
	if a.isPseudonym(lower) {
		return raw, true
	}
	if _, ok := a.hosts[lower]; ok {
		a.counts["hosts"]++
		return a.Host(raw), true
	}
	if _, ok := a.domains[lower]; ok || domainShaped(lower) {
		a.counts["domains"]++
		return a.Domain(raw), true
	}
	if ip := parseIPv4(lower); ip != nil && !ip.IsLoopback() {
		a.counts["ipv4"]++
		return a.IPv4(raw), true
	}
	if _, ok := a.accounts[lower]; ok {
		a.counts["accounts"]++
		return a.Account(raw), true
	}
	return "", false
}

// Only values actually emitted under this salt are exempt from rewriting.
// A raw name that merely starts with "host-" is still an identity.
func (a *Anonymizer) remember(value string) string {
	a.pseudonyms[value] = struct{}{}
	return value
}

func (a *Anonymizer) isPseudonym(value string) bool {
	_, ok := a.pseudonyms[strings.ToLower(value)]
	return ok
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

// findBoundedMatches returns the matches of re that are not glued to a
// letter or digit on the left; the match itself ends at a separator.
func findBoundedMatches(s string, re *regexp.Regexp) []string {
	var out []string
	for _, loc := range re.FindAllStringIndex(s, -1) {
		if loc[0] == 0 || !isAlnum(s[loc[0]-1]) {
			out = append(out, s[loc[0]:loc[1]])
		}
	}
	return out
}

// replaceLeftBounded applies fn to every match of re that is not glued to
// a letter or digit on the left; the match itself ends at a separator.
func replaceLeftBounded(s string, re *regexp.Regexp, fn func(m string) (string, bool)) string {
	var b strings.Builder
	last := 0
	for _, loc := range re.FindAllStringIndex(s, -1) {
		if loc[0] > 0 && isAlnum(s[loc[0]-1]) {
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
// name inside a longer label is not attributed to that learned identity.
func (a *Anonymizer) Verify(events []alert.AuditEvent) []string {
	var problems []string
	for i := range events {
		found := a.leaksIn(eventText(events[i]))
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
	// Pseudonyms this run emitted are blanked first, so a token that now
	// reads "kit-dom-xxxxxx.example" is not mistaken for a domain. Only
	// emitted values are blanked; a raw name shaped like one stays visible.
	masked := replaceBounded(lowerText, emittedNameRe, func(m string) (string, bool) {
		return " ", a.isPseudonym(m)
	})
	// This pass deliberately does not use Text, scrubTokens or labelBounds:
	// a replacement bug must not also disable the final refusal check.
	for _, loc := range domainCandidateRe.FindAllStringIndex(masked, -1) {
		// A candidate that stops inside a token ("el" of "el8") is a version
		// or a temp-file suffix, not a name.
		if !bounded(masked, loc[0], loc[1]) {
			continue
		}
		candidate := masked[loc[0]:loc[1]]
		for end := len(candidate); end > 0; end-- {
			if end != len(candidate) && candidate[end] != '.' && candidate[end] != '-' {
				continue
			}
			sub := candidate[:end]
			if domainShaped(sub) && !a.isPseudonym(sub) {
				found["domain "+sub] = struct{}{}
			}
		}
	}
	for name := range a.accounts {
		if containsLabel(masked, name) {
			found["account "+name] = struct{}{}
		}
	}
	for name := range a.hosts {
		if containsLabel(masked, name) {
			found["host "+name] = struct{}{}
		}
	}
	for name := range a.domains {
		if containsLabel(masked, name) {
			found["domain "+name] = struct{}{}
		}
	}
	for offset := 0; offset < len(lowerText); {
		loc := ipv4Re.FindStringIndex(lowerText[offset:])
		if loc == nil {
			break
		}
		loc[0], loc[1] = loc[0]+offset, loc[1]+offset
		// A filename's numeric suffix can begin an invalid overlapping
		// candidate (client4.203.0.113.9). Do not skip the address behind it.
		offset = loc[0] + 1
		sub := lowerText[loc[0]:loc[1]]
		if !bounded(lowerText, loc[0], loc[1]) {
			continue
		}
		if a.isPseudonym(sub) {
			// Do not reinterpret a generated address's suffix as another IP.
			offset = loc[1]
			continue
		}
		if ip := net.ParseIP(sub); ip != nil && !ip.IsLoopback() && !strings.HasPrefix(sub, "198.18.") && !strings.HasPrefix(sub, "198.19.") {
			found["ipv4 "+sub] = struct{}{}
		}
	}
	for _, m := range emailRe.FindAllString(text, -1) {
		local, domain, _ := strings.Cut(m, "@")
		if !a.isPseudonym(local) || !a.isPseudonym(domain) {
			found["mailbox "+m] = struct{}{}
		}
	}
	for _, m := range findBoundedMatches(text, localPartRe) {
		if local := m[:len(m)-1]; !systemUsers[local] && !a.isPseudonym(local) {
			found["mailbox "+m] = struct{}{}
		}
	}
	for _, raw := range unmaskedIPv6(text) {
		found["ipv6 "+raw] = struct{}{}
	}
	out := make([]string, 0, len(found))
	for f := range found {
		out = append(out, f)
	}
	return out
}

// Verify uses a bounded sliding scan and netip instead of the replacement
// regex. The longest IPv6 spelling, including a dotted IPv4 tail, is 45 bytes.
func unmaskedIPv6(text string) []string {
	var found []string
	documentation := netip.MustParsePrefix("2001:db8::/32")
	for start := 0; start < len(text); start++ {
		if start > 0 && isAlnum(text[start-1]) {
			continue
		}
		limit := start
		for limit < len(text) && limit-start < 45 {
			if !isIPByte(text[limit]) {
				break
			}
			limit++
		}
		for end := limit; end > start; end-- {
			if end < len(text) && isAlnum(text[end]) {
				continue
			}
			raw := text[start:end]
			ip, err := netip.ParseAddr(raw)
			if err != nil || !ip.Is6() {
				continue
			}
			if !ip.IsLoopback() && !documentation.Contains(ip) {
				found = append(found, raw)
			}
			start = end - 1
			break
		}
	}
	return found
}

func isIPByte(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == ':' || c == '.'
}

func containsLabel(text, name string) bool {
	for offset := 0; offset < len(text); {
		i := strings.Index(text[offset:], name)
		if i < 0 {
			return false
		}
		start := offset + i
		end := start + len(name)
		if bounded(text, start, end) {
			return true
		}
		offset = start + 1
	}
	return false
}

// eventText joins every free-text and identity field of an event, raw, so
// the leak check sees the same bytes the fields hold rather than their
// JSON escapes.
func eventText(e alert.AuditEvent) string {
	parts := []string{e.Check, e.Severity, e.FindingID, e.Message, e.Details, e.FilePath, e.Hostname, e.TenantID, e.Domain, e.Mailbox}
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
