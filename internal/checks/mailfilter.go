package checks

import (
	"context"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
)

// Mail-filter exfiltration detector.
//
// cPanel stores per-mailbox Exim filters at
// /home/<user>/etc/<domain>/<localpart>/filter and domain-wide defaults at
// /etc/vfilters/<domain>. A compromised webmail account is commonly weaponised
// by writing a filter that copies every inbound message to an external dropbox
// while keeping a local copy, so the victim never notices the interception
// (business email compromise). This check parses those Exim filters and scores
// the deliver/save actions for that stealth pattern.
//
// Unlike CheckForwarders (valiases redirects), the stealth combination here is
// inherently malicious, so it is reported even when the filter predates CSM --
// newness gating only applies to plain external forwards that are frequently
// legitimate customer configuration.

// filterAction is a single Exim filter action (deliver/save/pipe/finish/...).
type filterAction struct {
	verb   string
	arg    string
	unseen bool
}

// filterRule is one branch of an Exim filter: the condition that guards it and
// the actions it performs. The unconditional top level is represented as a rule
// with an empty condition.
type filterRule struct {
	condition  string
	matchesAll bool
	actions    []filterAction
}

// filterMailbox identifies the mailbox a filter file belongs to. localPart is
// "*" for a domain-wide /etc/vfilters file.
type filterMailbox struct {
	localPart string
	domain    string
}

func (m filterMailbox) String() string {
	return m.localPart + "@" + m.domain
}

// filterFinding is the scorer's intermediate result before it is turned into an
// alert.Finding (which needs file path and newness context).
type filterFinding struct {
	severity  alert.Severity
	check     string
	kind      string // "exfil" | "forwarder" | "pipe" | "blackhole"
	dest      string // external destination, when applicable, for correlation
	reason    string
	onlyIfNew bool
}

// matchAllRe matches an Exim address/header test whose comparison value is a
// bare "@". Every email address contains "@", so such a rule fires on all mail.
var matchAllRe = regexp.MustCompile(`contains\s+"@"`)

// safePipeCommands are cPanel built-in pipe targets that are not attacker code.
var safePipeCommands = []string{
	"/usr/local/cpanel/bin/autorespond",
	"/usr/local/cpanel/bin/boxtrapper",
	"/usr/local/cpanel/bin/mailman",
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

type eximToken struct {
	text string
	str  bool
}

// tokenizeExim splits Exim filter source into tokens. Quoted strings (with \"
// and \\ escapes) become a single string token with the quotes removed;
// parentheses are standalone tokens; everything else is a bareword. Comments
// (# to end of line, outside strings) are dropped.
func tokenizeExim(s string) []eximToken {
	var toks []eximToken
	runes := []rune(s)
	i := 0
	for i < len(runes) {
		c := runes[i]
		switch c {
		case ' ', '\t', '\n', '\r':
			i++
		case '#':
			for i < len(runes) && runes[i] != '\n' {
				i++
			}
		case '(', ')':
			toks = append(toks, eximToken{text: string(c)})
			i++
		case '"':
			i++
			var b strings.Builder
			for i < len(runes) && runes[i] != '"' {
				if runes[i] == '\\' && i+1 < len(runes) {
					i++
				}
				b.WriteRune(runes[i])
				i++
			}
			if i < len(runes) {
				i++ // closing quote
			}
			toks = append(toks, eximToken{text: b.String(), str: true})
		default:
			start := i
			for i < len(runes) {
				r := runes[i]
				if r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '(' || r == ')' || r == '"' || r == '#' {
					break
				}
				i++
			}
			toks = append(toks, eximToken{text: string(runes[start:i])})
		}
	}
	return toks
}

// renderCondition reconstructs a condition string from its tokens so the
// match-all heuristic can run against text that matches the source form
// (string tokens are re-quoted).
func renderCondition(toks []eximToken) string {
	var parts []string
	for _, t := range toks {
		if t.str {
			parts = append(parts, `"`+t.text+`"`)
		} else {
			parts = append(parts, t.text)
		}
	}
	return strings.Join(parts, " ")
}

var actionVerbs = map[string]bool{
	"deliver":  true,
	"save":     true,
	"pipe":     true,
	"finish":   true,
	"mail":     true,
	"vacation": true,
}

// parseEximFilter parses Exim filter source into a flat list of rules, one per
// if/elif/else branch plus one for any unconditional top-level actions. Nested
// ifs attach actions to their innermost condition.
func parseEximFilter(content string) []filterRule {
	toks := tokenizeExim(content)

	top := &filterRule{matchesAll: true}
	stack := []*filterRule{top}
	rules := []*filterRule{top}

	pendingUnseen := false
	i := 0
	for i < len(toks) {
		t := toks[i]
		if t.str {
			i++
			continue
		}
		switch t.text {
		case "if", "elif":
			if t.text == "elif" && len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
			i++
			condStart := i
			for i < len(toks) && (toks[i].text != "then" || toks[i].str) {
				i++
			}
			cond := renderCondition(toks[condStart:i])
			if i < len(toks) {
				i++ // consume "then"
			}
			r := &filterRule{condition: cond, matchesAll: conditionMatchesAll(cond)}
			rules = append(rules, r)
			stack = append(stack, r)
			pendingUnseen = false
		case "else":
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
			i++
			r := &filterRule{condition: "else"}
			rules = append(rules, r)
			stack = append(stack, r)
			pendingUnseen = false
		case "endif":
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
			i++
			pendingUnseen = false
		case "unseen":
			pendingUnseen = true
			i++
		default:
			if !actionVerbs[t.text] {
				i++
				continue
			}
			verb := t.text
			i++
			arg := ""
			if i < len(toks) && toks[i].str {
				arg = toks[i].text
				i++
			}
			cur := stack[len(stack)-1]
			cur.actions = append(cur.actions, filterAction{verb: verb, arg: arg, unseen: pendingUnseen})
			pendingUnseen = false
		}
	}

	out := make([]filterRule, 0, len(rules))
	for _, r := range rules {
		if len(r.actions) > 0 {
			out = append(out, *r)
		}
	}
	return out
}

// conditionMatchesAll reports whether a filter condition fires on effectively
// all mail: an unconditional rule, or one that only tests that an address or
// header "contains @" (true for every message).
func conditionMatchesAll(cond string) bool {
	c := strings.TrimSpace(cond)
	if c == "" {
		return true
	}
	return matchAllRe.MatchString(strings.ToLower(c))
}

// ---------------------------------------------------------------------------
// Scorer
// ---------------------------------------------------------------------------

// destIsExternal reports whether an Exim deliver destination leaves the local
// mail system. Exim variables ($domain etc.) and same-domain/local-domain
// addresses are not external.
func destIsExternal(dest string, mb filterMailbox, localDomains map[string]bool) bool {
	at := strings.LastIndexByte(dest, '@')
	if at < 0 || at == len(dest)-1 {
		return false
	}
	dom := strings.ToLower(strings.Trim(dest[at+1:], `" `))
	if strings.Contains(dom, "$") {
		return false
	}
	if dom == strings.ToLower(mb.domain) {
		return false
	}
	return !localDomains[dom]
}

// destIsLocalSelf reports whether a deliver destination routes back into the
// local mail system (a self re-delivery that keeps a copy for the victim).
func destIsLocalSelf(dest string, mb filterMailbox, localDomains map[string]bool) bool {
	if strings.Contains(dest, "$local_part") || strings.Contains(dest, "$domain") || strings.Contains(dest, "$home") {
		return true
	}
	at := strings.LastIndexByte(dest, '@')
	if at < 0 || at == len(dest)-1 {
		return false
	}
	dom := strings.ToLower(strings.Trim(dest[at+1:], `" `))
	return dom == strings.ToLower(mb.domain) || localDomains[dom]
}

func isSafePipe(cmd string) bool {
	for _, s := range safePipeCommands {
		if strings.Contains(cmd, s) {
			return true
		}
	}
	return false
}

// scoreFilterRules evaluates one mailbox's parsed filter rules and returns the
// dangerous patterns found. Suppression entries in known (format
// "local@domain: dest") drop matching external destinations.
func scoreFilterRules(rules []filterRule, mb filterMailbox, localDomains map[string]bool, known []string) []filterFinding {
	var out []filterFinding
	seen := map[string]bool{}
	add := func(f filterFinding) {
		key := f.kind + "|" + f.dest
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, f)
	}

	for _, r := range rules {
		var externalDest string
		externalUnseen := false
		hasLocalCopy := false
		hasDevNull := false

		for _, a := range r.actions {
			switch a.verb {
			case "deliver":
				switch {
				case destIsExternal(a.arg, mb, localDomains):
					if externalDest == "" {
						externalDest = a.arg
					}
					if a.unseen {
						externalUnseen = true
					}
				case destIsLocalSelf(a.arg, mb, localDomains):
					hasLocalCopy = true
				}
			case "save":
				if strings.TrimSpace(a.arg) == "/dev/null" {
					hasDevNull = true
				} else {
					hasLocalCopy = true
				}
			case "pipe":
				if !isSafePipe(a.arg) {
					add(filterFinding{
						severity: alert.Critical,
						check:    "email_filter_pipe",
						kind:     "pipe",
						dest:     a.arg,
						reason:   fmt.Sprintf("filter pipes mail to a command: %s", a.arg),
					})
				}
			}
		}

		if externalDest != "" {
			if isKnownForwarder(mb.localPart, mb.domain, externalDest, known) {
				continue
			}
			stealth := hasLocalCopy || hasDevNull || r.matchesAll || externalUnseen
			if stealth {
				add(filterFinding{
					severity: alert.Critical,
					check:    "email_filter_exfil",
					kind:     "exfil",
					dest:     externalDest,
					reason:   stealthReason(hasLocalCopy, hasDevNull, r.matchesAll, externalUnseen),
				})
			} else {
				add(filterFinding{
					severity:  alert.High,
					check:     "email_filter_forwarder",
					kind:      "forwarder",
					dest:      externalDest,
					reason:    "filter forwards mail to an external address",
					onlyIfNew: true,
				})
			}
			continue
		}

		if hasDevNull && r.matchesAll {
			add(filterFinding{
				severity: alert.High,
				check:    "email_filter_blackhole",
				kind:     "blackhole",
				reason:   "filter discards all mail to /dev/null",
			})
		}
	}

	return out
}

func stealthReason(localCopy, devNull, matchAll, unseen bool) string {
	switch {
	case devNull:
		return "filter forwards mail externally and discards the local copy to hide it"
	case localCopy || unseen:
		return "filter copies every message to an external address while keeping a local copy (stealth interception)"
	case matchAll:
		return "filter forwards all mail to an external address"
	}
	return "filter forwards mail to an external address"
}

// ---------------------------------------------------------------------------
// Check
// ---------------------------------------------------------------------------

// mailboxFromFilterPath derives the mailbox from a filter file path. Per-mailbox
// filters live at /home/<user>/etc/<domain>/<localpart>/filter; domain-wide
// filters at /etc/vfilters/<domain>.
func mailboxFromFilterPath(path string) filterMailbox {
	if dir := filepath.Dir(path); dir == "/etc/vfilters" {
		return filterMailbox{localPart: "*", domain: filepath.Base(path)}
	}
	parts := strings.Split(path, "/")
	for i := 0; i+2 < len(parts); i++ {
		if parts[i] == "etc" && parts[i+1] != "" && parts[i+2] != "" {
			return filterMailbox{localPart: parts[i+2], domain: parts[i+1]}
		}
	}
	return filterMailbox{localPart: "*", domain: filepath.Base(filepath.Dir(path))}
}

// CheckMailFilters scans per-mailbox and domain-wide Exim filters for BEC-style
// exfiltration rules. Throttled to PasswordCheckIntervalMin, like the forwarder
// audit it complements.
func CheckMailFilters(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	if ctx == nil {
		ctx = context.Background()
	}
	db := store.Global()
	if db == nil {
		return nil
	}

	if !ForceAll {
		if last := db.GetMetaString("email:mailfilter_last_refresh"); last != "" {
			if ts, err := time.Parse(time.RFC3339, last); err == nil {
				interval := time.Duration(cfg.EmailProtection.PasswordCheckIntervalMin) * time.Minute
				if time.Since(ts) < interval {
					return nil
				}
			}
		}
	}
	if ctx.Err() != nil {
		return nil
	}

	localDomains := loadLocalDomains()

	var files []string
	if perMailbox, err := homeGlob(ctx, "etc", "*", "*", "filter"); err == nil {
		files = append(files, perMailbox...)
	}
	if AccountFromContext(ctx) == "" {
		if vfilters, err := osFS.Glob("/etc/vfilters/*"); err == nil {
			files = append(files, vfilters...)
		}
	}

	ranked := rankPathsByMtimeDesc(ctx, files, effectiveAccountScanMaxFiles(cfg))
	if ctx.Err() != nil {
		return nil
	}

	var collected []mailFilterPending

	for _, path := range ranked {
		if ctx.Err() != nil {
			return findingsFromPending(collected)
		}
		data, err := osFS.ReadFile(path)
		if err != nil {
			continue
		}

		isNew := false
		currentHash := sha256Hex(data)
		if old, found := db.GetForwarderHash("mailfilter:" + path); found && old != currentHash {
			isNew = true
		}
		_ = db.SetForwarderHash("mailfilter:"+path, currentHash)

		mb := mailboxFromFilterPath(path)
		rules := parseEximFilter(string(data))
		for _, ff := range scoreFilterRules(rules, mb, localDomains, cfg.EmailProtection.KnownForwarders) {
			if ff.onlyIfNew && !isNew {
				continue
			}
			collected = append(collected, mailFilterPending{
				finding: alert.Finding{
					Severity: ff.severity,
					Check:    ff.check,
					Message:  fmt.Sprintf("%s: %s", mb.String(), ff.reason),
					Details:  mailFilterDetails(mb, path, ff),
					FilePath: path,
					Domain:   mb.domain,
					Mailbox:  mailboxField(mb),
				},
				dest:    ff.dest,
				mailbox: mb.String(),
			})
		}
	}

	annotateCrossAccount(collected)
	if ctx.Err() != nil {
		return nil
	}
	_ = db.SetMetaString("email:mailfilter_last_refresh", time.Now().Format(time.RFC3339))
	return findingsFromPending(collected)
}

func mailFilterDetails(mb filterMailbox, path string, ff filterFinding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Mailbox: %s\nDomain: %s\nFile: %s\n", mb.String(), mb.domain, path)
	if ff.dest != "" {
		fmt.Fprintf(&b, "Destination: %s\n", ff.dest)
	}
	b.WriteString(ff.reason)
	return b.String()
}

func mailboxField(mb filterMailbox) string {
	if mb.localPart == "*" {
		return ""
	}
	return mb.String()
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h[:])
}

// mailFilterPending is an in-flight finding plus the fields needed for the
// cross-account correlation pass before findings are emitted.
type mailFilterPending struct {
	finding alert.Finding
	dest    string
	mailbox string
}

// annotateCrossAccount marks exfil findings whose external destination appears
// across two or more distinct mailboxes -- a strong campaign signal.
func annotateCrossAccount(collected []mailFilterPending) {
	byDest := map[string]map[string]bool{}
	for _, p := range collected {
		if p.dest == "" {
			continue
		}
		if byDest[p.dest] == nil {
			byDest[p.dest] = map[string]bool{}
		}
		byDest[p.dest][p.mailbox] = true
	}
	for i := range collected {
		dest := collected[i].dest
		boxes := byDest[dest]
		if len(boxes) < 2 {
			continue
		}
		others := make([]string, 0, len(boxes))
		for b := range boxes {
			if b != collected[i].mailbox {
				others = append(others, b)
			}
		}
		sort.Strings(others)
		collected[i].finding.Severity = alert.Critical
		collected[i].finding.Details += fmt.Sprintf(
			"\nCross-account: the same destination %s is used by %d mailboxes (also %s). This indicates a coordinated campaign.",
			dest, len(boxes), strings.Join(others, ", "))
	}
}

func findingsFromPending(collected []mailFilterPending) []alert.Finding {
	out := make([]alert.Finding, 0, len(collected))
	for _, p := range collected {
		out = append(out, p.finding)
	}
	return out
}
