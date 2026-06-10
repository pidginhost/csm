package checks

import (
	"context"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

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

var actionArgs = map[string]bool{
	"deliver":  true,
	"save":     true,
	"pipe":     true,
	"mail":     true,
	"vacation": true,
}

var controlWords = map[string]bool{
	"if":     true,
	"elif":   true,
	"else":   true,
	"endif":  true,
	"then":   true,
	"unseen": true,
}

type filterRuleNode struct {
	rule   filterRule
	parent *filterRuleNode
}

// parseEximFilter parses Exim filter source into a flat list of rules, one per
// if/elif/else branch plus one for any unconditional top-level actions. Nested
// branches include ancestor actions so split deliver/save patterns still score
// as one executed branch.
func parseEximFilter(content string) []filterRule {
	toks := tokenizeExim(content)

	top := &filterRuleNode{rule: filterRule{matchesAll: true}}
	stack := []*filterRuleNode{top}
	rules := []*filterRuleNode{top}

	pendingUnseen := false
	i := 0
	for i < len(toks) {
		t := toks[i]
		if t.str {
			i++
			continue
		}
		kw := strings.ToLower(t.text)
		switch kw {
		case "if", "elif":
			if kw == "elif" && len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
			parent := stack[len(stack)-1]
			i++
			condStart := i
			for i < len(toks) && !tokenIs(toks[i], "then") {
				i++
			}
			cond := renderCondition(toks[condStart:i])
			if i < len(toks) {
				i++ // consume "then"
			}
			r := &filterRuleNode{
				rule:   filterRule{condition: cond, matchesAll: conditionMatchesAll(cond)},
				parent: parent,
			}
			rules = append(rules, r)
			stack = append(stack, r)
			pendingUnseen = false
		case "else":
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
			parent := stack[len(stack)-1]
			i++
			r := &filterRuleNode{
				rule:   filterRule{condition: "else"},
				parent: parent,
			}
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
			if !actionVerbs[kw] {
				i++
				continue
			}
			verb := kw
			i++
			arg := ""
			if actionArgs[verb] && i < len(toks) {
				if toks[i].str || isBareActionArg(toks[i]) {
					arg = toks[i].text
					i++
				}
			}
			cur := stack[len(stack)-1]
			cur.rule.actions = append(cur.rule.actions, filterAction{verb: verb, arg: arg, unseen: pendingUnseen})
			pendingUnseen = false
		}
	}

	out := make([]filterRule, 0, len(rules))
	for _, r := range rules {
		if len(r.rule.actions) > 0 {
			out = append(out, flattenRuleNode(r))
		}
	}
	return out
}

func tokenIs(t eximToken, word string) bool {
	return !t.str && strings.EqualFold(t.text, word)
}

func isBareActionArg(t eximToken) bool {
	if t.str {
		return true
	}
	lower := strings.ToLower(t.text)
	return !controlWords[lower] && !actionVerbs[lower]
}

func flattenRuleNode(node *filterRuleNode) filterRule {
	var chain []*filterRuleNode
	for n := node; n != nil; n = n.parent {
		chain = append(chain, n)
	}

	out := filterRule{matchesAll: true}
	var conditions []string
	for i := len(chain) - 1; i >= 0; i-- {
		r := chain[i].rule
		if r.condition != "" {
			conditions = append(conditions, r.condition)
		}
		if !r.matchesAll {
			out.matchesAll = false
		}
		out.actions = append(out.actions, r.actions...)
	}
	out.condition = strings.Join(conditions, " && ")
	return out
}

// conditionMatchesAll reports whether a filter condition fires on effectively
// all mail: an unconditional rule, or one that only tests that an address or
// header comparison is true for every normal email address.
func conditionMatchesAll(cond string) bool {
	c := strings.TrimSpace(cond)
	if c == "" {
		return true
	}
	return tokenExpressionMatchesAll(tokenizeExim(c))
}

func tokenExpressionMatchesAll(toks []eximToken) bool {
	toks = trimOuterParens(toks)
	if len(toks) == 0 {
		return false
	}
	for _, term := range splitTopLevel(toks, "or") {
		if tokenConjunctionMatchesAll(term) {
			return true
		}
	}
	return false
}

func tokenConjunctionMatchesAll(toks []eximToken) bool {
	toks = trimOuterParens(toks)
	if len(toks) == 0 {
		return false
	}
	parts := splitTopLevel(toks, "and")
	for _, part := range parts {
		if !tokenTermMatchesAll(part) {
			return false
		}
	}
	return len(parts) > 0
}

func tokenTermMatchesAll(toks []eximToken) bool {
	toks = trimOuterParens(toks)
	if len(toks) == 0 {
		return false
	}
	if parts := splitTopLevel(toks, "or"); len(parts) > 1 {
		return tokenExpressionMatchesAll(toks)
	}
	if parts := splitTopLevel(toks, "and"); len(parts) > 1 {
		return tokenConjunctionMatchesAll(toks)
	}

	hasMatchAllComparison := false
	for i := 0; i < len(toks); i++ {
		if toks[i].str {
			continue
		}
		if strings.EqualFold(toks[i].text, "not") {
			return false
		}
	}
	for i := 0; i+1 < len(toks); i++ {
		if toks[i].str {
			continue
		}
		op := strings.ToLower(toks[i].text)
		if !isAddressComparisonOperator(op) {
			continue
		}
		if !comparisonMatchesAllAddress(op, toks[i+1].text) || !comparisonHasAddressOperand(toks, i) {
			return false
		}
		hasMatchAllComparison = true
	}
	return hasMatchAllComparison
}

func splitTopLevel(toks []eximToken, word string) [][]eximToken {
	var parts [][]eximToken
	start := 0
	depth := 0
	for i, t := range toks {
		if t.str {
			continue
		}
		switch t.text {
		case "(":
			depth++
		case ")":
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 && strings.EqualFold(t.text, word) {
				if start < i {
					parts = append(parts, toks[start:i])
				}
				start = i + 1
			}
		}
	}
	if start < len(toks) {
		parts = append(parts, toks[start:])
	}
	return parts
}

func trimOuterParens(toks []eximToken) []eximToken {
	for len(toks) >= 2 && tokenIs(toks[0], "(") && tokenIs(toks[len(toks)-1], ")") && outerParensEncloseAll(toks) {
		toks = toks[1 : len(toks)-1]
	}
	return toks
}

func outerParensEncloseAll(toks []eximToken) bool {
	depth := 0
	for i, t := range toks {
		if t.str {
			continue
		}
		switch t.text {
		case "(":
			depth++
		case ")":
			depth--
			if depth == 0 && i != len(toks)-1 {
				return false
			}
			if depth < 0 {
				return false
			}
		}
	}
	return depth == 0
}

func isAddressComparisonOperator(op string) bool {
	switch op {
	case "contains", "matches", "is":
		return true
	}
	return false
}

func comparisonMatchesAllAddress(op, value string) bool {
	v := strings.ToLower(strings.TrimSpace(value))
	switch op {
	case "contains":
		return v == "@"
	case "matches":
		switch v {
		case "@", ".*@.*", ".+@.+", "^.*@.*$", "^.+@.+$":
			return true
		}
	case "is":
		return v == "*@*"
	}
	return false
}

func comparisonHasAddressOperand(toks []eximToken, opIndex int) bool {
	for i := opIndex - 1; i >= 0; i-- {
		if toks[i].str {
			continue
		}
		word := strings.ToLower(toks[i].text)
		switch word {
		case "and", "or", "then", "else":
			return false
		case "(", ")":
			return false
		case "not":
			continue
		}
		if tokenLooksAddressOperand(word) {
			return true
		}
	}
	return false
}

func tokenLooksAddressOperand(token string) bool {
	addressOperands := []string{
		"$thisaddress",
		"foranyaddress",
		"$sender_address",
		"$return_path",
		"$header_from",
		"$h_from",
		"$header_to",
		"$h_to",
		"$header_cc",
		"$h_cc",
		"$header_bcc",
		"$h_bcc",
		"$header_reply-to",
		"$h_reply-to",
		"$header_sender",
		"$h_sender",
		"$header_return-path",
		"$h_return-path",
	}
	for _, operand := range addressOperands {
		if strings.Contains(token, operand) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Scorer
// ---------------------------------------------------------------------------

// destIsExternal reports whether an Exim deliver destination leaves the local
// mail system. Exim variables ($domain etc.) and same-domain/local-domain
// addresses are not external.
func destIsExternal(dest string, mb filterMailbox, localDomains map[string]bool) bool {
	_, dom, ok := splitDeliverDest(dest)
	if !ok {
		return false
	}
	if deliverDomainIsLocal(dom, mb, localDomains) {
		return false
	}
	return true
}

// destIsLocalSelf reports whether a deliver destination routes back into the
// local mail system (a self re-delivery that keeps a copy for the victim).
func destIsLocalSelf(dest string, mb filterMailbox, localDomains map[string]bool) bool {
	_, dom, ok := splitDeliverDest(dest)
	if !ok {
		return false
	}
	return deliverDomainIsLocal(dom, mb, localDomains)
}

func splitDeliverDest(dest string) (string, string, bool) {
	clean := strings.Trim(strings.TrimSpace(dest), `"`)
	at := strings.LastIndexByte(clean, '@')
	if at < 0 || at == len(clean)-1 {
		return "", "", false
	}
	local := strings.Trim(strings.TrimSpace(clean[:at]), `"`)
	dom := strings.ToLower(strings.Trim(strings.TrimSpace(clean[at+1:]), `"`))
	if local == "" || dom == "" {
		return "", "", false
	}
	return local, dom, true
}

func deliverDomainIsLocal(dom string, mb filterMailbox, localDomains map[string]bool) bool {
	d := strings.ToLower(strings.TrimSpace(dom))
	if d == "$domain" || d == "${domain}" {
		return true
	}
	if d == strings.ToLower(mb.domain) {
		return true
	}
	return localDomains[d]
}

func isSafePipe(cmd string) bool {
	first := firstPipeCommandWord(cmd)
	for _, s := range safePipeCommands {
		if first == s {
			return true
		}
	}
	return false
}

func firstPipeCommandWord(cmd string) string {
	s := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(cmd), "|"))
	var b strings.Builder
	var quote rune
	for _, r := range s {
		if quote != 0 {
			if r == quote {
				quote = 0
				continue
			}
			b.WriteRune(r)
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			continue
		}
		if unicode.IsSpace(r) {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// scoreFilterRules evaluates one mailbox's parsed filter rules and returns the
// dangerous patterns found. Suppression entries in known (format
// "local@domain: dest") drop matching plain external destinations.
func scoreFilterRules(rules []filterRule, mb filterMailbox, localDomains map[string]bool, known []string) []filterFinding {
	var out []filterFinding
	seen := map[string]bool{}
	add := func(f filterFinding) {
		key := f.kind + "|" + f.dest
		if seen[key] {
			return
		}
		if f.kind == "forwarder" && seen["exfil|"+f.dest] {
			return
		}
		if f.kind == "exfil" && seen["forwarder|"+f.dest] {
			delete(seen, "forwarder|"+f.dest)
			for i := range out {
				if out[i].kind == "forwarder" && out[i].dest == f.dest {
					out = append(out[:i], out[i+1:]...)
					break
				}
			}
		}
		seen[key] = true
		out = append(out, f)
	}

	type externalDelivery struct {
		dest   string
		unseen bool
	}

	for _, r := range rules {
		var external []externalDelivery
		hasLocalCopy := false
		hasDevNull := false

		for _, a := range r.actions {
			switch a.verb {
			case "deliver":
				switch {
				case destIsExternal(a.arg, mb, localDomains):
					external = append(external, externalDelivery{dest: a.arg, unseen: a.unseen})
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

		if len(external) > 0 {
			for _, delivery := range external {
				stealth := hasLocalCopy || hasDevNull || r.matchesAll || delivery.unseen
				if !stealth && isKnownForwarder(mb.localPart, mb.domain, delivery.dest, known) {
					continue
				}
				if stealth {
					add(filterFinding{
						severity: alert.Critical,
						check:    "email_filter_exfil",
						kind:     "exfil",
						dest:     delivery.dest,
						reason:   stealthReason(hasLocalCopy, hasDevNull, r.matchesAll, delivery.unseen),
					})
				} else {
					add(filterFinding{
						severity:  alert.High,
						check:     "email_filter_forwarder",
						kind:      "forwarder",
						dest:      delivery.dest,
						reason:    "filter forwards mail to an external address",
						onlyIfNew: true,
					})
				}
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
		if matchAll {
			return "filter forwards all mail externally and discards the local copy to hide it"
		}
		return "filter forwards mail externally and discards the local copy to hide it"
	case localCopy || unseen:
		if !matchAll {
			return "filter sends matching mail to an external address while keeping a local copy (stealth interception)"
		}
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
		// Without the store the whole check is inoperative (hashes and the
		// throttle live there). Say so instead of looking like a clean host.
		return []alert.Finding{{
			Severity:  alert.Warning,
			Check:     "email_mail_filters",
			Message:   "Mail filter audit skipped: state store unavailable",
			Timestamp: time.Now(),
		}}
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

		currentHash := sha256Hex(data)
		isNew := forwarderFileIsNew(db, "email:mailfilter_last_refresh", "mailfilter:"+path, currentHash)
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
	// Only a full scan establishes the baseline / refreshes the throttle:
	// an account-scoped scan hashes one account's files, and marking it
	// complete would make the next full scan treat every other account's
	// existing filters as newly created.
	if AccountFromContext(ctx) == "" {
		_ = db.SetMetaString("email:mailfilter_last_refresh", time.Now().Format(time.RFC3339))
	}
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
