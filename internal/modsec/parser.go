package modsec

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// maxModsecLineBytes bounds a single logical line for the rule scanners. Far
// above any legitimate directive, but finite so a pathological file cannot
// drive an unbounded allocation.
const maxModsecLineBytes = 8 << 20 // 8 MiB

// Rule represents a parsed ModSecurity rule from the CSM custom config.
type Rule struct {
	ID          int    // e.g. 900112
	Description string // from msg:'...' field
	Action      string // disposition keyword: deny|drop|block|redirect|proxy|pause|allow|pass; "" if rule has only metadata (log, msg, ...) and inherits SecDefaultAction
	StatusCode  int    // 403, 429, 0 (for pass)
	Phase       int    // phase named in the action list, 1-5; 0 if none
	Raw         string // full rule text including chains
	IsCounter   bool   // true if pass,nolog (bookkeeping rule, hidden in UI)
}

var (
	reMsg    = regexp.MustCompile(`msg:'([^']*)'`)
	reStatus = regexp.MustCompile(`status:(\d+)`)
)

// defaultPhase is the phase ModSecurity uses for a rule or SecDefaultAction
// that does not name one.
const defaultPhase = 2

// dispositionPriority lists the ModSecurity action keywords that decide
// what happens to the request, ordered most-disruptive first. The first
// keyword present as a standalone token in the action string wins so an
// explicit disruptive action cannot be weakened by block inheritance.
// Metadata keywords (log, msg, severity, tag, ...) are
// intentionally excluded. A rule that carries only metadata has an empty
// Action; the registry leaves it out, so the LiteSpeed classifier treats it
// as unknown and defaults it to block. block itself names no disruptive
// action: the registry resolves it through SecDefaultAction.
var dispositionPriority = []string{
	"deny", "drop", "redirect", "proxy", "pause", "block", "allow", "pass",
}

// dispositionSet is dispositionPriority as a lookup table. Pre-built for
// O(1) membership checks during action-string tokenisation.
var dispositionSet = func() map[string]struct{} {
	m := make(map[string]struct{}, len(dispositionPriority))
	for _, k := range dispositionPriority {
		m[k] = struct{}{}
	}
	return m
}()

// ParseRulesFile reads a ModSecurity config file and extracts CSM-owned rules
// (IDs in 900000-900999). Use ParseRulesFileAll for the rule-action registry,
// which needs every rule including vendor packs.
func ParseRulesFile(path string) ([]Rule, error) {
	all, err := ParseRulesFileAll(path)
	if err != nil {
		return nil, err
	}
	var csm []Rule
	for _, r := range all {
		if r.ID >= 900000 && r.ID <= 900999 {
			csm = append(csm, r)
		}
	}
	return csm, nil
}

// ParseRulesFileAll reads a ModSecurity config file and extracts every rule,
// regardless of ID range. Handles line continuations (\) and chained rules
// (chain action keyword). Vendor packs (Comodo, OWASP CRS, Imunify360) all
// use this entrypoint via the rule-action registry so the daemon can tell
// pass-action rules apart from deny rules.
func ParseRulesFileAll(path string) ([]Rule, error) {
	// #nosec G304 -- path is operator-configured ModSec rules file.
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening rules file: %w", err)
	}
	defer f.Close()

	rules, _, err := parseRules(f)
	return rules, err
}

// parseRules returns the rules in a config file and the disruptive action
// each phase's SecDefaultAction in it declares. A later directive for the
// same phase replaces an earlier one.
func parseRules(reader io.Reader) ([]Rule, map[int]string, error) {
	// Phase 1: Read lines, joining backslash continuations into logical lines.
	var logicalLines []string
	var current strings.Builder
	appendCurrent := func(part string) error {
		if current.Len()+len(part) > maxModsecLineBytes {
			return fmt.Errorf("logical modsec line exceeds %d bytes", maxModsecLineBytes)
		}
		current.WriteString(part)
		return nil
	}
	scanner := bufio.NewScanner(reader)
	// Vendor packs (OWASP CRS, Comodo, Imunify360, cPanel modsec_assemble)
	// ship assembled/minified directives that can exceed the default 64 KB
	// token. Without a larger buffer Scan stops at ErrTooLong and the file's
	// rules drop out of the action registry, where unknown IDs then default
	// to "deny" and skew the modsec signal. Raise the ceiling so real files
	// parse in full.
	scanner.Buffer(make([]byte, 0, 64*1024), maxModsecLineBytes)
	for scanner.Scan() {
		raw := scanner.Text()
		trimmed := strings.TrimSpace(raw)

		if strings.HasSuffix(trimmed, "\\") {
			// Continuation: strip trailing \ and keep accumulating.
			if err := appendCurrent(strings.TrimSuffix(trimmed, "\\")); err != nil {
				return nil, nil, err
			}
			if err := appendCurrent(" "); err != nil {
				return nil, nil, err
			}
			continue
		}
		if err := appendCurrent(trimmed); err != nil {
			return nil, nil, err
		}
		logicalLines = append(logicalLines, current.String())
		current.Reset()
	}
	if current.Len() > 0 {
		logicalLines = append(logicalLines, current.String())
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}

	// Phase 2: Group logical lines into blocks.
	// Each block starts with a SecRule and may include chained SecRules.
	// When a directive's action string contains "chain", the next SecRule
	// is part of the same block.
	var blocks []string
	var block strings.Builder
	chainPending := false
	defaults := make(map[int]string)
	var parseErr error

	flushBlock := func() {
		if block.Len() > 0 {
			blocks = append(blocks, block.String())
			block.Reset()
		}
		chainPending = false
	}

	for _, line := range logicalLines {
		if rest, ok := directiveArgs(line, "SecDefaultAction"); ok {
			arg, _, valid := configArgument(rest)
			if !valid {
				parseErr = errors.Join(parseErr, fmt.Errorf("malformed SecDefaultAction argument"))
				continue
			}
			// SecDefaultAction must name a disruptive action other than
			// block; ModSecurity refuses to load one that does not.
			if action := pickDisposition(arg); action != "" && action != "block" {
				phase := actionPhase(arg)
				if phase == 0 {
					phase = defaultPhase
				}
				defaults[phase] = action
			}
			continue
		}
		_, isRule := directiveArgs(line, "SecRule")
		if isRule {
			if block.Len() > 0 && !chainPending {
				flushBlock()
			}
		} else if block.Len() == 0 {
			continue // skip comments and blank lines outside blocks
		}

		if block.Len() > 0 || isRule {
			block.WriteString(line)
			block.WriteString("\n")
			// Only update chainPending for SecRule lines - non-SecRule
			// directives between chained rules must not reset the flag.
			if isRule {
				chainPending = hasChainAction(line)
			}
		}
	}
	flushBlock()

	// Phase 3: Parse each block into a Rule.
	var rules []Rule
	for _, b := range blocks {
		if r, ok := parseBlock(b); ok {
			rules = append(rules, r)
		}
	}
	return rules, defaults, parseErr
}

// hasChainAction reads only the SecRule action argument: a regex or message
// containing chain must not swallow the next independent rule.
func hasChainAction(line string) bool {
	for _, token := range tokenizeActionString(secRuleActions(line)) {
		if strings.EqualFold(token, "chain") {
			return true
		}
	}
	return false
}

func parseBlock(block string) (Rule, bool) {
	line, _, _ := strings.Cut(block, "\n")
	actions := secRuleActions(line)
	id := 0
	for _, token := range tokenizeActionString(actions) {
		name, value, ok := strings.Cut(token, ":")
		if ok && strings.EqualFold(strings.TrimSpace(name), "id") {
			id, _ = strconv.Atoi(strings.Trim(strings.TrimSpace(value), `'"`))
			break
		}
	}
	if id <= 0 {
		return Rule{}, false
	}

	r := Rule{
		ID:     id,
		Raw:    strings.TrimSpace(block),
		Action: pickDisposition(actions),
		Phase:  actionPhase(actions),
	}
	if mm := reMsg.FindStringSubmatch(block); mm != nil {
		r.Description = mm[1]
	}
	if r.Action == "pass" && strings.Contains(strings.ToLower(actions), "nolog") {
		r.IsCounter = true
	}
	if sm := reStatus.FindStringSubmatch(block); sm != nil {
		r.StatusCode, _ = strconv.Atoi(sm[1])
	}
	return r, true
}

// Rule identity and disposition come from the third argument, never from
// an id-like substring in the operator or a chained rule's actions.
func secRuleActions(line string) string {
	rest, ok := directiveArgs(line, "SecRule")
	if !ok {
		return ""
	}
	var arg string
	for range 3 {
		arg, rest, ok = configArgument(rest)
		if !ok {
			return ""
		}
	}
	return arg
}

func directiveArgs(line, directive string) (string, bool) {
	if len(line) <= len(directive) || !strings.EqualFold(line[:len(directive)], directive) {
		return "", false
	}
	rest := line[len(directive):]
	if rest[0] != ' ' && rest[0] != '\t' {
		return "", false
	}
	return strings.TrimLeft(rest, " \t"), true
}

// Decode the outer Apache quoting before tokenizing the action list. A
// doubled backslash can escape an inner apostrophe only after this layer
// is removed; otherwise a following deny could look like message text.
func configArgument(s string) (string, string, bool) {
	s = strings.TrimLeft(s, " \t")
	if s == "" {
		return "", "", false
	}
	if quote := s[0]; quote == '\'' || quote == '"' {
		for i := 1; i < len(s); i++ {
			switch s[i] {
			case '\\':
				if i+1 < len(s) && (s[i+1] == quote || s[i+1] == '\\') {
					i++
				}
			case quote:
				return decodeConfigArgument(s[1:i], quote), s[i+1:], true
			}
		}
		return "", "", false
	}
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return decodeConfigArgument(s[:i], 0), s[i:], true
	}
	return decodeConfigArgument(s, 0), "", true
}

func decodeConfigArgument(s string, quote byte) string {
	var decoded strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && (s[i+1] == '\\' || (quote != 0 && s[i+1] == quote)) {
			i++
		}
		decoded.WriteByte(s[i])
	}
	return decoded.String()
}

// pickDisposition returns the ModSecurity disposition keyword present in
// the action string, preferring more-disruptive keywords when several are
// present (defensive: a rule labelled "deny" wins over a stray "allow").
// Returns "" if the action string carries only metadata and the rule
// therefore inherits SecDefaultAction.
func pickDisposition(actionStr string) string {
	tokens := tokenizeActionString(actionStr)
	seen := make(map[string]struct{}, len(tokens))
	for _, t := range tokens {
		name := t
		if i := strings.IndexByte(name, ':'); i >= 0 {
			name = name[:i]
		}
		name = strings.ToLower(strings.TrimSpace(name))
		if _, ok := dispositionSet[name]; ok {
			seen[name] = struct{}{}
		}
	}
	for _, kw := range dispositionPriority {
		if _, ok := seen[kw]; ok {
			return kw
		}
	}
	return ""
}

// actionPhase returns the phase an action list names, or 0 if it names none.
// ModSecurity also accepts request, response and logging for 2, 4 and 5.
func actionPhase(actionStr string) int {
	phase := 0
	for _, tok := range tokenizeActionString(actionStr) {
		name, value, ok := strings.Cut(tok, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(name), "phase") {
			continue
		}
		switch v := strings.ToLower(strings.Trim(strings.TrimSpace(value), "'")); v {
		case "request":
			phase = 2
		case "response":
			phase = 4
		case "logging":
			phase = 5
		default:
			if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 5 {
				phase = n
			}
		}
	}
	return phase
}

// tokenizeActionString splits a ModSecurity action list on top-level commas
// while respecting single-quoted string values (msg:'foo, bar', logdata:'...'),
// where commas are part of the literal and must not be treated as token
// separators. Backslash-escaped quotes inside the literals are preserved.
func tokenizeActionString(s string) []string {
	var out []string
	var cur strings.Builder
	inSingle := false
	escape := false
	for _, r := range s {
		switch {
		case escape:
			cur.WriteRune(r)
			escape = false
		case r == '\\':
			cur.WriteRune(r)
			escape = true
		case r == '\'':
			inSingle = !inSingle
			cur.WriteRune(r)
		case r == ',' && !inSingle:
			tok := strings.TrimSpace(cur.String())
			if tok != "" {
				out = append(out, tok)
			}
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	if tok := strings.TrimSpace(cur.String()); tok != "" {
		out = append(out, tok)
	}
	return out
}

// IsBlockingAction reports whether an action causes the request to be denied
// or otherwise diverted away from normal processing. Used by the LiteSpeed
// log-line classifier - error_log records every match as "triggered!"
// regardless of action, so the action lookup is the only way to tell a real
// deny apart from a pass-action informational rule. redirect, proxy and
// pause are disruptive: the original request never reaches the upstream
// application as intended, so they are classified the same as deny. The
// registry keeps block only when incomplete setup files prevent resolution;
// it must remain blocking until the default can be determined.
func IsBlockingAction(action string) bool {
	switch action {
	case "deny", "drop", "block", "redirect", "proxy", "pause":
		return true
	}
	return false
}
