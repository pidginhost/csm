package modsec

import (
	"bufio"
	"fmt"
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
	Phase       int    // 1 or 2
	Raw         string // full rule text including chains
	IsCounter   bool   // true if pass,nolog (bookkeeping rule, hidden in UI)
}

var (
	reID     = regexp.MustCompile(`[,"]id:(\d+)`)
	reMsg    = regexp.MustCompile(`msg:'([^']*)'`)
	rePhase  = regexp.MustCompile(`phase:(\d)`)
	reStatus = regexp.MustCompile(`status:(\d+)`)
)

// dispositionPriority lists the ModSecurity action keywords that decide
// what happens to the request, ordered most-disruptive first. The first
// keyword present as a standalone token in the action string wins; this
// matches how ModSecurity itself resolves multiple disruptive directives
// in a single rule. Metadata keywords (log, msg, severity, tag, ...) are
// intentionally excluded - a rule that carries only metadata inherits
// SecDefaultAction, which CSM does not parse, so the registry leaves
// Action empty and the LiteSpeed classifier defaults that rule to block.
var dispositionPriority = []string{
	"deny", "drop", "block", "redirect", "proxy", "pause", "allow", "pass",
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
	scanner := bufio.NewScanner(f)
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
				return nil, err
			}
			if err := appendCurrent(" "); err != nil {
				return nil, err
			}
			continue
		}
		if err := appendCurrent(trimmed); err != nil {
			return nil, err
		}
		logicalLines = append(logicalLines, current.String())
		current.Reset()
	}
	if current.Len() > 0 {
		logicalLines = append(logicalLines, current.String())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Phase 2: Group logical lines into blocks.
	// Each block starts with a SecRule and may include chained SecRules.
	// When a directive's action string contains "chain", the next SecRule
	// is part of the same block.
	var blocks []string
	var block strings.Builder
	chainPending := false

	flushBlock := func() {
		if block.Len() > 0 {
			blocks = append(blocks, block.String())
			block.Reset()
		}
		chainPending = false
	}

	for _, line := range logicalLines {
		if strings.HasPrefix(line, "SecRule ") {
			if block.Len() > 0 && !chainPending {
				flushBlock()
			}
		} else if block.Len() == 0 {
			continue // skip comments and blank lines outside blocks
		}

		if block.Len() > 0 || strings.HasPrefix(line, "SecRule ") {
			block.WriteString(line)
			block.WriteString("\n")
			// Only update chainPending for SecRule lines - non-SecRule
			// directives between chained rules must not reset the flag.
			if strings.HasPrefix(line, "SecRule ") {
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
	return rules, nil
}

// hasChainAction checks whether a logical line (continuations already joined)
// contains "chain" as a ModSecurity action keyword. Strips whitespace to handle
// action strings split across continuation lines like: "id:900004,..., chain"
func hasChainAction(line string) bool {
	// Remove all whitespace so ",  chain\"" becomes ",chain\""
	stripped := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, line)
	return strings.Contains(stripped, ",chain\"") ||
		strings.Contains(stripped, ",chain'") ||
		strings.Contains(stripped, ",chain,") ||
		strings.Contains(stripped, "\"chain\"") ||
		strings.Contains(stripped, "\"chain,")
}

func parseBlock(block string) (Rule, bool) {
	// Extract ID
	m := reID.FindStringSubmatch(block)
	if m == nil {
		return Rule{}, false
	}
	id, _ := strconv.Atoi(m[1])

	r := Rule{
		ID:  id,
		Raw: strings.TrimSpace(block),
	}

	// Extract description from msg
	if mm := reMsg.FindStringSubmatch(block); mm != nil {
		r.Description = mm[1]
	}

	// Extract phase
	if pm := rePhase.FindStringSubmatch(block); pm != nil {
		r.Phase, _ = strconv.Atoi(pm[1])
	}

	// Extract the action string (the quoted segment that carries id:N) and
	// pull the disposition keyword from its tokens. Substring matching
	// against the whole block would false-match on action-like text inside
	// regex operators, msg:'...' literals, and the like (e.g. "passive"
	// looks like "pass"). Token parsing inside the bounded action string
	// avoids those collisions.
	if actionStr := extractActionString(block, id); actionStr != "" {
		r.Action = pickDisposition(actionStr)
		// nolog/log are honoured only as flags, never as the action.
		actionLower := strings.ToLower(actionStr)
		if r.Action == "pass" && strings.Contains(actionLower, "nolog") {
			r.IsCounter = true
		}
	}

	// Extract status code
	if sm := reStatus.FindStringSubmatch(block); sm != nil {
		r.StatusCode, _ = strconv.Atoi(sm[1])
	}

	return r, true
}

// extractActionString returns the body of the quoted segment that contains
// "id:<ruleID>". ModSecurity rule blocks have one such segment per rule
// (chained sub-rules carry "chain,capture"-style action lists with no id),
// so finding the id-bearing quotes uniquely identifies the primary action
// list. Returns "" if the segment cannot be located, in which case the
// caller leaves Action empty and the registry treats the rule as unknown.
func extractActionString(block string, ruleID int) string {
	needle := "id:" + strconv.Itoa(ruleID)
	for i := 0; i < len(block); i++ {
		if block[i] != '"' {
			continue
		}
		start := i + 1
		escaped := false
		for j := start; j < len(block); j++ {
			switch {
			case escaped:
				escaped = false
			case block[j] == '\\':
				escaped = true
			case block[j] == '"':
				segment := block[start:j]
				if actionStringHasRuleID(segment, needle) {
					return segment
				}
				i = j
				j = len(block)
			}
		}
	}
	return ""
}

func actionStringHasRuleID(actionStr, needle string) bool {
	for _, tok := range tokenizeActionString(actionStr) {
		name, value, ok := strings.Cut(tok, ":")
		if !ok || strings.ToLower(strings.TrimSpace(name)) != "id" {
			continue
		}
		if strings.Trim(strings.TrimSpace(value), `'"`) == strings.TrimPrefix(needle, "id:") {
			return true
		}
	}
	return false
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
// application as intended, so they are classified the same as deny.
func IsBlockingAction(action string) bool {
	switch action {
	case "deny", "drop", "block", "redirect", "proxy", "pause":
		return true
	}
	return false
}
