package modsec

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// Rule represents a parsed ModSecurity rule from the CSM custom config.
type Rule struct {
	ID          int    // e.g. 900112
	Description string // from msg:'...' field
	Action      string // "deny", "block", "drop", "pass", "log", "allow"
	StatusCode  int    // 403, 429, 0 (for pass/log)
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
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		raw := scanner.Text()
		trimmed := strings.TrimSpace(raw)

		if strings.HasSuffix(trimmed, "\\") {
			// Continuation: strip trailing \ and keep accumulating
			current.WriteString(strings.TrimSuffix(trimmed, "\\"))
			current.WriteString(" ")
			continue
		}
		current.WriteString(trimmed)
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

	// Extract action from the action string (quoted section).
	// Use comma/quote-prefixed matching to avoid false matches
	// in variable names or patterns (e.g. "nolog" matching "log").
	// Order matters: deny/drop/block before pass/log/allow because some
	// blocking rules also carry a leading "log" attribute.
	lower := strings.ToLower(block)
	switch {
	case strings.Contains(lower, ",deny") || strings.Contains(lower, "\"deny"):
		r.Action = "deny"
	case strings.Contains(lower, ",drop") || strings.Contains(lower, "\"drop"):
		r.Action = "drop"
	case strings.Contains(lower, ",block") || strings.Contains(lower, "\"block"):
		r.Action = "block"
	case strings.Contains(lower, ",pass") || strings.Contains(lower, "\"pass"):
		r.Action = "pass"
	case strings.Contains(lower, ",allow") || strings.Contains(lower, "\"allow"):
		r.Action = "allow"
	case strings.Contains(lower, ",log,") || strings.Contains(lower, ",log\"") || strings.Contains(lower, "\"log,"):
		r.Action = "log"
	}

	// Extract status code
	if sm := reStatus.FindStringSubmatch(block); sm != nil {
		r.StatusCode, _ = strconv.Atoi(sm[1])
	}

	// Mark counter rules
	if r.Action == "pass" && strings.Contains(lower, "nolog") {
		r.IsCounter = true
	}

	return r, true
}

// IsBlockingAction reports whether an action causes the request to be denied.
// Used by the LiteSpeed log-line classifier - error_log records every match
// as "triggered!" regardless of action, so the action lookup is the only way
// to tell a real deny apart from a pass-action informational rule.
func IsBlockingAction(action string) bool {
	switch action {
	case "deny", "drop", "block":
		return true
	}
	return false
}
