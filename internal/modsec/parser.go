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
	Action      string // "deny", "pass", "log"
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

// ParseRulesFile reads a ModSecurity config file and extracts all rules
// with IDs in the 900000-900999 range. Handles line continuations (\) and
// chained rules (chain action keyword).
func ParseRulesFile(path string) ([]Rule, error) {
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

	// Filter to CSM range
	if id < 900000 || id > 900999 {
		return Rule{}, false
	}

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
	lower := strings.ToLower(block)
	switch {
	case strings.Contains(lower, ",deny") || strings.Contains(lower, "\"deny"):
		r.Action = "deny"
	case strings.Contains(lower, ",pass") || strings.Contains(lower, "\"pass"):
		r.Action = "pass"
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
