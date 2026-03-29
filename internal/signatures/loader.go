package signatures

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// Rule represents a single malware detection rule loaded from an external file.
type Rule struct {
	Name            string   `yaml:"name"`
	Description     string   `yaml:"description"`
	Severity        string   `yaml:"severity"`         // "critical", "high", "warning"
	Category        string   `yaml:"category"`         // "webshell", "backdoor", "phishing", "dropper", "exploit"
	FileTypes       []string `yaml:"file_types"`       // [".php", ".html", "*"] — which extensions to scan
	Patterns        []string `yaml:"patterns"`         // literal string patterns (case-insensitive match)
	Regexes         []string `yaml:"regexes"`          // regex patterns (for complex matching)
	ExcludePatterns []string `yaml:"exclude_patterns"` // if any match, rule is skipped (false positive reduction)
	ExcludeRegexes  []string `yaml:"exclude_regexes"`  // regex exclusions
	MinMatch        int      `yaml:"min_match"`        // minimum patterns that must match (default: 1)

	// Compiled regexes (populated by Compile())
	compiledRegexes        []*regexp.Regexp
	compiledExcludeRegexes []*regexp.Regexp
}

// RuleFile is the top-level structure of a rules YAML file.
type RuleFile struct {
	Version int    `yaml:"version"`
	Updated string `yaml:"updated"`
	Rules   []Rule `yaml:"rules"`
}

// Scanner holds compiled rules and provides file scanning.
type Scanner struct {
	mu       sync.RWMutex
	rules    []Rule
	version  int
	rulesDir string
}

// NewScanner creates a scanner that loads rules from the given directory.
// Returns a scanner with no rules if the directory doesn't exist (not an error).
func NewScanner(rulesDir string) *Scanner {
	s := &Scanner{rulesDir: rulesDir}
	_ = s.Reload() // best-effort load on init
	return s
}

// Reload loads/reloads all .yml and .yaml rule files from the rules directory.
func (s *Scanner) Reload() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.rulesDir == "" {
		return nil
	}

	entries, err := os.ReadDir(s.rulesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // no rules dir = no rules, not an error
		}
		return fmt.Errorf("reading rules dir %s: %w", s.rulesDir, err)
	}

	var allRules []Rule
	maxVersion := 0

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(name))
		if ext != ".yml" && ext != ".yaml" {
			continue
		}

		path := filepath.Join(s.rulesDir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "signatures: error reading %s: %v\n", path, err)
			continue
		}

		var rf RuleFile
		if err := yaml.Unmarshal(data, &rf); err != nil {
			fmt.Fprintf(os.Stderr, "signatures: error parsing %s: %v\n", path, err)
			continue
		}

		if rf.Version > maxVersion {
			maxVersion = rf.Version
		}

		// Compile rules
		for i := range rf.Rules {
			rule := &rf.Rules[i]
			if err := rule.compile(); err != nil {
				fmt.Fprintf(os.Stderr, "signatures: error compiling rule '%s' in %s: %v\n", rule.Name, path, err)
				continue
			}
			if rule.MinMatch == 0 {
				rule.MinMatch = 1
			}
			allRules = append(allRules, *rule)
		}
	}

	s.rules = allRules
	s.version = maxVersion

	if len(allRules) > 0 {
		fmt.Fprintf(os.Stderr, "signatures: loaded %d rules (version %d) from %s\n", len(allRules), maxVersion, s.rulesDir)
	}

	return nil
}

// compile pre-compiles regex patterns for a rule.
func (r *Rule) compile() error {
	r.compiledRegexes = nil
	for _, pattern := range r.Regexes {
		re, err := regexp.Compile("(?i)" + pattern) // case-insensitive
		if err != nil {
			return fmt.Errorf("invalid regex '%s': %w", pattern, err)
		}
		r.compiledRegexes = append(r.compiledRegexes, re)
	}
	r.compiledExcludeRegexes = nil
	for _, pattern := range r.ExcludeRegexes {
		re, err := regexp.Compile("(?i)" + pattern)
		if err != nil {
			return fmt.Errorf("invalid exclude regex '%s': %w", pattern, err)
		}
		r.compiledExcludeRegexes = append(r.compiledExcludeRegexes, re)
	}
	return nil
}

// Match represents a rule that matched a file.
type Match struct {
	RuleName    string
	Description string
	Severity    string
	Category    string
	Matched     []string // which patterns matched
}

// ScanContent scans file content against loaded rules.
// fileExt should include the dot (e.g., ".php").
func (s *Scanner) ScanContent(content []byte, fileExt string) []Match {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.rules) == 0 {
		return nil
	}

	contentLower := strings.ToLower(string(content))
	extLower := strings.ToLower(fileExt)
	var matches []Match

	for _, rule := range s.rules {
		// Check if this rule applies to this file type
		if !ruleMatchesExt(rule, extLower) {
			continue
		}

		// Check exclusions first — if any exclude pattern matches, skip this rule
		excluded := false
		for _, pattern := range rule.ExcludePatterns {
			if strings.Contains(contentLower, strings.ToLower(pattern)) {
				excluded = true
				break
			}
		}
		if !excluded {
			for _, re := range rule.compiledExcludeRegexes {
				if re.Match(content) {
					excluded = true
					break
				}
			}
		}
		if excluded {
			continue
		}

		// Count pattern matches
		var matched []string

		for _, pattern := range rule.Patterns {
			if strings.Contains(contentLower, strings.ToLower(pattern)) {
				matched = append(matched, pattern)
			}
		}

		for _, re := range rule.compiledRegexes {
			if re.Match(content) {
				matched = append(matched, re.String())
			}
		}

		if len(matched) >= rule.MinMatch {
			matches = append(matches, Match{
				RuleName:    rule.Name,
				Description: rule.Description,
				Severity:    rule.Severity,
				Category:    rule.Category,
				Matched:     matched,
			})
		}
	}

	return matches
}

// ScanFile reads a file and scans it against loaded rules.
func (s *Scanner) ScanFile(path string, maxBytes int) []Match {
	s.mu.RLock()
	ruleCount := len(s.rules)
	s.mu.RUnlock()

	if ruleCount == 0 {
		return nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, maxBytes)
	n, _ := f.Read(buf)
	if n == 0 {
		return nil
	}

	ext := filepath.Ext(path)
	return s.ScanContent(buf[:n], ext)
}

// RuleCount returns the number of loaded rules.
func (s *Scanner) RuleCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.rules)
}

// Version returns the highest version number across loaded rule files.
func (s *Scanner) Version() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.version
}

func ruleMatchesExt(rule Rule, ext string) bool {
	if len(rule.FileTypes) == 0 {
		return true // no filter = match all
	}
	for _, ft := range rule.FileTypes {
		if ft == "*" || strings.ToLower(ft) == ext {
			return true
		}
	}
	return false
}
