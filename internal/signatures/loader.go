package signatures

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/pidginhost/csm/internal/contenttype"
	"gopkg.in/yaml.v3"
)

// Rule represents a single malware detection rule loaded from an external file.
type Rule struct {
	Name            string   `yaml:"name"`
	Description     string   `yaml:"description"`
	Severity        string   `yaml:"severity"`         // "critical", "high", "warning"
	Category        string   `yaml:"category"`         // "webshell", "backdoor", "phishing", "dropper", "exploit"
	FileTypes       []string `yaml:"file_types"`       // [".php", ".html", "*"] - which extensions to scan
	Patterns        []string `yaml:"patterns"`         // literal string patterns (case-insensitive match)
	Regexes         []string `yaml:"regexes"`          // regex patterns (for complex matching)
	ExcludePatterns []string `yaml:"exclude_patterns"` // if any match, rule is skipped (false positive reduction)
	ExcludeRegexes  []string `yaml:"exclude_regexes"`  // regex exclusions
	MinMatch        int      `yaml:"min_match"`        // minimum patterns that must match (default: 1)
	RequireRegex    bool     `yaml:"require_regex"`    // if true, at least one regex must match in addition to min_match
	// MaxFileBytes skips the rule for content larger than this many bytes
	// (0 = no limit). MaxFileBytesExemptRegexes retain high-confidence
	// structural matches above the bound. This bounds weak heuristics by size
	// without making padding an escape from stronger branches.
	MaxFileBytes              int      `yaml:"max_file_bytes"`
	MaxFileBytesExemptRegexes []string `yaml:"max_file_bytes_exempt_regexes"`

	// Populated by compile().
	compiledRegexes                   []*compiledRegex
	compiledExcludeRegexes            []*compiledRegex
	compiledMaxFileBytesExemptRegexes []*compiledRegex
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
	loadErr  error
	// disabled holds the rule names the operator switched off, and
	// disabledUnmatched the subset that matched nothing in the loaded
	// ruleset. A name nobody recognises is almost always a typo, and a
	// typo here reads as "the rule is off" while it keeps firing.
	disabled          []string
	disabledUnmatched []string
	disabledCount     int
}

// NewScanner creates a scanner that loads rules from the given directory.
// Returns a scanner with no rules if the directory doesn't exist (not an error).
// Any load error is retained (see LoadError) so a best-effort init does not
// hide a corrupt rules directory that silently disabled all detection.
// Rule names in disabled are not loaded. This is the same operator setting
// that filters YARA-Forge downloads, applied to the rules CSM ships, so a
// misfiring signature can be switched off without editing rule files on a
// production host.
func NewScanner(rulesDir string, disabled ...string) *Scanner {
	s := &Scanner{rulesDir: rulesDir, disabled: normalizeDisabled(disabled)}
	s.disabledUnmatched = append([]string(nil), s.disabled...)
	_ = s.Reload() // best-effort load on init; error retained via LoadError()
	return s
}

// normalizeDisabled lowercases and de-duplicates the configured names, and
// drops empty entries. Rule names in the shipped files are lowercase, and an
// operator who types one in mixed case means the same rule.
func normalizeDisabled(names []string) []string {
	if len(names) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(names))
	out := make([]string, 0, len(names))
	for _, name := range names {
		trimmed := strings.ToLower(strings.TrimSpace(name))
		if trimmed == "" {
			continue
		}
		if _, dup := seen[trimmed]; dup {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

// DisabledRules returns the rule names this scanner was told to switch off.
func (s *Scanner) DisabledRules() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string(nil), s.disabled...)
}

// DisabledRulesWithoutMatch returns the configured names that matched no rule
// in the last load attempt. Config validation surfaces these: silently accepting
// a name nobody recognises is how an operator ends up believing a rule is off.
func (s *Scanner) DisabledRulesWithoutMatch() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string(nil), s.disabledUnmatched...)
}

// DisabledRuleCount counts rules omitted from the installed ruleset by config.
func (s *Scanner) DisabledRuleCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.disabledCount
}

// LoadError returns the error from the most recent Reload, or nil if the last
// load was clean. A non-nil value means at least one rule file failed to load
// (corrupt YAML, unreadable file, bad regex); the rules that did load are still
// installed. Callers that can alert should surface this loudly at startup.
func (s *Scanner) LoadError() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.loadErr
}

// Reload loads/reloads all .yml and .yaml rule files from the rules directory.
func (s *Scanner) Reload() error {
	if s.rulesDir == "" {
		s.setLoadErr(nil)
		return nil
	}

	entries, err := os.ReadDir(s.rulesDir)
	if err != nil {
		if os.IsNotExist(err) {
			s.setLoadErr(nil)
			return nil // no rules dir = no rules, not an error
		}
		e := fmt.Errorf("reading rules dir %s: %w", s.rulesDir, err)
		s.setLoadErr(e)
		return e
	}

	var allRules []Rule
	maxVersion := 0
	fileCount := 0
	disabledCount := 0
	disabled := make(map[string]struct{}, len(s.disabled))
	for _, name := range s.disabled {
		disabled[name] = struct{}{}
	}
	disabledSeen := make(map[string]struct{}, len(disabled))
	shared := make(map[string]*compiledRegex)
	// One corrupt or unreadable file must not abort the whole load: an
	// attacker or a fat-fingered operator dropping one bad file would
	// otherwise silently disable every other signature. Bad files/rules are
	// skipped and logged; their errors are aggregated and returned so a
	// caller that can alert still sees the failure.
	var loadErrs []error

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(name))
		if ext != ".yml" && ext != ".yaml" {
			continue
		}
		fileCount++

		path := filepath.Join(s.rulesDir, name)
		// #nosec G304 -- filepath.Join under operator-configured rulesDir.
		data, err := os.ReadFile(path)
		if err != nil {
			loadErrs = append(loadErrs, fmt.Errorf("reading %s: %w", path, err))
			fmt.Fprintf(os.Stderr, "signatures: skipping %s: %v\n", path, err)
			continue
		}

		var rf RuleFile
		if err := yaml.Unmarshal(data, &rf); err != nil {
			loadErrs = append(loadErrs, fmt.Errorf("parsing %s: %w", path, err))
			fmt.Fprintf(os.Stderr, "signatures: skipping %s: %v\n", path, err)
			continue
		}

		// Compile rules
		rulesBeforeFile := len(allRules)
		for i := range rf.Rules {
			rule := &rf.Rules[i]
			if _, off := disabled[strings.ToLower(rule.Name)]; off {
				disabledSeen[strings.ToLower(rule.Name)] = struct{}{}
				disabledCount++
				continue
			}
			if err := rule.compileShared(shared); err != nil {
				loadErrs = append(loadErrs, fmt.Errorf("compiling rule %q in %s: %w", rule.Name, path, err))
				fmt.Fprintf(os.Stderr, "signatures: skipping rule %q in %s: %v\n", rule.Name, path, err)
				continue
			}
			if rule.MinMatch == 0 {
				rule.MinMatch = 1
			}
			allRules = append(allRules, *rule)
		}
		if len(allRules) > rulesBeforeFile && rf.Version > maxVersion {
			maxVersion = rf.Version
		}
	}

	if fileCount == 0 {
		s.mu.RLock()
		hadRules := len(s.rules) > 0
		s.mu.RUnlock()
		if hadRules {
			e := fmt.Errorf("no signature rule files found in %s", s.rulesDir)
			s.setLoadErr(e)
			return e
		}
		s.setLoadErr(nil)
		return nil
	}

	var unmatched []string
	for _, name := range s.disabled {
		if _, seen := disabledSeen[name]; !seen {
			unmatched = append(unmatched, name)
		}
	}
	// Keep the old set on failure, but publish a clean load that config
	// intentionally emptied. Retaining old rules in that case scans a set
	// that is no longer on disk.
	if len(allRules) == 0 && (disabledCount == 0 || len(loadErrs) > 0) {
		err := errors.Join(append(loadErrs, fmt.Errorf("no signature rules loaded from %s", s.rulesDir))...)
		s.mu.Lock()
		s.loadErr = err
		s.disabledUnmatched = unmatched
		s.mu.Unlock()
		return err
	}

	s.mu.Lock()
	s.rules = allRules
	s.version = maxVersion
	s.loadErr = errors.Join(loadErrs...)
	s.disabledUnmatched = unmatched
	s.disabledCount = disabledCount
	s.mu.Unlock()

	if len(disabledSeen) > 0 {
		fmt.Fprintf(os.Stderr, "signatures: %d rule(s) disabled by configuration\n", len(disabledSeen))
	}

	fmt.Fprintf(os.Stderr, "signatures: loaded %d rules (version %d) from %s\n", len(allRules), maxVersion, s.rulesDir)

	// Rules installed, but report any skipped files so the caller can alert.
	return errors.Join(loadErrs...)
}

// setLoadErr records the outcome of a load under the write lock.
func (s *Scanner) setLoadErr(err error) {
	s.mu.Lock()
	s.loadErr = err
	s.mu.Unlock()
}

// compile pre-compiles regex patterns for a rule.
func (r *Rule) compile() error {
	return r.compileShared(make(map[string]*compiledRegex))
}

// compileShared compiles the rule, reusing a regex already compiled from the
// same source for an earlier rule in shared, so a scan evaluates it once.
func (r *Rule) compileShared(shared map[string]*compiledRegex) error {
	if r.MaxFileBytes < 0 {
		return fmt.Errorf("max_file_bytes must be non-negative")
	}
	var err error
	if r.compiledRegexes, err = compileRuleRegexes(shared, r.Regexes, "invalid regex"); err != nil {
		return err
	}
	if r.compiledExcludeRegexes, err = compileRuleRegexes(shared, r.ExcludeRegexes, "invalid exclude regex"); err != nil {
		return err
	}
	if r.compiledMaxFileBytesExemptRegexes, err = compileRuleRegexes(shared, r.MaxFileBytesExemptRegexes, "invalid max_file_bytes_exempt_regex"); err != nil {
		return err
	}
	return nil
}

func compileRuleRegexes(shared map[string]*compiledRegex, patterns []string, errLabel string) ([]*compiledRegex, error) {
	var out []*compiledRegex
	for _, pattern := range patterns {
		src := "(?i)" + pattern // rule regexes are case-insensitive
		cr, ok := shared[src]
		if !ok {
			re, err := regexp.Compile(src)
			if err != nil {
				return nil, fmt.Errorf("%s '%s': %w", errLabel, pattern, err)
			}
			cr = &compiledRegex{Regexp: re, gate: gateFor(src)}
			shared[src] = cr
		}
		out = append(out, cr)
	}
	return out, nil
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
	return s.ScanContentWithSize(content, fileExt, int64(len(content)))
}

// ScanContentWithSize scans content while using contentSize as the complete
// snapshot size for per-rule bounds. Prefix-scanning callers should pass the
// size of the open file represented by the prefix; ordinary callers should use
// ScanContent. A size smaller than the supplied bytes is raised to len(content)
// so a bad caller cannot turn a bounded rule back on for oversized content.
func (s *Scanner) ScanContentWithSize(content []byte, fileExt string, contentSize int64) []Match {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.rules) == 0 {
		return nil
	}
	extLower := strings.ToLower(fileExt)
	// Only a file that is an archive by name as well as by magic is left to the
	// extraction-time scan; PHP executes past any leading bytes, so magic alone
	// must never switch the rules off for an executable name.
	if contenttype.IsArchiveExt(extLower) && contenttype.IsCompressedArchive(content) {
		return nil
	}
	if contentSize < int64(len(content)) {
		contentSize = int64(len(content))
	}

	contentLower := strings.ToLower(string(content))
	eval := newRegexEval(content)
	var matches []Match

	for _, rule := range s.rules {
		// Check if this rule applies to this file type
		if !ruleMatchesExt(rule, extLower) {
			continue
		}

		// Check exclusions first - if any exclude pattern matches, skip this rule
		excluded := false
		for _, pattern := range rule.ExcludePatterns {
			if strings.Contains(contentLower, strings.ToLower(pattern)) {
				excluded = true
				break
			}
		}
		if !excluded {
			for _, re := range rule.compiledExcludeRegexes {
				if eval.match(re) {
					excluded = true
					break
				}
			}
		}
		if excluded {
			continue
		}

		if rule.MaxFileBytes > 0 && contentSize > int64(rule.MaxFileBytes) {
			exempt := false
			for _, re := range rule.compiledMaxFileBytesExemptRegexes {
				if eval.match(re) {
					exempt = true
					break
				}
			}
			if !exempt {
				continue
			}
		}

		// Count pattern matches
		var matched []string
		regexMatched := false

		for _, pattern := range rule.Patterns {
			if strings.Contains(contentLower, strings.ToLower(pattern)) {
				matched = append(matched, pattern)
			}
		}

		for _, re := range rule.compiledRegexes {
			if eval.match(re) {
				matched = append(matched, re.String())
				regexMatched = true
			}
		}

		if len(matched) >= rule.MinMatch && (!rule.RequireRegex || regexMatched) {
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

	if maxBytes <= 0 {
		return nil
	}

	// #nosec G304 -- ScanFile's whole purpose is to scan a file on disk;
	// `path` comes from the daemon's file index walker or a fanotify event.
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	// ReadAll over a LimitReader, not a single Read into a pre-sized buffer:
	// a bare f.Read can return a short count on the first call, which would
	// hand only a prefix to the scanner and silently miss malware further
	// into the file. LimitReader also makes a negative/huge maxBytes safe
	// (no make([]byte, maxBytes) panic / over-allocation).
	buf, err := io.ReadAll(io.LimitReader(f, int64(maxBytes)))
	if err != nil || len(buf) == 0 {
		return nil
	}

	contentSize := int64(len(buf))
	if info, statErr := f.Stat(); statErr == nil && info.Size() > contentSize {
		contentSize = info.Size()
	}
	ext := filepath.Ext(path)
	return s.ScanContentWithSize(buf, ext, contentSize)
}

// RuleNames returns the names of the loaded rules.
func (s *Scanner) RuleNames() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	names := make([]string, 0, len(s.rules))
	for _, r := range s.rules {
		names = append(names, r.Name)
	}
	return names
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

// canonicalScanExt folds extensions that carry PHP source but are not the
// extension rules are written against. Every extension a stock PHP handler
// executes (.phtml, .pht, .php5 ...) must meet the same rules as .php, and so
// must ".phps": it is PHP source by definition -- the extension exists so a
// server can display it -- so a payload staged under it is still matched.
// Without this fold such a file is read and then compared against nothing,
// because every PHP rule declares file_types [".php"].
func canonicalScanExt(ext string) string {
	ext = strings.ToLower(ext)
	if ext == ".phps" || contenttype.IsExecutablePHPExt(ext) {
		return ".php"
	}
	return ext
}

func ruleMatchesExt(rule Rule, ext string) bool {
	if len(rule.FileTypes) == 0 {
		return true // no filter = match all
	}
	ext = strings.ToLower(ext)
	canonicalExt := canonicalScanExt(ext)
	for _, ft := range rule.FileTypes {
		ft = strings.ToLower(ft)
		// The alias is one-way: PHP rules also inspect .phps source, while a
		// deliberately .phps-only rule must not broaden to executable .php.
		if ft == "*" || ft == ext || ft == canonicalExt {
			return true
		}
	}
	return false
}
