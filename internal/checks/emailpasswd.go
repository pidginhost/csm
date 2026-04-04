package checks

import (
	"bufio"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
)

// doveadmSemaphore limits concurrent doveadm processes.
var doveadmSemaphore = make(chan struct{}, 3)

// hibpClient is used for HIBP API requests.
var hibpClient = &http.Client{Timeout: 10 * time.Second}

// currentYear returns the current year. Called each audit cycle so
// long-running daemons don't use a stale year after Jan 1.
func currentYear() int { return time.Now().Year() }

// weakPasswordCache caches the bundled wordlist (loaded once).
var (
	weakPasswordOnce sync.Once
	weakPasswords    []string
)

// parseShadowLine parses a Dovecot shadow line "mailbox:{scheme}hash".
// Returns empty strings if the line is malformed.
func parseShadowLine(line string) (mailbox, hash string) {
	idx := strings.IndexByte(line, ':')
	if idx <= 0 || idx >= len(line)-1 {
		return "", ""
	}
	return line[:idx], line[idx+1:]
}

// isLockedHash returns true if the hash indicates a locked/disabled account.
func isLockedHash(hash string) bool {
	if hash == "" {
		return true
	}
	return hash[0] == '!' || hash[0] == '*'
}

// generateCandidates creates password candidates from username and domain.
// All candidates are >= 6 characters. No duplicates.
func generateCandidates(username, domain string) []string {
	seen := make(map[string]bool)
	var candidates []string

	add := func(s string) {
		if len(s) >= 6 && !seen[s] {
			seen[s] = true
			candidates = append(candidates, s)
		}
	}

	domainLabel := domain
	if idx := strings.IndexByte(domain, '.'); idx > 0 {
		domainLabel = domain[:idx]
	}

	bases := []string{username, domainLabel}

	for _, base := range bases {
		add(base)

		// Capitalize first letter variant
		upper := capitalizeFirst(base)

		add(upper)

		// Year variants: current year +/- 2
		year := currentYear()
		for y := year - 2; y <= year+2; y++ {
			ys := strconv.Itoa(y)
			add(base + ys)
			add(upper + ys)
		}

		// Two-digit suffix variants: 00-99
		for n := 0; n <= 99; n++ {
			suffix := fmt.Sprintf("%02d", n)
			add(base + suffix)
			add(upper + suffix)
		}
	}

	return candidates
}

// capitalizeFirst returns the string with its first rune upper-cased.
func capitalizeFirst(s string) string {
	if len(s) == 0 {
		return s
	}
	runes := []rune(s)
	runes[0] = unicode.ToUpper(runes[0])
	return string(runes)
}

// verifyDoveadm checks a candidate password against a stored hash.
// Returns true if the password matches.
func verifyDoveadm(hash, candidate string) bool {
	doveadmSemaphore <- struct{}{}
	defer func() { <-doveadmSemaphore }()

	cmd := exec.Command("doveadm", "pw", "-t", hash, "-p", candidate)
	return cmd.Run() == nil
}

// hashFingerprint returns a SHA256 hex fingerprint of a password hash
// (used for change detection -- re-audit only when hash changes).
func hashFingerprint(hash string) string {
	h := sha256.Sum256([]byte(hash))
	return fmt.Sprintf("%x", h[:])
}

// parseHIBPCount searches a HIBP range response body for a hash suffix
// and returns the breach count. Returns 0 if not found.
func parseHIBPCount(body, suffix string) int {
	upperSuffix := strings.ToUpper(suffix)
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		if strings.ToUpper(strings.TrimSpace(parts[0])) == upperSuffix {
			count, err := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err != nil {
				return 0
			}
			return count
		}
	}
	return 0
}

// checkHIBP queries the HIBP Pwned Passwords API for a plaintext password.
// Returns the breach count (0 if not found or on error).
func checkHIBP(plaintext string) int {
	h := sha1.Sum([]byte(plaintext)) //nolint:gosec // SHA1 required by HIBP API
	hex := fmt.Sprintf("%X", h[:])
	prefix := hex[:5]
	suffix := hex[5:]

	resp, err := hibpClient.Get("https://api.pwnedpasswords.com/range/" + prefix) //nolint:noctx
	if err != nil {
		return 0
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0
	}

	return parseHIBPCount(string(body), suffix)
}

type shadowFile struct {
	path    string
	account string
	domain  string
}

type mailboxEntry struct {
	account string
	domain  string
	mailbox string
	hash    string
}

// discoverShadowFiles finds all Dovecot shadow files under /home/*/etc/*/shadow.
func discoverShadowFiles() []shadowFile {
	matches, _ := filepath.Glob("/home/*/etc/*/shadow")
	var results []shadowFile
	for _, m := range matches {
		parts := strings.Split(m, "/")
		// /home/{account}/etc/{domain}/shadow
		if len(parts) >= 5 {
			results = append(results, shadowFile{
				path:    m,
				account: parts[2],
				domain:  parts[4],
			})
		}
	}
	return results
}

// readShadowFile reads all mailbox entries from a Dovecot shadow file.
func readShadowFile(sf shadowFile) []mailboxEntry {
	f, err := os.Open(sf.path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var entries []mailboxEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		mailbox, hash := parseShadowLine(line)
		if mailbox == "" || hash == "" {
			continue
		}
		if isLockedHash(hash) {
			continue
		}
		entries = append(entries, mailboxEntry{
			account: sf.account,
			domain:  sf.domain,
			mailbox: mailbox,
			hash:    hash,
		})
	}
	return entries
}

// loadWeakPasswords reads the bundled wordlist once and caches it.
func loadWeakPasswords() []string {
	weakPasswordOnce.Do(func() {
		f, err := os.Open("/opt/csm/configs/weak_passwords.txt")
		if err != nil {
			return
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			word := strings.TrimSpace(scanner.Text())
			if len(word) < 6 || strings.HasPrefix(word, "#") {
				continue
			}
			weakPasswords = append(weakPasswords, word)
		}
	})
	return weakPasswords
}

// checkWordlist tests a hash against the bundled weak passwords list.
// Returns the matched password or empty string.
func checkWordlist(hash string) string {
	for _, word := range loadWeakPasswords() {
		if verifyDoveadm(hash, word) {
			return word
		}
	}
	return ""
}

// CheckEmailPasswords audits Dovecot email account passwords for weak/predictable
// patterns. Uses internal throttle: skips if last refresh was less than
// password_check_interval_min ago.
func CheckEmailPasswords(cfg *config.Config, _ *state.Store) []alert.Finding {
	db := store.Global()
	if db == nil {
		return nil
	}

	// Internal throttle -- same pattern as CheckOutdatedPlugins
	if !ForceAll {
		lastRefresh := db.GetEmailPWLastRefresh()
		interval := time.Duration(cfg.EmailProtection.PasswordCheckIntervalMin) * time.Minute
		if time.Since(lastRefresh) < interval {
			return nil
		}
	}

	shadowFiles := discoverShadowFiles()
	if len(shadowFiles) == 0 {
		return nil
	}

	// Collect all mailbox entries
	var allEntries []mailboxEntry
	for _, sf := range shadowFiles {
		allEntries = append(allEntries, readShadowFile(sf)...)
	}

	if len(allEntries) == 0 {
		_ = db.SetEmailPWLastRefresh(time.Now())
		return nil
	}

	var mu sync.Mutex
	var findings []alert.Finding
	var wg sync.WaitGroup

	// Process each mailbox concurrently (bounded by semaphore)
	sem := make(chan struct{}, 5)
	for _, entry := range allEntries {
		wg.Add(1)
		go func(e mailboxEntry) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			fullMailbox := e.mailbox + "@" + e.domain
			storeKey := fmt.Sprintf("email:pwaudit:%s:%s", e.account, fullMailbox)

			// Skip if hash hasn't changed since last audit
			fp := hashFingerprint(e.hash)
			if stored := db.GetMetaString(storeKey); stored == fp {
				return
			}

			// Layer 1: Heuristic candidates
			candidates := generateCandidates(e.mailbox, e.domain)
			var matched string
			var matchType string
			for _, c := range candidates {
				if verifyDoveadm(e.hash, c) {
					matched = c
					matchType = "heuristic"
					break
				}
			}

			// Layer 2: Common wordlist (skip if layer 1 matched)
			if matched == "" {
				if w := checkWordlist(e.hash); w != "" {
					matched = w
					matchType = "wordlist"
				}
			}

			if matched != "" {
				details := fmt.Sprintf("Account: %s\nMailbox: %s\nMatch type: %s\nMatched password pattern: %q",
					e.account, fullMailbox, matchType, matched)

				// Layer 3: HIBP enrichment (only for confirmed matches)
				breachCount := checkHIBP(matched)
				if breachCount > 0 {
					details += fmt.Sprintf("\nHIBP: password found in %d data breaches", breachCount)
				}

				mu.Lock()
				findings = append(findings, alert.Finding{
					Severity: alert.Critical,
					Check:    "email_weak_password",
					Message:  fmt.Sprintf("Weak email password for %s (account: %s)", fullMailbox, e.account),
					Details:  details,
				})
				mu.Unlock()
			}

			// Record fingerprint so we don't re-audit until hash changes
			_ = db.SetMetaString(storeKey, fp)
		}(entry)
	}

	wg.Wait()
	_ = db.SetEmailPWLastRefresh(time.Now())

	return findings
}
