package checks

import (
	"bufio"
	"context"
	"crypto/sha1" // #nosec G505 -- SHA1 is the digest format required by the Have I Been Pwned range API (https://haveibeenpwned.com/API/v3#PwnedPasswords). We send the first 5 chars of the digest and compare remaining chars against the returned list — HIBP does not offer a stronger-hash endpoint.
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
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

// hibpClient is used for HIBP API requests.
var hibpClient = &http.Client{Timeout: 10 * time.Second}

// hibpEndpoint is the base URL queried for HIBP password-range lookups.
// Declared as a var (not const) so tests can swap in an httptest server.
// Production callers must not modify this.
var hibpEndpoint = "https://api.pwnedpasswords.com/range/"

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
	return checkHIBPWithContext(context.Background(), plaintext)
}

func checkHIBPWithContext(ctx context.Context, plaintext string) int {
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return 0
	}
	// #nosec G401 -- SHA1 is mandated by the HIBP Pwned Passwords range API; see import comment.
	h := sha1.Sum([]byte(plaintext))
	hex := fmt.Sprintf("%X", h[:])
	prefix := hex[:5]
	suffix := hex[5:]

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, hibpEndpoint+prefix, nil)
	if err != nil {
		return 0
	}
	resp, err := hibpClient.Do(req)
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
// Results are ranked by mtime desc so recently touched mailbox password files
// are inspected first when the check timeout cuts work short. maxFiles caps
// iteration; 0 disables the cap.
func discoverShadowFiles(ctx context.Context, maxFiles int) []shadowFile {
	matches, _ := accountHomeGlob("*/etc/*/shadow")
	ranked := rankPathsByMtimeDesc(ctx, matches, maxFiles)
	results := make([]shadowFile, 0, len(ranked))
	for _, m := range ranked {
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
	f, err := osFS.Open(sf.path)
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
		f, err := osFS.Open("/opt/csm/configs/weak_passwords.txt")
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

// CheckEmailPasswords audits Dovecot email account passwords for weak/predictable
// patterns. Uses internal throttle: skips if last refresh was less than
// password_check_interval_min ago.
func CheckEmailPasswords(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	if ctx == nil {
		ctx = context.Background()
	}
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

	shadowFiles := discoverShadowFiles(ctx, accountScanMaxFiles(ctx, cfg))
	if len(shadowFiles) == 0 {
		return nil
	}

	// Collect all mailbox entries
	var allEntries []mailboxEntry
	for _, sf := range shadowFiles {
		if ctx.Err() != nil {
			return nil
		}
		allEntries = append(allEntries, readShadowFile(sf)...)
	}
	if ctx.Err() != nil {
		return nil
	}

	if len(allEntries) == 0 {
		_ = db.SetEmailPWLastRefresh(time.Now())
		return nil
	}

	var mu sync.Mutex
	var findings []alert.Finding
	var incomplete int
	var wg sync.WaitGroup

	sem := make(chan struct{}, 5)
	batch := emailMailboxAudits.begin(len(allEntries), cap(sem))
	defer batch.abandon(ctx)
mailboxes:
	for i, entry := range allEntries {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			break mailboxes
		}
		work := batch.tasks[i]
		work.admit()
		wg.Go(func() {
			defer func() { <-sem }()
			work.run(ctx, checkTimeout, func() {
				if ctx.Err() != nil {
					return
				}
				fullMailbox := entry.mailbox + "@" + entry.domain
				storeKey := fmt.Sprintf("email:pwaudit:%s:%s", entry.account, fullMailbox)
				// Older versions also cached failed verifications as clean.
				fp := "v2:" + hashFingerprint(entry.hash)
				if db.GetMetaString(storeKey) == fp {
					return
				}

				finding, err := auditEmailPassword(ctx, entry)
				work.progress()
				if err != nil && !errors.Is(err, context.Canceled) &&
					!errors.Is(err, errEmailHashUnsupported) && !errors.Is(err, errEmailHashInvalid) &&
					!errors.Is(err, errEmailHashCost) && !errors.Is(err, errEmailCandidate) {
					work.fail()
				}
				mu.Lock()
				if err != nil {
					incomplete++
				} else if finding != nil {
					findings = append(findings, *finding)
				}
				mu.Unlock()
				if err != nil || ctx.Err() != nil {
					return
				}
				if err := db.SetMetaString(storeKey, fp); err != nil {
					work.fail()
				}
			})
		})
	}
	batch.abandon(ctx)
	wg.Wait()
	if incomplete > 0 || ctx.Err() != nil {
		markCheckIncomplete(ctx, "email_weak_password")
		findings = append(findings, alert.Finding{
			Severity: alert.Warning,
			Check:    "email_password_audit_incomplete",
			Message:  "Email password audit did not complete",
			Details:  fmt.Sprintf("Mailboxes with an unfinished verification: %d. Unsupported, malformed, or over-budget hashes remain unaudited and are retried. See the email password audit documentation for supported formats and limits.", incomplete),
		})
		return findings
	}
	_ = db.SetEmailPWLastRefresh(time.Now())
	return findings
}

func auditEmailPassword(ctx context.Context, entry mailboxEntry) (*alert.Finding, error) {
	verifier, err := parseEmailPasswordHash(entry.hash)
	if err != nil {
		return nil, err
	}
	matched, err := verifier.firstMatch(ctx, generateCandidates(entry.mailbox, entry.domain))
	if err != nil {
		return nil, err
	}
	matchType := "heuristic"
	if matched == "" {
		matched, err = verifier.firstMatch(ctx, loadWeakPasswords())
		if err != nil {
			return nil, err
		}
		matchType = "wordlist"
	}
	if matched == "" {
		return nil, nil
	}

	fullMailbox := entry.mailbox + "@" + entry.domain
	details := fmt.Sprintf("Account: %s\nMailbox: %s\nMatch type: %s", entry.account, fullMailbox, matchType)
	if breachCount := checkHIBPWithContext(ctx, matched); breachCount > 0 {
		details += fmt.Sprintf("\nHIBP: password found in %d data breaches", breachCount)
	}
	return &alert.Finding{
		Severity: alert.Critical,
		Check:    "email_weak_password",
		Message:  fmt.Sprintf("Weak email password for %s (account: %s)", fullMailbox, entry.account),
		Details:  details,
		Domain:   entry.domain,
		Mailbox:  fullMailbox,
	}, nil
}
