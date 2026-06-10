package checks

import (
	"bufio"
	"context"
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/store"
)

// parseValiasLine parses a valiases line "local_part: destination".
// Returns empty strings for comments, blank lines, or malformed lines.
func parseValiasLine(line string) (localPart, dest string) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", ""
	}
	idx := strings.IndexByte(line, ':')
	if idx < 0 {
		return "", ""
	}
	localPart = strings.TrimSpace(line[:idx])
	dest = strings.TrimSpace(line[idx+1:])
	return localPart, dest
}

// isPipeForwarder returns true if the destination is a pipe forwarder,
// excluding known-safe cPanel built-in pipes (autoresponder, BoxTrapper).
func isPipeForwarder(dest string) bool {
	if !strings.HasPrefix(dest, "|") {
		return false
	}
	safe := []string{
		"/usr/local/cpanel/bin/autorespond",
		"/usr/local/cpanel/bin/boxtrapper",
		"/usr/local/cpanel/bin/mailman",
	}
	for _, s := range safe {
		if strings.Contains(dest, s) {
			return false
		}
	}
	return true
}

// isDevNullForwarder returns true if the destination is /dev/null.
func isDevNullForwarder(dest string) bool {
	return dest == "/dev/null"
}

// isExternalDest returns true if the destination is an email address
// with a domain not in the local domains set.
func isExternalDest(dest string, localDomains map[string]bool) bool {
	atIdx := strings.LastIndexByte(dest, '@')
	if atIdx < 0 || atIdx >= len(dest)-1 {
		return false
	}
	domain := strings.ToLower(dest[atIdx+1:])
	return !localDomains[domain]
}

// parseVfilterExternalDests extracts external email destinations from vfilter content.
// Looks for `to "dest@domain"` directives.
func parseVfilterExternalDests(content string, localDomains map[string]bool) []string {
	var external []string
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Look for: to "email@domain"
		if !strings.HasPrefix(line, "to ") && !strings.HasPrefix(line, "to\t") {
			continue
		}
		// Extract the quoted destination
		quoteStart := strings.IndexByte(line, '"')
		if quoteStart < 0 {
			continue
		}
		rest := line[quoteStart+1:]
		quoteEnd := strings.IndexByte(rest, '"')
		if quoteEnd < 0 {
			continue
		}
		dest := rest[:quoteEnd]
		if isExternalDest(dest, localDomains) {
			external = append(external, dest)
		}
	}
	return external
}

// parseLocalDomainsContent parses the content of /etc/localdomains or /etc/virtualdomains.
func parseLocalDomainsContent(content string) map[string]bool {
	domains := make(map[string]bool)
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// virtualdomains format: "domain: user" - take domain part
		if idx := strings.IndexByte(line, ':'); idx > 0 {
			line = strings.TrimSpace(line[:idx])
		}
		domains[strings.ToLower(line)] = true
	}
	return domains
}

// loadLocalDomains reads /etc/localdomains and /etc/virtualdomains.
func loadLocalDomains() map[string]bool {
	domains := make(map[string]bool)
	for _, path := range []string{"/etc/localdomains", "/etc/virtualdomains"} {
		data, err := osFS.ReadFile(path)
		if err != nil {
			continue
		}
		for k, v := range parseLocalDomainsContent(string(data)) {
			domains[k] = v
		}
	}
	return domains
}

// isKnownForwarder checks if a forwarder rule matches the known forwarders suppression list.
func isKnownForwarder(localPart, domain, dest string, knownForwarders []string) bool {
	entry := fmt.Sprintf("%s@%s: %s", localPart, domain, dest)
	for _, known := range knownForwarders {
		if strings.EqualFold(strings.TrimSpace(known), entry) {
			return true
		}
	}
	return false
}

// fileContentHash returns the SHA256 hex hash of a file's content.
func fileContentHash(path string) (string, error) {
	data, err := osFS.ReadFile(path)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h[:]), nil
}

// CheckForwarders audits all valiases and vfilters files for dangerous forwarder
// patterns. Uses internal throttle: skips if last refresh was less than
// password_check_interval_min ago (reuses the same interval).
func CheckForwarders(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	if ctx == nil {
		ctx = context.Background()
	}
	db := store.Global()
	if db == nil {
		return nil
	}

	// Internal throttle (24h) - reuse PasswordCheckIntervalMin
	if !ForceAll {
		lastRefreshStr := db.GetMetaString("email:fwd_last_refresh")
		if lastRefreshStr != "" {
			if lastRefresh, err := time.Parse(time.RFC3339, lastRefreshStr); err == nil {
				interval := time.Duration(cfg.EmailProtection.PasswordCheckIntervalMin) * time.Minute
				if time.Since(lastRefresh) < interval {
					return nil
				}
			}
		}
	}
	if ctx.Err() != nil {
		return nil
	}

	localDomains := loadLocalDomains()
	var findings []alert.Finding

	// Audit valiases. Rank by mtime desc so recently-changed mail
	// domains process first when the check timeout cuts iteration short.
	if ctx.Err() != nil {
		return findings
	}
	maxFiles := effectiveAccountScanMaxFiles(cfg)
	baselineComplete := true
	valiasFiles, err := osFS.Glob("/etc/valiases/*")
	if err != nil {
		baselineComplete = false
	}
	baselineComplete = baselineComplete && scanCoversAllFiles(valiasFiles, maxFiles)
	rankedValiasFiles := rankPathsByMtimeDesc(ctx, valiasFiles, maxFiles)
	if ctx.Err() != nil {
		return findings
	}
	for _, path := range rankedValiasFiles {
		if ctx.Err() != nil {
			return findings
		}
		domain := filepath.Base(path)
		entries, ok := auditValiasFileWithStatus(path, domain, localDomains, cfg)
		if !ok {
			baselineComplete = false
		}
		findings = append(findings, entries...)
	}

	// Audit vfilters
	if ctx.Err() != nil {
		return findings
	}
	vfilterFiles, err := osFS.Glob("/etc/vfilters/*")
	if err != nil {
		baselineComplete = false
	}
	baselineComplete = baselineComplete && scanCoversAllFiles(vfilterFiles, maxFiles)
	rankedVfilterFiles := rankPathsByMtimeDesc(ctx, vfilterFiles, maxFiles)
	if ctx.Err() != nil {
		return findings
	}
	for _, path := range rankedVfilterFiles {
		if ctx.Err() != nil {
			return findings
		}
		domain := filepath.Base(path)
		entries, ok := auditVfilterFileWithStatus(path, domain, localDomains, cfg)
		if !ok {
			baselineComplete = false
		}
		findings = append(findings, entries...)
	}

	if ctx.Err() != nil {
		return findings
	}
	baselineExists := db.GetMetaString("email:fwd_last_refresh") != ""
	if baselineComplete || baselineExists {
		_ = db.SetMetaString("email:fwd_last_refresh", time.Now().Format(time.RFC3339))
	}

	return findings
}

// forwarderFileIsNew reports whether a forwarder/filter file should be
// treated as newly added. A stored hash that differs means the file changed.
// No stored hash means one of two things: before the first complete audit
// (no baseline marker) it is pre-existing install backlog and stays quiet;
// after the baseline it genuinely appeared post-audit -- the classic BEC
// drop the first-sight suppression used to silence forever, because the
// next scan saw an unchanged hash.
func forwarderFileIsNew(db *store.DB, baselineKey, hashKey, currentHash string) bool {
	old, found := db.GetForwarderHash(hashKey)
	if found {
		return old != currentHash
	}
	return db.GetMetaString(baselineKey) != ""
}

func scanCoversAllFiles(paths []string, maxFiles int) bool {
	return maxFiles <= 0 || len(paths) <= maxFiles
}

// auditValiasFile parses a valiases file and returns findings for dangerous entries.
func auditValiasFile(path, domain string, localDomains map[string]bool, cfg *config.Config) []alert.Finding {
	findings, _ := auditValiasFileWithStatus(path, domain, localDomains, cfg)
	return findings
}

func auditValiasFileWithStatus(path, domain string, localDomains map[string]bool, cfg *config.Config) ([]alert.Finding, bool) {
	f, err := osFS.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()

	db := store.Global()
	var findings []alert.Finding
	complete := true

	isNew := false
	hashKey := "valiases:" + domain
	var currentHash string
	if db != nil {
		var hashErr error
		currentHash, hashErr = fileContentHash(path)
		if hashErr == nil {
			isNew = forwarderFileIsNew(db, "email:fwd_last_refresh", hashKey, currentHash)
		} else {
			complete = false
		}
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		localPart, dest := parseValiasLine(scanner.Text())
		if localPart == "" || dest == "" {
			continue
		}

		// Check each destination (may be comma-separated)
		dests := strings.Split(dest, ",")
		for _, d := range dests {
			d = strings.TrimSpace(d)
			if d == "" {
				continue
			}

			// Suppression check
			if isKnownForwarder(localPart, domain, d, cfg.EmailProtection.KnownForwarders) {
				continue
			}

			newContext := ""
			if isNew {
				newContext = " (newly added)"
			}

			if isPipeForwarder(d) {
				findings = append(findings, alert.Finding{
					Severity: alert.Critical,
					Check:    "email_pipe_forwarder",
					Message:  fmt.Sprintf("Pipe forwarder detected: %s@%s -> %s%s", localPart, domain, d, newContext),
					Details:  fmt.Sprintf("Domain: %s\nLocal part: %s\nDestination: %s\nFile: %s\nPipe forwarders execute arbitrary commands on incoming mail.", domain, localPart, d, path),
				})
				continue
			}

			if isDevNullForwarder(d) {
				findings = append(findings, alert.Finding{
					Severity: alert.High,
					Check:    "email_suspicious_forwarder",
					Message:  fmt.Sprintf("Mail blackhole: %s@%s -> /dev/null%s", localPart, domain, newContext),
					Details:  fmt.Sprintf("Domain: %s\nLocal part: %s\nDestination: /dev/null\nFile: %s\nAll mail to this address is silently discarded.", domain, localPart, path),
				})
				continue
			}

			if isExternalDest(d, localDomains) && isNew {
				severity := alert.High
				msg := fmt.Sprintf("External forwarder: %s@%s -> %s%s", localPart, domain, d, newContext)
				if localPart == "*" {
					msg = fmt.Sprintf("Wildcard catch-all to external: *@%s -> %s%s", domain, d, newContext)
				}
				findings = append(findings, alert.Finding{
					Severity: severity,
					Check:    "email_suspicious_forwarder",
					Message:  msg,
					Details:  fmt.Sprintf("Domain: %s\nLocal part: %s\nDestination: %s\nFile: %s", domain, localPart, d, path),
				})
			}
		}
	}

	if err := scanner.Err(); err != nil {
		complete = false
	}
	if complete && db != nil {
		if err := db.SetForwarderHash(hashKey, currentHash); err != nil {
			complete = false
		}
	}

	return findings, complete
}

// auditVfilterFile parses a vfilters file and returns findings for external destinations.
func auditVfilterFile(path, domain string, localDomains map[string]bool, cfg *config.Config) []alert.Finding {
	findings, _ := auditVfilterFileWithStatus(path, domain, localDomains, cfg)
	return findings
}

func auditVfilterFileWithStatus(path, domain string, localDomains map[string]bool, cfg *config.Config) ([]alert.Finding, bool) {
	data, err := osFS.ReadFile(path)
	if err != nil {
		return nil, false
	}

	db := store.Global()
	content := string(data)
	complete := true

	// Same newness logic as valiases above.
	isNew := false
	if db != nil {
		currentHash := fmt.Sprintf("%x", sha256.Sum256(data))
		isNew = forwarderFileIsNew(db, "email:fwd_last_refresh", "vfilters:"+domain, currentHash)
		if err := db.SetForwarderHash("vfilters:"+domain, currentHash); err != nil {
			complete = false
		}
	}

	externalDests := parseVfilterExternalDests(content, localDomains)
	var findings []alert.Finding

	for _, dest := range externalDests {
		// Suppression check - use "*" as localPart for vfilter entries
		if isKnownForwarder("*", domain, dest, cfg.EmailProtection.KnownForwarders) {
			continue
		}

		// Only alert when the vfilter file actually changed; existing forwarders
		// are normal customer configuration, not an attack indicator.
		if !isNew {
			continue
		}

		findings = append(findings, alert.Finding{
			Severity: alert.High,
			Check:    "email_suspicious_forwarder",
			Message:  fmt.Sprintf("External destination in vfilter: %s -> %s (newly added)", domain, dest),
			Details:  fmt.Sprintf("Domain: %s\nDestination: %s\nFile: %s\nA mail filter rule forwards messages to an external address.", domain, dest, path),
		})
	}

	return findings, complete
}
