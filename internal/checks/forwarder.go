package checks

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"os"
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

// isPipeForwarder returns true if the destination is a pipe forwarder.
func isPipeForwarder(dest string) bool {
	return strings.HasPrefix(dest, "|")
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
		// virtualdomains format: "domain: user" — take domain part
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
		data, err := os.ReadFile(path)
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
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h[:]), nil
}

// CheckForwarders audits all valiases and vfilters files for dangerous forwarder
// patterns. Uses internal throttle: skips if last refresh was less than
// password_check_interval_min ago (reuses the same interval).
func CheckForwarders(cfg *config.Config, _ *state.Store) []alert.Finding {
	db := store.Global()
	if db == nil {
		return nil
	}

	// Internal throttle (24h) — reuse PasswordCheckIntervalMin
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

	localDomains := loadLocalDomains()
	var findings []alert.Finding

	// Audit valiases
	valiasFiles, _ := filepath.Glob("/etc/valiases/*")
	for _, path := range valiasFiles {
		domain := filepath.Base(path)
		entries := auditValiasFile(path, domain, localDomains, cfg)
		findings = append(findings, entries...)

		// Store hash for change detection (enrichment, not filtering)
		hash, err := fileContentHash(path)
		if err == nil {
			_ = db.SetForwarderHash("valiases:"+domain, hash)
		}
	}

	// Audit vfilters
	vfilterFiles, _ := filepath.Glob("/etc/vfilters/*")
	for _, path := range vfilterFiles {
		domain := filepath.Base(path)
		entries := auditVfilterFile(path, domain, localDomains, cfg)
		findings = append(findings, entries...)

		hash, err := fileContentHash(path)
		if err == nil {
			_ = db.SetForwarderHash("vfilters:"+domain, hash)
		}
	}

	_ = db.SetMetaString("email:fwd_last_refresh", time.Now().Format(time.RFC3339))

	return findings
}

// auditValiasFile parses a valiases file and returns findings for dangerous entries.
func auditValiasFile(path, domain string, localDomains map[string]bool, cfg *config.Config) []alert.Finding {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	db := store.Global()
	var findings []alert.Finding

	// Check if file hash changed (for "newly added" context)
	isNew := false
	if db != nil {
		currentHash, hashErr := fileContentHash(path)
		if hashErr == nil {
			oldHash, found := db.GetForwarderHash("valiases:" + domain)
			if !found || oldHash != currentHash {
				isNew = true
			}
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

			if isExternalDest(d, localDomains) {
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

	return findings
}

// auditVfilterFile parses a vfilters file and returns findings for external destinations.
func auditVfilterFile(path, domain string, localDomains map[string]bool, cfg *config.Config) []alert.Finding {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	db := store.Global()
	content := string(data)

	// Check if file hash changed
	isNew := false
	if db != nil {
		currentHash := fmt.Sprintf("%x", sha256.Sum256(data))
		oldHash, found := db.GetForwarderHash("vfilters:" + domain)
		if !found || oldHash != currentHash {
			isNew = true
		}
	}

	externalDests := parseVfilterExternalDests(content, localDomains)
	var findings []alert.Finding

	for _, dest := range externalDests {
		// Suppression check — use "*" as localPart for vfilter entries
		if isKnownForwarder("*", domain, dest, cfg.EmailProtection.KnownForwarders) {
			continue
		}

		newContext := ""
		if isNew {
			newContext = " (newly added)"
		}

		findings = append(findings, alert.Finding{
			Severity: alert.High,
			Check:    "email_suspicious_forwarder",
			Message:  fmt.Sprintf("External destination in vfilter: %s -> %s%s", domain, dest, newContext),
			Details:  fmt.Sprintf("Domain: %s\nDestination: %s\nFile: %s\nA mail filter rule forwards messages to an external address.", domain, dest, path),
		})
	}

	return findings
}
