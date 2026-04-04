package daemon

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/pidginhost/cpanel-security-monitor/internal/alert"
)

// parseValiasFileForFindings parses a valiases file and returns findings.
// Used by both the realtime watcher and tests.
func parseValiasFileForFindings(path, domain string, localDomains map[string]bool, knownForwarders []string) []alert.Finding {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var findings []alert.Finding
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		idx := strings.IndexByte(line, ':')
		if idx < 0 {
			continue
		}
		localPart := strings.TrimSpace(line[:idx])
		dest := strings.TrimSpace(line[idx+1:])
		if localPart == "" || dest == "" {
			continue
		}

		dests := strings.Split(dest, ",")
		for _, d := range dests {
			d = strings.TrimSpace(d)
			if d == "" {
				continue
			}

			// Suppression check
			if isKnownForwarderWatcher(localPart, domain, d, knownForwarders) {
				continue
			}

			if strings.HasPrefix(d, "|") {
				findings = append(findings, alert.Finding{
					Severity: alert.Critical,
					Check:    "email_pipe_forwarder",
					Message:  fmt.Sprintf("Pipe forwarder detected: %s@%s -> %s", localPart, domain, d),
					Details:  fmt.Sprintf("Domain: %s\nLocal part: %s\nDestination: %s\nFile: %s", domain, localPart, d, path),
				})
				continue
			}

			if d == "/dev/null" {
				findings = append(findings, alert.Finding{
					Severity: alert.High,
					Check:    "email_suspicious_forwarder",
					Message:  fmt.Sprintf("Mail blackhole: %s@%s -> /dev/null", localPart, domain),
					Details:  fmt.Sprintf("Domain: %s\nLocal part: %s\nDestination: /dev/null\nFile: %s", domain, localPart, path),
				})
				continue
			}

			// Check if external
			atIdx := strings.LastIndexByte(d, '@')
			if atIdx >= 0 && atIdx < len(d)-1 {
				destDomain := strings.ToLower(d[atIdx+1:])
				if !localDomains[destDomain] {
					msg := fmt.Sprintf("External forwarder: %s@%s -> %s", localPart, domain, d)
					if localPart == "*" {
						msg = fmt.Sprintf("Wildcard catch-all to external: *@%s -> %s", domain, d)
					}
					findings = append(findings, alert.Finding{
						Severity: alert.High,
						Check:    "email_suspicious_forwarder",
						Message:  msg,
						Details:  fmt.Sprintf("Domain: %s\nLocal part: %s\nDestination: %s\nFile: %s", domain, localPart, d, path),
					})
				}
			}
		}
	}

	return findings
}

// isKnownForwarderWatcher checks if a forwarder matches the suppression list.
// Separate from checks package to avoid import cycles.
func isKnownForwarderWatcher(localPart, domain, dest string, knownForwarders []string) bool {
	entry := fmt.Sprintf("%s@%s: %s", localPart, domain, dest)
	for _, known := range knownForwarders {
		if strings.EqualFold(strings.TrimSpace(known), entry) {
			return true
		}
	}
	return false
}
