package daemon

import (
	"fmt"
	"os"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/checks"
)

// parseValiasFileForFindings parses a valiases file and returns findings.
// Used by both the realtime watcher and tests.
func parseValiasFileForFindings(path, domain string, localDomains map[string]bool, knownForwarders []string) []alert.Finding {
	return parseValiasFileForFindingsFiltered(path, domain, localDomains, knownForwarders, true)
}

func parseValiasFileForFindingsFiltered(path, domain string, localDomains map[string]bool, knownForwarders []string, includeExternal bool) []alert.Finding {
	// #nosec G304 -- path from cPanel valiases directory walk; operator-scoped.
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	// A read error mid-file still reports the entries parsed before it.
	entries, _ := checks.ParseValiasEntries(f, domain)

	var findings []alert.Finding
	for _, e := range entries {
		localPart, mailDomain, d := e.LocalPart, e.Domain, e.Dest

		if checks.IsKnownForwarder(localPart, mailDomain, d, knownForwarders) {
			continue
		}

		if checks.IsPipeForwarder(d) {
			findings = append(findings, alert.Finding{
				Severity: alert.Critical,
				Check:    "email_pipe_forwarder",
				Message:  fmt.Sprintf("Pipe forwarder detected: %s@%s -> %s", localPart, mailDomain, d),
				Details:  fmt.Sprintf("Domain: %s\nLocal part: %s\nDestination: %s\nFile: %s", mailDomain, localPart, d, path),
			})
			continue
		}

		if d == "/dev/null" {
			findings = append(findings, alert.Finding{
				Severity: alert.High,
				Check:    "email_suspicious_forwarder",
				Message:  fmt.Sprintf("Mail blackhole: %s@%s -> /dev/null", localPart, mailDomain),
				Details:  fmt.Sprintf("Domain: %s\nLocal part: %s\nDestination: /dev/null\nFile: %s", mailDomain, localPart, path),
			})
			continue
		}

		if includeExternal && checks.IsExternalDest(d, localDomains) {
			msg := fmt.Sprintf("External forwarder: %s@%s -> %s", localPart, mailDomain, d)
			if localPart == "*" {
				msg = fmt.Sprintf("Wildcard catch-all to external: *@%s -> %s", mailDomain, d)
			}
			findings = append(findings, alert.Finding{
				Severity: alert.High,
				Check:    "email_suspicious_forwarder",
				Message:  msg,
				Details:  fmt.Sprintf("Domain: %s\nLocal part: %s\nDestination: %s\nFile: %s", mailDomain, localPart, d, path),
			})
		}
	}

	return findings
}
