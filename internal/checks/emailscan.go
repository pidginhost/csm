package checks

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/emailspool"
	"github.com/pidginhost/csm/internal/state"
)

const emailBodySampleSize = 4096 // Read first 4KB of email body

// Suspicious mailer headers that indicate mass mailing scripts.
var suspiciousMailers = []string{
	"phpmailer", "swiftmailer", "mass mailer", "bulk mailer",
	"leaf phpmailer", "phpmail", "mail.php",
}

// Known safe mailers that should not be flagged.
var safeMailers = []string{
	"wordpress", "woocommerce", "roundcube", "squirrelmail",
	"thunderbird", "outlook", "apple mail", "cpanel",
	"postfix", "exim", "dovecot",
}

// Phishing URL patterns in email body.
var emailPhishPatterns = []string{
	".workers.dev",
	"//bit.ly/", "//tinyurl.com/", "//is.gd/", "//rb.gy/",
	"//t.co/",
	"/redir?url=", "/redirect?url=", "link?url=",
	"effi.redir",
}

// Phishing language in email body.
var emailPhishLanguage = []string{
	"verify your account",
	"confirm your identity",
	"unusual activity",
	"your account will be",
	"suspended unless",
	"click here to verify",
	"update your payment",
	"confirm your email address",
	"security alert",
	"unauthorized access",
}

// Brand impersonation in email body (when sender doesn't match).
var emailBrandNames = []string{
	"paypal", "microsoft", "apple", "google", "amazon",
	"netflix", "facebook", "instagram", "bank of",
	"wells fargo", "chase", "citibank",
}

// CheckOutboundEmailContent samples outbound email content from Exim spool
// for phishing URLs, credential harvesting language, suspicious mailers,
// and Reply-To mismatches.
func CheckOutboundEmailContent(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
	var findings []alert.Finding

	// Read recent outbound messages from exim_mainlog
	lines := tailFile("/var/log/exim_mainlog", 200)
	if len(lines) == 0 {
		return nil
	}

	// Extract message IDs for outbound emails
	msgIDRegex := regexp.MustCompile(`^\S+\s+(\S+)\s+<=\s+(\S+)`)
	scanned := make(map[string]bool) // avoid scanning same message twice

	for _, line := range lines {
		matches := msgIDRegex.FindStringSubmatch(line)
		if len(matches) < 3 {
			continue
		}
		msgID := matches[1]
		sender := matches[2]

		if sender == "<>" || sender == "" {
			continue // bounce message
		}
		if scanned[msgID] {
			continue
		}
		scanned[msgID] = true

		// Scan the message
		result := scanEximMessage(msgID, sender, cfg)
		if result != nil {
			findings = append(findings, *result)
		}
	}

	return findings
}

// scanEximMessage reads an Exim spool message and checks for suspicious content.
func scanEximMessage(msgID, sender string, cfg *config.Config) *alert.Finding {
	// Exim spool paths
	// Headers: /var/spool/exim/input/{msgID}-H
	// Body: /var/spool/exim/input/{msgID}-D
	spoolDirs := []string{
		"/var/spool/exim/input",
		"/var/spool/exim4/input",
	}

	var headerPath, bodyPath string
	for _, dir := range spoolDirs {
		h := filepath.Join(dir, msgID+"-H")
		b := filepath.Join(dir, msgID+"-D")
		if _, err := osFS.Stat(h); err == nil {
			headerPath = h
			bodyPath = b
			break
		}
	}

	if headerPath == "" {
		return nil // message already delivered/removed from spool
	}

	var indicators []string

	// Read and parse headers via the emailspool Exim -H parser. We go through
	// osFS.ReadFile + bytes.NewReader rather than emailspool.ParseHeaders(path)
	// so check tests can inject mock spool contents through the existing
	// osFS seam.
	headerData, err := osFS.ReadFile(headerPath)
	if err != nil {
		return nil
	}
	parsed, err := emailspool.ParseHeadersReader(bytes.NewReader(headerData))
	if err != nil {
		// Malformed or truncated -H file: nothing to check, skip silently as
		// the previous loose parse would have done.
		return nil
	}
	// Lower-cased raw bytes are still required for two heuristics that the
	// emailspool Headers struct does not surface: User-Agent (X-Mailer
	// fallback) and the base64-text/html combination.
	headersLower := strings.ToLower(string(headerData))

	// Check 1: Reply-To mismatch
	if parsed.From != "" && parsed.ReplyTo != "" {
		fromDomain := emailspool.ExtractDomain(parsed.From)
		replyDomain := emailspool.ExtractDomain(parsed.ReplyTo)
		if fromDomain != "" && replyDomain != "" && fromDomain != replyDomain {
			indicators = append(indicators, fmt.Sprintf("Reply-To mismatch: From=%s, Reply-To=%s", fromDomain, replyDomain))
		}
	}

	// Check 2: Suspicious X-Mailer (fall back to User-Agent header captured
	// in the raw bytes -- emailspool.Headers does not surface User-Agent).
	mailer := parsed.XMailer
	if mailer == "" {
		mailer = scanRawHeader(headerData, "User-Agent")
	}
	if mailer != "" {
		mailerLower := strings.ToLower(mailer)
		isSafe := false
		for _, safe := range safeMailers {
			if strings.Contains(mailerLower, safe) {
				isSafe = true
				break
			}
		}
		if !isSafe {
			for _, suspicious := range suspiciousMailers {
				if strings.Contains(mailerLower, suspicious) {
					indicators = append(indicators, fmt.Sprintf("suspicious mailer: %s", strings.TrimSpace(mailer)))
					break
				}
			}
		}
	}

	// Check 3: Spoofed display name (brand name in From: but sender is not that brand)
	if parsed.From != "" {
		fromLower := strings.ToLower(parsed.From)
		senderDomain := emailspool.ExtractDomain(sender)
		for _, brand := range emailBrandNames {
			if strings.Contains(fromLower, brand) && !strings.Contains(strings.ToLower(senderDomain), brand) {
				indicators = append(indicators, fmt.Sprintf("spoofed brand in From: '%s' (actual sender: %s)", strings.TrimSpace(parsed.From), sender))
				break
			}
		}
	}

	// Read and analyze body (sample first 4KB)
	bodyData, _ := osFS.ReadFile(bodyPath)
	if len(bodyData) > emailBodySampleSize {
		bodyData = bodyData[:emailBodySampleSize]
	}
	if len(bodyData) > 0 {
		bodyLower := strings.ToLower(string(bodyData))

		// Check 4: Phishing URLs in body
		for _, pattern := range emailPhishPatterns {
			if strings.Contains(bodyLower, pattern) {
				indicators = append(indicators, fmt.Sprintf("phishing URL pattern: %s", pattern))
				break
			}
		}

		// Check 5: Credential harvesting language
		harvestCount := 0
		for _, phrase := range emailPhishLanguage {
			if strings.Contains(bodyLower, phrase) {
				harvestCount++
			}
		}
		if harvestCount >= 2 {
			indicators = append(indicators, fmt.Sprintf("credential harvesting language (%d phrases)", harvestCount))
		}

		// Check 6: Base64-encoded HTML body (used to bypass filters)
		if strings.Contains(headersLower, "content-transfer-encoding: base64") &&
			strings.Contains(headersLower, "text/html") {
			// Check if decoded content has phishing patterns
			indicators = append(indicators, "base64-encoded HTML body (potential filter bypass)")
		}
	}

	if len(indicators) == 0 {
		return nil
	}

	severity := alert.High
	if len(indicators) >= 3 {
		severity = alert.Critical
	}

	return &alert.Finding{
		Severity: severity,
		Check:    "email_phishing_content",
		Message:  fmt.Sprintf("Suspicious outbound email from %s (message: %s)", sender, msgID),
		Details:  fmt.Sprintf("Indicators:\n- %s", strings.Join(indicators, "\n- ")),
	}
}

// scanRawHeader looks up a single RFC 5322 header value by name in raw Exim -H
// bytes. Used for headers that emailspool.Headers does not surface
// (e.g. User-Agent) on the cold path where we already have the buffer.
// Returns "" when the header is absent or malformed.
//
// The lookup is line-oriented and tolerates either bare RFC 5322
// ("Name: value") or Exim -H prefixed ("NNNX Name: value") shapes; the colon
// is required, and the name match is case-insensitive.
func scanRawHeader(data []byte, name string) string {
	target := strings.ToLower(name) + ":"
	for _, line := range strings.Split(string(data), "\n") {
		// Strip the optional 5-byte Exim -H prefix ("NNNX ") if present so
		// we can match either the bare RFC 5322 form or the spool form.
		stripped := line
		if len(line) >= 5 &&
			line[0] >= '0' && line[0] <= '9' &&
			line[1] >= '0' && line[1] <= '9' &&
			line[2] >= '0' && line[2] <= '9' &&
			line[4] == ' ' {
			stripped = line[5:]
		}
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(stripped)), target) {
			parts := strings.SplitN(stripped, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}
