package checks

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/emailspool"
	"github.com/pidginhost/csm/internal/state"
)

const emailBodySampleSize = 65536 // Analyze the first 64KB of email body

// Suspicious mailer headers that indicate mass mailing scripts. PHPMailer is
// deliberately absent: it is the default WordPress transport and appears on
// essentially all legitimate WordPress mail, so it carries no signal. The
// "phpmail" substring is excluded for the same reason (it matches PHPMailer).
var suspiciousMailers = []string{
	"swiftmailer", "mass mailer", "bulk mailer",
	"leaf phpmailer", "mail.php",
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
	// Lower-cased raw bytes are still required for the base64-text/html
	// combination heuristic, which inspects MIME framing the emailspool
	// Headers struct does not surface.
	headersLower := strings.ToLower(string(headerData))

	// Check 1: Reply-To mismatch
	if parsed.From != "" && parsed.ReplyTo != "" {
		fromDomain := emailspool.ExtractDomain(parsed.From)
		replyDomain := emailspool.ExtractDomain(parsed.ReplyTo)
		if fromDomain != "" && replyDomain != "" && fromDomain != replyDomain {
			indicators = append(indicators, fmt.Sprintf("Reply-To mismatch: From=%s, Reply-To=%s", fromDomain, replyDomain))
		}
	}

	// Check 2: Suspicious X-Mailer (fall back to User-Agent, which the
	// emailspool parser surfaces alongside the other RFC 5322 fields).
	mailer := parsed.XMailer
	if mailer == "" {
		mailer = parsed.UserAgent
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

	// Read and analyze a bounded body sample.
	bodyData, _ := osFS.ReadFile(bodyPath)
	if len(bodyData) > emailBodySampleSize {
		bodyData = bodyData[:emailBodySampleSize]
	}
	if len(bodyData) > 0 {
		bodyLower := strings.ToLower(string(bodyData))
		indicators = append(indicators, bodyContentIndicators(bodyLower)...)

		// A base64 Content-Transfer-Encoding is standard MIME framing, not an
		// indicator by itself. Decode the body and run the same content checks
		// on the plaintext so a payload hidden behind base64 is caught -- the
		// raw base64 blob would otherwise sail past every text pattern.
		if hasBase64HTMLMIME(headersLower, bodyLower) {
			if decoded := decodeBase64Body(bodyData); decoded != "" {
				indicators = append(indicators, bodyContentIndicators(strings.ToLower(decoded))...)
			}
		}
	}

	indicators = uniqueStrings(indicators)

	// Require at least two independent indicators before alerting. A lone weak
	// signal (Reply-To mismatch, one brand word, one suspicious header) fires
	// on ordinary legitimate mail, so a single indicator is not enough.
	if len(indicators) < 2 {
		return nil
	}

	severity := alert.High
	if len(indicators) >= 3 {
		severity = alert.Critical
	}

	_, senderDomain := alert.SplitEmail(sender)
	return &alert.Finding{
		Severity: severity,
		Check:    "email_phishing_content",
		Message:  fmt.Sprintf("Suspicious outbound email from %s (message: %s)", sender, msgID),
		Details:  fmt.Sprintf("Indicators:\n- %s", strings.Join(indicators, "\n- ")),
		Domain:   senderDomain,
		Mailbox:  sender,
	}
}

func hasBase64HTMLMIME(headersLower, bodyLower string) bool {
	hasBase64 := strings.Contains(headersLower, "content-transfer-encoding: base64") ||
		strings.Contains(bodyLower, "content-transfer-encoding: base64")
	hasHTML := strings.Contains(headersLower, "text/html") ||
		strings.Contains(bodyLower, "text/html")
	return hasBase64 && hasHTML
}

// bodyContentIndicators runs the phishing-URL and credential-harvesting content
// checks over an already-lowercased body text. Shared by the raw-body pass and
// the decoded-base64 pass so both apply identical logic.
func bodyContentIndicators(bodyLower string) []string {
	var indicators []string

	for _, pattern := range emailPhishPatterns {
		if strings.Contains(bodyLower, pattern) {
			indicators = append(indicators, fmt.Sprintf("phishing URL pattern: %s", pattern))
			break
		}
	}

	harvestCount := 0
	for _, phrase := range emailPhishLanguage {
		if strings.Contains(bodyLower, phrase) {
			harvestCount++
		}
	}
	if harvestCount >= 2 {
		indicators = append(indicators, fmt.Sprintf("credential harvesting language (%d phrases)", harvestCount))
	}

	return indicators
}

// base64BodyLineRe matches a single line that is entirely standard-base64 (with
// optional trailing padding). MIME wraps base64 bodies at 76 columns, so the
// payload spans many such lines; envelope preamble, MIME boundary markers, and
// the "<msgID>-D" spool marker contain characters outside this set and are
// skipped.
var base64BodyLineRe = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)

// decodeBase64Body extracts every run of consecutive base64 lines from a spool
// body sample and decodes each valid run. Multipart messages can put a larger
// benign image part before a shorter phishing HTML part; decoding only the
// longest run misses that payload. A sample may clip the final blob mid-run, so
// the trailing partial group is dropped to keep the remaining prefix decodable.
func decodeBase64Body(raw []byte) string {
	var decodedParts []string
	var cur []string
	flush := func() {
		if len(cur) == 0 {
			return
		}
		blob := strings.Join(cur, "")
		if rem := len(blob) % 4; rem != 0 {
			blob = blob[:len(blob)-rem]
		}
		if blob != "" {
			if decoded, err := base64.StdEncoding.DecodeString(blob); err == nil {
				decodedParts = append(decodedParts, string(decoded))
			}
		}
		cur = nil
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && base64BodyLineRe.MatchString(line) {
			cur = append(cur, line)
			continue
		}
		flush()
	}
	flush()
	if len(decodedParts) == 0 {
		return ""
	}
	return strings.Join(decodedParts, "\n")
}
