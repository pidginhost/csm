package daemon

import (
	"fmt"
	"regexp"
	"strings"
)

// AccountExtractor pulls the account/mailbox identifier out of a mail
// server log line. Used by mailbrute for per-account scoring. Selected
// by cfg.Thresholds.MailBruteAccountKey at daemon startup.
type AccountExtractor struct {
	mode string
	re   *regexp.Regexp
}

// NewAccountExtractor parses the spec string from cfg.Thresholds.MailBruteAccountKey.
// Empty spec defaults to "builtin:dovecot-user" (matches the legacy behavior).
func NewAccountExtractor(spec string) (*AccountExtractor, error) {
	switch {
	case spec == "" || spec == "builtin:dovecot-user":
		return &AccountExtractor{mode: "dovecot-user"}, nil
	case spec == "builtin:postfix-sasl":
		return &AccountExtractor{mode: "postfix-sasl"}, nil
	case strings.HasPrefix(spec, "regex:"):
		re, err := regexp.Compile(strings.TrimPrefix(spec, "regex:"))
		if err != nil {
			return nil, fmt.Errorf("invalid regex: %w", err)
		}
		return &AccountExtractor{mode: "regex", re: re}, nil
	default:
		return nil, fmt.Errorf("unknown extractor spec: %s", spec)
	}
}

// Extract returns the account/mailbox key, or "" when no match.
func (e *AccountExtractor) Extract(line string) string {
	switch e.mode {
	case "dovecot-user":
		return extractAngleBracket(line, "user=")
	case "postfix-sasl":
		return extractEqualsValue(line, "sasl_username=")
	case "regex":
		m := e.re.FindStringSubmatch(line)
		if len(m) >= 2 {
			return m[1]
		}
	}
	return ""
}

// extractAngleBracket matches `key<value>` with balanced angle brackets.
func extractAngleBracket(line, key string) string {
	idx := strings.Index(line, key+"<")
	if idx < 0 {
		return ""
	}
	end := strings.IndexByte(line[idx+len(key)+1:], '>')
	if end < 0 {
		return ""
	}
	return line[idx+len(key)+1 : idx+len(key)+1+end]
}

// extractEqualsValue matches `key=<value>` where value is delimited by
// whitespace or comma (postfix log format).
func extractEqualsValue(line, key string) string {
	idx := strings.Index(line, key)
	if idx < 0 {
		return ""
	}
	rest := line[idx+len(key):]
	end := strings.IndexAny(rest, " ,\t\n")
	if end < 0 {
		return rest
	}
	return rest[:end]
}

// defaultAccountExtractor is the package-level singleton set at daemon startup.
var defaultAccountExtractor *AccountExtractor

// SetAccountExtractor installs the configured extractor; called from
// Daemon.Run() after applyDefaults has set the spec.
func SetAccountExtractor(ex *AccountExtractor) {
	defaultAccountExtractor = ex
}

// currentAccountExtractor returns the installed extractor, or lazily
// initializes the default so test code that doesn't call SetAccountExtractor
// gets the legacy dovecot-user behavior.
func currentAccountExtractor() *AccountExtractor {
	if defaultAccountExtractor == nil {
		ex, _ := NewAccountExtractor("")
		defaultAccountExtractor = ex
	}
	return defaultAccountExtractor
}
