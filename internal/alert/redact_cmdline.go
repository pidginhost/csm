package alert

import (
	"path"
	"strings"
	"unicode"
)

const redactedToken = "[REDACTED]"

// RedactCommandLine masks credential-bearing arguments in a command line
// (or any text quoting one): the MySQL family's attached -pSECRET, KEY=VALUE
// tokens whose key names a password, token, secret or API key (on options
// and on environment assignments alike), separated --password VALUE forms,
// curl-style user:password pairs, and URL userinfo or query credentials.
// Whitespace is preserved so the rest of the line stays readable.
func RedactCommandLine(s string) string {
	if s == "" {
		return s
	}
	tokens := splitTokens(s)
	if len(tokens) == 0 {
		return s
	}

	mysqlAt := -1
	sshpassAt := -1
	for i, tok := range tokens {
		base := strings.ToLower(path.Base(tok.text))
		if mysqlAt < 0 && mysqlFamily[base] {
			mysqlAt = i
		}
		if sshpassAt < 0 && base == "sshpass" {
			sshpassAt = i
		}
	}

	changed := false
	redactNext := false
	redactNextPair := false
	sshpassPending := false
	for i := range tokens {
		tok := &tokens[i]
		text := tok.text

		switch {
		case redactNext:
			redactNext = false
			if !strings.HasPrefix(text, "-") {
				tok.text = redactedToken
				changed = changed || tok.text != text
				continue
			}
		case redactNextPair:
			redactNextPair = false
			if !strings.HasPrefix(text, "-") {
				if r, ok := redactPair(text); ok {
					tok.text = r
					changed = true
					continue
				}
			}
		}

		if mysqlAt >= 0 && i > mysqlAt && len(text) > 2 && strings.HasPrefix(text, "-p") && text[2] != '-' {
			tok.text = "-p" + redactedToken
			changed = true
			continue
		}
		if sshpassAt >= 0 && i == sshpassAt {
			sshpassPending = true
		}
		if sshpassPending && i > sshpassAt && text == "-p" {
			sshpassPending = false
			redactNext = true
			continue
		}
		if separatedSecretFlags[strings.ToLower(text)] {
			redactNext = true
			continue
		}
		if separatedPairFlags[strings.ToLower(text)] {
			redactNextPair = true
			continue
		}
		if strings.Contains(text, "://") {
			if r := redactURLToken(text); r != text {
				tok.text = r
				changed = true
			}
			continue
		}
		if r, ok := redactAssignments(text); ok {
			tok.text = r
			changed = true
		}
	}
	if !changed {
		return s
	}

	var b strings.Builder
	b.Grow(len(s))
	last := 0
	for _, tok := range tokens {
		b.WriteString(s[last:tok.start])
		b.WriteString(tok.text)
		last = tok.end
	}
	b.WriteString(s[last:])
	return b.String()
}

type cmdToken struct {
	start, end int
	text       string
}

func splitTokens(s string) []cmdToken {
	var tokens []cmdToken
	start := -1
	for i, r := range s {
		if unicode.IsSpace(r) {
			if start >= 0 {
				tokens = append(tokens, cmdToken{start, i, s[start:i]})
				start = -1
			}
			continue
		}
		if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		tokens = append(tokens, cmdToken{start, len(s), s[start:]})
	}
	return tokens
}

var mysqlFamily = map[string]bool{
	"mysql": true, "mysqldump": true, "mysqladmin": true, "mysqlimport": true,
	"mysqlcheck": true, "mysqlshow": true, "mysqlbinlog": true, "mysqlpump": true,
	"mysqlslap": true, "mariadb": true, "mariadb-dump": true, "mariadb-admin": true,
	"mariadb-import": true, "mariadb-check": true, "mariadb-show": true,
	"mariadb-binlog": true, "mydumper": true, "myloader": true,
}

// separatedSecretFlags take their secret as the following argument.
var separatedSecretFlags = map[string]bool{
	"--password": true, "--passwd": true, "--pass": true, "--pw": true, "-pw": true,
	"--token": true, "--secret": true, "--api-key": true, "--apikey": true,
	"--access-token": true, "--auth-token": true, "--client-secret": true,
}

// separatedPairFlags take a user:password (or user%password) pair next.
var separatedPairFlags = map[string]bool{
	"-u": true, "--user": true, "-U": true, "--username": true, "--credentials": true,
}

// redactAssignments applies the KEY=VALUE rules to a token, treating a
// form-encoded token (a=1&b=2) segment by segment so the other fields
// survive. An empty value is left alone.
func redactAssignments(text string) (string, bool) {
	segments := strings.Split(text, "&")
	changed := false
	for i, seg := range segments {
		eq := strings.IndexByte(seg, '=')
		if eq <= 0 || eq == len(seg)-1 {
			continue
		}
		key := strings.TrimLeft(seg[:eq], "-")
		value := seg[eq+1:]
		if value == redactedToken {
			continue
		}
		if sensitiveKey(key) {
			segments[i] = seg[:eq+1] + redactedToken
			changed = true
			continue
		}
		if pairKey(key) {
			if r, ok := redactPair(value); ok {
				segments[i] = seg[:eq+1] + r
				changed = true
			}
		}
	}
	if !changed {
		return text, false
	}
	return strings.Join(segments, "&"), true
}

func pairKey(key string) bool {
	switch strings.ToLower(key) {
	case "u", "user", "username", "credentials", "creds", "userpwd", "auth":
		return true
	}
	return false
}

// redactPair masks the password half of user:password or user%password.
func redactPair(v string) (string, bool) {
	sep := strings.IndexAny(v, ":%")
	if sep <= 0 || sep == len(v)-1 {
		return v, false
	}
	return v[:sep+1] + redactedToken, true
}

// sensitiveKey reports whether an option or variable name denotes a secret.
func sensitiveKey(key string) bool {
	lower := strings.ToLower(key)
	parts := strings.FieldsFunc(lower, func(r rune) bool { return r == '_' || r == '-' || r == '.' })
	hasKey := false
	hasKeyQualifier := false
	for _, p := range parts {
		switch {
		case strings.Contains(p, "password"), strings.Contains(p, "passwd"),
			p == "pass", strings.HasSuffix(p, "pwd"),
			strings.Contains(p, "secret"), strings.Contains(p, "token"),
			p == "apikey", p == "credential", p == "credentials":
			return true
		case p == "key":
			hasKey = true
		case p == "api", p == "access", p == "private", p == "auth", p == "license", p == "signing":
			hasKeyQualifier = true
		}
	}
	return hasKey && hasKeyQualifier
}

// redactURLToken masks the password in userinfo and the values of sensitive
// query parameters inside a URL token.
func redactURLToken(tok string) string {
	schemeEnd := strings.Index(tok, "://")
	if schemeEnd < 0 {
		return tok
	}
	rest := tok[schemeEnd+3:]
	authorityEnd := strings.IndexAny(rest, "/?#")
	if authorityEnd < 0 {
		authorityEnd = len(rest)
	}
	authority := rest[:authorityEnd]
	tail := rest[authorityEnd:]
	if at := strings.LastIndexByte(authority, '@'); at > 0 {
		userinfo := authority[:at]
		if colon := strings.IndexByte(userinfo, ':'); colon >= 0 && colon < len(userinfo)-1 {
			authority = userinfo[:colon+1] + redactedToken + authority[at:]
		}
	}
	if q := strings.IndexByte(tail, '?'); q >= 0 {
		query := tail[q+1:]
		fragment := ""
		if h := strings.IndexByte(query, '#'); h >= 0 {
			fragment = query[h:]
			query = query[:h]
		}
		params := strings.Split(query, "&")
		for i, p := range params {
			eq := strings.IndexByte(p, '=')
			if eq <= 0 || eq == len(p)-1 {
				continue
			}
			if sensitiveKey(p[:eq]) {
				params[i] = p[:eq+1] + redactedToken
			}
		}
		tail = tail[:q+1] + strings.Join(params, "&") + fragment
	}
	return tok[:schemeEnd+3] + authority + tail
}
