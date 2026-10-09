package antispam

import (
	"strconv"
	"strings"
)

// FilterSpamUses returns the 1-based lines of Exim system filter data items
// that read $spam_*. The filter runs after CSM's scan for every account.
func FilterSpamUses(filter string) []int {
	var out []int
	var token strings.Builder
	line, start := 1, 1
	quoted := false
	flush := func() {
		if readsExpandedSpamVariable(token.String()) && (len(out) == 0 || out[len(out)-1] != start) {
			out = append(out, start)
		}
		token.Reset()
	}
	for i := 0; i < len(filter); i++ {
		c := filter[i]
		if !quoted && filterSeparator(c) {
			flush()
			if c == '\n' {
				line++
			}
			continue
		}
		if !quoted && c == '#' && token.Len() == 0 {
			for i < len(filter) && filter[i] != '\n' {
				i++
			}
			if i < len(filter) {
				line++
			}
			continue
		}
		if token.Len() == 0 && !quoted {
			start = line
		}
		if c == '"' {
			if quoted {
				flush()
			}
			quoted = !quoted
			continue
		}
		if quoted && c == '\\' && i+1 < len(filter) {
			i++
			c = filter[i]
			if c == '\n' {
				line++
				for i+1 < len(filter) && (filter[i+1] == ' ' || filter[i+1] == '\t' || filter[i+1] == '\r') {
					i++
				}
				continue
			}
			// Quoted data is unescaped before expansion. A decoded dollar
			// can read a variable; a decoded backslash can suppress it.
			switch c {
			case 'n':
				c = '\n'
			case 'r':
				c = '\r'
			case 't':
				c = '\t'
			default:
				base, limit, first := 8, 3, i
				if c == 'x' {
					base, limit, first = 16, 2, i+1
				}
				end := first
				for end < len(filter) && end-first < limit && filterDigit(filter[end], base) {
					end++
				}
				if end > first {
					n, _ := strconv.ParseUint(filter[first:end], base, 16)
					c, i = byte(n&0xff), end-1
				}
			}
		} else if c == '\n' {
			line++
		}
		token.WriteByte(c)
	}
	flush()
	return out
}

func filterSeparator(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '\v' || c == '(' || c == ')'
}

func filterDigit(c byte, base int) bool {
	if base == 8 {
		return c >= '0' && c <= '7'
	}
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func readsExpandedSpamVariable(s string) bool {
	literal := false
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			if s[i+1] == 'N' {
				literal = !literal
			}
			i++
			continue
		}
		if !literal && s[i] == '$' && (strings.HasPrefix(s[i+1:], "spam_") || strings.HasPrefix(s[i+1:], "{spam_")) {
			return true
		}
	}
	return false
}
