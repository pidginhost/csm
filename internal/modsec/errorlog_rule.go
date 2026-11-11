package modsec

import "strings"

// LogRule is the rule a ModSecurity error-log line names.
type LogRule struct {
	ID, File, Msg, Hostname, URI string
	Tags                         []string
}

// Only tags may repeat in the order both ModSecurity engines write fields.
var ruleFields = [...]string{"file", "line", "id", "rev", "msg", "data", "severity", "ver",
	"maturity", "accuracy", "tag", "hostname", "uri", "unique_id", "ref"}

// ErrorLogRule reads the rule fields of a ModSecurity error-log line. Both
// engines write client text before the fields: the matched variable's name,
// and in libmodsecurity 3 its value, which it also leaves unescaped in
// macro-expanded messages and the URI. Client text can add a field but never
// remove one the engine wrote, so repeated or out-of-order fields leave the
// rule unknowable and ok false. Unclosed fields are also unknown.
func ErrorLogRule(line string) (LogRule, bool) {
	msg, isLiteSpeed := ErrorLogMessage(line)
	type field struct {
		name         string
		start, value int
	}
	var fields []field
	last := -1
	for off := 0; off < len(msg); {
		pos := strings.IndexByte(msg[off:], '[')
		if pos < 0 {
			break
		}
		pos += off
		off = pos + 1
		for i, name := range ruleFields {
			marker := "[" + name + ` "`
			if !strings.HasPrefix(msg[pos:], marker) {
				continue
			}
			if i < last || (i == last && name != "tag") {
				return LogRule{}, false
			}
			last = i
			off = pos + len(marker)
			fields = append(fields, field{name: name, start: pos, value: off})
			break
		}
	}

	var rule LogRule
	for i, f := range fields {
		end := len(msg)
		if i+1 < len(fields) {
			end = fields[i+1].start
		}
		// The next field bounds the value. Quotes within msg/uri may be
		// escaped by Apache or raw in v3; neither is a field delimiter.
		value, closed := strings.CutSuffix(strings.TrimRight(msg[f.value:end], " \t"), `"]`)
		nativeID := isLiteSpeed && strings.HasPrefix(msg, "mod_security rule ") && f.name == "id"
		if nativeID || (i+1 == len(fields) && (f.name == "unique_id" || f.name == "ref")) {
			// LiteSpeed's id is followed by its file location and action text.
			// Terminal server fields can precede a connector's request suffix.
			value, _, closed = strings.Cut(msg[f.value:], `"]`)
		}
		if !closed {
			return LogRule{}, false
		}
		switch f.name {
		case "id":
			rule.ID = value
			if isLiteSpeed {
				if rest, ok := strings.CutPrefix(msg[f.value+len(value):], `"] at [`); ok {
					if loc, _, ok := strings.Cut(rest, "]"); ok {
						if colon := strings.LastIndexByte(loc, ':'); colon > 0 {
							loc = loc[:colon]
						}
						rule.File = loc
					}
				}
			}
		case "file":
			rule.File = value
		case "msg":
			rule.Msg = value
		case "tag":
			rule.Tags = append(rule.Tags, value)
		case "hostname":
			rule.Hostname = value
		case "uri":
			rule.URI = value
		}
	}
	return rule, true
}
