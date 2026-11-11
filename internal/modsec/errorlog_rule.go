package modsec

import "strings"

// LogRule is the rule a ModSecurity error-log line names.
type LogRule struct {
	ID, File, Msg, Hostname, URI string
	Tags                         []string
}

// ruleFields is the order ModSecurity 2.9 and libmodsecurity 3 write rule
// fields in, each at most once. Tags sit between the fields before hostname
// and hostname.
var ruleFields = [...]string{"file", "line", "id", "rev", "msg", "data", "severity", "ver",
	"maturity", "accuracy", "hostname", "uri", "unique_id", "ref"}

const firstFieldAfterTags = 10 // hostname

const tagMarker = `[tag "`

// ErrorLogRule reads the rule fields of a ModSecurity error-log line. Both
// engines write client text before the fields: the matched variable's name,
// and in libmodsecurity 3 its value, which it also leaves unescaped in
// macro-expanded messages and the URI. Client text can add a field but never
// remove one the engine wrote, so a repeated field, a field out of order or a
// tag outside the tag run leaves the rule unknowable and ok false.
func ErrorLogRule(line string) (LogRule, bool) {
	msg, isLiteSpeed := ErrorLogMessage(line)
	at := map[string]int{}
	last := -1
	tagsFrom, tagsTo := 0, len(msg)
	for i, name := range ruleFields {
		marker := "[" + name + ` "`
		pos := strings.Index(msg, marker)
		if pos < 0 {
			continue
		}
		if pos < last || strings.Count(msg, marker) > 1 {
			return LogRule{}, false
		}
		last = pos
		at[name] = pos + len(marker)
		if i < firstFieldAfterTags {
			tagsFrom = at[name]
		} else if tagsTo == len(msg) {
			tagsTo = pos
		}
	}
	value := func(name string) string {
		pos, ok := at[name]
		if !ok {
			return ""
		}
		v, _, closed := strings.Cut(msg[pos:], `"]`)
		if !closed {
			return ""
		}
		return v
	}
	rule := LogRule{ID: value("id"), File: value("file"), Msg: value("msg"), Hostname: value("hostname"), URI: value("uri")}
	for off := 0; ; {
		pos := strings.Index(msg[off:], tagMarker)
		if pos < 0 {
			break
		}
		off += pos + len(tagMarker)
		if off < tagsFrom || off > tagsTo {
			return LogRule{}, false
		}
		if v, _, closed := strings.Cut(msg[off:], `"]`); closed {
			rule.Tags = append(rule.Tags, v)
		}
	}
	if isLiteSpeed && rule.File == "" && rule.ID != "" {
		// LiteSpeed names the rule file right after the id: [id "N"] at [path:line].
		if rest, ok := strings.CutPrefix(msg[at["id"]+len(rule.ID):], `"] at [`); ok {
			if loc, _, closed := strings.Cut(rest, "]"); closed {
				if i := strings.LastIndexByte(loc, ':'); i > 0 {
					loc = loc[:i]
				}
				rule.File = loc
			}
		}
	}
	return rule, true
}
