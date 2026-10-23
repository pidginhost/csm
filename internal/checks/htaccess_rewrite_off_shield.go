package checks

import "strings"

func htaccessLineGrantsAccess(line string) bool {
	fields, valid := parseApacheDirectiveFields(line)
	if !valid || len(fields) < 3 {
		return false
	}
	if strings.EqualFold(fields[0], "Allow") && strings.EqualFold(fields[1], "from") {
		for _, host := range fields[2:] {
			if strings.EqualFold(host, "all") {
				return true
			}
		}
	}
	return len(fields) == 3 && strings.EqualFold(fields[0], "Require") && strings.EqualFold(fields[1], "all") && strings.EqualFold(fields[2], "granted")
}

func htaccessBodyGrantsAccess(body []byte) bool {
	for _, line := range htaccessLogicalByteLines(body) {
		if htaccessLineGrantsAccess(line.text) {
			return true
		}
	}
	return false
}

// detectRewriteOffShield recognizes the kit's empty grant together with its
// rewrite switch. Logical lines keep comments and continuations from becoming
// directives, and retain the original byte spans for surgical removal.
func detectRewriteOffShield(content []byte, _ string) []htaccessMatch {
	type container struct {
		name     string
		argument string
		span     htaccessByteRange
		switches int
	}
	var stack []container
	var grants, switches []htaccessMatch
	for _, line := range htaccessLogicalByteLines(content) {
		text := strings.TrimSpace(line.text)
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		tag, isTag, valid := parseApacheContainerTag(text)
		if isTag {
			if !valid {
				return nil
			}
			name := strings.ToLower(tag.name)
			if !tag.closing {
				stack = append(stack, container{name, apacheContainerArgument(text), line.span, len(switches)})
				continue
			}
			if len(stack) == 0 || stack[len(stack)-1].name != name {
				return nil
			}
			open := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			span := htaccessByteRange{Start: open.span.Start, End: line.span.End}
			if name == "filesmatch" && filesMatchNamesNoFile(open.argument) &&
				htaccessBodyGrantsAccess(content[open.span.End:line.span.Start]) {
				grants = append(grants, htaccessMatch{Range: span, Excerpt: trimExcerpt(content, span.Start, span.End)})
			}
			// Remove a wrapper only when the switch is its entire body. Other
			// settings and comments inside a shared wrapper must survive.
			if name == "ifmodule" && (strings.EqualFold(open.argument, "mod_rewrite.c") || strings.EqualFold(open.argument, "rewrite_module")) &&
				len(switches) == open.switches+1 {
				m := &switches[open.switches]
				if strings.TrimSpace(string(content[open.span.End:m.Range.Start])) == "" &&
					strings.TrimSpace(string(content[m.Range.End:line.span.Start])) == "" {
					m.Range = span
					m.Excerpt = trimExcerpt(content, span.Start, span.End)
				}
			}
			continue
		}
		fields, valid := parseApacheDirectiveFields(text)
		if valid && len(fields) == 2 && strings.EqualFold(fields[0], "RewriteEngine") && strings.EqualFold(fields[1], "off") {
			switches = append(switches, htaccessMatch{Range: line.span, Excerpt: trimExcerpt(content, line.span.Start, line.span.End)})
		}
	}
	if len(stack) != 0 || len(grants) == 0 || len(switches) == 0 {
		return nil
	}
	return append(switches, grants...)
}
