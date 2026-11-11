package checks

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// A running Apache rejects recursive includes. The audit still bounds descent
// so a changed-on-disk configuration cannot recurse forever before the next
// config test or reload notices the error.
const apacheIncludeMaxDepth = 32

// apacheConfigLine is one line of an assembled Apache configuration, tagged
// with its source so findings can name the file that set a directive.
type apacheConfigLine struct {
	File string
	Text string
}

var apacheConditionalContainers = map[string]bool{
	"if":          true,
	"else":        true,
	"elseif":      true,
	"ifmodule":    true,
	"ifdefine":    true,
	"ifversion":   true,
	"iffile":      true,
	"ifsection":   true,
	"ifdirective": true,
}

// assembleApacheConfig reads path and splices Include and IncludeOptional
// targets at the directive position. Apache applies later directives over
// earlier ones, so appending snippets would invert precedence.
func assembleApacheConfig(path string) []apacheConfigLine {
	lines, _ := assembleApacheConfigWithStatus(path)
	return lines
}

func assembleApacheConfigWithStatus(path string) ([]apacheConfigLine, bool) {
	assembler := apacheConfigAssembler{
		serverRoot:  defaultApacheServerRoot(path),
		activePaths: make(map[string]bool),
		complete:    true,
	}
	lines := assembler.appendPath(nil, path, false, 0)
	if len(assembler.containers) != 0 {
		assembler.complete = false
	}
	return lines, assembler.complete
}

// defaultApacheServerRoot covers the compiled-in layouts used by supported
// distributions when the main file does not set ServerRoot.
func defaultApacheServerRoot(path string) string {
	dir := filepath.Dir(path)
	if strings.EqualFold(filepath.Base(path), "httpd.conf") &&
		strings.EqualFold(filepath.Base(dir), "conf") {
		return filepath.Dir(dir)
	}
	return dir
}

type apacheConfigAssembler struct {
	serverRoot  string
	activePaths map[string]bool
	containers  []string
	complete    bool
}

func (a *apacheConfigAssembler) appendPath(dst []apacheConfigLine, path string, optional bool, depth int) []apacheConfigLine {
	if depth > apacheIncludeMaxDepth {
		a.complete = false
		return dst
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		abs = filepath.Clean(path)
	}
	if a.activePaths[abs] {
		a.complete = false
		return dst
	}
	a.activePaths[abs] = true
	defer delete(a.activePaths, abs)

	if info, statErr := osFS.Stat(path); statErr == nil && info.IsDir() {
		// An unreadable directory is not an empty one.
		entries, readErr := osFS.ReadDir(path)
		if readErr != nil {
			a.complete = false
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, entry := range entries {
			dst = a.appendPath(dst, filepath.Join(path, entry.Name()), false, depth+1)
		}
		return dst
	}

	data, err := osFS.ReadFile(path)
	if err != nil {
		if !optional || !errors.Is(err, os.ErrNotExist) {
			a.complete = false
		}
		return dst
	}

	lines := strings.SplitAfter(string(data), "\n")
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}

	continued := ""
	for i, physical := range lines {
		line, continues := apacheContinuationPrefix(continued + physical)
		if continues && i < len(lines)-1 {
			continued = line
			continue
		}
		continued = ""

		// Section handlers discard their suffix before reading arguments;
		// quotes in that ignored text must not invalidate the whole tree.
		if tag, isContainer, tagValid := parseApacheContainerTag(line); isContainer {
			switch {
			case !tagValid || apacheArgumentHasVariable(tag.name):
				a.complete = false
			case tag.closing:
				last := len(a.containers) - 1
				if last < 0 || !strings.EqualFold(a.containers[last], tag.name) {
					a.complete = false
				} else {
					a.containers = a.containers[:last]
				}
			default:
				a.containers = append(a.containers, tag.name)
			}
			dst = append(dst, apacheConfigLine{File: path, Text: line})
			continue
		}

		fields, valid := parseApacheDirectiveFields(stripApacheComment(line))
		if !valid {
			a.complete = false
			dst = append(dst, apacheConfigLine{File: path, Text: line})
			continue
		}
		if len(fields) == 0 {
			dst = append(dst, apacheConfigLine{File: path, Text: line})
			continue
		}
		// Apache expands Define and process environment variables before it
		// reads the directive name. An unresolved name could be an Include.
		if apacheArgumentHasVariable(fields[0]) {
			a.complete = false
		}

		switch {
		case strings.EqualFold(fields[0], "ServerRoot"):
			if len(a.containers) != 0 || len(fields) != 2 || fields[1] == "" || apacheArgumentHasVariable(fields[1]) || !filepath.IsAbs(fields[1]) {
				a.complete = false
			} else {
				a.serverRoot = filepath.Clean(fields[1])
			}
			dst = append(dst, apacheConfigLine{File: path, Text: line})
		case strings.EqualFold(fields[0], "Include"), strings.EqualFold(fields[0], "IncludeOptional"):
			optionalInclude := strings.EqualFold(fields[0], "IncludeOptional")
			if len(fields) != 2 || fields[1] == "" || apacheArgumentHasVariable(fields[1]) {
				a.complete = false
				continue
			}
			paths, globbed, expanded := expandApacheInclude(fields[1], a.serverRoot)
			if !expanded || (!optionalInclude && len(paths) == 0) {
				a.complete = false
			}
			// A file a glob found must be read; only an absent literal
			// IncludeOptional target may be missing.
			for _, included := range paths {
				dst = a.appendPath(dst, included, optionalInclude && !globbed, depth+1)
			}
		default:
			dst = append(dst, apacheConfigLine{File: path, Text: line})
		}
	}
	return dst
}

func apacheArgumentHasVariable(arg string) bool {
	return strings.Contains(arg, "${")
}

// expandApacheInclude resolves an Include target. A glob reports whether
// every directory it walked could be read: filepath.Glob drops those
// errors, so an unreadable directory would look empty.
func expandApacheInclude(target, serverRoot string) (paths []string, globbed, complete bool) {
	if !filepath.IsAbs(target) {
		target = filepath.Join(serverRoot, target)
	}
	// APR normalizes absolute as well as relative Include arguments.
	target = filepath.Clean(target)
	if !apacheIncludeHasGlob(target) {
		return []string{target}, false, true
	}
	matches, complete := checkedApacheConfigGlob(target)
	sort.Strings(matches)
	return matches, true, complete
}

func apacheContinuationPrefix(line string) (string, bool) {
	// Only a backslash immediately before LF or CRLF continues a line.
	// Spaces after a comment's backslash must not swallow the next setting.
	if !strings.HasSuffix(line, "\n") {
		return line, false
	}
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")
	if !strings.HasSuffix(line, "\\") {
		return line, false
	}
	return line[:len(line)-1], true
}

func stripApacheComment(line string) string {
	// httpd only treats a leading hash as a comment. A hash in an Include
	// path is literal; truncating it can silently select a different tree.
	if strings.HasPrefix(strings.TrimLeft(line, " \t\r\n\v\f"), "#") {
		return ""
	}
	return line
}

// parseApacheDirectiveFields handles the quoting and escapes accepted in
// include paths and container arguments.
func parseApacheDirectiveFields(line string) ([]string, bool) {
	var fields []string
	for {
		line = strings.TrimLeft(line, " \t\r\n\v\f")
		if line == "" {
			return fields, true
		}
		var field strings.Builder
		var quote byte
		if line[0] == '\'' || line[0] == '"' {
			quote, line = line[0], line[1:]
		}
		i := 0
		for i < len(line) {
			c := line[i]
			if quote != 0 && c == quote || quote == 0 && strings.ContainsRune(" \t\r\n\v\f", rune(c)) {
				break
			}
			if c == '\r' || c == '\n' {
				return fields, false
			}
			// ap_getword_conf only decodes a doubled backslash or the
			// matching quote inside a quoted argument.
			if c == '\\' && i+1 < len(line) && (line[i+1] == '\\' || quote != 0 && line[i+1] == quote) {
				i++
				c = line[i]
			}
			field.WriteByte(c)
			i++
		}
		if quote != 0 {
			if i == len(line) {
				return fields, false
			}
			i++
		}
		fields = append(fields, field.String())
		line = line[i:]
	}
}

type apacheParsedContainerTag struct {
	name    string
	label   string
	closing bool
}

func parseApacheContainerTag(line string) (apacheParsedContainerTag, bool, bool) {
	text := strings.TrimSpace(stripApacheComment(line))
	if !strings.HasPrefix(text, "<") {
		return apacheParsedContainerTag{}, false, true
	}
	wordEnd := strings.IndexAny(text, " \t\r\n\v\f")
	if strings.HasPrefix(text, "</") {
		word := text
		if wordEnd >= 0 {
			word = text[:wordEnd]
		}
		// Closing tags are directive names, not section arguments. httpd
		// checks the whole first word, including its terminating bracket.
		if !strings.HasSuffix(word, ">") {
			return apacheParsedContainerTag{}, true, false
		}
		name := word[2 : len(word)-1]
		if name == "" || strings.ContainsAny(name, "<>") {
			return apacheParsedContainerTag{}, true, false
		}
		if wordEnd >= 0 {
			switch strings.ToLower(name) {
			case "ifmodule", "ifdefine", "ifversion", "iffile", "ifsection", "ifdirective":
				// Active read-time sections require an exact closing line.
				// Their runtime condition is unavailable to this parser.
				return apacheParsedContainerTag{}, true, false
			}
		}
		return apacheParsedContainerTag{name: name, label: name, closing: true}, true, true
	}
	// Core section handlers end their arguments at the last '>'. A bracket
	// inside the directive name cannot terminate a nonempty argument list.
	end := strings.LastIndexByte(text, '>')
	if end < 0 || (wordEnd >= 0 && end < wordEnd) || (wordEnd < 0 && end != len(text)-1) {
		return apacheParsedContainerTag{}, true, false
	}
	label := strings.TrimSpace(text[1:end])
	fields, valid := parseApacheDirectiveFields(label)
	if !valid || len(fields) == 0 {
		return apacheParsedContainerTag{}, true, false
	}
	// mod_version parses a fixed argument list instead of raw section text.
	if strings.EqualFold(fields[0], "IfVersion") && end != len(text)-1 {
		return apacheParsedContainerTag{}, true, false
	}
	return apacheParsedContainerTag{name: fields[0], label: label}, true, true
}

type apacheLineContext struct {
	Scope         []string
	ScopeKey      []string
	Condition     string
	LateCondition bool
}

// walkApacheLines calls fn for directive lines and validates the container
// stack. A mismatched close never pops an unrelated scope.
func walkApacheLines(lines []apacheConfigLine, fn func(apacheConfigLine, []string, apacheLineContext)) bool {
	type container struct {
		name            string
		label           string
		key             string
		scoped          bool
		conditional     bool
		lateConditional bool
	}

	var stack []container
	valid := true
	serial := 0

	context := func() apacheLineContext {
		var ctx apacheLineContext
		var conditions []string
		for _, item := range stack {
			if item.scoped {
				ctx.Scope = append(ctx.Scope, item.label)
				ctx.ScopeKey = append(ctx.ScopeKey, item.key)
			}
			if item.conditional {
				conditions = append(conditions, item.key)
			}
			if item.lateConditional {
				ctx.LateCondition = true
			}
		}
		ctx.Condition = strings.Join(conditions, "\x1e")
		return ctx
	}

	for _, line := range lines {
		text := strings.TrimSpace(stripApacheComment(line.Text))
		if text == "" {
			continue
		}
		tag, isContainer, tagValid := parseApacheContainerTag(text)
		if isContainer {
			if !tagValid {
				valid = false
				continue
			}
			if tag.closing {
				if len(stack) == 0 || !strings.EqualFold(stack[len(stack)-1].name, tag.name) {
					valid = false
					continue
				}
				stack = stack[:len(stack)-1]
				continue
			}

			serial++
			lowerName := strings.ToLower(tag.name)
			conditional := apacheConditionalContainers[lowerName]
			key := canonicalApacheContainerKey(tag.label)
			if conditional || lowerName == "virtualhost" {
				key += "\x00" + strconv.Itoa(serial)
			}
			stack = append(stack, container{
				name:            tag.name,
				label:           normalizeApacheContainerLabel(tag.label),
				key:             key,
				scoped:          !conditional,
				conditional:     conditional,
				lateConditional: lowerName == "if" || lowerName == "else" || lowerName == "elseif",
			})
			continue
		}

		fields, fieldsValid := parseApacheDirectiveFields(text)
		if !fieldsValid {
			valid = false
			continue
		}
		if len(fields) > 0 {
			fn(line, fields, context())
		}
	}
	return valid && len(stack) == 0
}

func canonicalApacheContainerKey(label string) string {
	fields, valid := parseApacheDirectiveFields(label)
	if !valid || len(fields) == 0 {
		return strings.ToLower(strings.TrimSpace(label))
	}
	fields[0] = strings.ToLower(fields[0])
	return strings.Join(fields, "\x1f")
}

func normalizeApacheContainerLabel(label string) string {
	fields, valid := parseApacheDirectiveFields(label)
	if !valid {
		return strings.TrimSpace(label)
	}
	return strings.Join(fields, " ")
}

type apacheDirectiveValue struct {
	File            string
	Scope           string
	Value           string
	Conditional     bool
	lateConditional bool
	scopeKey        string
}

// apacheDirectiveValues returns the last explicit value in each scope and
// keeps conditional branches separate from the unconditional default.
func apacheDirectiveValues(lines []apacheConfigLine, directive string) ([]apacheDirectiveValue, bool) {
	const serverScope = "server config"
	values := make(map[string]apacheDirectiveValue)
	var order []string
	conditionalValues := make(map[string]apacheDirectiveValue)
	var conditionalOrder []string
	directiveValid := true

	containersValid := walkApacheLines(lines, func(line apacheConfigLine, fields []string, ctx apacheLineContext) {
		if !strings.EqualFold(fields[0], directive) {
			return
		}
		if len(fields) < 2 {
			directiveValid = false
			return
		}

		key := serverScope
		displayScope := serverScope
		if len(ctx.Scope) > 0 {
			key = strings.Join(ctx.ScopeKey, "\x1d")
			displayScope = strings.Join(ctx.Scope, " > ")
		}
		value := apacheDirectiveValue{
			File:            line.File,
			Scope:           displayScope,
			Value:           strings.Join(fields[1:], " "),
			Conditional:     ctx.Condition != "",
			lateConditional: ctx.LateCondition,
			scopeKey:        key,
		}
		if value.Conditional {
			conditionalKey := key + "\x00" + ctx.Condition
			if _, seen := conditionalValues[conditionalKey]; !seen {
				conditionalOrder = append(conditionalOrder, conditionalKey)
			}
			conditionalValues[conditionalKey] = value
			return
		}

		if _, seen := values[key]; !seen {
			order = append(order, key)
		}
		values[key] = value
		for conditionalKey, conditionalValue := range conditionalValues {
			if conditionalValue.scopeKey == key && !conditionalValue.lateConditional {
				conditionalValue.File = value.File
				conditionalValue.Value = value.Value
				conditionalValues[conditionalKey] = conditionalValue
			}
		}
	})

	out := make([]apacheDirectiveValue, 0, len(values)+len(conditionalValues))
	for _, key := range order {
		out = append(out, values[key])
	}
	for _, key := range conditionalOrder {
		out = append(out, conditionalValues[key])
	}
	return out, containersValid && directiveValid
}

func apacheIndexesScopes(lines []apacheConfigLine) []string {
	scopes, _ := apacheIndexesScopesWithStatus(lines)
	return scopes
}

func apacheIndexesScopesWithStatus(lines []apacheConfigLine) ([]string, bool) {
	const serverScope = "server config"
	effective := make(map[string]bool)
	conditionalEffective := make(map[string]bool)
	conditionalScopes := make(map[string]string)
	lateConditional := make(map[string]bool)
	displayScopes := make(map[string]string)
	seen := make(map[string]bool)
	var order []string
	optionsValid := true

	containersValid := walkApacheLines(lines, func(_ apacheConfigLine, fields []string, ctx apacheLineContext) {
		if !strings.EqualFold(fields[0], "Options") {
			return
		}
		if len(fields) < 2 {
			optionsValid = false
			return
		}

		key := serverScope
		displayScope := serverScope
		if len(ctx.Scope) > 0 {
			key = strings.Join(ctx.ScopeKey, "\x1d")
			displayScope = strings.Join(ctx.Scope, " > ")
		}
		if !seen[key] {
			seen[key] = true
			order = append(order, key)
			displayScopes[key] = displayScope
		}

		if ctx.Condition != "" {
			conditionalKey := key + "\x00" + ctx.Condition
			current, exists := conditionalEffective[conditionalKey]
			if !exists {
				current = effective[key]
			}
			conditionalEffective[conditionalKey] = optionsEnableIndexes(fields[1:], current)
			conditionalScopes[conditionalKey] = key
			lateConditional[conditionalKey] = ctx.LateCondition
			return
		}

		effective[key] = optionsEnableIndexes(fields[1:], effective[key])
		for conditionalKey, conditionalValue := range conditionalEffective {
			if conditionalScopes[conditionalKey] == key && !lateConditional[conditionalKey] {
				conditionalEffective[conditionalKey] = optionsEnableIndexes(fields[1:], conditionalValue)
			}
		}
	})

	var out []string
	for _, key := range order {
		enabled := effective[key]
		for conditionalKey, conditionalValue := range conditionalEffective {
			if conditionalScopes[conditionalKey] == key && conditionalValue {
				enabled = true
				break
			}
		}
		if enabled {
			out = append(out, displayScopes[key])
		}
	}
	return out, containersValid && optionsValid
}

// optionsEnableIndexes applies one Options directive to the scope's current
// state. Signed tokens merge; bare tokens replace the option set.
func optionsEnableIndexes(tokens []string, current bool) bool {
	merge := false
	for _, token := range tokens {
		if strings.HasPrefix(token, "+") || strings.HasPrefix(token, "-") {
			merge = true
			break
		}
	}
	if !merge {
		for _, token := range tokens {
			if strings.EqualFold(token, "Indexes") || strings.EqualFold(token, "All") {
				return true
			}
		}
		return false
	}
	for _, token := range tokens {
		name := strings.TrimLeft(token, "+-")
		if !strings.EqualFold(name, "Indexes") && !strings.EqualFold(name, "All") {
			continue
		}
		current = strings.HasPrefix(token, "+")
	}
	return current
}
