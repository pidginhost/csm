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
		entries, globErr := osFS.Glob(filepath.Join(path, "*"))
		if globErr != nil {
			a.complete = false
			return dst
		}
		sort.Strings(entries)
		for _, entry := range entries {
			dst = a.appendPath(dst, entry, false, depth+1)
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

	lines := strings.Split(string(data), "\n")
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}

	continued := ""
	for _, physical := range lines {
		line := continued + physical
		if prefix, continues := apacheContinuationPrefix(line); continues {
			continued = prefix + " "
			continue
		}
		continued = ""

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
		if tag, isContainer, tagValid := parseApacheContainerTag(line); isContainer {
			switch {
			case !tagValid:
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
			paths, expanded := expandApacheInclude(fields[1], a.serverRoot)
			if !expanded || (!optionalInclude && len(paths) == 0) {
				a.complete = false
			}
			for _, included := range paths {
				dst = a.appendPath(dst, included, optionalInclude, depth+1)
			}
		default:
			dst = append(dst, apacheConfigLine{File: path, Text: line})
		}
	}
	if continued != "" {
		a.complete = false
	}
	return dst
}

func apacheArgumentHasVariable(arg string) bool {
	return strings.Contains(arg, "${")
}

func expandApacheInclude(target, serverRoot string) ([]string, bool) {
	if !filepath.IsAbs(target) {
		target = filepath.Join(serverRoot, target)
	}
	if !strings.ContainsAny(target, "*?[") {
		return []string{target}, true
	}
	matches, err := osFS.Glob(target)
	if err != nil {
		return nil, false
	}
	sort.Strings(matches)
	return matches, true
}

func apacheContinuationPrefix(line string) (string, bool) {
	line = strings.TrimRight(line, " \t\r")
	backslashes := 0
	for i := len(line) - 1; i >= 0 && line[i] == '\\'; i-- {
		backslashes++
	}
	if backslashes%2 == 0 {
		return line, false
	}
	return line[:len(line)-1], true
}

func stripApacheComment(line string) string {
	var quote byte
	escaped := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			continue
		}
		if c == '#' {
			return line[:i]
		}
	}
	return line
}

// parseApacheDirectiveFields handles the quoting and escapes accepted in
// include paths and container arguments.
func parseApacheDirectiveFields(line string) ([]string, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, true
	}

	var fields []string
	var field strings.Builder
	var quote byte
	escaped := false
	inField := false
	flush := func() {
		if !inField {
			return
		}
		fields = append(fields, field.String())
		field.Reset()
		inField = false
	}

	for i := 0; i < len(line); i++ {
		c := line[i]
		if escaped {
			field.WriteByte(c)
			inField = true
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			inField = true
			continue
		}
		if quote != 0 {
			if c == quote {
				quote = 0
			} else {
				field.WriteByte(c)
			}
			inField = true
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			inField = true
			continue
		}
		if c == ' ' || c == '\t' || c == '\r' {
			flush()
			continue
		}
		field.WriteByte(c)
		inField = true
	}
	flush()
	return fields, quote == 0 && !escaped
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
	if !strings.HasSuffix(text, ">") {
		return apacheParsedContainerTag{}, true, false
	}

	closing := strings.HasPrefix(text, "</")
	prefix := "<"
	if closing {
		prefix = "</"
	}
	label := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(text, prefix), ">"))
	fields, valid := parseApacheDirectiveFields(label)
	if !valid || len(fields) == 0 || (closing && len(fields) != 1) {
		return apacheParsedContainerTag{}, true, false
	}
	return apacheParsedContainerTag{name: fields[0], label: label, closing: closing}, true, true
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
