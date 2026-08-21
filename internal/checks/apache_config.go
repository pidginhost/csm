package checks

import (
	"path/filepath"
	"sort"
	"strings"
)

// apacheIncludeMaxDepth bounds Include recursion and directory descent.
// Apache rejects include cycles outright; the audit just stops descending.
const apacheIncludeMaxDepth = 16

// apacheConfigLine is one line of an assembled Apache configuration,
// tagged with the file it came from so findings can name the snippet that
// actually set a directive.
type apacheConfigLine struct {
	File string
	Text string
}

// apacheConditionalContainers are blocks that gate whether the enclosed
// directives apply, without changing the scope they apply to.
var apacheConditionalContainers = map[string]bool{
	"ifmodule":    true,
	"ifdefine":    true,
	"ifversion":   true,
	"iffile":      true,
	"ifsection":   true,
	"ifdirective": true,
}

// assembleApacheConfig reads path and splices Include / IncludeOptional
// targets in at the position of the directive. Apache applies later
// directives over earlier ones, so appending snippets at the end instead
// of splicing them in place would invert precedence.
func assembleApacheConfig(path string) []apacheConfigLine {
	serverRoot := apacheServerRoot(path)
	return appendApachePath(nil, path, serverRoot, map[string]bool{}, 0)
}

// apacheServerRoot resolves the ServerRoot that relative Include paths are
// taken against. Debian leaves it to the compiled-in default, which always
// matches the directory holding the main config.
func apacheServerRoot(path string) string {
	data, err := osFS.ReadFile(path)
	if err != nil {
		return filepath.Dir(path)
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 2 && strings.EqualFold(fields[0], "ServerRoot") {
			if root := unquoteApacheArg(fields[1]); root != "" {
				return root
			}
		}
	}
	return filepath.Dir(path)
}

func appendApachePath(dst []apacheConfigLine, path, serverRoot string, visited map[string]bool, depth int) []apacheConfigLine {
	if depth > apacheIncludeMaxDepth {
		return dst
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	if visited[abs] {
		return dst
	}
	visited[abs] = true

	if info, statErr := osFS.Stat(path); statErr == nil && info.IsDir() {
		entries, _ := osFS.Glob(filepath.Join(path, "*"))
		sort.Strings(entries)
		for _, e := range entries {
			dst = appendApachePath(dst, e, serverRoot, visited, depth+1)
		}
		return dst
	}

	data, err := osFS.ReadFile(path)
	if err != nil {
		return dst
	}
	lines := strings.Split(string(data), "\n")
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	for _, line := range lines {
		target, ok := apacheIncludeTarget(line)
		if !ok {
			dst = append(dst, apacheConfigLine{File: path, Text: line})
			continue
		}
		for _, p := range expandApacheInclude(target, serverRoot) {
			dst = appendApachePath(dst, p, serverRoot, visited, depth+1)
		}
	}
	return dst
}

// apacheIncludeTarget returns the argument of an Include / IncludeOptional
// directive.
func apacheIncludeTarget(line string) (string, bool) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 2 {
		return "", false
	}
	if !strings.EqualFold(fields[0], "Include") && !strings.EqualFold(fields[0], "IncludeOptional") {
		return "", false
	}
	return unquoteApacheArg(fields[1]), true
}

// expandApacheInclude turns one Include argument into the concrete paths it
// names, sorted the way Apache reads glob matches.
func expandApacheInclude(target, serverRoot string) []string {
	if target == "" {
		return nil
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(serverRoot, target)
	}
	if !strings.ContainsAny(target, "*?[") {
		return []string{target}
	}
	matches, err := osFS.Glob(target)
	if err != nil {
		return nil
	}
	sort.Strings(matches)
	return matches
}

func unquoteApacheArg(arg string) string {
	return strings.Trim(arg, `"'`)
}

// walkApacheLines calls fn for every directive line, passing the stack of
// scope-defining containers the line sits in. Comments, blank lines and the
// container tags themselves are skipped.
func walkApacheLines(lines []apacheConfigLine, fn func(line apacheConfigLine, fields []string, scope []string)) {
	type container struct {
		label  string
		scoped bool
	}
	var stack []container
	scope := func() []string {
		var out []string
		for _, c := range stack {
			if c.scoped {
				out = append(out, c.label)
			}
		}
		return out
	}

	for _, l := range lines {
		text := strings.TrimSpace(l.Text)
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		if strings.HasPrefix(text, "</") {
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			continue
		}
		if strings.HasPrefix(text, "<") {
			label := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(text, "<"), ">"))
			name := label
			if i := strings.IndexAny(label, " \t"); i >= 0 {
				name = label[:i]
			}
			stack = append(stack, container{
				label:  normalizeApacheContainerLabel(label),
				scoped: !apacheConditionalContainers[strings.ToLower(name)],
			})
			continue
		}
		fields := strings.Fields(text)
		if len(fields) == 0 {
			continue
		}
		fn(l, fields, scope())
	}
}

// normalizeApacheContainerLabel renders a container tag as a readable scope
// label: `<Directory "/var/www/">` becomes `Directory /var/www/`.
func normalizeApacheContainerLabel(label string) string {
	fields := strings.Fields(label)
	for i, f := range fields {
		fields[i] = unquoteApacheArg(f)
	}
	return strings.Join(fields, " ")
}

// apacheServerScopeLines returns the directive lines that apply at server
// scope. Directives inside <Directory>, <VirtualHost> and friends are
// scoped to those containers and must not be read as the global setting.
func apacheServerScopeLines(lines []apacheConfigLine) []apacheConfigLine {
	var out []apacheConfigLine
	walkApacheLines(lines, func(line apacheConfigLine, _ []string, scope []string) {
		if len(scope) == 0 {
			out = append(out, line)
		}
	})
	return out
}

// apacheIndexesScopes returns the scopes whose effective Options grant
// directory indexing, in the order they first appear. Only scopes that set
// Options themselves are considered; inherited values are not modelled, so
// the result never invents a finding for a container that stays silent.
func apacheIndexesScopes(lines []apacheConfigLine) []string {
	const serverScope = "server config"
	effective := map[string]bool{}
	var order []string

	walkApacheLines(lines, func(_ apacheConfigLine, fields []string, scope []string) {
		if !strings.EqualFold(fields[0], "Options") || len(fields) < 2 {
			return
		}
		key := serverScope
		if len(scope) > 0 {
			key = strings.Join(scope, " > ")
		}
		if _, seen := effective[key]; !seen {
			order = append(order, key)
		}
		effective[key] = optionsEnableIndexes(fields[1:], effective[key])
	})

	var out []string
	for _, k := range order {
		if effective[k] {
			out = append(out, k)
		}
	}
	return out
}

// optionsEnableIndexes applies one Options directive to the scope's current
// indexing state. Tokens carrying + or - merge with what is already set;
// bare tokens replace the whole set, so `Options FollowSymLinks` turns
// indexing off even though it never names Indexes.
func optionsEnableIndexes(tokens []string, current bool) bool {
	merge := false
	for _, tok := range tokens {
		if strings.HasPrefix(tok, "+") || strings.HasPrefix(tok, "-") {
			merge = true
			break
		}
	}
	if !merge {
		for _, tok := range tokens {
			if strings.EqualFold(tok, "Indexes") || strings.EqualFold(tok, "All") {
				return true
			}
		}
		return false
	}
	for _, tok := range tokens {
		name := strings.TrimLeft(tok, "+-")
		if !strings.EqualFold(name, "Indexes") && !strings.EqualFold(name, "All") {
			continue
		}
		current = strings.HasPrefix(tok, "+")
	}
	return current
}
