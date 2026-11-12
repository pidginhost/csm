package checks

import (
	"path/filepath"
	"sort"
	"strings"
)

// nginxDirective is one simple or block directive of an nginx
// configuration, tagged with the file that set it.
type nginxDirective struct {
	Name    string
	Args    []string
	File    string
	Module  string
	Context string
	Block   bool
}

// nginxDirectives returns every directive of the nginx configuration at
// path, with include targets expanded in place, and whether every file was
// read and parsed. Relative includes resolve against the main file's
// directory, nginx's configuration prefix.
func nginxDirectives(path string) ([]nginxDirective, bool) {
	prefix, _ := filepath.Split(path)
	if prefix == "" {
		prefix = "."
	}
	r := nginxReader{prefix: strings.TrimSuffix(prefix, string(filepath.Separator)), active: make(map[string]bool), complete: true}
	out := r.read(nil, path, 0, "", "")
	return out, r.complete
}

type nginxReader struct {
	prefix   string
	active   map[string]bool
	complete bool
}

func (r *nginxReader) read(dst []nginxDirective, path string, depth int, module, context string) []nginxDirective {
	if depth > apacheIncludeMaxDepth || r.active[path] {
		r.complete = false
		return dst
	}
	r.active[path] = true
	defer delete(r.active, path)

	data, err := osFS.ReadFile(path)
	if err != nil {
		r.complete = false
		return dst
	}
	directives, ok := parseNginxDirectives(string(data), path)
	if !ok {
		r.complete = false
	}
	for _, d := range directives {
		if d.Module == "" {
			d.Module = module
		}
		if d.Context == "" {
			d.Context = context
		}
		if d.Name != "include" {
			dst = append(dst, d)
			continue
		}
		if len(d.Args) != 1 || d.Block {
			r.complete = false
			continue
		}
		target := d.Args[0]
		if !filepath.IsAbs(target) {
			target = joinWebConfigPath(r.prefix, target)
		}
		if !strings.ContainsAny(target, "*?[") {
			dst = r.read(dst, target, depth+1, d.Module, d.Context)
			continue
		}
		// An unreadable directory is not an empty one.
		matches, listed := checkedWebConfigGlob(target)
		if !listed {
			r.complete = false
		}
		sort.Strings(matches)
		for _, m := range matches {
			// nginx cannot read a directory as a configuration file.
			if info, statErr := osFS.Stat(m); statErr != nil || info.IsDir() {
				r.complete = false
				continue
			}
			dst = r.read(dst, m, depth+1, d.Module, d.Context)
		}
	}
	return dst
}

// parseNginxDirectives splits one file into directives with nginx's token
// rules (ngx_conf_read_token): a comment, a quote or a block brace starts
// only at a token boundary, a backslash escapes the next character, and
// "${" stays inside a variable. ok is false wherever nginx would refuse the
// file: an unterminated quote, statement or block, a stray brace or
// semicolon, text glued to a closing quote, or an empty directive name.
func parseNginxDirectives(text, file string) ([]nginxDirective, bool) {
	var out []nginxDirective
	var words []string
	modules := []string{""}
	contexts := []string{""}
	depth, start := 0, 0
	lastSpace, needSpace, comment, escaped, variable := true, false, false, false, false
	var quote byte
	ok := true
	statement := func(block bool) {
		if len(words) == 0 || words[0] == "" {
			ok = false
		} else {
			out = append(out, nginxDirective{
				Name: words[0], Args: words[1:], File: file,
				Module: modules[depth], Context: contexts[depth], Block: block,
			})
		}
		if block {
			module := modules[depth]
			if len(words) > 0 && (words[0] == "http" || words[0] == "stream") {
				module = words[0]
			}
			modules = append(modules, module)
			context := ""
			if len(words) > 0 {
				context = words[0]
			}
			contexts = append(contexts, context)
			depth++
		}
		words = nil
	}
	for i := 0; i < len(text); i++ {
		c := text[i]
		space := c == ' ' || c == '\t' || c == '\r' || c == '\n'
		switch {
		case comment:
			comment = c != '\n'
		case escaped:
			escaped = false
		case needSpace:
			needSpace = false
			switch {
			case space:
				lastSpace = true
			case c == ';' || c == '{':
				statement(c == '{')
				lastSpace = true
			case c == ')':
				// ngx_conf_read_token starts a new token with the closing
				// parenthesis after a quoted condition operand.
				start, lastSpace = i, false
			default:
				return out, false
			}
		case lastSpace:
			if space {
				continue
			}
			start = i
			switch c {
			case ';', '{':
				statement(c == '{')
				continue
			case '}':
				if len(words) != 0 || depth == 0 {
					ok = false
				} else {
					modules = modules[:depth]
					contexts = contexts[:depth]
					depth--
				}
				continue
			case '#':
				comment = true
				continue
			case '\\':
				escaped = true
			case '"', '\'':
				quote, start = c, i+1
			case '$':
				variable = true
			}
			lastSpace = false
		default:
			if c == '{' && variable {
				continue
			}
			variable = false
			switch {
			case c == '\\':
				escaped = true
				continue
			case c == '$':
				variable = true
				continue
			case quote != 0:
				if c != quote {
					continue
				}
				quote, needSpace = 0, true
			case space || c == ';' || c == '{':
				lastSpace = true
			default:
				continue
			}
			words = append(words, nginxUnescape(text[start:i]))
			if c == ';' || c == '{' {
				statement(c == '{')
			}
		}
	}
	return out, ok && depth == 0 && len(words) == 0 && lastSpace && !needSpace && quote == 0 && !escaped
}

// nginxUnescape decodes a token as nginx copies it: \", \', \\, \t, \r
// and \n are decoded; any other backslash is kept.
func nginxUnescape(token string) string {
	if !strings.Contains(token, "\\") {
		return token
	}
	var b strings.Builder
	for i := 0; i < len(token); i++ {
		if token[i] == '\\' && i+1 < len(token) {
			switch token[i+1] {
			case '"', '\'', '\\':
				i++
			case 't':
				b.WriteByte('\t')
				i++
				continue
			case 'r':
				b.WriteByte('\r')
				i++
				continue
			case 'n':
				b.WriteByte('\n')
				i++
				continue
			}
		}
		b.WriteByte(token[i])
	}
	return b.String()
}
