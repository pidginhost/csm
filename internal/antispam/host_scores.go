package antispam

import (
	"encoding/json"
	"strings"
)

// hostScores lists the symbols CSM weighs that the host's group files
// define. rspamd loads those files at the same priority as CSM's
// groups.conf and lets the later include, CSM's, win; the operator's
// weight must stay. A file CSM cannot read may define any of them.
func hostScores(files map[string]GroupFile) []string {
	var out []string
	for _, w := range scoreWeights {
		for _, f := range files {
			if f.Err != nil || definesSymbol(f.Content, w.symbol) {
				out = append(out, w.symbol)
				break
			}
		}
	}
	return out
}

// definesSymbol conservatively recognizes symbol tokens, including escaped
// keys and array definitions. Macros and unfamiliar string syntax may hide
// definitions, so leave their weights to the host without evaluating UCL or
// following includes. Comments must be lexed with strings, not stripped
// first: a quoted comment marker must never erase a later definition.
func definesSymbol(content, symbol string) bool {
	for i := 0; i < len(content); {
		switch {
		case strings.ContainsRune(" \t\r\n\v\f{}[]=:;,()", rune(content[i])):
			i++
		case content[i] == '#':
			for i < len(content) && content[i] != '\n' {
				i++
			}
		case strings.HasPrefix(content[i:], "/*"):
			i += 2
			depth := 1
			quoted := false
			for i < len(content) && depth > 0 {
				switch {
				case content[i] == '"' && content[i-1] != '\\':
					// UCL ignores comment delimiters inside quoted examples.
					quoted = !quoted
					i++
				case quoted:
					i++
				case strings.HasPrefix(content[i:], "/*"):
					depth++
					i += 2
				case strings.HasPrefix(content[i:], "*/"):
					depth--
					i += 2
				default:
					i++
				}
			}
			if depth != 0 {
				return true
			}
		case content[i] == '"' || content[i] == '\'':
			start, quote := i, content[i]
			i++
			for i < len(content) && content[i] != quote {
				if content[i] == '\\' {
					i++
				}
				i++
			}
			if i >= len(content) {
				return true
			}
			i++
			value := content[start+1 : i-1]
			if quote == '"' {
				if json.Unmarshal([]byte(content[start:i]), &value) != nil {
					return true
				}
			} else {
				value = strings.NewReplacer("\\'", "'", "\\\n", "").Replace(value)
			}
			if value == symbol {
				return true
			}
		default:
			start := i
			for i < len(content) && !strings.ContainsRune(" \t\r\n\v\f{}[]=:;,()#\"'", rune(content[i])) && !strings.HasPrefix(content[i:], "/*") {
				i++
			}
			token := content[start:i]
			macro := len(token) > 1 && token[0] == '.' && (token[1] >= 'a' && token[1] <= 'z' || token[1] >= 'A' && token[1] <= 'Z')
			if token == symbol || macro || strings.HasPrefix(token, "<<") {
				return true
			}
		}
	}
	return false
}
