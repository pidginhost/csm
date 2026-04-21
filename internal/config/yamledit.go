package config

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// YAMLChange describes a single scalar, list, or map replacement to apply
// to a YAML document. Path is the dotted YAML key path from the document
// root. Value is the Go value to serialise; nil means YAML null.
type YAMLChange struct {
	Path  []string
	Value interface{}
}

// lineIndex maps 1-based line numbers to byte offsets of their first byte.
// lineIndex[i] is the byte offset of line i+1 (i.e. lineIndex[0] == 0 == start of line 1).
type lineIndex []int

func buildLineIndex(data []byte) lineIndex {
	idx := lineIndex{0} // line 1 starts at offset 0
	for i, b := range data {
		if b == '\n' {
			idx = append(idx, i+1) // line starts after the newline
		}
	}
	return idx
}

// offset returns the byte offset for a 1-based line and 1-based column.
func (li lineIndex) offset(line, col int) int {
	if line < 1 || line > len(li) {
		// line beyond end of file -- treat as EOF
		if len(li) == 0 {
			return 0
		}
		return li[len(li)-1]
	}
	return li[line-1] + col - 1
}

// lineEnd returns the byte offset of the '\n' at the end of the given 1-based line,
// or the length of data if the last line has no trailing newline.
func (li lineIndex) lineEnd(line int, data []byte) int {
	if line < len(li) {
		// next line starts at li[line]; the '\n' is at li[line]-1
		return li[line] - 1
	}
	// last line
	return len(data)
}

// lineStart returns the byte offset of the start of 1-based line.
func (li lineIndex) lineStart(line int) int {
	if line < 1 {
		return 0
	}
	if line > len(li) {
		return li[len(li)-1]
	}
	return li[line-1]
}

// maxLine returns the maximum Line value in the node subtree.
func maxLine(n *yaml.Node) int {
	m := n.Line
	for _, child := range n.Content {
		if cl := maxLine(child); cl > m {
			m = cl
		}
	}
	return m
}

// findNode walks the yaml.Node document tree and returns the key node and value node
// for the last segment of path, plus the parent mapping node.
// Returns (keyNode, valueNode, parentMapping, error).
func findNode(root *yaml.Node, path []string) (keyN, valN, parentMap *yaml.Node, err error) {
	// root should be a DocumentNode; its Content[0] is the real root mapping.
	cur := root
	if cur.Kind == yaml.DocumentNode {
		if len(cur.Content) == 0 {
			return nil, nil, nil, fmt.Errorf("empty document")
		}
		cur = cur.Content[0]
	}

	for i, seg := range path {
		if cur.Kind != yaml.MappingNode {
			return nil, nil, nil, fmt.Errorf("path %v: segment %q: expected mapping, got kind %d", path[:i+1], seg, cur.Kind)
		}
		found := false
		for j := 0; j+1 < len(cur.Content); j += 2 {
			k := cur.Content[j]
			v := cur.Content[j+1]
			if k.Value == seg {
				if i == len(path)-1 {
					return k, v, cur, nil
				}
				cur = v
				found = true
				break
			}
		}
		if !found {
			// segment not found; return the parent mapping so caller can insert
			if i == len(path)-1 {
				return nil, nil, cur, nil // key missing, parent is cur
			}
			return nil, nil, nil, fmt.Errorf("path %v: segment %q not found", path[:i+1], seg)
		}
	}
	return nil, nil, nil, fmt.Errorf("empty path")
}

// renderValueInline renders a scalar value to its YAML inline form.
// nil -> "null", bool -> "true"/"false", numbers via fmt, strings quoted if needed.
func renderValueInline(v interface{}) (string, error) {
	if v == nil {
		return "null", nil
	}
	// Use yaml.Marshal on a single-value map to get the marshalled scalar,
	// then extract just the value part.
	type wrapper struct {
		V interface{} `yaml:"v"`
	}
	b, err := yaml.Marshal(wrapper{V: v})
	if err != nil {
		return "", err
	}
	// b looks like "v: VALUE\n"
	s := strings.TrimPrefix(string(b), "v: ")
	s = strings.TrimSuffix(s, "\n")
	return s, nil
}

// renderKeyInline renders a mapping key string in a YAML-safe form.
// If the key needs quoting (contains special characters, starts with special
// indicators, etc.) yaml.Marshal will add the necessary quotes.
// Returns an error if the key cannot be represented as a single-line YAML key
// (e.g. the key itself contains literal newlines).
func renderKeyInline(key string) (string, error) {
	// Marshal a scalar node tagged !!str -- yaml.v3 will add quotes when the
	// bare value would be misinterpreted (e.g. "1", ":", " x").
	node := &yaml.Node{
		Kind:  yaml.ScalarNode,
		Value: key,
		Tag:   "!!str",
	}
	b, err := yaml.Marshal(node)
	if err != nil {
		return "", err
	}
	// yaml.Marshal of a scalar node produces "value\n"
	rendered := strings.TrimSuffix(string(b), "\n")
	// Block literal (|) and folded (>) scalars span multiple lines and cannot
	// serve as a simple inline mapping key (key: value on one line).
	if strings.ContainsAny(rendered, "\n\r") || strings.HasPrefix(rendered, "|") || strings.HasPrefix(rendered, ">") {
		return "", fmt.Errorf("key %q requires multi-line YAML representation and cannot be used as a simple mapping key", key)
	}
	return rendered, nil
}

// renderValueBlock renders a sequence or mapping value to a block of lines,
// indented at the given column (1-based). Returns lines like:
//
//	"      - a\n      - b\n"
func renderValueBlock(v interface{}, indent int) (string, error) {
	raw, err := yaml.Marshal(v)
	if err != nil {
		return "", err
	}
	// raw is like "- a\n- b\n" for a sequence, or "key: val\n" for a mapping.
	prefix := strings.Repeat(" ", indent-1)
	lines := strings.Split(string(raw), "\n")
	var sb strings.Builder
	for _, line := range lines {
		if line == "" {
			continue
		}
		sb.WriteString(prefix)
		sb.WriteString(line)
		sb.WriteByte('\n')
	}
	return sb.String(), nil
}

// isBlockValue returns true when the node needs block rendering (sequence or mapping
// that is not on the same line as its key).
func isBlockValue(keyN, valN *yaml.Node) bool {
	if valN.Kind == yaml.ScalarNode {
		return false
	}
	return valN.Line > keyN.Line
}

// splice replaces data[start:end] with replacement.
func splice(data []byte, start, end int, replacement []byte) []byte {
	var buf bytes.Buffer
	buf.Write(data[:start])
	buf.Write(replacement)
	buf.Write(data[end:])
	return buf.Bytes()
}

// edit holds a resolved splice operation.
type edit struct {
	start       int
	end         int
	replacement []byte
}

// YAMLEdit applies changes to data and returns the new document bytes.
// For every path that already exists, only the value span is rewritten
// at the same indent; untouched bytes (including all comments and
// whitespace) remain byte-identical. For a path that does not exist,
// a new key:value block is appended to the parent mapping at the parent's
// indent. Applies later edits first so earlier offsets remain valid.
func YAMLEdit(data []byte, changes []YAMLChange) ([]byte, error) {
	if len(changes) == 0 {
		return data, nil
	}

	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("yamledit: parse: %w", err)
	}

	li := buildLineIndex(data)

	var edits []edit

	for _, ch := range changes {
		if len(ch.Path) == 0 {
			return nil, fmt.Errorf("yamledit: empty path")
		}

		keyN, valN, parentMap, err := findNode(&root, ch.Path)
		if err != nil {
			return nil, fmt.Errorf("yamledit: %w", err)
		}

		if valN == nil {
			// Key does not exist -- insert into parentMap.
			ed, err := buildInsertEdit(data, li, parentMap, ch.Path[len(ch.Path)-1], ch.Value)
			if err != nil {
				return nil, fmt.Errorf("yamledit: insert %v: %w", ch.Path, err)
			}
			edits = append(edits, ed)
			continue
		}

		// Key exists -- replace value span.
		ed, err := buildReplaceEdit(data, li, keyN, valN, ch.Value)
		if err != nil {
			return nil, fmt.Errorf("yamledit: replace %v: %w", ch.Path, err)
		}
		edits = append(edits, ed)
	}

	// Sort by start offset descending so we splice end-to-start.
	sort.Slice(edits, func(i, j int) bool {
		return edits[i].start > edits[j].start
	})

	result := data
	for _, ed := range edits {
		result = splice(result, ed.start, ed.end, ed.replacement)
	}

	// Validate that the output is still parseable YAML. This catches edge cases
	// where unusual input formats (complex key notation, etc.) produce invalid output.
	var check yaml.Node
	if err := yaml.Unmarshal(result, &check); err != nil {
		return nil, fmt.Errorf("yamledit: output is not valid YAML: %w", err)
	}

	return result, nil
}

// buildReplaceEdit computes the splice for replacing an existing value node.
func buildReplaceEdit(data []byte, li lineIndex, keyN, valN *yaml.Node, value interface{}) (edit, error) {
	if isBlockValue(keyN, valN) {
		// Block sequence or mapping: value occupies one or more complete lines
		// starting at valN.Line. Replace from the start of valN.Line to the
		// end of the last line in the subtree.
		lastLine := maxLine(valN)
		start := li.lineStart(valN.Line)
		end := li.lineEnd(lastLine, data)
		if end < len(data) && data[end] == '\n' {
			end++ // include the trailing newline so we replace whole lines
		}
		rendered, err := renderValueBlock(value, valN.Column)
		if err != nil {
			return edit{}, err
		}
		return edit{start: start, end: end, replacement: []byte(rendered)}, nil
	}

	// Inline / scalar: replace from the value node's column to end of that line.
	// Leave the '\n' in place.
	start := li.offset(valN.Line, valN.Column)
	end := li.lineEnd(valN.Line, data)
	rendered, err := renderValueInline(value)
	if err != nil {
		return edit{}, err
	}
	return edit{start: start, end: end, replacement: []byte(rendered)}, nil
}

// buildInsertEdit computes the splice for appending a new key to a mapping node.
func buildInsertEdit(data []byte, li lineIndex, parentMap *yaml.Node, key string, value interface{}) (edit, error) {
	// Find the insertion point: end of the last content line of parentMap.
	// If parentMap has no content (empty mapping), insert after the mapping's own line.
	insertLine := parentMap.Line
	if len(parentMap.Content) > 0 {
		// last child is parentMap.Content[len-1]
		last := parentMap.Content[len(parentMap.Content)-1]
		insertLine = maxLine(last)
	}

	insertOff := li.lineEnd(insertLine, data)
	needsNewline := false
	if insertOff < len(data) && data[insertOff] == '\n' {
		insertOff++ // insert after the newline
	} else if insertOff > 0 && data[insertOff-1] != '\n' {
		// Last line has no trailing newline; we must add one before the new key.
		needsNewline = true
	}

	// Determine indent from the parent's column (1-based -> spaces).
	indent := parentMap.Column // column where parent mapping starts
	// For a top-level mapping, Column is typically 1.
	// Child keys should be indented by 2 relative to the parent.
	// But actually, parentMap.Column already tells us where this mapping starts.
	// We want to match the indent of sibling keys inside the mapping.
	// Sibling keys are at parentMap.Column (for top-level) or parentMap.Column+2 for nested.
	// Actually, look at first sibling key's column:
	siblingCol := indent
	if len(parentMap.Content) >= 1 {
		siblingCol = parentMap.Content[0].Column
	}

	prefix := strings.Repeat(" ", siblingCol-1)

	renderedKey, err := renderKeyInline(key)
	if err != nil {
		return edit{}, fmt.Errorf("render key %q: %w", key, err)
	}

	var rendered string
	// Determine if value needs block style.
	switch value.(type) {
	case []string, []interface{}:
		block, err := renderValueBlock(value, siblingCol+2)
		if err != nil {
			return edit{}, err
		}
		rendered = prefix + renderedKey + ":\n" + block
	default:
		inline, err := renderValueInline(value)
		if err != nil {
			return edit{}, err
		}
		rendered = prefix + renderedKey + ": " + inline + "\n"
	}
	if needsNewline {
		rendered = "\n" + rendered
	}

	return edit{start: insertOff, end: insertOff, replacement: []byte(rendered)}, nil
}
