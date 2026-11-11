package modsec

import "strings"

// RuleMetadata contains the literal message and tags from a rule's action
// list. Macro references are removed: their names are not attack evidence,
// and their expanded values can be controlled by the request.
type RuleMetadata struct {
	Message, Tags string
}

// Metadata returns configuration text, never macro-expanded log text. The
// value contains no mutable state and belongs to the same snapshot as Action.
func (r *Registry) Metadata(ruleID int) (RuleMetadata, bool) {
	if r == nil {
		return RuleMetadata{}, false
	}
	m, ok := r.metadata[ruleID]
	return m, ok
}

func ruleMetadata(raw string) RuleMetadata {
	// A chain's metadata belongs to its starter. Operators and chained
	// conditions can contain msg/tag-like text without defining either.
	line, _, _ := strings.Cut(raw, "\n")
	var m RuleMetadata
	var tags []string
	for _, token := range tokenizeActionString(secRuleActions(line)) {
		name, value, ok := strings.Cut(token, ":")
		if !ok {
			continue
		}
		name = strings.ToLower(strings.TrimSpace(name))
		if name != "msg" && name != "tag" {
			continue
		}
		value = strings.TrimSpace(value)
		if strings.HasPrefix(value, "'") {
			var rest string
			value, rest, ok = configArgument(value)
			if !ok || strings.TrimSpace(rest) != "" {
				continue
			}
		}
		value = literalMetadataText(value)
		if name == "msg" {
			m.Message = value
		} else {
			tags = append(tags, value)
		}
	}
	m.Tags = strings.Join(tags, " ")
	return m
}

func literalMetadataText(value string) string {
	var literal strings.Builder
	for {
		before, rest, macro := strings.Cut(value, "%{")
		literal.WriteString(before)
		if !macro {
			return literal.String()
		}
		// Keep the surrounding words separate rather than creating a keyword.
		literal.WriteByte(' ')
		_, value, _ = strings.Cut(rest, "}")
	}
}
