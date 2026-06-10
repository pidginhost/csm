package config

import "gopkg.in/yaml.v3"

// CollisionFn is invoked when DeepMergeTracked detects a scalar in the
// overlay overwriting a different scalar in the base. Identical-value
// rewrites are not reported because the operator cannot act on them.
// keyPath uses dotted YAML notation rooted at the document
// ("mail_logs.source"); top-level keys have no parent.
type CollisionFn func(keyPath, oldVal, newVal string)

// DeepMerge merges overlay into base in place and returns base.
// Both inputs must be DocumentNodes. Rules:
//   - mapping ∩ mapping → key-by-key recurse
//   - sequence ∩ sequence → append (base then overlay), with duplicate
//     scalar entries removed from all-scalar lists
//   - any other combination → overlay replaces base
//
// AliasNodes are treated as opaque scalars: an overlay alias replaces the
// base node; an alias inside base/overlay is not resolved before merging.
func DeepMerge(base, overlay *yaml.Node) *yaml.Node {
	return DeepMergeTracked(base, overlay, nil)
}

// DeepMergeTracked is DeepMerge with an optional collision callback. The
// callback fires once per scalar-vs-scalar override across the document
// tree. Callers can pass nil for the previous DeepMerge behaviour.
func DeepMergeTracked(base, overlay *yaml.Node, onCollision CollisionFn) *yaml.Node {
	if base == nil || overlay == nil {
		return base
	}
	// An empty yaml.Unmarshal result has Kind==0; treat it as an empty document.
	if base.Kind == 0 {
		base.Kind = yaml.DocumentNode
	}
	if overlay.Kind == 0 {
		overlay.Kind = yaml.DocumentNode
	}
	if base.Kind != yaml.DocumentNode || overlay.Kind != yaml.DocumentNode {
		return base
	}
	if len(overlay.Content) == 0 {
		return base
	}
	if len(base.Content) == 0 {
		base.Content = overlay.Content
		return base
	}
	mergeNodesAt(base.Content[0], overlay.Content[0], "", onCollision)
	return base
}

func mergeNodesAt(b, o *yaml.Node, path string, onCollision CollisionFn) {
	switch {
	case b.Kind == yaml.MappingNode && o.Kind == yaml.MappingNode:
		mergeMapAt(b, o, path, onCollision)
	case b.Kind == yaml.SequenceNode && o.Kind == yaml.SequenceNode:
		b.Content = dedupScalarSequence(append(b.Content, o.Content...))
	default:
		if onCollision != nil && b.Kind == yaml.ScalarNode && o.Kind == yaml.ScalarNode && b.Value != o.Value {
			onCollision(path, b.Value, o.Value)
		}
		*b = *o
	}
}

// dedupScalarSequence removes duplicate scalar entries (by value+tag),
// keeping the first occurrence and preserving order. It only acts when every
// element is a scalar: lists of maps (e.g. webui.tokens) keep every entry,
// where position and identity matter. Idempotent-by-content security lists
// (infra_ips, c2_blocklist, trusted_countries, disabled_checks) merged from a
// fragment that repeats a main-config entry would otherwise carry duplicates
// into validation and enforcement on every load.
func dedupScalarSequence(content []*yaml.Node) []*yaml.Node {
	for _, n := range content {
		if n.Kind != yaml.ScalarNode {
			return content
		}
	}
	seen := make(map[string]struct{}, len(content))
	out := content[:0]
	for _, n := range content {
		key := n.Tag + "\x00" + n.Value
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, n)
	}
	return out
}

func mergeMapAt(b, o *yaml.Node, parent string, onCollision CollisionFn) {
	for i := 0; i+1 < len(o.Content); i += 2 {
		key := o.Content[i].Value
		val := o.Content[i+1]
		childPath := key
		if parent != "" {
			childPath = parent + "." + key
		}
		if idx := findKey(b, key); idx >= 0 {
			mergeNodesAt(b.Content[idx+1], val, childPath, onCollision)
		} else {
			b.Content = append(b.Content, o.Content[i], val)
		}
	}
}

func findKey(m *yaml.Node, key string) int {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return i
		}
	}
	return -1
}
