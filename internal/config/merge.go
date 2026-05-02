package config

import "gopkg.in/yaml.v3"

// DeepMerge merges overlay into base in place and returns base.
// Both inputs must be DocumentNodes. Rules:
//   - mapping ∩ mapping → key-by-key recurse
//   - sequence ∩ sequence → append (base then overlay)
//   - any other combination → overlay replaces base
//
// AliasNodes are treated as opaque scalars: an overlay alias replaces the
// base node; an alias inside base/overlay is not resolved before merging.
func DeepMerge(base, overlay *yaml.Node) *yaml.Node {
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
	mergeNodes(base.Content[0], overlay.Content[0])
	return base
}

func mergeNodes(b, o *yaml.Node) {
	switch {
	case b.Kind == yaml.MappingNode && o.Kind == yaml.MappingNode:
		mergeMap(b, o)
	case b.Kind == yaml.SequenceNode && o.Kind == yaml.SequenceNode:
		b.Content = append(b.Content, o.Content...)
	default:
		*b = *o
	}
}

func mergeMap(b, o *yaml.Node) {
	for i := 0; i+1 < len(o.Content); i += 2 {
		key := o.Content[i].Value
		val := o.Content[i+1]
		if idx := findKey(b, key); idx >= 0 {
			mergeNodes(b.Content[idx+1], val)
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
