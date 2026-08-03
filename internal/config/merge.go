package config

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

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

const maxYAMLMergeExpansionNodes = 100_000

// normalizeYAMLForMerge resolves aliases and YAML merge keys before custom
// main+conf.d merging. Scalar nodes are preserved verbatim: decoding through
// interface{} would coerce date-like strings and other tagged values before
// Config gets its typed decode.
func normalizeYAMLForMerge(root *yaml.Node) (*yaml.Node, error) {
	if root == nil || !containsAliasOrMerge(root) {
		return root, nil
	}
	n := yamlMergeNormalizer{active: make(map[*yaml.Node]bool)}
	// The initial scan already proved the tree needs normalization. Clone the
	// whole tree in one pass so a deeply nested alias cannot make each ancestor
	// rescan the same descendants.
	return n.normalize(root)
}

func containsAliasOrMerge(node *yaml.Node) bool {
	if node == nil {
		return false
	}
	if node.Kind == yaml.AliasNode {
		return true
	}
	if node.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(node.Content); i += 2 {
			if isYAMLMergeKey(node.Content[i]) {
				return true
			}
		}
	}
	for _, child := range node.Content {
		if containsAliasOrMerge(child) {
			return true
		}
	}
	return false
}

type yamlMergeNormalizer struct {
	active  map[*yaml.Node]bool
	created int
}

func (n *yamlMergeNormalizer) normalize(node *yaml.Node) (*yaml.Node, error) {
	if node == nil {
		return nil, nil
	}
	if node.Kind == yaml.AliasNode {
		if node.Alias == nil {
			return nil, fmt.Errorf("YAML alias %q has no anchor", node.Value)
		}
		if n.active[node.Alias] {
			return nil, fmt.Errorf("YAML anchor %q contains itself", node.Value)
		}
		return n.normalize(node.Alias)
	}
	if n.active[node] {
		return nil, fmt.Errorf("YAML anchor %q contains itself", node.Anchor)
	}
	if n.created >= maxYAMLMergeExpansionNodes {
		return nil, fmt.Errorf("YAML alias expansion exceeds %d nodes", maxYAMLMergeExpansionNodes)
	}
	n.created++
	n.active[node] = true
	defer delete(n.active, node)

	if node.Kind == yaml.MappingNode {
		return n.normalizeMapping(node)
	}

	clone := *node
	clone.Anchor = ""
	clone.Alias = nil
	clone.Content = make([]*yaml.Node, 0, len(node.Content))
	for _, child := range node.Content {
		normalized, err := n.normalize(child)
		if err != nil {
			return nil, err
		}
		clone.Content = append(clone.Content, normalized)
	}
	return &clone, nil
}

func (n *yamlMergeNormalizer) normalizeMapping(node *yaml.Node) (*yaml.Node, error) {
	clone := *node
	clone.Anchor = ""
	clone.Alias = nil
	clone.Content = make([]*yaml.Node, 0, len(node.Content))
	explicit := make(map[string]bool, len(node.Content)/2)
	var mergeValue *yaml.Node

	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i]
		if isYAMLMergeKey(key) {
			if mergeValue != nil {
				return nil, fmt.Errorf("YAML mapping contains multiple merge keys")
			}
			mergeValue = node.Content[i+1]
			continue
		}
		normalizedKey, err := n.normalize(key)
		if err != nil {
			return nil, err
		}
		normalizedValue, err := n.normalize(node.Content[i+1])
		if err != nil {
			return nil, err
		}
		clone.Content = append(clone.Content, normalizedKey, normalizedValue)
		if id, ok := yamlScalarKeyID(normalizedKey); ok {
			explicit[id] = true
		}
	}

	if mergeValue == nil {
		return &clone, nil
	}
	mergeMappings, err := n.normalizeMergeValue(mergeValue)
	if err != nil {
		return nil, err
	}
	for _, mapping := range mergeMappings {
		if err := validateMergeMappingKeys(mapping); err != nil {
			return nil, err
		}
		for i := 0; i+1 < len(mapping.Content); i += 2 {
			id, _ := yamlScalarKeyID(mapping.Content[i])
			if explicit[id] {
				continue
			}
			explicit[id] = true
			clone.Content = append(clone.Content, mapping.Content[i], mapping.Content[i+1])
		}
	}
	return &clone, nil
}

func (n *yamlMergeNormalizer) normalizeMergeValue(node *yaml.Node) ([]*yaml.Node, error) {
	normalized, err := n.normalize(node)
	if err != nil {
		return nil, err
	}
	switch normalized.Kind {
	case yaml.MappingNode:
		return []*yaml.Node{normalized}, nil
	case yaml.SequenceNode:
		mappings := make([]*yaml.Node, 0, len(normalized.Content))
		for _, child := range normalized.Content {
			if child.Kind != yaml.MappingNode {
				return nil, fmt.Errorf("YAML map merge requires a map or sequence of maps")
			}
			mappings = append(mappings, child)
		}
		return mappings, nil
	default:
		return nil, fmt.Errorf("YAML map merge requires a map or sequence of maps")
	}
}

func validateMergeMappingKeys(mapping *yaml.Node) error {
	seen := make(map[string]bool, len(mapping.Content)/2)
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		id, ok := yamlScalarKeyID(mapping.Content[i])
		if !ok {
			return fmt.Errorf("YAML map merge contains a non-scalar key")
		}
		if seen[id] {
			return fmt.Errorf("YAML map merge contains duplicate key %q", mapping.Content[i].Value)
		}
		seen[id] = true
	}
	return nil
}

func yamlScalarKeyID(key *yaml.Node) (string, bool) {
	if key == nil || key.Kind != yaml.ScalarNode {
		return "", false
	}
	return key.ShortTag() + "\x00" + key.Value, true
}

func isYAMLMergeKey(key *yaml.Node) bool {
	return key != nil && key.Kind == yaml.ScalarNode && key.Value == "<<" &&
		(key.Tag == "" || key.Tag == "!" || key.ShortTag() == "!!merge")
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
