package checks

import "path/filepath"

// DocrootIndex holds the web document roots, normalized once per refresh.
// Lookups run on every file event and every process start, so they walk the
// path's ancestors instead of the root list: the cost follows path depth, not
// the number of docroots on the host.
type DocrootIndex struct {
	roots map[string]struct{}
}

// NewDocrootIndex indexes docroots. Relative entries are ignored.
func NewDocrootIndex(docroots []string) *DocrootIndex {
	idx := &DocrootIndex{roots: make(map[string]struct{}, len(docroots))}
	for _, configuredRoot := range docroots {
		root := filepath.Clean(configuredRoot)
		if filepath.IsAbs(root) {
			idx.roots[root] = struct{}{}
		}
	}
	return idx
}

// Lookup returns the longest docroot that contains path, or "" when the path
// is not inside any docroot. Matching is component-safe:
// /home/a/public_html_old is not inside /home/a/public_html.
func (idx *DocrootIndex) Lookup(path string) string {
	if idx == nil || len(idx.roots) == 0 {
		return ""
	}
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) {
		return ""
	}
	// The first ancestor found is the deepest, so the longest root wins. A
	// path equal to a root is not inside it, so the walk starts at the parent.
	for dir := path; ; {
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		if _, ok := idx.roots[parent]; ok {
			return parent
		}
		dir = parent
	}
}
