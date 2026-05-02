package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadConfDir reads every *.yaml file in dir in lexicographic order and
// returns each as a parsed yaml.DocumentNode. A missing directory is not
// an error and returns an empty slice; an unreadable file or invalid YAML
// is fatal so operators see misconfigurations at startup.
func LoadConfDir(dir string) ([]*yaml.Node, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading %s: %w", dir, err)
	}

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !strings.HasSuffix(e.Name(), ".yaml") && !strings.HasSuffix(e.Name(), ".yml") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	out := make([]*yaml.Node, 0, len(names))
	for _, name := range names {
		path := filepath.Join(dir, name)
		// #nosec G304 -- dir is operator-supplied (config flag); name is filtered to .yaml/.yml.
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", path, err)
		}
		var node yaml.Node
		if err := yaml.Unmarshal(data, &node); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", path, err)
		}
		// Skip empty files (Unmarshal yields a zero-Content document).
		if len(node.Content) == 0 {
			continue
		}
		out = append(out, &node)
	}
	return out, nil
}
