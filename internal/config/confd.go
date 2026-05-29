package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"gopkg.in/yaml.v3"
)

type confFragment struct {
	path string
	node *yaml.Node
}

// ValidateConfDir vets an operator-selected conf.d directory before any YAML
// fragments are loaded from it. The returned path is symlink-resolved so later
// reads do not depend on a mutable link name.
func ValidateConfDir(dir string) (string, error) {
	if dir == "" {
		return "", nil
	}
	if !filepath.IsAbs(dir) {
		return "", fmt.Errorf("conf.d directory must be an absolute path, got %q", dir)
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("conf.d directory does not exist: %s", dir)
		}
		return "", fmt.Errorf("conf.d directory symlink resolution: %w", err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("conf.d directory stat: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("conf.d directory is not a directory: %s", resolved)
	}
	if trustErr := validateConfPathTrust("conf.d directory", resolved, info); trustErr != nil {
		return "", trustErr
	}
	return resolved, nil
}

// LoadConfDir reads every *.yaml file in dir in lexicographic order and
// returns each as a parsed yaml.DocumentNode. A missing directory is not
// an error and returns an empty slice; an unreadable file or invalid YAML
// is fatal so operators see misconfigurations at startup.
func LoadConfDir(dir string) ([]*yaml.Node, error) {
	frags, err := loadConfDirFragments(dir)
	if err != nil {
		return nil, err
	}
	out := make([]*yaml.Node, 0, len(frags))
	for _, frag := range frags {
		out = append(out, frag.node)
	}
	return out, nil
}

// ConfDirFragment is one conf.d drop-in fragment's filename and raw bytes,
// exported so the integrity hasher can cover the same fragment set the loader
// merges without duplicating the enumeration rules.
type ConfDirFragment struct {
	Name string
	Data []byte
}

// ConfDirFragmentDigestInput returns every non-empty trusted conf.d fragment in
// merge order (sorted .yaml/.yml, symlink-resolved, trust-validated) as
// name+content pairs for integrity hashing. An empty dir or no mergeable
// fragments yields nil so a config without conf.d hashes to the empty digest
// and its baseline is unaffected.
func ConfDirFragmentDigestInput(dir string) ([]ConfDirFragment, error) {
	files, err := confDirFragmentFiles(dir)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, nil
	}
	out := make([]ConfDirFragment, 0, len(files))
	for _, ff := range files {
		if _, ok, err := parseConfFragment(ff); err != nil {
			return nil, err
		} else if !ok {
			continue
		}
		out = append(out, ConfDirFragment{Name: ff.name, Data: ff.data})
	}
	return out, nil
}

type confFragmentFile struct {
	name string
	path string
	data []byte
}

// confDirFragmentFiles enumerates trusted conf.d fragment files and returns
// their raw bytes in merge order. Shared by loadConfDirFragments and the
// integrity hasher so both observe exactly the same fragment set.
func confDirFragmentFiles(dir string) ([]confFragmentFile, error) {
	if dir == "" {
		return nil, nil
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("conf.d directory symlink resolution: %w", err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("conf.d directory stat: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("conf.d directory is not a directory: %s", resolved)
	}
	if trustErr := validateConfPathTrust("conf.d directory", resolved, info); trustErr != nil {
		return nil, trustErr
	}
	dir = resolved
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

	out := make([]confFragmentFile, 0, len(names))
	for _, name := range names {
		path := filepath.Join(dir, name)
		data, err := readTrustedConfFragment(path)
		if err != nil {
			return nil, err
		}
		out = append(out, confFragmentFile{name: name, path: path, data: data})
	}
	return out, nil
}

func loadConfDirFragments(dir string) ([]confFragment, error) {
	files, err := confDirFragmentFiles(dir)
	if err != nil {
		return nil, err
	}
	out := make([]confFragment, 0, len(files))
	for _, ff := range files {
		node, ok, err := parseConfFragment(ff)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		out = append(out, confFragment{path: ff.path, node: node})
	}
	return out, nil
}

func parseConfFragment(ff confFragmentFile) (*yaml.Node, bool, error) {
	var node yaml.Node
	if err := yaml.Unmarshal(ff.data, &node); err != nil {
		return nil, false, fmt.Errorf("parsing %s: %w", ff.path, err)
	}
	// Skip empty files (Unmarshal yields a zero-Content document).
	if len(node.Content) == 0 {
		return nil, false, nil
	}
	if hasTopLevelKey(&node, "integrity") {
		return nil, false, fmt.Errorf("conf.d fragment %s must not set daemon-managed integrity metadata", ff.path)
	}
	return &node, true, nil
}

func hasTopLevelKey(root *yaml.Node, key string) bool {
	cur := root
	if cur.Kind == yaml.DocumentNode {
		if len(cur.Content) == 0 {
			return false
		}
		cur = cur.Content[0]
	}
	if cur.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i+1 < len(cur.Content); i += 2 {
		if cur.Content[i].Value == key {
			return true
		}
	}
	return false
}

func readTrustedConfFragment(path string) ([]byte, error) {
	// #nosec G304 -- path is built from an operator-selected conf.d and a directory entry.
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("conf.d fragment is not a regular file: %s", path)
	}
	if trustErr := validateConfPathTrust("conf.d fragment", path, info); trustErr != nil {
		return nil, trustErr
	}
	data, err := readConfigBytesLimited(f)
	if errors.Is(err, errConfigTooLarge) {
		return nil, fmt.Errorf("conf.d fragment %s exceeds %d byte cap", path, MaxConfigBytes)
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return data, nil
}

func validateConfPathTrust(kind, path string, info os.FileInfo) error {
	if mode := info.Mode().Perm(); mode&0022 != 0 {
		return fmt.Errorf("%s %s has unsafe mode %04o (group or world writable); set 0750/0640 or stricter", kind, path, mode)
	}
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	// #nosec G115 -- Linux uid_t is uint32; os.Geteuid returns the kernel
	// effective UID and cannot overflow that type on supported hosts.
	selfUID := uint32(os.Geteuid())
	if sys.Uid != 0 && sys.Uid != selfUID {
		return fmt.Errorf("%s %s owner uid=%d is neither root (0) nor process uid=%d; refusing to load untrusted YAML", kind, path, sys.Uid, selfUID)
	}
	return nil
}
