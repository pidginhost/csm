package attackcorpus

import (
	"fmt"
	"os"
	"path/filepath"
)

// Plant writes the sample's files into an account tree: root/account/<path>,
// and the @crontab file to cronDir/account. It returns each sample path's
// absolute path. It never writes onto an existing file or symlink, nor through
// a symlink that leads out of either tree, because a private corpus is input
// this harness does not control.
func (s Sample) Plant(root, cronDir, account string) (map[string]string, error) {
	planted := make(map[string]string, len(s.Files))
	for _, f := range s.Files {
		data, err := s.Content(f)
		if err != nil {
			return nil, fmt.Errorf("plant %s: %w", f.Path, err)
		}
		base, rel := root, filepath.Join(account, f.Path)
		if f.Path == "@crontab" {
			base, rel = cronDir, account
		}
		if err := writeNew(base, rel, data, os.FileMode(f.Mode)); err != nil {
			return nil, fmt.Errorf("plant %s: %w", f.Path, err)
		}
		planted[f.Path] = filepath.Join(base, rel)
	}
	return planted, nil
}

// writeNew creates base/rel through an os.Root, which refuses symlinks that
// leave base, and O_EXCL refuses a symlink or file already at rel.
func writeNew(base, rel string, data []byte, mode os.FileMode) error {
	if mode == 0 {
		mode = 0o644
	}
	// #nosec G301 -- account trees get the directory mode a real home has.
	if err := os.MkdirAll(base, 0o755); err != nil {
		return err
	}
	r, err := os.OpenRoot(base)
	if err != nil {
		return err
	}
	defer func() { _ = r.Close() }()
	if err = r.MkdirAll(filepath.Dir(rel), 0o755); err != nil {
		return err
	}
	f, err := r.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	// The umask would otherwise drop bits such as the world-write a sample sets.
	if err == nil {
		err = f.Chmod(mode)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// Attribute maps an absolute path to its sample path: "@crontab" for the
// account's crontab, the path relative to the account home for anything
// inside it, and "" for everything else.
func Attribute(abs, root, cronDir, account string) string {
	if abs == filepath.Join(cronDir, account) {
		return "@crontab"
	}
	rel, err := filepath.Rel(filepath.Join(root, account), abs)
	if err != nil || rel == "." || !filepath.IsLocal(rel) {
		return ""
	}
	return filepath.ToSlash(rel)
}
