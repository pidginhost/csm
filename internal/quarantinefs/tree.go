package quarantinefs

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"golang.org/x/sys/unix"
)

// SyncTree persists a directory being moved without following symlinks inside
// it. expected binds the traversal to the directory admitted by the caller.
func SyncTree(path string, expected os.FileInfo) error {
	root, err := os.OpenRoot(path)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	info, err := root.Stat(".")
	if err != nil {
		return err
	}
	if !info.IsDir() || !os.SameFile(info, expected) {
		return fmt.Errorf("quarantine directory changed before syncing")
	}
	var directories []string
	err = fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			directories = append(directories, name)
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		file, openErr := root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if openErr != nil {
			return openErr
		}
		info, statErr := file.Stat()
		if statErr != nil || !info.Mode().IsRegular() {
			_ = file.Close()
			return fmt.Errorf("cannot sync non-regular quarantine entry %s: %v", name, statErr)
		}
		return errors.Join(syncFile(file), closeFile(file))
	})
	if err != nil {
		return err
	}
	// Persist child contents before the directory entries that make them reachable.
	for i := len(directories) - 1; i >= 0; i-- {
		dir, openErr := root.OpenFile(directories[i], os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		if openErr != nil {
			return openErr
		}
		if err := errors.Join(syncFile(dir), closeFile(dir)); err != nil {
			return err
		}
	}
	return nil
}
