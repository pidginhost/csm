package checks

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pidginhost/csm/internal/quarantinefs"
	"github.com/pidginhost/csm/internal/safepath"
	"golang.org/x/sys/unix"
)

func quarantineTarget(path, qPath string, info os.FileInfo, metadata QuarantineMeta) error {
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding quarantine metadata: %w", err)
	}
	if err := quarantinefs.EnsureDir(filepath.Dir(qPath), 0700); err != nil {
		return err
	}
	if info.IsDir() {
		return quarantineDirectory(path, qPath, info, data)
	}
	return quarantineFileTOCTOUSafe(path, qPath, info, data)
}

var storeQuarantineBackup = func(path string, content []byte, metadata QuarantineMeta, mode os.FileMode) error {
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding quarantine metadata: %w", err)
	}
	return quarantinefs.Store(path, bytes.NewReader(content), data, mode)
}

var syncQuarantineTree = quarantinefs.SyncTree
var syncQuarantineDirectory = (*safepath.Dir).Sync
var renameQuarantineDirectory = (*safepath.Dir).RenameTo

func quarantineDirectory(path, qPath string, expected os.FileInfo, metadata []byte) error {
	source, err := safepath.OpenDir(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer func() { _ = source.Close() }()
	quarantine, err := safepath.OpenDir(filepath.Dir(qPath))
	if err != nil {
		return err
	}
	defer func() { _ = quarantine.Close() }()
	sourceName, name := filepath.Base(path), filepath.Base(qPath)
	dir, err := source.OpenFile(sourceName, os.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return err
	}
	defer dir.Close()
	info, err := dir.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(info, expected) {
		return errors.New("quarantine directory changed before capture")
	}
	if err := syncQuarantineTree(path, info); err != nil {
		return fmt.Errorf("syncing quarantine directory: %w", err)
	}
	if err := dir.Close(); err != nil {
		return fmt.Errorf("closing quarantine directory before move: %w", err)
	}
	if err := quarantinefs.WriteExclusive(qPath+".meta", bytes.NewReader(metadata), 0600); err != nil {
		return fmt.Errorf("writing quarantine directory metadata: %w", err)
	}
	if err := renameQuarantineDirectory(source, sourceName, quarantine, name); err != nil {
		return errors.Join(fmt.Errorf("moving quarantine directory: %w", err), os.Remove(qPath+".meta"))
	}
	got, statErr := quarantine.Stat(name)
	if statErr != nil || !os.SameFile(got, info) {
		if rollbackErr := quarantine.RenameTo(name, source, sourceName); rollbackErr != nil {
			return fmt.Errorf("quarantine directory changed during capture; displaced directory retained at %s: %w", qPath, rollbackErr)
		}
		if syncErr := errors.Join(source.Sync(), quarantine.Sync()); syncErr != nil {
			return fmt.Errorf("quarantine directory changed; rollback sync failed, inspect %s and %s: %w", path, qPath, syncErr)
		}
		if removeErr := os.Remove(qPath + ".meta"); removeErr != nil {
			return fmt.Errorf("quarantine directory changed; original name restored but metadata retained at %s: %w", qPath+".meta", removeErr)
		}
		return errors.New("quarantine directory changed during capture; original name restored")
	}
	if err := syncQuarantineDirectory(quarantine); err != nil {
		return fmt.Errorf("quarantine directory moved to %s, but destination sync failed; inspect both %s and %s before retrying: %w", qPath, path, qPath, err)
	}
	if err := syncQuarantineDirectory(source); err != nil {
		return fmt.Errorf("quarantine directory retained at %s, but source removal is not durable; inspect %s before retrying: %w", qPath, path, err)
	}
	return nil
}
