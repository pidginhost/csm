//go:build !linux

package checks

import (
	"fmt"
	"os"
	"path/filepath"
)

func commitVirtualPatchTemp(tmp, htaccess string, state, tempState htaccessState) error {
	if !state.existed {
		if err := os.Link(tmp, htaccess); err != nil {
			return fmt.Errorf("committing new .htaccess without overwrite: %v", err)
		}
		if err := htaccessStateMatchesPath(htaccess, tempState); err != nil {
			if removeErr := os.Remove(htaccess); removeErr != nil {
				return fmt.Errorf("%w: temporary .htaccess changed and cleanup failed: %v", errVirtualPatchRollbackIncomplete, removeErr)
			}
			return fmt.Errorf("temporary .htaccess changed before commit: %v", err)
		}
		if err := os.Remove(tmp); err != nil {
			if removeErr := os.Remove(htaccess); removeErr != nil {
				return fmt.Errorf("%w: removing temporary link failed (%v) and cleanup failed: %v", errVirtualPatchRollbackIncomplete, err, removeErr)
			}
			return fmt.Errorf("removing temporary .htaccess link: %v", err)
		}
		return nil
	}
	if err := htaccessStateMatchesPath(htaccess, state); err != nil {
		return fmt.Errorf(".htaccess changed while preparing virtual-patch: %v", err)
	}
	oldFile, err := os.CreateTemp(filepath.Dir(htaccess), ".htaccess.csm-replaced-*")
	if err != nil {
		return fmt.Errorf("creating replacement placeholder: %v", err)
	}
	oldPath := oldFile.Name()
	if closeErr := oldFile.Close(); closeErr != nil {
		_ = os.Remove(oldPath)
		return fmt.Errorf("closing replacement placeholder: %v", closeErr)
	}
	if removeErr := os.Remove(oldPath); removeErr != nil {
		return fmt.Errorf("removing replacement placeholder: %v", removeErr)
	}
	if err := os.Rename(htaccess, oldPath); err != nil {
		return fmt.Errorf("isolating existing .htaccess: %v", err)
	}
	rollback := func(cause error) error {
		if rollbackErr := os.Rename(oldPath, htaccess); rollbackErr != nil {
			return fmt.Errorf("%w: %v; rollback failed: %v", errVirtualPatchRollbackIncomplete, cause, rollbackErr)
		}
		return cause
	}
	if err := htaccessStateMatchesPath(oldPath, state); err != nil {
		return rollback(fmt.Errorf(".htaccess changed while preparing virtual-patch: %v", err))
	}
	if err := os.Rename(tmp, htaccess); err != nil {
		return rollback(fmt.Errorf("installing replacement .htaccess: %v", err))
	}
	if err := htaccessStateMatchesPath(htaccess, tempState); err != nil {
		cause := fmt.Errorf("temporary .htaccess changed before commit: %v", err)
		if removeErr := os.Remove(htaccess); removeErr != nil {
			return fmt.Errorf("%w: %v; removing changed replacement failed: %v", errVirtualPatchRollbackIncomplete, cause, removeErr)
		}
		return rollback(cause)
	}
	if err := os.Remove(oldPath); err != nil {
		cause := fmt.Errorf("removing replaced .htaccess: %v", err)
		if removeErr := os.Remove(htaccess); removeErr != nil {
			return fmt.Errorf("%w: %v; removing replacement failed: %v", errVirtualPatchRollbackIncomplete, cause, removeErr)
		}
		return rollback(cause)
	}
	return nil
}

func removeVirtualPatchIfUnchanged(htaccess string, state htaccessState) error {
	if err := htaccessStateMatchesPath(htaccess, state); err != nil {
		return fmt.Errorf("live .htaccess changed: %v", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(htaccess), ".htaccess.csm-restore-*")
	if err != nil {
		return fmt.Errorf("creating restore placeholder: %v", err)
	}
	tmpPath := tmp.Name()
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("closing restore placeholder: %v", err)
	}
	if err := os.Remove(tmpPath); err != nil {
		return fmt.Errorf("removing restore placeholder: %v", err)
	}
	if err := os.Rename(htaccess, tmpPath); err != nil {
		return fmt.Errorf("isolating .htaccess for removal: %v", err)
	}
	if err := htaccessStateMatchesPath(tmpPath, state); err != nil {
		_ = os.Rename(tmpPath, htaccess)
		return fmt.Errorf("live .htaccess changed: %v", err)
	}
	if err := os.Remove(tmpPath); err != nil {
		_ = os.Rename(tmpPath, htaccess)
		return fmt.Errorf("removing patched .htaccess: %v", err)
	}
	return nil
}
