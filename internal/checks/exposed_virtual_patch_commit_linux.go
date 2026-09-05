//go:build linux

package checks

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func commitVirtualPatchTemp(tmp, htaccess string, state, tempState htaccessState) error {
	if !state.existed {
		if err := unix.Renameat2(unix.AT_FDCWD, tmp, unix.AT_FDCWD, htaccess, unix.RENAME_NOREPLACE); err != nil {
			if errors.Is(err, unix.EEXIST) {
				return fmt.Errorf(".htaccess changed while preparing virtual-patch")
			}
			return fmt.Errorf("committing new .htaccess: %v", err)
		}
		if err := htaccessStateMatchesPath(htaccess, tempState); err != nil {
			if rollbackErr := unix.Renameat2(unix.AT_FDCWD, htaccess, unix.AT_FDCWD, tmp, unix.RENAME_NOREPLACE); rollbackErr != nil {
				return fmt.Errorf("%w: temporary .htaccess changed and rollback failed: %v", errVirtualPatchRollbackIncomplete, rollbackErr)
			}
			return fmt.Errorf("temporary .htaccess changed before commit: %v", err)
		}
		return nil
	}

	if err := unix.Renameat2(unix.AT_FDCWD, tmp, unix.AT_FDCWD, htaccess, unix.RENAME_EXCHANGE); err != nil {
		return fmt.Errorf("atomically exchanging .htaccess: %v", err)
	}
	oldErr := htaccessStateMatchesPath(tmp, state)
	newErr := htaccessStateMatchesPath(htaccess, tempState)
	if oldErr != nil || newErr != nil {
		if rollbackErr := unix.Renameat2(unix.AT_FDCWD, tmp, unix.AT_FDCWD, htaccess, unix.RENAME_EXCHANGE); rollbackErr != nil {
			return fmt.Errorf("%w: .htaccess changed while preparing virtual-patch and rollback failed: %v", errVirtualPatchRollbackIncomplete, rollbackErr)
		}
		if oldErr != nil {
			return fmt.Errorf(".htaccess changed while preparing virtual-patch: %v", oldErr)
		}
		return fmt.Errorf("temporary .htaccess changed before commit: %v", newErr)
	}
	if err := os.Remove(tmp); err != nil {
		if rollbackErr := unix.Renameat2(unix.AT_FDCWD, tmp, unix.AT_FDCWD, htaccess, unix.RENAME_EXCHANGE); rollbackErr != nil {
			return fmt.Errorf("%w: removing replaced .htaccess failed (%v) and rollback failed: %v", errVirtualPatchRollbackIncomplete, err, rollbackErr)
		}
		_ = os.Remove(tmp)
		return fmt.Errorf("removing replaced .htaccess: %v", err)
	}
	return nil
}
