// Package sourcewalk supports source inventories in a checkout shared with tests.
package sourcewalk

import (
	"errors"
	"io/fs"
)

// IgnoreVanished lets a walk continue when another test removes a descendant.
// Root errors and errors returned by the visitor still fail the inventory.
func IgnoreVanished(root string, visit fs.WalkDirFunc) fs.WalkDirFunc {
	return func(name string, entry fs.DirEntry, err error) error {
		if name != root && errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return visit(name, entry, err)
	}
}
