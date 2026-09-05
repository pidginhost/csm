//go:build !linux && !darwin

package safepath

import "errors"

func renameat(_ int, _ string, _ int, _ string, _ bool) error {
	return errors.New("atomic restore rename is unsupported on this platform")
}
