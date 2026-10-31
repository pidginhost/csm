//go:build !linux

package yaraipc

import (
	"errors"
	"os"
)

// SealedMemfd needs Linux memfds.
func SealedMemfd(string, []byte) (*os.File, error) {
	return nil, errors.New("yaraipc: memfds need Linux")
}

// CopySealedMemfd needs Linux memfds.
func CopySealedMemfd(string, *os.File, int64) (*os.File, error) {
	return nil, errors.New("yaraipc: memfds need Linux")
}
