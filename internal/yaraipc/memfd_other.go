//go:build !linux

package yaraipc

import (
	"errors"
	"os"
)

func sealedMemfd([]byte) (*os.File, error) {
	return nil, errors.New("yaraipc: byte scans need Linux memfds")
}
