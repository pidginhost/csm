//go:build !darwin && !linux

package checks

import "os"

func selfWriteIdentityFromFileInfo(os.FileInfo) (selfWriteFileIdentity, bool) {
	return selfWriteFileIdentity{}, false
}
