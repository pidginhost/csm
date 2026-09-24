package integrity

import (
	"fmt"
	"os"
)

// FileChangeKey changes when the file behind info is replaced or rewritten:
// its size and modification time, plus on Linux its device, inode and change
// time, which a rewrite cannot keep even when size and mtime match.
func FileChangeKey(info os.FileInfo) string {
	return fmt.Sprintf("%d:%d:%s", info.Size(), info.ModTime().UnixNano(), fileChangeIdentity(info))
}
