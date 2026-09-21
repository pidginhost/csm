//go:build linux

package daemon

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"

	"github.com/pidginhost/csm/internal/yara"
	"github.com/pidginhost/csm/internal/yaraipc"
)

// scanRealtimeYARA preserves the event's bounded read across an IPC retry.
// Reopening the event path can read a replacement, and a full-file scan rejects
// a larger file when data holds only its prefix. A sealed memfd gives the worker
// exactly the original bytes without creating a file on a monitored mount.
func scanRealtimeYARA(backend yara.Backend, path string, data []byte) ([]yara.Match, string, error) {
	matches, err := yara.ScanBytesChecked(backend, path, data)
	if !errors.Is(err, yaraipc.ErrPayloadTooLarge) {
		return matches, "", err
	}

	fd, err := unix.MemfdCreate("csm-yara-snapshot", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, "", fmt.Errorf("create YARA snapshot: %w", err)
	}
	f := os.NewFile(uintptr(fd), "csm-yara-snapshot")
	defer f.Close()
	if _, err = f.Write(data); err != nil {
		return nil, "", fmt.Errorf("write YARA snapshot: %w", err)
	}
	if _, err = unix.FcntlInt(f.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL); err != nil {
		return nil, "", fmt.Errorf("seal YARA snapshot: %w", err)
	}

	// The worker has a different descriptor table. Keep our descriptor alive
	// until its synchronous scan returns, and name our process explicitly.
	snapshotPath := fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), fd)
	result, err := yara.ScanFileChecked(backend, snapshotPath, len(data))
	if err != nil {
		return nil, "", err
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(data))
	if result.ContentSHA256 != digest {
		return nil, "", errors.New("YARA retry scanned different content than the event snapshot")
	}
	return result.Matches, digest, nil
}
