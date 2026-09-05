package main

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	defaultBackupMaxBytes = 16 << 30
	backupSpaceReserve    = 64 << 20
)

var errBackupSizeLimit = errors.New("backup exceeds uncompressed archive size limit; use --max-bytes to raise it for both backup and restore")

func backupArchiveLimit(maxBytes int64) (int64, error) {
	if maxBytes < 0 {
		return 0, errors.New("backup size limit must be positive")
	}
	if maxBytes == 0 {
		return defaultBackupMaxBytes, nil
	}
	return maxBytes, nil
}

type backupSizeWriter struct {
	w         io.Writer
	remaining int64
}

func (w *backupSizeWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.remaining {
		return 0, errBackupSizeLimit
	}
	n, err := w.w.Write(p)
	w.remaining -= int64(n)
	return n, err
}

type backupSizeReader struct{ io.LimitedReader }

func (r *backupSizeReader) Read(p []byte) (int, error) {
	if r.N == 0 {
		return 0, errBackupSizeLimit
	}
	return r.LimitedReader.Read(p)
}

var backupFreeBytes = filesystemFreeBytes

func filesystemFreeBytes(path string) (uint64, error) {
	var fs unix.Statfs_t
	if err := unix.Statfs(path, &fs); err != nil {
		return 0, err
	}
	// #nosec G115 -- Statfs returns a positive filesystem block size.
	return fs.Bavail * uint64(fs.Bsize), nil
}

func requireBackupSpace(path string, size int64) error {
	available, err := backupFreeBytes(path)
	if err != nil {
		return fmt.Errorf("checking backup space at %s: %w", path, err)
	}
	// #nosec G115 -- callers pass validated tar sizes or regular file sizes.
	needed := uint64(size)
	if needed > available || backupSpaceReserve > available-needed {
		return fmt.Errorf("insufficient backup space at %s: need %d bytes plus %d bytes reserve, have %d: %w", path, size, backupSpaceReserve, available, unix.ENOSPC)
	}
	return nil
}

func parseBackupRestoreArgs(args []string) (string, int64, error) {
	var archive string
	var maxBytes int64
	positional := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !positional && arg == "--" {
			positional = true
			continue
		}
		if !positional && strings.HasPrefix(arg, "--") {
			name, value, assigned := strings.Cut(arg, "=")
			switch name {
			case "--config", "--config-dir", "--max-bytes":
			default:
				return "", 0, fmt.Errorf("unknown backup/restore option %s", name)
			}
			if assigned && name != "--max-bytes" {
				return "", 0, fmt.Errorf("use %s <path> with a separate value", name)
			}
			if !assigned {
				i++
				if i == len(args) {
					return "", 0, fmt.Errorf("%s requires a value", name)
				}
				value = args[i]
			}
			if name == "--max-bytes" {
				parsed, err := strconv.ParseInt(value, 10, 64)
				if err != nil || parsed <= 0 {
					return "", 0, errors.New("--max-bytes must be a positive byte count")
				}
				maxBytes = parsed
			}
			continue
		}
		if !positional && strings.HasPrefix(arg, "-") {
			return "", 0, fmt.Errorf("unknown backup/restore option %s", arg)
		}
		if archive != "" {
			return "", 0, errors.New("backup/restore requires exactly one archive path")
		}
		archive = arg
	}
	if archive == "" {
		return "", 0, errors.New("backup/restore requires an archive path")
	}
	return archive, maxBytes, nil
}
