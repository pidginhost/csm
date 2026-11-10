package corpusgate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"
)

// Only this reserved namespace is tool-owned. Flat caches from older versions
// may share an operator's directory, so they are read-only inputs.
const archiveCacheDir = ".csm-corpus-v1"

func openArchiveCache(parent *os.Root) (*os.Root, *os.File, error) {
	if err := parent.Mkdir(archiveCacheDir, 0700); err != nil && !os.IsExist(err) {
		return nil, nil, err
	}
	info, err := parent.Lstat(archiveCacheDir)
	if err != nil {
		return nil, nil, err
	}
	if !info.IsDir() {
		return nil, nil, fmt.Errorf("corpus archive namespace must be a directory, not a symlink")
	}
	root, err := parent.OpenRoot(archiveCacheDir)
	if err != nil {
		return nil, nil, err
	}
	// OpenRoot follows in-root symlinks. Compare the opened directory to the
	// checked inode so a replacement during open cannot redirect pruning.
	opened, err := root.Stat(".")
	if err != nil {
		_ = root.Close()
		return nil, nil, err
	}
	if !os.SameFile(info, opened) {
		_ = root.Close()
		return nil, nil, fmt.Errorf("corpus archive namespace changed while opening")
	}
	lock, err := root.OpenFile("lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		_ = root.Close()
		return nil, nil, err
	}
	// Keep this inode: unlinking it would let concurrent runs hold different
	// locks and prune each other's downloads. Closing releases the kernel lock.
	// #nosec G115 -- POSIX file descriptors fit in int.
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lock.Close()
		_ = root.Close()
		return nil, nil, fmt.Errorf("corpus archive cache is busy: %w", err)
	}
	return root, lock, nil
}

func cacheDigest(name, suffix string) bool {
	if !strings.HasSuffix(name, suffix) {
		return false
	}
	digest := strings.TrimSuffix(name, suffix)
	if len(digest) != sha256.Size*2 || digest != strings.ToLower(digest) {
		return false
	}
	_, err := hex.DecodeString(digest)
	return err == nil
}

func dropUnpinned(cache *os.Root, pinned map[string]bool) error {
	entries, err := fs.ReadDir(cache.FS(), ".")
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !e.Type().IsRegular() && e.Type()&os.ModeSymlink == 0 {
			continue
		}
		// Interrupted downloads never become reusable entries. The cache lock
		// makes every leftover temporary file safe to remove on the next run.
		retired := cacheDigest(e.Name(), ".zip") && !pinned[e.Name()]
		if cacheDigest(e.Name(), ".download") || retired {
			if err := cache.Remove(e.Name()); err != nil {
				return err
			}
		}
	}
	return nil
}

func cachedArchive(ctx context.Context, legacy, cache *os.Root, source Source) (*os.File, int64, error) {
	digest := strings.ToLower(source.SHA256)
	name := digest + ".zip"
	f, n, err := verifiedArchive(cache, name, digest)
	if err == nil {
		return f, n, nil
	}
	if !os.IsNotExist(err) {
		// Remove the entry itself, never a symlink target. A failed repair can
		// then be retried without trusting or repeatedly re-reading bad bytes.
		if err := cache.Remove(name); err != nil {
			return nil, 0, err
		}
	}
	// A valid flat archive still avoids a download. Its name is not proof of
	// ownership, so neither importing it nor retiring it may delete the input.
	for _, old := range []string{source.ID + "-" + source.SHA256 + ".zip", source.ID + "-" + source.Version + ".zip"} {
		if f, _, err := verifiedArchive(legacy, old, digest); err == nil {
			_, seekErr := f.Seek(0, io.SeekStart)
			if seekErr != nil {
				_ = f.Close()
				return nil, 0, seekErr
			}
			imported, n, err := storeArchive(cache, digest, f)
			closeErr := f.Close()
			if err == nil && closeErr != nil {
				_ = imported.Close()
				return nil, 0, closeErr
			}
			return imported, n, err
		}
	}
	return download(ctx, source.URL, cache, digest)
}

func verifiedArchive(cache *os.Root, name, digest string) (*os.File, int64, error) {
	info, err := cache.Lstat(name)
	if err != nil {
		return nil, 0, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxArchive {
		return nil, 0, fmt.Errorf("archive is not a regular file within the size limit")
	}
	f, err := cache.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, 0, err
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, maxArchive+1))
	if err != nil || n > maxArchive || hex.EncodeToString(h.Sum(nil)) != digest {
		_ = f.Close()
		return nil, 0, fmt.Errorf("archive checksum/size/read failure")
	}
	return f, n, nil
}

func download(ctx context.Context, address string, cache *os.Root, digest string) (*os.File, int64, error) {
	client := &http.Client{Timeout: 3 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" || len(via) >= 10 {
			return fmt.Errorf("unsafe corpus redirect")
		}
		return nil
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, 0, err
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("corpus download HTTP %d", response.StatusCode)
	}
	return storeArchive(cache, digest, response.Body)
}

func storeArchive(cache *os.Root, digest string, input io.Reader) (*os.File, int64, error) {
	tmp := digest + ".download"
	file, err := cache.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = cache.Remove(tmp) }()
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(file, h), io.LimitReader(input, maxArchive+1))
	closeErr := file.Close()
	if copyErr != nil {
		return nil, 0, copyErr
	}
	if closeErr != nil {
		return nil, 0, closeErr
	}
	if n > maxArchive || hex.EncodeToString(h.Sum(nil)) != digest {
		return nil, 0, fmt.Errorf("downloaded archive checksum/size failure")
	}
	name := digest + ".zip"
	if err := cache.Rename(tmp, name); err != nil {
		return nil, 0, err
	}
	// Verify and extract the same open file, including after publication.
	return verifiedArchive(cache, name, digest)
}
