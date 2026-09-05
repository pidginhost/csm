// Package corpusgate provisions pinned clean applications for detector tests.
package corpusgate

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Manifest struct {
	Version int      `json:"version"`
	Sources []Source `json:"sources"`
}

type Source struct {
	ID          string `json:"id"`
	Version     string `json:"version"`
	URL         string `json:"url"`
	SHA256      string `json:"sha256"`
	License     string `json:"license"`
	LicenseFile string `json:"license_file"`
	Files       int    `json:"files"`
}

type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

const maxArchive = 512 << 20
const maxExpanded = 1 << 30

// Prepare refuses to reuse extracted trees: only authenticated archive caches
// survive runs, so removed vendor files cannot inflate the next inventory.
func Prepare(ctx context.Context, manifest Manifest, cache, destination string) ([]File, error) {
	if manifest.Version != 1 || len(manifest.Sources) == 0 {
		return nil, fmt.Errorf("empty or unsupported corpus manifest")
	}
	seen := make(map[string]bool)
	for _, s := range manifest.Sources {
		u, err := url.Parse(s.URL)
		digest, hashErr := hex.DecodeString(s.SHA256)
		if err != nil || u.Scheme != "https" || u.Host == "" || hashErr != nil || len(digest) != sha256.Size || s.ID == "" || s.Version == "" || strings.ContainsAny(s.ID+s.Version, "/\\\x00") || s.ID == "." || s.ID == ".." || s.License == "" || !filepath.IsLocal(s.LicenseFile) || s.Files < 1 || s.Files > 30000 || seen[s.ID] {
			return nil, fmt.Errorf("invalid source %q", s.ID)
		}
		seen[s.ID] = true
	}
	if err := os.Mkdir(destination, 0700); err != nil {
		return nil, fmt.Errorf("new corpus directory: %w", err)
	}
	if err := os.MkdirAll(cache, 0700); err != nil {
		return nil, err
	}
	cacheRoot, err := os.OpenRoot(cache)
	if err != nil {
		return nil, err
	}
	defer func() { _ = cacheRoot.Close() }()
	var inventory []File
	for _, s := range manifest.Sources {
		archive := filepath.Join(cache, s.ID+"-"+s.Version+".zip")
		if _, err := os.Stat(archive); os.IsNotExist(err) {
			if downloadErr := download(ctx, s.URL, archive); downloadErr != nil {
				return nil, downloadErr
			}
		} else if err != nil {
			return nil, err
		}
		f, err := cacheRoot.Open(filepath.Base(archive))
		if err != nil {
			return nil, err
		}
		h := sha256.New()
		n, copyErr := io.Copy(h, io.LimitReader(f, maxArchive+1))
		if copyErr != nil || n > maxArchive || hex.EncodeToString(h.Sum(nil)) != s.SHA256 {
			_ = f.Close()
			return nil, fmt.Errorf("archive checksum/size/read failure for %s", s.ID)
		}
		rows, err := extract(f, n, destination, s)
		closeErr := f.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			return nil, fmt.Errorf("extract %s: %w", s.ID, err)
		}
		inventory = append(inventory, rows...)
	}
	sort.Slice(inventory, func(i, j int) bool { return inventory[i].Path < inventory[j].Path })
	return inventory, nil
}

func download(ctx context.Context, address, destination string) error {
	client := &http.Client{Timeout: 3 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" || len(via) >= 10 {
			return fmt.Errorf("unsafe corpus redirect")
		}
		return nil
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("corpus download HTTP %d", response.StatusCode)
	}
	file, err := os.CreateTemp(filepath.Dir(destination), ".corpus-download-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	n, copyErr := io.Copy(file, io.LimitReader(response.Body, maxArchive+1))
	closeErr := file.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if n > maxArchive {
		return fmt.Errorf("corpus archive too large")
	}
	return os.Rename(file.Name(), destination)
}

func extract(archive io.ReaderAt, size int64, destination string, source Source) ([]File, error) {
	z, err := zip.NewReader(archive, size)
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(destination, source.ID)
	if err = os.Mkdir(dir, 0700); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	var rows []File
	var expanded int64
	license := false
	for _, entry := range z.File {
		name := strings.TrimSuffix(entry.Name, "/")
		if !filepath.IsLocal(name) || strings.Contains(name, "\\") {
			return nil, fmt.Errorf("unsafe archive name %q", name)
		}
		if entry.FileInfo().IsDir() {
			if err := root.MkdirAll(name, 0700); err != nil {
				return nil, err
			}
			continue
		}
		if !entry.Mode().IsRegular() {
			return nil, fmt.Errorf("unsupported archive entry %q", name)
		}
		if len(rows) >= source.Files || entry.UncompressedSize64 > maxExpanded || expanded+int64(entry.UncompressedSize64) > maxExpanded {
			return nil, fmt.Errorf("corpus exceeds pinned inventory or size limit")
		}
		if err := root.MkdirAll(filepath.Dir(name), 0700); err != nil {
			return nil, err
		}
		out, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return nil, err
		}
		in, err := entry.Open()
		if err != nil {
			_ = out.Close()
			return nil, err
		}
		h := sha256.New()
		n, copyErr := io.Copy(io.MultiWriter(out, h), io.LimitReader(in, maxExpanded-expanded+1))
		readClose, writeClose := in.Close(), out.Close()
		if copyErr != nil {
			return nil, copyErr
		}
		if readClose != nil {
			return nil, readClose
		}
		if writeClose != nil {
			return nil, writeClose
		}
		expanded += n
		if expanded > maxExpanded || n != int64(entry.UncompressedSize64) {
			return nil, fmt.Errorf("invalid expanded size")
		}
		if name == source.LicenseFile && n > 0 {
			license = true
		}
		rows = append(rows, File{Path: filepath.ToSlash(filepath.Join(source.ID, name)), SHA256: hex.EncodeToString(h.Sum(nil)), Bytes: n})
	}
	if len(rows) != source.Files || !license {
		return nil, fmt.Errorf("incomplete corpus: files=%d want=%d license=%t", len(rows), source.Files, license)
	}
	return rows, nil
}

func WriteJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	// #nosec G703 -- The local command or test runner selects this artifact path; vendor content never supplies it.
	return os.WriteFile(path, append(data, '\n'), 0600)
}
