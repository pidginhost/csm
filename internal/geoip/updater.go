package geoip

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
)

const (
	maxMindBaseURL  = "https://download.maxmind.com/geoip/databases"
	maxDownloadSize = 150 * 1024 * 1024 // 150MB
	// maxExtractedSize bounds the size of the .mmdb entry we extract from
	// the tar.gz. Real GeoLite2 files are ~70MB; 500MiB is generous. The
	// check sits on the tar header and prevents io.Copy from writing a
	// bomb-compressed entry to disk.
	maxExtractedSize = 500 * 1024 * 1024
	downloadTimeout  = 120 * time.Second
)

// EditionResult reports the outcome of updating a single GeoLite2 edition.
type EditionResult struct {
	Edition string // e.g. "GeoLite2-City"
	Status  string // "updated", "up_to_date", "error"
	Err     error  // nil unless Status == "error"
}

// Update downloads GeoLite2 databases from MaxMind's direct download API.
// Returns one EditionResult per edition. Returns nil if credentials are empty.
func Update(dbDir, accountID, licenseKey string, editions []string) []EditionResult {
	if accountID == "" || licenseKey == "" {
		return nil
	}

	if err := os.MkdirAll(dbDir, 0700); err != nil {
		result := make([]EditionResult, len(editions))
		for i, ed := range editions {
			result[i] = EditionResult{Edition: ed, Status: "error", Err: fmt.Errorf("creating directory: %w", err)}
		}
		return result
	}

	client := &http.Client{Timeout: downloadTimeout}
	results := make([]EditionResult, len(editions))

	for i, edition := range editions {
		results[i] = updateEdition(client, dbDir, accountID, licenseKey, edition)
	}
	return results
}

func updateEdition(client *http.Client, dbDir, accountID, licenseKey, edition string) EditionResult {
	return updateEditionWithURL(client, dbDir, accountID, licenseKey, edition, maxMindBaseURL)
}

func updateEditionWithURL(client *http.Client, dbDir, accountID, licenseKey, edition, baseURL string) EditionResult {
	url := fmt.Sprintf("%s/%s/download?suffix=tar.gz", baseURL, edition)
	markerPath := filepath.Join(dbDir, ".last-modified-"+edition)

	// Read stored Last-Modified
	storedLM := ""
	if data, err := os.ReadFile(markerPath); err == nil {
		storedLM = strings.TrimSpace(string(data))
	}

	// HEAD request to check Last-Modified
	headReq, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return EditionResult{Edition: edition, Status: "error", Err: err}
	}
	headReq.SetBasicAuth(accountID, licenseKey)

	headResp, err := client.Do(headReq)
	if err != nil {
		return EditionResult{Edition: edition, Status: "error", Err: fmt.Errorf("HEAD request: %w", err)}
	}
	headResp.Body.Close()

	if headResp.StatusCode == 401 {
		return EditionResult{Edition: edition, Status: "error", Err: fmt.Errorf("invalid MaxMind credentials")}
	}
	if headResp.StatusCode == 429 {
		return EditionResult{Edition: edition, Status: "error", Err: fmt.Errorf("rate limited by MaxMind")}
	}
	if headResp.StatusCode != 200 {
		return EditionResult{Edition: edition, Status: "error", Err: fmt.Errorf("HEAD returned HTTP %d", headResp.StatusCode)}
	}

	remoteLM := headResp.Header.Get("Last-Modified")
	if storedLM != "" && remoteLM != "" && storedLM == remoteLM {
		return EditionResult{Edition: edition, Status: "up_to_date"}
	}

	// GET request to download
	getReq, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return EditionResult{Edition: edition, Status: "error", Err: err}
	}
	getReq.SetBasicAuth(accountID, licenseKey)

	getResp, err := client.Do(getReq)
	if err != nil {
		return EditionResult{Edition: edition, Status: "error", Err: fmt.Errorf("download: %w", err)}
	}
	defer getResp.Body.Close()

	if getResp.StatusCode != 200 {
		return EditionResult{Edition: edition, Status: "error", Err: fmt.Errorf("download returned HTTP %d", getResp.StatusCode)}
	}

	// Reject oversized responses upfront if Content-Length is known
	if getResp.ContentLength > maxDownloadSize {
		return EditionResult{Edition: edition, Status: "error", Err: fmt.Errorf("download too large: %d bytes (max %d)", getResp.ContentLength, maxDownloadSize)}
	}

	// LimitReader as safety net for responses without Content-Length
	mmdbTmpPath := filepath.Join(dbDir, edition+".mmdb.tmp")
	if err := extractMMDB(io.LimitReader(getResp.Body, maxDownloadSize), mmdbTmpPath, edition); err != nil {
		os.Remove(mmdbTmpPath)
		return EditionResult{Edition: edition, Status: "error", Err: fmt.Errorf("extract: %w", err)}
	}
	if err := validateMMDB(mmdbTmpPath); err != nil {
		os.Remove(mmdbTmpPath)
		return EditionResult{Edition: edition, Status: "error", Err: fmt.Errorf("validate: %w", err)}
	}

	// Atomic install
	destPath := filepath.Join(dbDir, edition+".mmdb")
	if err := os.Rename(mmdbTmpPath, destPath); err != nil {
		os.Remove(mmdbTmpPath)
		return EditionResult{Edition: edition, Status: "error", Err: fmt.Errorf("install: %w", err)}
	}

	// Save Last-Modified marker
	if remoteLM != "" {
		_ = os.WriteFile(markerPath, []byte(remoteLM), 0600)
	}

	return EditionResult{Edition: edition, Status: "updated"}
}

func validateMMDB(path string) error {
	db, err := maxminddb.Open(path)
	if err != nil {
		return err
	}
	return db.Close()
}

// extractMMDB reads a tar.gz stream and extracts the .mmdb file to destPath.
// MaxMind tar.gz archives contain a single directory with the .mmdb inside,
// e.g. GeoLite2-City_20260328/GeoLite2-City.mmdb
func extractMMDB(r io.Reader, destPath, edition string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("gzip: %w", err)
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	suffix := edition + ".mmdb"

	for {
		header, err := tr.Next()
		if err == io.EOF {
			return fmt.Errorf("no %s found in archive", suffix)
		}
		if err != nil {
			return fmt.Errorf("reading tar: %w", err)
		}

		if header.Typeflag != tar.TypeReg {
			continue
		}
		if !strings.HasSuffix(header.Name, suffix) {
			continue
		}
		if header.Size > maxExtractedSize {
			return fmt.Errorf("archive entry too large: %d bytes", header.Size)
		}

		f, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			return fmt.Errorf("creating %s: %w", destPath, err)
		}
		_, copyErr := io.Copy(f, io.LimitReader(tr, maxExtractedSize))
		closeErr := f.Close()
		if copyErr != nil {
			return fmt.Errorf("writing mmdb: %w", copyErr)
		}
		if closeErr != nil {
			return fmt.Errorf("closing mmdb: %w", closeErr)
		}
		return nil
	}
}
