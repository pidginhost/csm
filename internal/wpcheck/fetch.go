package wpcheck

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

var httpClient = &http.Client{Timeout: 10 * time.Second}

// checksumAPIURL returns the WordPress.org checksum API URL for a version and locale.
func checksumAPIURL(version, locale string) string {
	return fmt.Sprintf("https://api.wordpress.org/core/checksums/1.0/?version=%s&locale=%s", version, locale)
}

// checksumResponse is the JSON structure returned by the WP checksum API.
type checksumResponse struct {
	Checksums map[string]string `json:"checksums"`
}

// ParseChecksumResponse parses the JSON response from the WP checksum API.
// Returns a map of relative_path -> md5_hex.
func ParseChecksumResponse(data []byte) (map[string]string, error) {
	var resp checksumResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	if len(resp.Checksums) == 0 {
		return nil, errors.New("empty or missing checksums in response")
	}
	return resp.Checksums, nil
}

// FetchChecksums fetches official checksums from api.wordpress.org for a given
// version and locale. Returns the raw response body and parsed checksums.
func FetchChecksums(version, locale string) (rawJSON []byte, checksums map[string]string, err error) {
	url := checksumAPIURL(version, locale)
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20)) // 2MB limit
	if err != nil {
		return nil, nil, fmt.Errorf("reading response: %w", err)
	}

	checksums, err = ParseChecksumResponse(body)
	if err != nil {
		return nil, nil, err
	}
	return body, checksums, nil
}
