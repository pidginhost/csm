package signatures

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/yara"
)

const (
	forgeReleasesURL = "https://api.github.com/repos/YARAHQ/yara-forge/releases/latest"
	forgeDownloadFmt = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-%s.zip"
	forgeHTTPTimeout = 30 * time.Second
	forgeMaxZIPSize  = 20 * 1024 * 1024
)

var forgeTierAsset = map[string]string{
	"core":     "packages/core/yara-rules-core.yar",
	"extended": "packages/extended/yara-rules-extended.yar",
	"full":     "packages/full/yara-rules-full.yar",
}

// ForgeUpdate checks for a new YARA Forge release and downloads it if newer.
// If signingKey is non-empty, a detached signature is fetched from the ZIP URL + ".sig"
// and verified against the raw ZIP content before extraction.
func ForgeUpdate(rulesDir, tier, currentVersion, signingKey string, disabledRules []string) (newVersion string, ruleCount int, err error) {
	if _, ok := forgeTierAsset[tier]; !ok {
		return "", 0, fmt.Errorf("unknown YARA Forge tier: %q (valid: core, extended, full)", tier)
	}

	latestTag, err := forgeLatestTag()
	if err != nil {
		return "", 0, fmt.Errorf("checking YARA Forge release: %w", err)
	}

	if latestTag == currentVersion {
		return currentVersion, 0, nil
	}

	zipURL := fmt.Sprintf(forgeDownloadFmt, tier)
	zipData, err := forgeDownload(zipURL)
	if err != nil {
		return "", 0, fmt.Errorf("downloading YARA Forge %s: %w", tier, err)
	}

	if signingKey != "" {
		sig, err := fetchSignature(zipURL + ".sig")
		if err != nil {
			return "", 0, fmt.Errorf("YARA Forge signature verification required but failed: %w", err)
		}
		if err := VerifySignature(signingKey, zipData, sig); err != nil {
			return "", 0, fmt.Errorf("YARA Forge signature invalid: %w", err)
		}
	}

	assetPath := forgeTierAsset[tier]
	yarContent, err := forgeExtractYar(zipData, assetPath)
	if err != nil {
		return "", 0, fmt.Errorf("extracting YARA Forge rules: %w", err)
	}

	if len(disabledRules) > 0 {
		yarContent = filterDisabledRules(yarContent, disabledRules)
	}

	ruleCount = countRules(yarContent)

	outFile := filepath.Join(rulesDir, fmt.Sprintf("yara-forge-%s.yar", tier))
	tmpFile := outFile + ".tmp"
	if err := os.WriteFile(tmpFile, yarContent, 0644); err != nil {
		return "", 0, fmt.Errorf("writing temp file: %w", err)
	}

	if err := yara.TestCompile(string(yarContent)); err != nil {
		_ = os.Remove(tmpFile)
		return "", 0, fmt.Errorf("YARA compilation test failed (keeping existing rules): %w", err)
	}

	// Remove other tier files (only one tier active at a time)
	for t := range forgeTierAsset {
		if t != tier {
			_ = os.Remove(filepath.Join(rulesDir, fmt.Sprintf("yara-forge-%s.yar", t)))
		}
	}

	if err := os.Rename(tmpFile, outFile); err != nil {
		_ = os.Remove(tmpFile)
		return "", 0, fmt.Errorf("installing rules: %w", err)
	}

	return latestTag, ruleCount, nil
}

func forgeLatestTag() (string, error) {
	client := &http.Client{Timeout: forgeHTTPTimeout}
	resp, err := client.Get(forgeReleasesURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1024*1024)).Decode(&release); err != nil {
		return "", fmt.Errorf("parsing release JSON: %w", err)
	}
	if release.TagName == "" {
		return "", fmt.Errorf("empty tag_name in release")
	}
	return release.TagName, nil
}

func forgeDownload(url string) ([]byte, error) {
	client := &http.Client{Timeout: forgeHTTPTimeout}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download returned %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, forgeMaxZIPSize))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}
	return data, nil
}

func forgeExtractYar(zipData []byte, assetPath string) ([]byte, error) {
	reader, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return nil, fmt.Errorf("opening ZIP: %w", err)
	}

	for _, f := range reader.File {
		if f.Name == assetPath {
			rc, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("opening %s in ZIP: %w", assetPath, err)
			}
			defer rc.Close()
			data, err := io.ReadAll(rc)
			if err != nil {
				return nil, fmt.Errorf("reading %s: %w", assetPath, err)
			}
			return data, nil
		}
	}
	return nil, fmt.Errorf("asset %s not found in ZIP", assetPath)
}

func filterDisabledRules(content []byte, disabled []string) []byte {
	if len(disabled) == 0 {
		return content
	}

	disabledSet := make(map[string]bool, len(disabled))
	for _, name := range disabled {
		disabledSet[name] = true
	}

	lines := strings.Split(string(content), "\n")
	var result []string
	skipping := false
	braceDepth := 0

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if skipping {
			for _, ch := range trimmed {
				switch ch {
				case '{':
					braceDepth++
				case '}':
					braceDepth--
				}
			}
			if braceDepth <= 0 {
				skipping = false
				braceDepth = 0
			}
			continue
		}

		ruleName := extractRuleName(trimmed)
		if ruleName != "" && disabledSet[ruleName] {
			skipping = true
			braceDepth = 0
			for _, ch := range trimmed {
				switch ch {
				case '{':
					braceDepth++
				case '}':
					braceDepth--
				}
			}
			if braceDepth <= 0 {
				skipping = false
				braceDepth = 0
			}
			continue
		}

		result = append(result, line)
	}

	return []byte(strings.Join(result, "\n"))
}

func extractRuleName(line string) string {
	s := strings.TrimPrefix(line, "private ")
	if !strings.HasPrefix(s, "rule ") {
		return ""
	}
	s = s[5:]
	for i, ch := range s {
		if ch == ' ' || ch == '\t' || ch == ':' || ch == '{' {
			return s[:i]
		}
	}
	return s
}

func countRules(content []byte) int {
	count := 0
	for _, line := range strings.Split(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		if extractRuleName(trimmed) != "" {
			count++
		}
	}
	return count
}
