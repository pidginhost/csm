package signatures

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/pidginhost/csm/internal/atomicio"
	"github.com/pidginhost/csm/internal/yara"
)

const (
	forgeReleasesURL = "https://api.github.com/repos/YARAHQ/yara-forge/releases/latest"
	forgeHTTPTimeout = 30 * time.Second
	forgeMaxZIPSize  = 20 * 1024 * 1024
	// forgeMaxYarSize caps the decompressed size of a single .yar entry. The
	// compressed ZIP is bounded by forgeMaxZIPSize, but a zip bomb (or a
	// compromised CDN / signing key) can encode a far larger decompressed
	// payload; the full ruleset tier is a few MiB, so 64 MiB is generous.
	forgeMaxYarSize = 64 * 1024 * 1024
)

var forgeTierAsset = map[string]string{
	"core":     "packages/core/yara-rules-core.yar",
	"extended": "packages/extended/yara-rules-extended.yar",
	"full":     "packages/full/yara-rules-full.yar",
}

var forgeAtomicWrite = atomicio.AtomicWrite

// ForgeUpdate checks for a new YARA Forge release and downloads it if newer.
// A detached signature is fetched from the ZIP URL + ".sig" and verified
// against the raw ZIP content before extraction.
func ForgeUpdate(rulesDir, tier, currentVersion, signingKey string, disabledRules []string) (newVersion string, ruleCount int, err error) {
	return ForgeUpdateFromURL(rulesDir, tier, currentVersion, signingKey, "", disabledRules)
}

// ForgeUpdateFromURL is ForgeUpdate with an explicit signed ZIP source. The
// downloadURL may contain {tier} and {version}; the signature is fetched from
// the resolved ZIP URL plus ".sig".
func ForgeUpdateFromURL(rulesDir, tier, currentVersion, signingKey, downloadURL string, disabledRules []string) (newVersion string, ruleCount int, err error) {
	if _, ok := forgeTierAsset[tier]; !ok {
		return "", 0, fmt.Errorf("unknown YARA Forge tier: %q (valid: core, extended, full)", tier)
	}
	if e := requireSigningKey(signingKey); e != nil {
		return "", 0, e
	}
	if strings.TrimSpace(downloadURL) == "" {
		return "", 0, fmt.Errorf("signatures.yara_forge.download_url is required: upstream YARA Forge does not publish CSM detached signatures")
	}

	latestTag, err := forgeResolveLatestTag(downloadURL)
	if err != nil {
		return "", 0, fmt.Errorf("checking YARA Forge release: %w", err)
	}

	if latestTag == currentVersion {
		return currentVersion, 0, nil
	}

	zipURL := forgeDownloadURL(downloadURL, tier, latestTag)
	zipData, err := forgeDownload(zipURL)
	if err != nil {
		return "", 0, fmt.Errorf("downloading YARA Forge %s: %w", tier, err)
	}

	sig, err := fetchSignature(zipURL + ".sig")
	if err != nil {
		return "", 0, fmt.Errorf("YARA Forge signature verification required but failed: %w", err)
	}
	if e := VerifySignature(signingKey, zipData, sig); e != nil {
		return "", 0, fmt.Errorf("YARA Forge signature invalid: %w", e)
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
	outFileExisted := false
	if _, err := os.Stat(outFile); err == nil {
		outFileExisted = true
	} else if !os.IsNotExist(err) {
		return "", 0, fmt.Errorf("checking existing Forge tier: %w", err)
	}

	if err := yara.TestCompile(string(yarContent)); err != nil {
		return "", 0, fmt.Errorf("YARA compilation test failed (keeping existing rules): %w", err)
	}

	if err := os.MkdirAll(rulesDir, 0700); err != nil {
		return "", 0, fmt.Errorf("creating rules dir: %w", err)
	}
	if outFileExisted {
		if err := removeInactiveForgeTiers(rulesDir, tier); err != nil {
			return "", 0, err
		}
		if err := forgeAtomicWrite(outFile, 0600, yarContent); err != nil {
			return "", 0, fmt.Errorf("installing rules: %w", err)
		}
		return latestTag, ruleCount, nil
	}
	if err := forgeAtomicWrite(outFile, 0600, yarContent); err != nil {
		return "", 0, fmt.Errorf("installing rules: %w", err)
	}
	if err := removeInactiveForgeTiers(rulesDir, tier); err != nil {
		return "", 0, err
	}

	return latestTag, ruleCount, nil
}

func removeInactiveForgeTiers(rulesDir, activeTier string) error {
	for t := range forgeTierAsset {
		if t == activeTier {
			continue
		}
		path := filepath.Join(rulesDir, fmt.Sprintf("yara-forge-%s.yar", t))
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("removing inactive Forge tier %s: %w", t, err)
		}
	}
	return nil
}

func forgeDownloadURL(tmpl, tier, version string) string {
	url := strings.TrimSpace(tmpl)
	url = strings.ReplaceAll(url, "{tier}", tier)
	url = strings.ReplaceAll(url, "{version}", version)
	return url
}

// errForgePointerAbsent signals that the mirror publishes no latest-version
// pointer (404 or a template without a {version} directory), so the caller
// should fall back to the upstream GitHub release tag.
var errForgePointerAbsent = errors.New("mirror latest pointer absent")

// forgeTagPattern constrains a version tag before it is interpolated into a
// download URL. YARA Forge tags are short date/version tokens (e.g. 20260705,
// v2026.04.11); restricting the charset stops a tampered pointer from
// redirecting the download via path traversal.
var forgeTagPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func forgeValidTag(tag string) bool {
	return forgeTagPattern.MatchString(strings.TrimSpace(tag))
}

// forgeLatestPointerURL derives the mirror's latest-version pointer URL from
// the download template. The pointer lives in the directory that holds the
// per-{version} subdirectories:
//
//	https://host/csm/yara-forge/{version}/yara-forge-rules-{tier}.zip
//	                                    -> https://host/csm/yara-forge/latest
//
// Returns ("", false) when the template has no {version} path segment, in
// which case there is no version-scoped directory to point into.
func forgeLatestPointerURL(tmpl string) (string, bool) {
	tmpl = strings.TrimSpace(tmpl)
	i := strings.Index(tmpl, "{version}")
	if i < 0 {
		return "", false
	}
	base := tmpl[:i]
	if !strings.HasSuffix(base, "/") {
		// {version} is not a standalone path segment; refuse to guess.
		return "", false
	}
	return base + "latest", true
}

// forgeLatestTagFromMirror fetches the mirror's latest-version pointer and
// returns the tag it names. It returns errForgePointerAbsent when the pointer
// is not published so the caller can fall back to the GitHub release API.
func forgeLatestTagFromMirror(downloadURL string) (string, error) {
	pointerURL, ok := forgeLatestPointerURL(downloadURL)
	if !ok {
		return "", errForgePointerAbsent
	}

	client := &http.Client{Timeout: forgeHTTPTimeout}
	resp, err := client.Get(pointerURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", errForgePointerAbsent
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("mirror latest pointer returned %d", resp.StatusCode)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 128))
	if err != nil {
		return "", fmt.Errorf("reading mirror latest pointer: %w", err)
	}
	tag := strings.TrimSpace(string(raw))
	if !forgeValidTag(tag) {
		return "", fmt.Errorf("mirror latest pointer has invalid tag %q", tag)
	}
	return tag, nil
}

// forgeResolveLatestTag resolves the newest downloadable version. It prefers
// the mirror's own latest pointer -- the mirror only holds versions it has
// signed and published, so resolving from it can never request a version the
// mirror lacks (the root cause of the release-day 404 gap when GitHub outran
// the weekly mirror sync). It falls back to the upstream GitHub release tag
// only when the mirror publishes no pointer, preserving prior behavior for
// older mirror layouts and download_url templates without a {version} segment.
func forgeResolveLatestTag(downloadURL string) (string, error) {
	tag, err := forgeLatestTagFromMirror(downloadURL)
	if err == nil {
		return tag, nil
	}
	if !errors.Is(err, errForgePointerAbsent) {
		return "", err
	}
	return forgeLatestTag()
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
			data, err := io.ReadAll(io.LimitReader(rc, forgeMaxYarSize+1))
			if err != nil {
				return nil, fmt.Errorf("reading %s: %w", assetPath, err)
			}
			if len(data) > forgeMaxYarSize {
				return nil, fmt.Errorf("%s exceeds decompressed size limit of %d bytes", assetPath, forgeMaxYarSize)
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
