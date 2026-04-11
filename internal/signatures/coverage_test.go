package signatures

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- helpers -----------------------------------------------------------

func genSigningKey(t *testing.T) (pubHex string, priv ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(pub), priv
}

func sign(priv ed25519.PrivateKey, data []byte) []byte {
	return ed25519.Sign(priv, data)
}

// sampleRulesYAML is a minimal rules file used to seed test scanners.
// The patterns here are intentionally malware-like because this package's
// whole job is to detect them — no hook can flag this as a real finding.
const sampleRulesYAML = `version: 7
updated: "2026-04-11"
rules:
  - name: test_webshell_chain
    description: webshell marker pair
    severity: critical
    category: webshell
    file_types: [".php"]
    patterns:
      - "TOKEN_A"
      - "TOKEN_B"
    min_match: 2
`

// --- requireSigningKey -------------------------------------------------

func TestRequireSigningKeyEmpty(t *testing.T) {
	if err := requireSigningKey(""); err == nil {
		t.Fatal("empty key should error")
	}
}

func TestRequireSigningKeyNonEmpty(t *testing.T) {
	if err := requireSigningKey("deadbeef"); err != nil {
		t.Errorf("non-empty key should not error, got %v", err)
	}
}

// --- Init / Global -----------------------------------------------------

func TestInitAndGlobal(t *testing.T) {
	// Init uses a sync.Once, so subsequent calls are no-ops.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rules.yml"), []byte(sampleRulesYAML), 0644); err != nil {
		t.Fatal(err)
	}
	s := Init(dir)
	if s == nil {
		t.Fatal("Init returned nil")
	}
	if g := Global(); g != s {
		t.Errorf("Global() != Init() return value")
	}
	// Second call should return the same instance (sync.Once).
	if s2 := Init(filepath.Join(t.TempDir(), "other")); s2 != s {
		t.Errorf("second Init returned a different scanner (sync.Once broken?)")
	}
}

// --- Scanner.Version / RuleCount / ScanFile ---------------------------

func TestScannerVersionReportsMaxFromRules(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.yml"), []byte(sampleRulesYAML), 0644); err != nil {
		t.Fatal(err)
	}
	s := NewScanner(dir)
	if s.Version() != 7 {
		t.Errorf("Version = %d, want 7", s.Version())
	}
}

func TestScannerScanFileMatchesPattern(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rules.yml"), []byte(sampleRulesYAML), 0644); err != nil {
		t.Fatal(err)
	}
	s := NewScanner(dir)

	target := filepath.Join(t.TempDir(), "sample.php")
	// Needs BOTH tokens to trigger (min_match: 2).
	if err := os.WriteFile(target, []byte("<?php TOKEN_A TOKEN_B ?>"), 0644); err != nil {
		t.Fatal(err)
	}
	matches := s.ScanFile(target, 1<<20)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].RuleName != "test_webshell_chain" {
		t.Errorf("match rule = %q", matches[0].RuleName)
	}
}

func TestScannerScanFileMissingFileReturnsNil(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rules.yml"), []byte(sampleRulesYAML), 0644); err != nil {
		t.Fatal(err)
	}
	s := NewScanner(dir)
	matches := s.ScanFile(filepath.Join(t.TempDir(), "missing.php"), 1<<20)
	if matches != nil {
		t.Errorf("missing file should return nil, got %v", matches)
	}
}

func TestScannerScanFileEmptyFileReturnsNil(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rules.yml"), []byte(sampleRulesYAML), 0644); err != nil {
		t.Fatal(err)
	}
	s := NewScanner(dir)
	empty := filepath.Join(t.TempDir(), "empty.php")
	if err := os.WriteFile(empty, nil, 0644); err != nil {
		t.Fatal(err)
	}
	matches := s.ScanFile(empty, 1<<20)
	if matches != nil {
		t.Errorf("empty file should return nil, got %v", matches)
	}
}

func TestScannerScanFileNoRulesReturnsNil(t *testing.T) {
	s := NewScanner(t.TempDir()) // empty rules dir
	target := filepath.Join(t.TempDir(), "sample.php")
	if err := os.WriteFile(target, []byte("TOKEN_A TOKEN_B"), 0644); err != nil {
		t.Fatal(err)
	}
	matches := s.ScanFile(target, 1<<20)
	if matches != nil {
		t.Errorf("scanner with no rules should return nil, got %v", matches)
	}
}

// --- ruleMatchesExt ---------------------------------------------------

func TestRuleMatchesExtWildcard(t *testing.T) {
	r := Rule{FileTypes: []string{"*"}}
	if !ruleMatchesExt(r, ".anything") {
		t.Error("wildcard FileTypes should match any extension")
	}
}

func TestRuleMatchesExtExplicit(t *testing.T) {
	r := Rule{FileTypes: []string{".php", ".html"}}
	if !ruleMatchesExt(r, ".php") {
		t.Error("should match .php")
	}
	if ruleMatchesExt(r, ".txt") {
		t.Error("should not match .txt")
	}
}

func TestRuleMatchesExtCaseInsensitive(t *testing.T) {
	r := Rule{FileTypes: []string{".PHP"}}
	if !ruleMatchesExt(r, ".php") {
		t.Error("extension match should be case-insensitive on the rule side")
	}
}

func TestRuleMatchesExtEmptyMatchesAll(t *testing.T) {
	r := Rule{}
	if !ruleMatchesExt(r, ".whatever") {
		t.Error("empty FileTypes should match everything")
	}
}

// --- Update (HTTP) ----------------------------------------------------

func TestUpdateRequiresURL(t *testing.T) {
	_, err := Update(t.TempDir(), "", "deadbeef")
	if err == nil {
		t.Fatal("Update with empty URL should error")
	}
}

func TestUpdateRequiresSigningKey(t *testing.T) {
	_, err := Update(t.TempDir(), "https://example.com/rules.yml", "")
	if err == nil {
		t.Fatal("Update with empty signing key should error")
	}
}

func TestUpdateSuccessInstallsRules(t *testing.T) {
	pubHex, priv := genSigningKey(t)
	payload := []byte(sampleRulesYAML)
	sig := sign(priv, payload)

	mux := http.NewServeMux()
	mux.HandleFunc("/rules.yml", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	})
	mux.HandleFunc("/rules.yml.sig", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(sig)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	rulesDir := t.TempDir()
	n, err := Update(rulesDir, srv.URL+"/rules.yml", pubHex)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if n != 1 {
		t.Errorf("Update returned %d rules, want 1", n)
	}
	installed := filepath.Join(rulesDir, "malware.yml")
	if _, err := os.Stat(installed); err != nil {
		t.Errorf("malware.yml not installed: %v", err)
	}
}

func TestUpdateFailsOnWrongSignature(t *testing.T) {
	pubHex, _ := genSigningKey(t) // valid pub
	_, priv := genSigningKey(t)   // different priv
	payload := []byte(sampleRulesYAML)
	badSig := sign(priv, payload)

	mux := http.NewServeMux()
	mux.HandleFunc("/rules.yml", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(payload) })
	mux.HandleFunc("/rules.yml.sig", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(badSig) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	_, err := Update(t.TempDir(), srv.URL+"/rules.yml", pubHex)
	if err == nil {
		t.Fatal("Update with wrong signature should fail")
	}
	if !strings.Contains(err.Error(), "signature") {
		t.Errorf("err = %v, want signature-related", err)
	}
}

func TestUpdateFailsOnHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := Update(t.TempDir(), srv.URL+"/rules.yml", "deadbeef")
	if err == nil {
		t.Fatal("Update with HTTP 500 should fail")
	}
}

func TestUpdateFailsOnInvalidYAML(t *testing.T) {
	pubHex, priv := genSigningKey(t)
	// yaml.v3 rejects a mapping where a value block is unterminated.
	payload := []byte("rules:\n  - name: oops\n    severity: \"unterminated\n")
	sig := sign(priv, payload)

	mux := http.NewServeMux()
	mux.HandleFunc("/rules.yml", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(payload) })
	mux.HandleFunc("/rules.yml.sig", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(sig) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	_, err := Update(t.TempDir(), srv.URL+"/rules.yml", pubHex)
	if err == nil {
		t.Fatal("Update with invalid YAML should fail")
	}
	if !strings.Contains(err.Error(), "invalid rules file") {
		t.Errorf("err = %v, want invalid rules file", err)
	}
}

func TestUpdateFailsOnEmptyRules(t *testing.T) {
	pubHex, priv := genSigningKey(t)
	payload := []byte("version: 1\nrules: []\n")
	sig := sign(priv, payload)

	mux := http.NewServeMux()
	mux.HandleFunc("/rules.yml", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(payload) })
	mux.HandleFunc("/rules.yml.sig", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(sig) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	_, err := Update(t.TempDir(), srv.URL+"/rules.yml", pubHex)
	if err == nil || !strings.Contains(err.Error(), "no rules") {
		t.Fatalf("Update with empty rules = %v, want 'no rules' error", err)
	}
}

func TestUpdateFailsOnMissingSignature(t *testing.T) {
	pubHex, _ := genSigningKey(t)
	payload := []byte(sampleRulesYAML)

	mux := http.NewServeMux()
	mux.HandleFunc("/rules.yml", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(payload) })
	mux.HandleFunc("/rules.yml.sig", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	_, err := Update(t.TempDir(), srv.URL+"/rules.yml", pubHex)
	if err == nil {
		t.Fatal("Update with missing signature should fail")
	}
}

// --- fetchSignature ---------------------------------------------------

func TestFetchSignatureOK(t *testing.T) {
	want := []byte("sig-bytes-here")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(want)
	}))
	defer srv.Close()

	got, err := fetchSignature(srv.URL + "/rules.yml.sig")
	if err != nil {
		t.Fatalf("fetchSignature: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestFetchSignatureNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	_, err := fetchSignature(srv.URL + "/rules.yml.sig")
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("err = %v, want 403", err)
	}
}

func TestFetchSignatureDialFailure(t *testing.T) {
	_, err := fetchSignature("http://127.0.0.1:1/nonexistent.sig")
	if err == nil {
		t.Fatal("fetchSignature on unreachable should error")
	}
}

// --- forgeExtractYar (pure ZIP code) ----------------------------------

func TestForgeExtractYarFindsAsset(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	f, err := zw.Create("packages/core/yara-rules-core.yar")
	if err != nil {
		t.Fatal(err)
	}
	ruleContent := []byte("rule core_rule_1 { condition: true }\n")
	if _, err := f.Write(ruleContent); err != nil {
		t.Fatal(err)
	}
	zw.Close()

	got, err := forgeExtractYar(buf.Bytes(), "packages/core/yara-rules-core.yar")
	if err != nil {
		t.Fatalf("forgeExtractYar: %v", err)
	}
	if !bytes.Equal(got, ruleContent) {
		t.Errorf("got %q, want %q", got, ruleContent)
	}
}

func TestForgeExtractYarAssetNotFound(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	f, _ := zw.Create("other/path.yar")
	_, _ = f.Write([]byte("x"))
	zw.Close()

	_, err := forgeExtractYar(buf.Bytes(), "packages/core/yara-rules-core.yar")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("err = %v, want not found", err)
	}
}

func TestForgeExtractYarInvalidZip(t *testing.T) {
	_, err := forgeExtractYar([]byte("not a zip"), "packages/core/yara-rules-core.yar")
	if err == nil {
		t.Fatal("invalid ZIP should error")
	}
}

// --- ForgeUpdate / forgeLatestTag / forgeDownload ---------------------
//
// forge.go talks to hardcoded api.github.com and github.com URLs via
// fresh &http.Client{Timeout: X}, which defaults to http.DefaultTransport.
// We hijack DefaultTransport for the duration of the test to route the
// requests to a local httptest server. Tests in this package run
// sequentially so the global mutation is safe.

type forgeRoundTripper struct {
	releases []byte // JSON for /repos/YARAHQ/yara-forge/releases/latest
	zipBody  []byte // body for the download URL
	sigBody  []byte // body for the .sig URL
	status   int    // override status (0 = default logic)
}

func (rt *forgeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	body := []byte{}
	status := http.StatusOK
	switch {
	case strings.Contains(req.URL.Path, "/releases/latest") && req.URL.Host == "api.github.com":
		body = rt.releases
	case strings.HasSuffix(req.URL.Path, ".zip.sig"):
		body = rt.sigBody
	case strings.HasSuffix(req.URL.Path, ".zip"):
		body = rt.zipBody
	default:
		status = http.StatusNotFound
	}
	if rt.status != 0 {
		status = rt.status
	}
	return &http.Response{
		StatusCode:    status,
		Status:        http.StatusText(status),
		Body:          readCloserWrap{Reader: bytes.NewReader(body)},
		ContentLength: int64(len(body)),
		Header:        make(http.Header),
		Request:       req,
	}, nil
}

type readCloserWrap struct{ *bytes.Reader }

func (readCloserWrap) Close() error { return nil }

func swapDefaultTransport(t *testing.T, rt http.RoundTripper) {
	t.Helper()
	orig := http.DefaultTransport
	http.DefaultTransport = rt
	t.Cleanup(func() { http.DefaultTransport = orig })
}

func buildForgeZip(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	f, err := zw.Create("packages/core/yara-rules-core.yar")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write([]byte("rule core_rule { condition: true }\n"))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestForgeUpdateHappyPath(t *testing.T) {
	pubHex, priv := genSigningKey(t)
	zipData := buildForgeZip(t)
	sig := sign(priv, zipData)

	swapDefaultTransport(t, &forgeRoundTripper{
		releases: []byte(`{"tag_name":"v2026.04.11"}`),
		zipBody:  zipData,
		sigBody:  sig,
	})

	rulesDir := t.TempDir()
	newVersion, ruleCount, err := ForgeUpdate(rulesDir, "core", "v2026.01.01", pubHex, nil)
	if err != nil {
		t.Fatalf("ForgeUpdate: %v", err)
	}
	if newVersion != "v2026.04.11" {
		t.Errorf("newVersion = %q", newVersion)
	}
	if ruleCount != 1 {
		t.Errorf("ruleCount = %d, want 1", ruleCount)
	}
	if _, err := os.Stat(filepath.Join(rulesDir, "yara-forge-core.yar")); err != nil {
		t.Errorf("installed file missing: %v", err)
	}
}

func TestForgeUpdateUnknownTier(t *testing.T) {
	_, _, err := ForgeUpdate(t.TempDir(), "nonsense-tier", "", "deadbeef", nil)
	if err == nil || !strings.Contains(err.Error(), "unknown YARA Forge tier") {
		t.Fatalf("err = %v, want unknown tier", err)
	}
}

func TestForgeUpdateRequiresSigningKey(t *testing.T) {
	_, _, err := ForgeUpdate(t.TempDir(), "core", "", "", nil)
	if err == nil || !strings.Contains(err.Error(), "signing_key") {
		t.Fatalf("err = %v, want signing_key error", err)
	}
}

func TestForgeUpdateSameVersionNoOp(t *testing.T) {
	pubHex, _ := genSigningKey(t)
	swapDefaultTransport(t, &forgeRoundTripper{
		releases: []byte(`{"tag_name":"v2026.04.11"}`),
	})
	version, count, err := ForgeUpdate(t.TempDir(), "core", "v2026.04.11", pubHex, nil)
	if err != nil {
		t.Fatalf("ForgeUpdate: %v", err)
	}
	if version != "v2026.04.11" {
		t.Errorf("version = %q", version)
	}
	if count != 0 {
		t.Errorf("count = %d, want 0 (no-op)", count)
	}
}

func TestForgeUpdateReleasesAPIError(t *testing.T) {
	pubHex, _ := genSigningKey(t)
	swapDefaultTransport(t, &forgeRoundTripper{
		releases: nil,
		status:   http.StatusInternalServerError,
	})
	_, _, err := ForgeUpdate(t.TempDir(), "core", "", pubHex, nil)
	if err == nil {
		t.Fatal("API error should propagate")
	}
}

func TestForgeUpdateBadSignature(t *testing.T) {
	pubHex, _ := genSigningKey(t)     // legit key
	_, otherPriv := genSigningKey(t) // unrelated priv
	zipData := buildForgeZip(t)
	badSig := sign(otherPriv, zipData)

	swapDefaultTransport(t, &forgeRoundTripper{
		releases: []byte(`{"tag_name":"v2026.04.11"}`),
		zipBody:  zipData,
		sigBody:  badSig,
	})
	_, _, err := ForgeUpdate(t.TempDir(), "core", "", pubHex, nil)
	if err == nil || !strings.Contains(err.Error(), "signature invalid") {
		t.Fatalf("err = %v, want signature invalid", err)
	}
}

func TestForgeUpdateDisabledRulesApplied(t *testing.T) {
	pubHex, priv := genSigningKey(t)

	// Build a ZIP containing two rules — we'll disable one.
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	f, _ := zw.Create("packages/core/yara-rules-core.yar")
	_, _ = f.Write([]byte(`rule keep_me { condition: true }
rule drop_me { condition: false }
`))
	_ = zw.Close()
	zipData := buf.Bytes()

	swapDefaultTransport(t, &forgeRoundTripper{
		releases: []byte(`{"tag_name":"v2026.04.11"}`),
		zipBody:  zipData,
		sigBody:  sign(priv, zipData),
	})

	rulesDir := t.TempDir()
	_, ruleCount, err := ForgeUpdate(rulesDir, "core", "v2026.01.01", pubHex, []string{"drop_me"})
	if err != nil {
		t.Fatalf("ForgeUpdate: %v", err)
	}
	if ruleCount != 1 {
		t.Errorf("ruleCount = %d, want 1 (drop_me filtered)", ruleCount)
	}

	got, err := os.ReadFile(filepath.Join(rulesDir, "yara-forge-core.yar"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(got, []byte("drop_me")) {
		t.Errorf("drop_me should have been filtered:\n%s", got)
	}
	if !bytes.Contains(got, []byte("keep_me")) {
		t.Errorf("keep_me should be present:\n%s", got)
	}
}

// --- filterDisabledRules more branches --------------------------------

func TestFilterDisabledRulesMultipleRulesOnOneLine(t *testing.T) {
	content := []byte(`rule keep_me { condition: true }
rule drop_me { condition: false }
rule also_keep { strings: $a = "x" condition: $a }
`)
	got := filterDisabledRules(content, []string{"drop_me"})
	if bytes.Contains(got, []byte("drop_me")) {
		t.Errorf("drop_me should be filtered out:\n%s", got)
	}
	if !bytes.Contains(got, []byte("keep_me")) {
		t.Errorf("keep_me should be preserved:\n%s", got)
	}
	if !bytes.Contains(got, []byte("also_keep")) {
		t.Errorf("also_keep should be preserved:\n%s", got)
	}
}

// --- extractRuleName more branches ------------------------------------

func TestExtractRuleNameWithColon(t *testing.T) {
	if got := extractRuleName("rule my_rule : tag1"); got != "my_rule" {
		t.Errorf("got %q, want my_rule", got)
	}
}

func TestExtractRuleNameWithBrace(t *testing.T) {
	if got := extractRuleName("rule my_rule{"); got != "my_rule" {
		t.Errorf("got %q, want my_rule", got)
	}
}

func TestExtractRuleNameNoWhitespace(t *testing.T) {
	// The whole rest of the string is the name.
	if got := extractRuleName("rule only_name"); got != "only_name" {
		t.Errorf("got %q, want only_name", got)
	}
}

func TestExtractRuleNameNotARule(t *testing.T) {
	if got := extractRuleName("import \"pe\""); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

// --- Reload variants --------------------------------------------------

func TestReloadEmptyRulesDirString(t *testing.T) {
	s := &Scanner{rulesDir: ""} // explicit blank
	if err := s.Reload(); err != nil {
		t.Errorf("Reload with empty dir string should be no-op, got %v", err)
	}
}

func TestReloadMissingDirIsNotError(t *testing.T) {
	s := &Scanner{rulesDir: filepath.Join(t.TempDir(), "never")}
	if err := s.Reload(); err != nil {
		t.Errorf("Reload on missing dir should return nil, got %v", err)
	}
}

func TestReloadFileCountZeroWithoutExistingRules(t *testing.T) {
	// Dir exists but has no .yml/.yaml files. With no previously-loaded
	// rules, this is a silent no-op.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("not rules"), 0644); err != nil {
		t.Fatal(err)
	}
	s := &Scanner{rulesDir: dir}
	if err := s.Reload(); err != nil {
		t.Errorf("Reload with no rule files on fresh scanner should not error, got %v", err)
	}
}

func TestReloadFileCountZeroWithExistingRulesIsError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rules.yml"), []byte(sampleRulesYAML), 0644); err != nil {
		t.Fatal(err)
	}
	s := NewScanner(dir)
	if s.RuleCount() == 0 {
		t.Fatal("precondition: NewScanner should have loaded rules")
	}

	// Remove the rule file.
	if err := os.Remove(filepath.Join(dir, "rules.yml")); err != nil {
		t.Fatal(err)
	}
	err := s.Reload()
	if err == nil {
		t.Fatal("Reload with zero rule files on a populated scanner should error")
	}
	if !strings.Contains(err.Error(), "no signature rule files found") {
		t.Errorf("err = %v, want 'no signature rule files found'", err)
	}
}

func TestReloadParseErrorDoesNotReplaceRules(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rules.yml"), []byte(sampleRulesYAML), 0644); err != nil {
		t.Fatal(err)
	}
	s := NewScanner(dir)
	initial := s.RuleCount()

	// Replace with broken YAML.
	if err := os.WriteFile(filepath.Join(dir, "rules.yml"), []byte("::: broken :::"), 0644); err != nil {
		t.Fatal(err)
	}
	err := s.Reload()
	if err == nil {
		t.Fatal("Reload with broken YAML should error")
	}
	if s.RuleCount() != initial {
		t.Errorf("RuleCount changed from %d to %d on parse failure", initial, s.RuleCount())
	}
}

// --- ScanContent file-type skip ---------------------------------------

func TestScanContentSkipsRulesByFileType(t *testing.T) {
	dir := t.TempDir()
	yamlContent := `version: 1
rules:
  - name: php_only
    severity: critical
    category: webshell
    file_types: [".php"]
    patterns: ["TOKEN_X"]
`
	if err := os.WriteFile(filepath.Join(dir, "rules.yml"), []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}
	s := NewScanner(dir)

	// .txt file with the pattern — should be skipped (file_types mismatch).
	matches := s.ScanContent([]byte("TOKEN_X found here"), ".txt")
	if len(matches) != 0 {
		t.Errorf(".txt scan should skip .php-only rule, got %v", matches)
	}

	// .php file — should match.
	matches = s.ScanContent([]byte("TOKEN_X found here"), ".php")
	if len(matches) != 1 {
		t.Errorf(".php scan should match, got %d matches", len(matches))
	}
}
