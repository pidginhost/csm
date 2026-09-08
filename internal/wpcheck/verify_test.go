package wpcheck

import (
	"crypto/md5" // #nosec G501 -- wordpress.org publishes MD5 digests for core files
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// WordPress unpacks every update under wp-content/upgrade/ before moving it
// into place, and the realtime analyzer sees each staged file before the
// checksum fetch for that package version has finished. The verifier must
// therefore expose the package identity and the fetch state separately from
// the hash comparison, so a caller can hash now and compare once the official
// checksums land.

const stagedPluginHeader = "<?php\n/*\nPlugin Name: GTM Kit\nVersion: 2.18.1\n*/\n"

func writeStaged(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func openFd(t *testing.T, path string) int {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return int(f.Fd())
}

func waitVerdict(t *testing.T, want Verdict, probe func() Verdict) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		got := probe()
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("verdict = %v, want %v after waiting", got, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// servePackages answers plugin ZIP downloads and core checksum lookups from
// one test server so the background fetchers run their real code paths.
func servePackages(t *testing.T, pluginZips map[string][]byte, coreChecksums map[string]string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".zip") {
			body, ok := pluginZips[filepath.Base(r.URL.Path)]
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write(body)
			return
		}
		if coreChecksums == nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"checksums": coreChecksums})
	}))
	t.Cleanup(srv.Close)
	withTestHTTPClient(t, srv)
	origTransport := httpClient.Transport
	httpClient.Transport = &rewriteTransport{target: srv.URL, inner: http.DefaultTransport}
	t.Cleanup(func() { httpClient.Transport = origTransport })
}

func TestDescribe_StagedPluginWithoutHeaderIsNoVersion(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "public_html", "wp-content", "upgrade", "gtm-kit.2.18.1", "gtm-kit", "inc", "frontend-functions.php")
	writeStaged(t, path, "<?php\n")

	v := NewCache(t.TempDir()).Describe(path)
	if v.Kind != KindPlugin || v.Slug != "gtm-kit" || v.Rel != filepath.Join("inc", "frontend-functions.php") {
		t.Fatalf("Describe = %+v, want a gtm-kit plugin file", v)
	}
	if v.Verdict != VerdictNoVersion {
		t.Errorf("Verdict = %v, want NoVersion while the plugin header is not unpacked yet", v.Verdict)
	}
}

func TestDescribe_StagedPluginFetchesChecksumsThenReady(t *testing.T) {
	body := []byte("<?php return array( 'slug' => 'gtm-kit' );\n")
	servePackages(t, map[string][]byte{
		"gtm-kit.2.18.1.zip": buildPluginZip(t, map[string][]byte{
			"gtm-kit/gtm-kit.php": []byte(stagedPluginHeader),
			"gtm-kit/inc/a.php":   body,
		}),
	}, nil)

	staging := filepath.Join(t.TempDir(), "public_html", "wp-content", "upgrade", "gtm-kit.2.18.1", "gtm-kit")
	writeStaged(t, filepath.Join(staging, "gtm-kit.php"), stagedPluginHeader)
	path := filepath.Join(staging, "inc", "a.php")
	writeStaged(t, path, string(body))

	c := NewCache(t.TempDir())
	v := c.Describe(path)
	if v.Verdict != VerdictPending || v.Version != "2.18.1" {
		t.Fatalf("Describe = %+v, want Pending for version 2.18.1 while the fetch runs", v)
	}
	waitVerdict(t, VerdictReady, func() Verdict { return c.Describe(path).Verdict })
}

func TestDescribe_PackageNotOnWordPressOrgIsUnavailable(t *testing.T) {
	servePackages(t, nil, nil)
	staging := filepath.Join(t.TempDir(), "public_html", "wp-content", "upgrade", "js_composer-jhi6eq", "js_composer")
	writeStaged(t, filepath.Join(staging, "js_composer.php"), "<?php\n/*\nPlugin Name: WPBakery\nVersion: 8.0\n*/\n")
	path := filepath.Join(staging, "include", "classes", "core.php")
	writeStaged(t, path, "<?php\n")

	c := NewCache(t.TempDir())
	waitVerdict(t, VerdictUnavailable, func() Verdict { return c.Describe(path).Verdict })
}

func TestDescribe_StagedThemeIsUnavailable(t *testing.T) {
	staging := filepath.Join(t.TempDir(), "public_html", "wp-content", "upgrade", "twentytwentyfour.1.2", "twentytwentyfour")
	writeStaged(t, filepath.Join(staging, "style.css"), "/*\nTheme Name: Twenty Twenty-Four\nVersion: 1.2\n*/\n")
	path := filepath.Join(staging, "functions.php")
	writeStaged(t, path, "<?php\n")

	v := NewCache(t.TempDir()).Describe(path)
	if v.Kind != KindTheme || v.Slug != "twentytwentyfour" || v.Version != "1.2" {
		t.Fatalf("Describe = %+v, want the twentytwentyfour theme at 1.2", v)
	}
	if v.Verdict != VerdictUnavailable {
		t.Errorf("Verdict = %v, want Unavailable: themes have no checksum source", v.Verdict)
	}
}

func TestDescribe_StagedCoreReadsStagedVersion(t *testing.T) {
	staging := filepath.Join(t.TempDir(), "public_html", "wp-content", "upgrade", "wp_6a9e080f774ec", "wordpress")
	loginBody := "<?php // login\n"
	sum := md5.Sum([]byte(loginBody)) // #nosec G401 -- test computes the digest wordpress.org publishes
	servePackages(t, nil, map[string]string{"wp-login.php": hex.EncodeToString(sum[:])})
	writeStaged(t, filepath.Join(staging, "wp-includes", "version.php"), "<?php $wp_version = '7.1';")
	path := filepath.Join(staging, "wp-login.php")
	writeStaged(t, path, loginBody)

	c := NewCache(t.TempDir())
	v := c.Describe(path)
	if v.Kind != KindCore || v.Version != "7.1" || v.Locale != "en_US" || v.Rel != "wp-login.php" {
		t.Fatalf("Describe = %+v, want core 7.1 en_US wp-login.php", v)
	}
	if v.Verdict != VerdictPending {
		t.Fatalf("Verdict = %v, want Pending while core checksums are fetched", v.Verdict)
	}
	waitVerdict(t, VerdictReady, func() Verdict { return c.Describe(path).Verdict })

	v = c.Describe(path)
	v.Digest = c.Digest(KindCore, openFd(t, path))
	if got := c.Verify(v); got != VerdictVerified {
		t.Errorf("Verify = %v, want Verified for a stock core file", got)
	}
}

func TestDescribe_StagedCoreWithoutVersionFileIsNoVersion(t *testing.T) {
	staging := filepath.Join(t.TempDir(), "public_html", "wp-content", "upgrade", "wordpress-7.1-no-content", "wordpress")
	path := filepath.Join(staging, "wp-admin", "includes", "update-core.php")
	writeStaged(t, path, "<?php\n")

	v := NewCache(t.TempDir()).Describe(path)
	if v.Kind != KindCore || v.Verdict != VerdictNoVersion {
		t.Fatalf("Describe = %+v, want core NoVersion before version.php is unpacked", v)
	}
}

func TestDescribe_PathOutsideAnyPackageIsUnknown(t *testing.T) {
	v := NewCache(t.TempDir()).Describe("/home/user/public_html/wp-content/upgrade/version-current.php")
	if v.Verdict != VerdictUnknown || v.Kind != KindNone {
		t.Fatalf("Describe = %+v, want Unknown for a file in no package", v)
	}
}

func TestVerify_ResolvesStoredDigestAgainstOfficialChecksums(t *testing.T) {
	staging := filepath.Join(t.TempDir(), "public_html", "wp-content", "upgrade", "gtm-kit.2.18.1", "gtm-kit")
	writeStaged(t, filepath.Join(staging, "gtm-kit.php"), stagedPluginHeader)
	body := "<?php return 1;\n"
	path := filepath.Join(staging, "inc", "a.php")
	writeStaged(t, path, body)
	extra := filepath.Join(staging, "inc", "not-in-package.php")
	writeStaged(t, extra, body)
	sum := sha256.Sum256([]byte(body))

	c := NewCache(t.TempDir())
	c.setPluginChecksums("gtm-kit", "2.18.1", map[string]string{filepath.Join("inc", "a.php"): hex.EncodeToString(sum[:])})

	v := c.Describe(path)
	if v.Verdict != VerdictReady {
		t.Fatalf("Verdict = %v, want Ready with checksums cached", v.Verdict)
	}
	v.Digest = c.Digest(KindPlugin, openFd(t, path))
	if got := c.Verify(v); got != VerdictVerified {
		t.Errorf("Verify = %v, want Verified for a stock file", got)
	}
	v.Digest = strings.Repeat("0", 64)
	if got := c.Verify(v); got != VerdictMismatch {
		t.Errorf("Verify = %v, want Mismatch for a modified file", got)
	}
	v.Digest = ""
	if got := c.Verify(v); got != VerdictUnverifiable {
		t.Errorf("Verify = %v, want Unverifiable when the file could not be hashed", got)
	}

	other := c.Describe(extra)
	other.Digest = c.Digest(KindPlugin, openFd(t, extra))
	if got := c.Verify(other); got != VerdictMismatch {
		t.Errorf("Verify = %v, want Mismatch for a file the official package does not contain", got)
	}
}

// The realtime analyzer hashes while the fetch is still running and asks
// again later. A description taken while Pending must resolve to a real
// comparison once the checksums are cached.
func TestVerify_PendingDescriptionResolvesOnceChecksumsLand(t *testing.T) {
	body := []byte("<?php return 2;\n")
	servePackages(t, map[string][]byte{
		"gtm-kit.2.18.1.zip": buildPluginZip(t, map[string][]byte{
			"gtm-kit/gtm-kit.php": []byte(stagedPluginHeader),
			"gtm-kit/inc/a.php":   body,
		}),
	}, nil)
	staging := filepath.Join(t.TempDir(), "public_html", "wp-content", "upgrade", "gtm-kit.2.18.1", "gtm-kit")
	writeStaged(t, filepath.Join(staging, "gtm-kit.php"), stagedPluginHeader)
	path := filepath.Join(staging, "inc", "a.php")
	writeStaged(t, path, string(body))

	c := NewCache(t.TempDir())
	v := c.Describe(path)
	v.Digest = c.Digest(KindPlugin, openFd(t, path))
	if v.Verdict != VerdictPending {
		t.Fatalf("Verdict = %v, want Pending", v.Verdict)
	}
	if got := c.Verify(v); got != VerdictPending {
		t.Fatalf("Verify = %v, want Pending passed through before the fetch completes", got)
	}
	waitVerdict(t, VerdictVerified, func() Verdict { return c.Verify(v) })
}

func TestVerify_UnavailablePassesThrough(t *testing.T) {
	c := NewCache(t.TempDir())
	c.markPluginNotFound("js_composer", "8.0", time.Hour)
	v := Verification{Verdict: VerdictUnavailable, Kind: KindPlugin, Slug: "js_composer", Version: "8.0", Rel: "x.php", Digest: strings.Repeat("a", 64)}
	if got := c.Verify(v); got != VerdictUnavailable {
		t.Errorf("Verify = %v, want Unavailable", got)
	}
}

func TestDigest_UsesTheAlgorithmWordPressOrgPublishes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f.php")
	body := "<?php echo 1;\n"
	writeStaged(t, path, body)
	c := NewCache(t.TempDir())

	s := sha256.Sum256([]byte(body))
	if got := c.Digest(KindPlugin, openFd(t, path)); got != hex.EncodeToString(s[:]) {
		t.Errorf("plugin digest = %q, want sha256", got)
	}
	m := md5.Sum([]byte(body)) // #nosec G401 -- wordpress.org core checksums are MD5
	if got := c.Digest(KindCore, openFd(t, path)); got != hex.EncodeToString(m[:]) {
		t.Errorf("core digest = %q, want md5", got)
	}
	if got := c.Digest(KindTheme, openFd(t, path)); got != "" {
		t.Errorf("theme digest = %q, want empty: no checksum source", got)
	}
}

func TestDigest_EmptyWhenFileExceedsHashCap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big.php")
	if err := os.WriteFile(path, make([]byte, maxFileSize+1), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := NewCache(t.TempDir()).Digest(KindPlugin, openFd(t, path)); got != "" {
		t.Errorf("digest = %q, want empty for a file over the hash cap", got)
	}
}

func TestVerifyFile_InstalledPluginMatchesCachedHash(t *testing.T) {
	root := filepath.Join(t.TempDir(), "public_html", "wp-content", "plugins", "gtm-kit")
	writeStaged(t, filepath.Join(root, "gtm-kit.php"), stagedPluginHeader)
	sum := sha256.Sum256([]byte(stagedPluginHeader))
	c := NewCache(t.TempDir())
	c.setPluginChecksums("gtm-kit", "2.18.1", map[string]string{"gtm-kit.php": hex.EncodeToString(sum[:])})

	path := filepath.Join(root, "gtm-kit.php")
	v := c.VerifyFile(openFd(t, path), path)
	if v.Verdict != VerdictVerified || v.Kind != KindPlugin {
		t.Fatalf("VerifyFile = %+v, want Verified plugin file", v)
	}
	if err := os.WriteFile(path, []byte(stagedPluginHeader+"// tampered\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if v := c.VerifyFile(openFd(t, path), path); v.Verdict != VerdictMismatch {
		t.Errorf("VerifyFile = %+v, want Mismatch after tampering", v)
	}
}

func TestVerifyFile_StagedCoreUsesPackageRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "wp-content", "upgrade", "wp_random", "wordpress")
	c := NewCache(t.TempDir())
	body := "<?php return 42;\n"
	sum := md5.Sum([]byte(body)) // #nosec G401 -- test uses official core digest format
	rels := []string{"index.php", "extra.php", "wp-admin/includes/a.php", "wp-content/plugins/akismet/class.php"}
	var pending []Verification
	for _, rel := range rels {
		path := filepath.Join(root, rel)
		writeStaged(t, path, body)
		v := c.VerifyFile(openFd(t, path), path)
		if v.Kind != KindCore || v.Root != root || v.Rel != rel || v.Verdict != VerdictNoVersion || v.Digest != hex.EncodeToString(sum[:]) {
			t.Errorf("VerifyFile(%s) = %+v, want core identity and digest before version.php exists", rel, v)
		}
		pending = append(pending, v)
	}
	writeStaged(t, filepath.Join(root, "wp-includes", "version.php"), "<?php $wp_version = '7.1';")
	c.checksums[cacheKey("7.1", "en_US")] = map[string]string{"index.php": hex.EncodeToString(sum[:])}
	for i, rel := range rels {
		v := c.Describe(filepath.Join(root, rel))
		v.Digest = pending[i].Digest
		want := VerdictMismatch
		if rel == "index.php" {
			want = VerdictVerified
		}
		if got := c.Verify(v); got != want {
			t.Errorf("Verify(%s) = %v, want %v", rel, got, want)
		}
	}
}

func TestVerifyFile_PluginCoreNamesKeepPluginIdentity(t *testing.T) {
	for _, staged := range []bool{false, true} {
		for _, slug := range []string{"example", "wordpress"} {
			if staged && slug == "wordpress" {
				continue // this staging layout denotes the core distribution
			}
			root := filepath.Join(t.TempDir(), "wp-content", "plugins", slug)
			if staged {
				root = filepath.Join(t.TempDir(), "wp-content", "upgrade", "example.1.0", slug)
			}
			writeStaged(t, filepath.Join(root, slug+".php"), "<?php\n/* Plugin Name: Example\nVersion: 1.0\n*/")
			c := NewCache(t.TempDir())
			body := "<?php return 1;"
			sum := sha256.Sum256([]byte(body))
			c.setPluginChecksums(slug, "1.0", map[string]string{"wp-load.php": hex.EncodeToString(sum[:])})
			path := filepath.Join(root, "wp-load.php")
			writeStaged(t, path, body)
			for _, nestedCore := range []bool{false, true} {
				if nestedCore {
					writeStaged(t, filepath.Join(root, "wp-includes", "version.php"), "<?php $wp_version = '7.1';")
					c.checksums[cacheKey("7.1", "en_US")] = map[string]string{"wp-load.php": strings.Repeat("0", 32)}
				}
				if v := c.VerifyFile(openFd(t, path), path); v.Kind != KindPlugin || v.Verdict != VerdictVerified {
					t.Errorf("staged=%v slug=%s nestedCore=%v: %+v, want verified plugin", staged, slug, nestedCore, v)
				}
			}
		}
	}
}

func TestDescribe_InstalledPluginOwnsNestedUpgradeFixture(t *testing.T) {
	root := filepath.Join(t.TempDir(), "wp-content/plugins/outer")
	writeStaged(t, filepath.Join(root, "outer.php"), "<?php\n/* Plugin Name: Outer\nVersion: 1.0\n*/")
	rel := "tests/wp-content/upgrade/package/inner/file.php"
	c := NewCache(t.TempDir())
	c.setPluginChecksums("outer", "1.0", map[string]string{})
	if v := c.Describe(filepath.Join(root, rel)); v.Kind != KindPlugin || v.Root != root || v.Rel != rel || v.Verdict != VerdictReady {
		t.Fatalf("nested fixture escaped its outer plugin identity: %+v", v)
	}
}

func TestDescribe_RecreatedCoreTreeNeedsItsOwnHeader(t *testing.T) {
	root := filepath.Join(t.TempDir(), "wp-content/upgrade/package/wordpress")
	path := filepath.Join(root, "wp-admin/file.php")
	writeStaged(t, filepath.Join(root, "wp-includes/version.php"), "<?php $wp_version = '6.9';")
	writeStaged(t, path, "<?php return 1;")
	sum := md5.Sum([]byte("<?php return 1;")) // #nosec G401 -- official core digest
	c := NewCache(t.TempDir())
	c.checksums[cacheKey("6.9", "en_US")] = map[string]string{"wp-admin/file.php": hex.EncodeToString(sum[:])}
	if v := c.Describe(path); v.Version != "6.9" {
		t.Fatalf("old tree was not identified: %+v", v)
	}
	if !c.IsVerifiedCoreFile(openFd(t, path), path) {
		t.Fatal("stock old tree did not verify")
	}
	if err := os.Rename(root, root+"-old"); err != nil {
		t.Fatal(err)
	}
	writeStaged(t, path, "<?php return 1;")
	if v := c.Describe(path); v.Verdict != VerdictNoVersion || v.Version != "" {
		t.Fatalf("replacement reused old core header: %+v", v)
	}
	if c.IsVerifiedCoreFile(openFd(t, path), path) {
		t.Fatal("core verification reused the old tree's cached header")
	}
}

func TestVerify_StagedCoreCannotChangeItsRecordedRelease(t *testing.T) {
	root := filepath.Join(t.TempDir(), "wp-content/upgrade/package/wordpress")
	path := filepath.Join(root, "wp-admin/file.php")
	body := "<?php return 1;"
	writeStaged(t, path, body)
	writeStaged(t, filepath.Join(root, "wp-includes/version.php"), "<?php $wp_version = '7.1';")
	c := NewCache(t.TempDir())
	c.checksums[cacheKey("7.1", "en_US")] = map[string]string{"wp-admin/file.php": strings.Repeat("0", 32)}
	v := c.Describe(path)
	v.Digest = c.Digest(KindCore, openFd(t, path))
	writeStaged(t, filepath.Join(root, "wp-includes/version.php"), "<?php $wp_version = '7.2';")
	c.checksums[cacheKey("7.2", "en_US")] = map[string]string{"wp-admin/file.php": v.Digest}
	if got := c.Verify(v); got != VerdictMismatch {
		t.Fatalf("recorded 7.1 mismatch was verified against a later header: %v", got)
	}
}
