//go:build linux

package daemon

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/state"
	"github.com/pidginhost/csm/internal/wpcheck"
)

// WordPress unpacks every update into a fresh wp-content/upgrade/<random>/
// directory. A package that cannot be checked against wordpress.org is the
// same condition however often it is uploaded again, so its warning must keep
// one identity across staging directories and go through the normal reminder
// window instead of alerting on every upload.

const stagedDedupSite = "/home/exampleuser/public_html"

func stagedDedupPath(site, staging, unpacked, rel string) string {
	return filepath.Join(site, "wp-content", "upgrade", staging, unpacked, rel)
}

func stagedDedupPlugin(slug, version string, verdict wpcheck.Verdict, path string) wpcheck.Verification {
	pkg := parseWPStagedPackage(path)
	root := pkg.dir + "/" + pkg.unpacked
	return wpcheck.Verification{
		Verdict: verdict, Kind: wpcheck.KindPlugin, Root: root, Slug: slug, Version: version,
		Rel: strings.TrimPrefix(path, root+"/"),
	}
}

func stagedDedupFinding(t *testing.T, path string, v wpcheck.Verification, queueLimit int) alert.Finding {
	t.Helper()
	fm, ch := newStagedPackageMonitor(t, nil)
	if queueLimit >= 0 {
		fm.wpPending = newStagedPackageQueue(queueLimit)
	}
	if !fm.handleStagedPackageFile(path, v, "") {
		t.Fatalf("%s was not handled as a staged package file", path)
	}
	got := drainFindings(ch)
	if len(got) != 1 {
		t.Fatalf("findings = %+v, want exactly one", got)
	}
	return got[0]
}

func openDedupState(t *testing.T) *state.Store {
	t.Helper()
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func requireRepeat(t *testing.T, first, second alert.Finding) {
	t.Helper()
	if first.Key() != second.Key() {
		t.Fatalf("keys differ for one package:\n first  %q\n second %q", first.Key(), second.Key())
	}
	st := openDedupState(t)
	st.Update([]alert.Finding{first})
	if fresh := st.FilterNew([]alert.Finding{second}); len(fresh) != 0 {
		t.Fatalf("re-staged package alerted again: %+v", fresh)
	}
}

func requireDistinct(t *testing.T, base, other alert.Finding) {
	t.Helper()
	if base.Key() == other.Key() {
		t.Fatalf("distinct condition shares key %q", base.Key())
	}
	st := openDedupState(t)
	st.Update([]alert.Finding{base})
	if fresh := st.FilterNew([]alert.Finding{other}); len(fresh) != 1 {
		t.Fatalf("distinct condition was filtered as a repeat: %+v", other)
	}
}

func unavailablePackageFinding(t *testing.T, site, staging, slug, version string) alert.Finding {
	t.Helper()
	path := stagedDedupPath(site, staging, slug, slug+".php")
	return stagedDedupFinding(t, path, stagedDedupPlugin(slug, version, wpcheck.VerdictUnavailable, path), -1)
}

func TestStagedPackageWarningKeepsIdentityAcrossStagingDirs(t *testing.T) {
	first := unavailablePackageFinding(t, stagedDedupSite, "acme-forms-x7k2p9", "acme-forms", "3.1.0")
	// WordPress names the staging directory after the uploaded archive, so
	// the same package can also arrive under a case variant.
	second := unavailablePackageFinding(t, stagedDedupSite, "Acme-forms-q3m8z1", "acme-forms", "3.1.0")
	if first.FilePath == second.FilePath {
		t.Fatalf("fixture error: both stagings share %s", first.FilePath)
	}
	requireRepeat(t, first, second)
}

func TestStagedPackageWarningIdentitySeparatesPackages(t *testing.T) {
	base := unavailablePackageFinding(t, stagedDedupSite, "acme-forms-x7k2p9", "acme-forms", "3.1.0")
	t.Run("version", func(t *testing.T) {
		requireDistinct(t, base, unavailablePackageFinding(t, stagedDedupSite, "acme-forms-q3m8z1", "acme-forms", "3.2.0"))
	})
	t.Run("site", func(t *testing.T) {
		requireDistinct(t, base, unavailablePackageFinding(t, "/home/exampleuser/shop.example.test", "acme-forms-q3m8z1", "acme-forms", "3.1.0"))
	})
	t.Run("account", func(t *testing.T) {
		requireDistinct(t, base, unavailablePackageFinding(t, "/home/otheruser/public_html", "acme-forms-q3m8z1", "acme-forms", "3.1.0"))
	})
	t.Run("slug", func(t *testing.T) {
		requireDistinct(t, base, unavailablePackageFinding(t, stagedDedupSite, "acme-forms-q3m8z1", "acme-forms-pro", "3.1.0"))
	})
	t.Run("type", func(t *testing.T) {
		// Same reason for both, so only the package type differs.
		path := stagedDedupPath(stagedDedupSite, "acme-forms-q3m8z1", "acme-forms", "style.php")
		plugin := stagedDedupPlugin("acme-forms", "3.1.0", wpcheck.VerdictPending, path)
		theme := plugin
		theme.Kind = wpcheck.KindTheme
		requireDistinct(t, stagedDedupFinding(t, path, plugin, 0), stagedDedupFinding(t, path, theme, 0))
	})
	t.Run("reason", func(t *testing.T) {
		path := stagedDedupPath(stagedDedupSite, "acme-forms-q3m8z1", "acme-forms", "acme-forms.php")
		queued := stagedDedupFinding(t, path, stagedDedupPlugin("acme-forms", "3.1.0", wpcheck.VerdictPending, path), 0)
		if !strings.Contains(queued.Details, "queue full") {
			t.Fatalf("Details = %q, want the queue-full reason", queued.Details)
		}
		requireDistinct(t, base, queued)
	})
}

func stagedFileFinding(t *testing.T, staging, rel string, verdict wpcheck.Verdict, digest string) alert.Finding {
	t.Helper()
	path := stagedDedupPath(stagedDedupSite, staging, "acme-forms", rel)
	v := stagedDedupPlugin("acme-forms", "3.1.0", verdict, path)
	v.Digest = digest
	return stagedDedupFinding(t, path, v, -1)
}

func TestStagedFileWarningKeepsIdentityAcrossStagingDirs(t *testing.T) {
	sum := strings.Repeat("a", 64)
	t.Run("unverifiable", func(t *testing.T) {
		first := stagedFileFinding(t, "acme-forms-x7k2p9", "includes/loader.php", wpcheck.VerdictUnverifiable, "")
		second := stagedFileFinding(t, "acme-forms-q3m8z1", "includes/loader.php", wpcheck.VerdictUnverifiable, "")
		if !strings.Contains(first.Message, "could not be verified") {
			t.Fatalf("Message = %q, want the unverifiable variant", first.Message)
		}
		requireDistinct(t, first, second)
		requireDistinct(t, first, stagedFileFinding(t, "acme-forms-q3m8z1", "includes/admin.php", wpcheck.VerdictUnverifiable, ""))
	})
	t.Run("mismatch", func(t *testing.T) {
		first := stagedFileFinding(t, "acme-forms-x7k2p9", "includes/loader.php", wpcheck.VerdictMismatch, sum)
		second := stagedFileFinding(t, "acme-forms-q3m8z1", "includes/loader.php", wpcheck.VerdictMismatch, sum)
		requireRepeat(t, first, second)
		// Different bytes at the same place are a different modification.
		requireDistinct(t, first, stagedFileFinding(t, "acme-forms-q3m8z1", "includes/loader.php", wpcheck.VerdictMismatch, strings.Repeat("b", 64)))
	})
	t.Run("not the package warning", func(t *testing.T) {
		file := stagedFileFinding(t, "acme-forms-x7k2p9", "includes/loader.php", wpcheck.VerdictUnverifiable, "")
		requireDistinct(t, unavailablePackageFinding(t, stagedDedupSite, "acme-forms-x7k2p9", "acme-forms", "3.1.0"), file)
	})
}

func requireNotDismissed(t *testing.T, first, second alert.Finding) {
	t.Helper()
	st := openDedupState(t)
	st.Update([]alert.Finding{first})
	st.DismissFinding(first.Key())
	if fresh := st.FilterNew([]alert.Finding{second}); len(fresh) != 1 {
		t.Fatalf("new evidence inherited a dismissed identity: %+v", second)
	}
}

func TestStagedPackageIncompleteIdentityCannotCrossUploads(t *testing.T) {
	for _, verdict := range []wpcheck.Verdict{wpcheck.VerdictUnknown, wpcheck.VerdictUnavailable, wpcheck.VerdictNoVersion} {
		t.Run(verdict.String(), func(t *testing.T) {
			var findings []alert.Finding
			for _, staging := range []string{"first", "second"} {
				path := stagedDedupPath(stagedDedupSite, staging, "acme-forms", "loader.php")
				v := stagedDedupPlugin("acme-forms", "", verdict, path)
				switch verdict {
				case wpcheck.VerdictUnknown:
					v = wpcheck.Verification{}
				case wpcheck.VerdictUnavailable:
					v.Kind = wpcheck.KindTheme
				}
				f := stagedDedupFinding(t, path, v, 0)
				if f.DedupKey != "" {
					t.Errorf("incomplete header pins identity %q", f.DedupKey)
				}
				findings = append(findings, f)
			}
			requireNotDismissed(t, findings[0], findings[1])
		})
	}
}

// The first warning may be a dismissed repeat. A later header or reason
// must still reach persistent dedup, even within the per-directory cooldown.
func TestStagedPackageLateIdentityEscapesDirectoryCooldown(t *testing.T) {
	for _, change := range []string{"version", "type", "reason", "missing-version"} {
		t.Run(change, func(t *testing.T) {
			fm, ch := newStagedPackageMonitor(t, nil)
			fm.wpPending = newStagedPackageQueue(0)
			path := stagedDedupPath(stagedDedupSite, "same-staging", "acme-forms", "loader.php")
			v := stagedDedupPlugin("acme-forms", "3.1.0", wpcheck.VerdictUnavailable, path)
			if change == "missing-version" {
				v.Version, v.Verdict = "", wpcheck.VerdictNoVersion
			}
			fm.handleStagedPackageFile(path, v, "")
			first := drainFindings(ch)
			if len(first) != 1 {
				t.Fatalf("initial findings = %+v", first)
			}
			switch change {
			case "version", "missing-version":
				v.Version = "3.2.0"
			case "type":
				v.Kind = wpcheck.KindTheme
			case "reason":
				v.Verdict = wpcheck.VerdictPending
			}
			fm.handleStagedPackageFile(path, v, "")
			second := drainFindings(ch)
			if len(second) != 1 {
				t.Fatalf("changed %s was lost to directory cooldown: %+v", change, second)
			}
			requireNotDismissed(t, first[0], second[0])
			fm.handleStagedPackageFile(path, v, "")
			if got := drainFindings(ch); len(got) != 0 {
				t.Fatalf("unchanged package bypassed cooldown: %+v", got)
			}
		})
	}
}

func TestStagedFileMissingDigestCannotInheritDismissal(t *testing.T) {
	first := stagedFileFinding(t, "first", "loader.php", wpcheck.VerdictUnverifiable, "")
	second := stagedFileFinding(t, "second", "loader.php", wpcheck.VerdictUnverifiable, "")
	if second.DedupKey != "" {
		t.Errorf("unhashed file pins identity %q", second.DedupKey)
	}
	requireNotDismissed(t, first, second)
}

func TestStagedPackageLateThemeHeaderDoesNotSilenceNewUpload(t *testing.T) {
	site := filepath.Join(t.TempDir(), "public_html")
	cache := wpcheck.NewCache(t.TempDir())
	fm, ch := newStagedPackageMonitor(t, cache)
	var previous alert.Finding
	for _, staging := range []string{"first", "second"} {
		path := stagedDedupPath(site, staging, "example-theme", "functions.php")
		style := filepath.Join(filepath.Dir(path), "style.css")
		// The name can be readable before the version line has been written.
		writeStagedFile(t, style, "/* Theme Name: Example Theme\n")
		analyzeStaged(t, fm, path)
		if staging == "first" {
			got := drainFindings(ch)
			if len(got) != 1 {
				t.Fatalf("initial upload findings = %+v", got)
			}
			previous = got[0]
			continue
		}
		writeStagedFile(t, style, "/* Theme Name: Example Theme\nVersion: 2.0\n*/")
		analyzeStaged(t, fm, filepath.Join(filepath.Dir(path), "index.php"))
		st := openDedupState(t)
		st.Update([]alert.Finding{previous})
		st.DismissFinding(previous.Key())
		if got := st.FilterNew(drainFindings(ch)); len(got) == 0 {
			t.Fatal("new release was silenced by the previous upload's partial header")
		}
	}
}

func TestStagedFileUnhashedBytesCannotInheritDismissal(t *testing.T) {
	site := filepath.Join(t.TempDir(), "public_html")
	cache := wpcheck.NewCache(t.TempDir())
	if err := cache.PersistChecksums("7.1", "en_US", nil, map[string]string{"extra.php": strings.Repeat("a", 32)}); err != nil {
		t.Fatal(err)
	}
	fm, ch := newStagedPackageMonitor(t, cache)
	var findings []alert.Finding
	for _, staging := range []string{"first", "second"} {
		path := stagedDedupPath(site, staging, "wordpress", "extra.php")
		writeStagedFile(t, filepath.Join(filepath.Dir(path), "wp-includes", "version.php"), "<?php $wp_version = '7.1';")
		// Exceed the verifier's complete-file bound; different uploads carry
		// different bytes but both have an empty comparison digest.
		fd := writeStagedFile(t, path, cleanStagedPHP+strings.Repeat("// padding\n", 300000)+"// "+staging)
		fm.analyzeFile(fileEvent{path: path, fd: fd})
		got := drainFindings(ch)
		if len(got) != 1 || !strings.Contains(got[0].Message, "could not be verified") || got[0].DedupKey != "" {
			t.Fatalf("unhashed file must keep its upload identity: %+v", got)
		}
		findings = append(findings, got[0])
	}
	requireNotDismissed(t, findings[0], findings[1])
}

func TestStagedContentCannotInheritPackageDismissal(t *testing.T) {
	for _, verdict := range []wpcheck.Verdict{wpcheck.VerdictUnavailable, wpcheck.VerdictPending, wpcheck.VerdictNoVersion, wpcheck.VerdictUnverifiable, wpcheck.VerdictMismatch} {
		t.Run(verdict.String(), func(t *testing.T) {
			site := filepath.Join(t.TempDir(), "public_html")
			path := stagedDedupPath(site, "chosen-by-uploader", "acme-forms", "loader.php")
			pkg := parseWPStagedPackage(path)
			fake := &fakeWPVerifier{
				describe: describeStagedPlugin(pkg.dir, "acme-forms", "3.1.0", verdict),
				verify:   func(wpcheck.Verification) wpcheck.Verdict { return verdict },
			}
			fm, ch := newStagedPackageMonitor(t, fake)
			fm.wpPending = newStagedPackageQueue(0)
			analyzeStaged(t, fm, path)
			first := drainFindings(ch)
			if len(first) != 1 || first[0].Severity != alert.Warning {
				t.Fatalf("expected a warning to dismiss: %+v", first)
			}
			fm.analyzeFile(fileEvent{path: path, fd: writeStagedFile(t, path, "<?php system($_GET['cmd']);")})
			fm.drainStagedPackages(time.Now().Add(stagedPackageTimeout + time.Second))
			got := drainFindings(ch)
			if len(got) != 1 || got[0].Severity != alert.Critical || got[0].DedupKey != "" {
				t.Fatalf("content-positive event must keep its own finding: %+v", got)
			}
			requireNotDismissed(t, first[0], got[0])
		})
	}
}

// Content findings are never folded into a package identity: each staged
// file a content rule flags keeps its own path-based identity.
func TestStagedContentFindingKeepsPerFileIdentity(t *testing.T) {
	site := filepath.Join(t.TempDir(), "public_html")
	var findings []alert.Finding
	for _, staging := range []string{"acme-forms-x7k2p9", "acme-forms-q3m8z1"} {
		fm, ch := newStagedPackageMonitor(t, nil)
		path := stagedDedupPath(site, staging, "acme-forms", "includes/loader.php")
		fm.analyzeFile(fileEvent{path: path, fd: writeStagedFile(t, path, "<?php system($_GET['cmd']);")})
		for _, f := range drainFindings(ch) {
			if f.Severity == alert.Critical {
				findings = append(findings, f)
			}
		}
	}
	if len(findings) != 2 {
		t.Fatalf("content findings = %+v, want one per staged file", findings)
	}
	for _, f := range findings {
		if f.DedupKey != "" {
			t.Errorf("content finding %s carries a pinned identity %q", f.FilePath, f.DedupKey)
		}
	}
	requireDistinct(t, findings[0], findings[1])
}
