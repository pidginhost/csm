package checks

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/state"
)

// A successful sibling must not make a failed filesystem walk look complete.
func TestRestoredScansPreserveFindingsOnReadFailure(t *testing.T) {
	for _, tc := range []struct {
		name, finding, path string
	}{
		{"filesystem", "suid_binary", "nested/payload"},
		{"webshells", "world_writable_php", "public_html/index.php"},
		{"htaccess", "htaccess_injection", "public_html/.htaccess"},
		{"phishing", "phishing_page", "public_html/login.html"},
	} {
		for _, failure := range []string{"inventory", "partial inventory", "home", "subdirectory", "metadata", "open"} {
			if failure == "open" && (tc.name == "filesystem" || tc.name == "webshells") {
				continue
			}
			if failure == "metadata" && tc.name == "htaccess" {
				continue
			}
			t.Run(tc.name+"/"+failure, func(t *testing.T) {
				root := t.TempDir()
				home := filepath.Join(root, "alice")
				path := filepath.Join(home, tc.path)
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, make([]byte, 4000), 0600); err != nil {
					t.Fatal(err)
				}
				oldRoots := accountHomeRoots
				accountHomeRoots = func() []string { return []string{root, root + "-unreadable"} }
				t.Cleanup(func() { accountHomeRoots = oldRoots })
				broken := true
				withMockOS(t, &mockOS{
					readDir: func(dir string) ([]os.DirEntry, error) {
						if broken && ((failure == "inventory" && dir == root) ||
							(failure == "partial inventory" && dir == root+"-unreadable") ||
							(failure == "home" && dir == home) ||
							(failure == "subdirectory" && dir == filepath.Dir(path))) {
							return nil, os.ErrPermission
						}
						if dir == "/tmp" || dir == "/var/tmp" || dir == "/dev/shm" {
							return nil, nil
						}
						entries, err := os.ReadDir(dir)
						if broken && failure == "metadata" {
							for i, entry := range entries {
								if filepath.Join(dir, entry.Name()) == path {
									entries[i] = unreadableScanEntry{entry}
								}
							}
						}
						return entries, err
					},
					open: func(name string) (*os.File, error) {
						if broken && failure == "open" && name == path {
							return nil, os.ErrPermission
						}
						return os.Open(name)
					},
					stat: os.Stat,
				})
				st, err := state.Open(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = st.Close() }()
				prior := alert.Finding{Check: tc.finding, FilePath: path, Message: "prior detection", Severity: alert.Critical}
				st.SetLatestFindings([]alert.Finding{prior})
				checks := reducedDeepChecks()
				for i := range checks {
					if checks[i].name != tc.name {
						checks[i].fn = func(context.Context, *config.Config, *state.Store) []alert.Finding { return nil }
					}
				}
				findings, purge := runParallel(&config.Config{}, st, checks, "deep", true)
				StoreLatestScanFindings(st, purge, findings)
				if !slices.ContainsFunc(st.LatestFindings(), func(f alert.Finding) bool { return f.Key() == prior.Key() }) {
					t.Errorf("failed %s read retired prior finding; purge=%v", failure, purge)
				}
				// A later complete clean scan must still retire the finding.
				broken = false
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				findings, purge = runParallel(&config.Config{}, st, checks, "deep", true)
				StoreLatestScanFindings(st, purge, findings)
				if containsFindingCheck(st.LatestFindings(), tc.finding) {
					t.Error("complete scan retained stale finding")
				}
			})
		}
	}
}

type unreadableScanEntry struct{ os.DirEntry }

func (e unreadableScanEntry) Info() (os.FileInfo, error) { return nil, os.ErrPermission }

func TestExposedFilesIncompleteRunRetriesAcrossTiers(t *testing.T) {
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	var runs int
	check := namedCheck{"exposed_files", func(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
		runs++
		if runs == 1 {
			markCheckIncomplete(ctx, "exposed_files")
		}
		return nil
	}}
	for _, tier := range []string{"reduced", "deep", "reduced"} {
		runParallel(&config.Config{}, st, []namedCheck{check}, tier, true)
	}
	if runs != 2 {
		t.Fatalf("runs=%d, want incomplete attempt, successful retry, then throttle skip", runs)
	}
}

func TestFilesystemCapPreservesEarlierBackdoor(t *testing.T) {
	root := t.TempDir()
	oldRoots := accountHomeRoots
	accountHomeRoots = func() []string { return []string{root} }
	t.Cleanup(func() { accountHomeRoots = oldRoots })
	var paths []string
	for _, name := range []string{"defunct", "gs-netcat"} {
		path := filepath.Join(root, "alice", ".config", "htop", name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("binary"), 0600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	withMockOS(t, &mockOS{glob: filepath.Glob, stat: os.Stat, readDir: func(path string) ([]os.DirEntry, error) {
		if path == "/tmp" || path == "/var/tmp" || path == "/dev/shm" {
			return nil, nil
		}
		return os.ReadDir(path)
	}})
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	// First establish both detections, then reduce the candidate budget.
	cfg := &config.Config{}
	checks := []namedCheck{{"filesystem", CheckFilesystem}}
	findings, purge := runParallel(cfg, st, checks, "deep", true)
	StoreLatestScanFindings(st, purge, findings)
	cfg.Thresholds.AccountScanMaxFiles = 1
	findings, purge = runParallel(cfg, st, checks, "deep", true)
	StoreLatestScanFindings(st, purge, findings)
	for _, path := range paths {
		if !hasFindingPath(st.LatestFindings(), "backdoor_binary", path) {
			t.Errorf("capped run retired %s", path)
		}
	}
}

func TestPhishingReadFailuresMarkIncomplete(t *testing.T) {
	readers := map[string]func(context.Context, string){
		"html":        func(ctx context.Context, path string) { analyzeHTMLForPhishing(ctx, path) },
		"php":         func(ctx context.Context, path string) { analyzePHPForPhishing(ctx, path) },
		"quick":       func(ctx context.Context, path string) { quickPhishingCheck(ctx, path) },
		"redirector":  func(ctx context.Context, path string) { checkPHPRedirector(ctx, path) },
		"iframe":      func(ctx context.Context, path string) { checkIframePhishing(ctx, path) },
		"credentials": func(ctx context.Context, path string) { checkCredentialLog(ctx, path) },
		"zip":         func(ctx context.Context, path string) { zipLooksLikeKit(ctx, path) },
	}
	for name, read := range readers {
		for _, failure := range []string{"open", "read", "archive parse"} {
			if failure == "archive parse" && name != "zip" {
				continue
			}
			t.Run(name+"/"+failure, func(t *testing.T) {
				root := t.TempDir()
				path := filepath.Join(root, "candidate")
				if err := os.WriteFile(path, make([]byte, 4000), 0600); err != nil {
					t.Fatal(err)
				}
				withMockOS(t, &mockOS{open: func(string) (*os.File, error) {
					if failure == "open" {
						return nil, os.ErrPermission
					}
					if failure == "archive parse" {
						return os.Open(path)
					}
					// Reading an open directory fails even though Open succeeds.
					return os.Open(root)
				}})
				ctx, incomplete := withIncompleteCheckCollector(context.Background())
				read(ctx, path)
				if !incomplete.contains("phishing") {
					t.Fatal("unreadable candidate reported complete")
				}
			})
		}
	}
}

func TestHtaccessRegistryReadFailurePreservesFinding(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".htaccess")
	if err := os.WriteFile(path, []byte("# clean\n"), 0600); err != nil {
		t.Fatal(err)
	}
	opens := 0
	withMockOS(t, &mockOS{readDir: os.ReadDir, open: func(name string) (*os.File, error) {
		opens++
		if opens == 2 {
			return nil, os.ErrPermission
		}
		return os.Open(name)
	}})
	st, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	st.SetLatestFindings([]alert.Finding{{Check: "htaccess_php_in_uploads", FilePath: path, Message: "prior detection"}})
	checks := []namedCheck{{"htaccess", func(ctx context.Context, cfg *config.Config, _ *state.Store) []alert.Finding {
		var findings []alert.Finding
		scanHtaccess(ctx, root, 1, nil, nil, cfg, &findings)
		return findings
	}}}
	findings, purge := runParallel(&config.Config{}, st, checks, "deep", true)
	StoreLatestScanFindings(st, purge, findings)
	if opens != 2 || !containsFindingCheck(st.LatestFindings(), "htaccess_php_in_uploads") {
		t.Fatal("generic scan success cleared the registry's unreadable finding")
	}
}

func TestReducedDeepSharedFindingsRequireEveryOwner(t *testing.T) {
	for _, partial := range []string{"php_content", "file_index"} {
		t.Run(partial, func(t *testing.T) {
			st, err := state.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = st.Close() }()
			prior := alert.Finding{Check: "obfuscated_php", FilePath: "/home/alice/public_html/payload.php", Message: "prior detection"}
			st.SetLatestFindings([]alert.Finding{prior})
			checks := reducedDeepChecks()
			incomplete := true
			for i := range checks {
				name := checks[i].name
				checks[i].fn = func(ctx context.Context, _ *config.Config, _ *state.Store) []alert.Finding {
					if incomplete && name == partial {
						markCheckIncomplete(ctx, name)
					}
					return nil
				}
			}
			ctx, gaps := WithCoverageGaps(context.Background())
			findings, purge := runParallelWithContext(ctx, &config.Config{}, st, checks, "deep", true)
			StoreLatestScanFindingsWithCoverage(st, purge, findings, gaps.Snapshot())
			if slices.Contains(purge, prior.Check) || !containsFindingCheck(st.LatestFindings(), prior.Check) {
				t.Fatal("completed sibling retired shared finding")
			}
			incomplete = false
			findings, purge = runParallelWithContext(ctx, &config.Config{}, st, checks, "deep", true)
			StoreLatestScanFindingsWithCoverage(st, purge, findings, gaps.Snapshot())
			if !slices.Contains(purge, prior.Check) || containsFindingCheck(st.LatestFindings(), prior.Check) {
				t.Fatal("completed owners failed to retire stale finding")
			}
		})
	}
}
