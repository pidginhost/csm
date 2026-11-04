package main

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// writeFakeProc builds a /proc tree: pid 1 in the root namespace, plus one
// process per cage. A cage whose value is true has the event mount in its
// mount table.
func writeFakeProc(t *testing.T, cages []bool) string {
	t.Helper()

	root := t.TempDir()
	mkProc := func(pid, ns, mounts string) {
		dir := filepath.Join(root, pid)
		if err := os.MkdirAll(filepath.Join(dir, "ns"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(ns, filepath.Join(dir, "ns", "mnt")); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "mounts"), []byte(mounts), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	const rootNS = "mnt:[4026531840]"
	// init plus a daemon that shares its namespace: neither is a cage.
	mkProc("1", rootNS, "/dev/md127 / xfs rw 0 0\n")
	mkProc("2", rootNS, "/dev/md127 / xfs rw 0 0\n")

	for i, mounted := range cages {
		body := "/dev/md127 / xfs rw 0 0\n"
		if mounted {
			body += "/dev/md127 " + phpShieldEventDir + " xfs rw 0 0\n"
		}
		mkProc(strconv.Itoa(1000+i), "mnt:[40265334"+strconv.Itoa(90+i)+"]", body)
	}
	return root
}

func withFakeProc(t *testing.T, cages []bool) {
	t.Helper()
	oldProc, oldUID, oldHome, oldName := procPath, cagefsMinUID, cagefsAccountHomeForUID, cagefsAccountNameForUID
	procPath = writeFakeProc(t, cages)
	// The fixture's /proc entries are owned by whoever runs the test, which is
	// root in CI and an ordinary user locally. Sample every uid, and treat it
	// as a hosting account, so the test exercises the namespace logic rather
	// than the host's uid numbering or passwd file. Names resolve to nothing,
	// so a missing cage is reported by uid regardless of who runs the test.
	cagefsMinUID = 0
	cagefsAccountHomeForUID = func(uint64) (string, bool) { return "/home/alice", true }
	cagefsAccountNameForUID = func(uint64) (string, bool) { return "", false }
	t.Cleanup(func() {
		procPath, cagefsMinUID, cagefsAccountHomeForUID, cagefsAccountNameForUID = oldProc, oldUID, oldHome, oldName
	})
}

// CloudLinux in "Enable All" mode cages every uid above the minimum, service
// accounts included. rspamd, chrony and memcached each get a mount namespace
// and none of them will ever execute PHP, so counting them as cages missing
// the event mount inflates the number and points the operator at accounts
// where a remount would achieve nothing.
func TestSampleCageShieldMountsCountsOnlyHostingAccounts(t *testing.T) {
	withFakeProc(t, []bool{false, false})
	cagefsAccountHomeForUID = func(uint64) (string, bool) { return "/var/lib/rspamd", true }

	missing, sampled, err := sampleCageShieldMounts()
	if err != nil {
		t.Fatal(err)
	}
	if sampled != 0 || len(missing) != 0 {
		t.Fatalf("sampled = %d, missing = %v; service-account cages must not be counted", sampled, missing)
	}
}

// A uid with no passwd entry is still counted: an account CSM cannot resolve
// is not evidence that its cage can be ignored, and under-reporting a blind
// cage is the failure that matters.
func TestSampleCageShieldMountsCountsUnknownUIDs(t *testing.T) {
	withFakeProc(t, []bool{false, false})
	cagefsAccountHomeForUID = func(uint64) (string, bool) { return "", false }

	missing, sampled, err := sampleCageShieldMounts()
	if err != nil {
		t.Fatal(err)
	}
	if sampled != 2 || len(missing) != 2 {
		t.Fatalf("sampled = %d, missing = %v; want 2 and 2 for uids with no passwd entry", sampled, missing)
	}
	for _, name := range missing {
		if want := "uid:" + strconv.Itoa(os.Geteuid()); name != want {
			t.Errorf("cage without a passwd entry = %q, want %q", name, want)
		}
	}
}

func TestSampleCageShieldMountsNamesMissingAccount(t *testing.T) {
	withFakeProc(t, []bool{true, false})
	cagefsAccountNameForUID = func(uint64) (string, bool) { return "alice", true }

	missing, sampled, err := sampleCageShieldMounts()
	if err != nil {
		t.Fatal(err)
	}
	if sampled != 2 || len(missing) != 1 || missing[0] != "alice" {
		t.Fatalf("sampled = %d, missing = %v; want 2 and [alice]", sampled, missing)
	}
}

// cPanel spreads accounts across /home, /home2 and any root the operator
// configures. Keying on the panel's primary root would drop a real cage and
// let Doctor report OK while that account stayed blind.
func TestSampleCageShieldMountsCountsAccountsOutsideThePrimaryHomeRoot(t *testing.T) {
	withFakeProc(t, []bool{false, true})
	cagefsAccountHomeForUID = func(uint64) (string, bool) { return "/home2/alice", true }

	missing, sampled, err := sampleCageShieldMounts()
	if err != nil {
		t.Fatal(err)
	}
	if sampled != 2 || len(missing) != 1 {
		t.Fatalf("sampled = %d, missing = %v; want 2 and 1 for an account under /home2", sampled, missing)
	}
}

func TestIsHostingAccountHome(t *testing.T) {
	for home, want := range map[string]bool{
		"/home/alice":          true,
		"/home2/alice":         true,
		"/var/www/vhosts/site": true,
		"/customers/bob":       true,
		"/var/lib/rspamd":      false,
		"/var/lib/chrony":      false,
		"/run/memcached":       false,
		"/usr/share/empty":     false,
		"/nonexistent":         false,
		"/sbin":                false,
		"/":                    false,
		"":                     false,
	} {
		if got := isHostingAccountHome(home, []string{"/var/www/vhosts"}); got != want {
			t.Errorf("isHostingAccountHome(%q) = %v, want %v", home, got, want)
		}
	}
}

// The bug this replaced: keying on the cage skeleton reported "applied" for the
// whole server once a single user had been remounted, while every other cage
// was still blind. A per-cage mount table cannot be fooled that way.
func TestSampleCageShieldMountsCountsPerCageNotServerWide(t *testing.T) {
	withFakeProc(t, []bool{true, false, false})

	missing, sampled, err := sampleCageShieldMounts()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sampled != 3 {
		t.Fatalf("sampled %d cages, want 3", sampled)
	}
	if len(missing) != 2 {
		t.Errorf("missing = %v with 2 unmounted cages out of %d sampled", missing, sampled)
	}
}

// Every cage mounted: nothing to report.
func TestSampleCageShieldMountsCleanWhenAllMounted(t *testing.T) {
	withFakeProc(t, []bool{true, true})

	missing, sampled, err := sampleCageShieldMounts()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sampled != 2 || len(missing) != 0 {
		t.Errorf("missing = %v of %d, want none of 2 sampled cages", missing, sampled)
	}
}

// Processes sharing init's mount namespace are not cages. Counting them would
// make a plain Debian host report itself full of blind cages.
func TestSampleCageShieldMountsIgnoresRootNamespace(t *testing.T) {
	withFakeProc(t, nil)

	_, sampled, err := sampleCageShieldMounts()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sampled != 0 {
		t.Errorf("sampled = %d, want 0 when only root-namespace processes exist", sampled)
	}
}

// The mount point is a whole field, so a longer path that merely starts with
// the event directory is not this mount.
func TestMountsContainMatchesWholeMountPoint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mounts")
	body := "/dev/md127 " + phpShieldEventDir + "-old xfs rw 0 0\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := mountsContain(path, phpShieldEventDir)
	if err != nil {
		t.Fatal(err)
	}
	if got {
		t.Errorf("%q must not match the longer mount point in %q", phpShieldEventDir, body)
	}
}

// CSM's own scan and parse workers run in transient systemd units as dynamic
// users. CloudLinux in "Enable All" mode gives them CageFS-enabled uids and
// they have private mount namespaces, but they never run PHP. Their uids are
// resolved only by NSS, so the passwd lookup fails and they must not fall into
// the "unknown uid is counted" rule.
func TestSampleCageShieldMountsSkipsCSMWorkers(t *testing.T) {
	withFakeProc(t, []bool{false, false, false})
	cagefsAccountHomeForUID = func(uint64) (string, bool) { return "", false }
	writeCgroup := func(pid, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(procPath, pid, "cgroup"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeCgroup("1000", "12:memory:/system.slice/system-csm\\x2dyara\\x2dworker.slice/csm-yara-worker-1793821384247465609.service\n11:hugetlb:/\n1:name=systemd:/system.slice/system-csm\\x2dyara\\x2dworker.slice/csm-yara-worker-1793821384247465609.service\n")
	writeCgroup("1001", "0::/system.slice/system-csm\\x2dparse\\x2dworker\\x2dmail0.slice/csm-parse-worker-mail0-1793821384247465612.service\n")
	// A tenant process named like a worker but outside system.slice is a cage.
	writeCgroup("1002", "0::/user.slice/csm-yara-worker-1.service\n")

	missing, sampled, err := sampleCageShieldMounts()
	if err != nil {
		t.Fatal(err)
	}
	if sampled != 1 || len(missing) != 1 {
		t.Fatalf("sampled = %d, missing = %v; want only the tenant process counted", sampled, missing)
	}
}

// A healthy cage must not hide a blind tenant cage just because the tenant's
// service or delegated subgroup resembles a CSM worker.
func TestSampleCageShieldMountsKeepsNonWorkers(t *testing.T) {
	const scan = `/system.slice/system-csm\x2dyara\x2dworker.slice/csm-yara-worker-1.service`
	for _, tc := range []struct {
		name, cgroup string
	}{
		{"unrelated service", `0::/system.slice/system-csm\x2dhosting.slice/csm-php.service`},
		{"delegated subgroup", `0::/system.slice/system-csm\x2dhosting.slice/tenant.service/csm-yara-worker-1.service`},
		{"nested worker lookalike", "0::" + scan + "/csm-yara-worker-2.service"},
		{"wrong slice", `0::/system.slice/system-csm\x2dparse\x2dworker\x2dmail0.slice/csm-yara-worker-1.service`},
		{"user unit", `0::/user.slice/user-1000.slice/csm-yara-worker-1.service`},
		{"slice lookalike", `0::/system.slice/system-csm\x2dyara\x2dworker.slice-extra/csm-yara-worker-1.service`},
		{"non-worker instance", `0::/system.slice/system-csm\x2dyara\x2dworker.slice/csm-yara-worker-tenant.service`},
		{"unknown parser", `0::/system.slice/system-csm\x2dparse\x2dworker\x2dtenant.slice/csm-parse-worker-tenant-1.service`},
		{"numeric service", `0::/system.slice/system-123.slice/123-1.service`},
		{"empty generation", `0::/system.slice/system-csm\x2dyara\x2dworker.slice/csm-yara-worker-.service`},
		{"wrong unit type", `0::/system.slice/system-csm\x2dyara\x2dworker.slice/csm-yara-worker-1.scope`},
		{"empty mail slot", `0::/system.slice/system-csm\x2dparse\x2dworker\x2dmail.slice/csm-parse-worker-mail-1.service`},
		{"empty cli pid", `0::/system.slice/system-csm\x2dparse\x2dworker\x2dcli\x2d.slice/csm-parse-worker-cli--1.service`},
		{"malformed cgroup", "invalid"},
		{"controller only", "7:memory:" + scan},
		{"controller differs from systemd", "7:memory:" + scan + "\n1:name=systemd:/user.slice/tenant.service"},
		{"hybrid differs from systemd", "0::" + scan + "\n1:name=systemd:/user.slice/tenant.service"},
		{"systemd before hybrid", "1:name=systemd:/user.slice/tenant.service\n0::" + scan},
		{"missing cgroup", ""},
		{"unreadable cgroup", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withFakeProc(t, []bool{true, false})
			cagefsAccountHomeForUID = func(uint64) (string, bool) { return "", false }
			path := filepath.Join(procPath, "1001", "cgroup")
			if tc.name == "unreadable cgroup" {
				// A directory produces a read error even when tests run as root.
				if err := os.Mkdir(path, 0o755); err != nil {
					t.Fatal(err)
				}
			} else if tc.cgroup != "" {
				if err := os.WriteFile(path, []byte(tc.cgroup+"\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			missing, sampled, err := sampleCageShieldMounts()
			want := "uid:" + strconv.Itoa(os.Geteuid())
			if err != nil || sampled != 2 || len(missing) != 1 || missing[0] != want {
				t.Fatalf("sampled=%d missing=%v err=%v; want 2 cages, missing [%s]", sampled, missing, err, want)
			}
		})
	}
}

func TestSampleCageShieldMountsSkipsEveryWorkerKind(t *testing.T) {
	for _, path := range []string{
		`/system.slice/system-csm\x2dyara\x2dworker.slice/csm-yara-worker-1.service`,
		`/system.slice/system-csm\x2dyara\x2dcompile\x2dworker.slice/csm-yara-compile-worker-2.service`,
		`/system.slice/system-csm\x2dparse\x2dworker\x2dzip0.slice/csm-parse-worker-zip0-3.service`,
		`/system.slice/system-csm\x2dparse\x2dworker\x2dmail0.slice/csm-parse-worker-mail0-4.service`,
		`/system.slice/system-csm\x2dparse\x2dworker\x2dmail12.slice/csm-parse-worker-mail12-5.service`,
		`/system.slice/system-csm\x2dparse\x2dworker\x2dcli\x2d123.slice/csm-parse-worker-cli-123-6.service`,
		`/system.slice/system-csm\x2dphptaint\x2dworker.slice/csm-phptaint-worker-7.service`,
	} {
		for _, hierarchy := range []string{"0::", "7:memory:/\n1:name=systemd:"} {
			t.Run(hierarchy+path, func(t *testing.T) {
				withFakeProc(t, []bool{false, false})
				cagefsAccountHomeForUID = func(uint64) (string, bool) { return "", false }
				if err := os.WriteFile(filepath.Join(procPath, "1000", "cgroup"), []byte(hierarchy+path+"\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				missing, sampled, err := sampleCageShieldMounts()
				want := "uid:" + strconv.Itoa(os.Geteuid())
				if err != nil || sampled != 1 || len(missing) != 1 || missing[0] != want {
					t.Fatalf("sampled=%d missing=%v err=%v; want only the tenant cage [%s]", sampled, missing, err, want)
				}
			})
		}
	}
}
