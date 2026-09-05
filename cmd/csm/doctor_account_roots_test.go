package main

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/pidginhost/csm/internal/config"
)

func TestDoctorChecksCustomRootsBeforeDaemonProbe(t *testing.T) {
	cfg := validDoctorConfig()
	cfg.AccountRoots = []string{filepath.Join(t.TempDir(), "missing", "*")}
	report := buildDoctorReport(func() (*config.Config, error) { return cfg, nil }, func() ([]byte, error) { return nil, errors.New("daemon offline") }, integrityOK)
	for _, check := range report.Checks {
		if check.Name == "account root access" {
			if check.Status == "ok" || check.Fix == "" {
				t.Fatalf("unavailable custom root reported healthy: %+v", check)
			}
			return
		}
	}
	t.Fatalf("doctor omitted custom root access: %+v", report.Checks)
}

func TestDoctorAccountRootGrantsAndLiveMounts(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := validDoctorConfig()
	cfg.AccountRoots = []string{root}
	oldRead, oldProbe := readAccountServiceAccess, accountServiceRootWritable
	t.Cleanup(func() { readAccountServiceAccess, accountServiceRootWritable = oldRead, oldProbe })
	for _, tc := range []struct {
		name, status      string
		granted, writable bool
		pid               uint32
		readErr, mountErr error
	}{
		{name: "missing grant", status: "fail", writable: true, pid: 42},
		{name: "live read only", status: "fail", granted: true, pid: 42},
		{name: "live writable", status: "ok", granted: true, writable: true, pid: 42},
		{name: "stopped", status: "warn", granted: true},
		{name: "bus unavailable", status: "warn", readErr: errors.New("bus down")},
		{name: "mount unknown", status: "fail", granted: true, pid: 42, mountErr: errors.New("process exited")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			readAccountServiceAccess = func() (accountServiceAccess, error) {
				access := accountServiceAccess{ProtectSystem: "strict", MainPID: tc.pid, WritePaths: []string{root + "-sibling"}}
				if tc.granted {
					access.WritePaths = append(access.WritePaths, root)
				}
				return access, tc.readErr
			}
			calls := 0
			accountServiceRootWritable = func(pid uint32, path string) (bool, error) {
				calls++
				if pid != tc.pid || path != root {
					t.Fatalf("probe pid=%d path=%s", pid, path)
				}
				return tc.writable, tc.mountErr
			}
			got := doctorAccountRootAccess(cfg)
			if len(got) != 1 || got[0].Status != tc.status || got[0].Name != "account root access" {
				t.Fatalf("checks=%+v", got)
			}
			if tc.status != "ok" && got[0].Fix == "" {
				t.Fatalf("missing remedy: %+v", got)
			}
			expected := 0
			if tc.granted && tc.pid != 0 && tc.readErr == nil {
				expected = 1
			}
			if calls != expected {
				t.Fatalf("live probe calls=%d want=%d", calls, expected)
			}
		})
	}
}
