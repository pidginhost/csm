package checks

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pidginhost/csm/internal/config"
)

func TestCheckFakeKernelThreadsDetectsFake(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			return []string{"/proc/12345/status"}, nil
		},
		readFile: func(name string) ([]byte, error) {
			switch {
			case strings.HasSuffix(name, "/status"):
				return []byte("Name:\t[kworker/0:1]\nUid:\t1000\t1000\t1000\t1000\nPid:\t12345\n"), nil
			case strings.HasSuffix(name, "/cmdline"):
				return []byte("[kworker/0:1]\x00"), nil
			}
			return nil, os.ErrNotExist
		},
		readlink: func(name string) (string, error) {
			return "/tmp/malware", nil
		},
	})

	findings := CheckFakeKernelThreads(context.Background(), &config.Config{}, nil)
	if len(findings) == 0 {
		t.Fatal("expected finding for fake kernel thread")
	}
	if findings[0].Check != "fake_kernel_thread" {
		t.Errorf("check = %q", findings[0].Check)
	}
}

func TestCheckFakeKernelThreadsIgnoresReal(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			return []string{"/proc/1/status"}, nil
		},
		readFile: func(name string) ([]byte, error) {
			if strings.HasSuffix(name, "/status") {
				return []byte("Name:\t[kworker/0:1]\nUid:\t0\t0\t0\t0\nPid:\t1\n"), nil
			}
			return nil, os.ErrNotExist
		},
	})

	findings := CheckFakeKernelThreads(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("real kernel thread should not be flagged, got %d findings", len(findings))
	}
}

func TestCheckFakeKernelThreadsNoProcs(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			return nil, nil
		},
	})

	findings := CheckFakeKernelThreads(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("no procs should return 0 findings, got %d", len(findings))
	}
}

func TestCheckSuspiciousProcessesDetects(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			return []string{"/proc/9999/status"}, nil
		},
		readFile: func(name string) ([]byte, error) {
			switch {
			case strings.HasSuffix(name, "/status"):
				return []byte("Name:\txmrig\nUid:\t1000\t1000\t1000\t1000\nPid:\t9999\n"), nil
			case strings.HasSuffix(name, "/cmdline"):
				return []byte("xmrig\x00--donate-level\x001\x00"), nil
			}
			return nil, os.ErrNotExist
		},
		readlink: func(name string) (string, error) {
			return "/tmp/.hidden/xmrig", nil
		},
	})

	findings := CheckSuspiciousProcesses(context.Background(), &config.Config{}, nil)
	if len(findings) == 0 {
		t.Fatal("expected finding for xmrig miner")
	}
}

func TestCheckPHPProcessesNone(t *testing.T) {
	withMockOS(t, &mockOS{
		glob: func(pattern string) ([]string, error) {
			return nil, nil
		},
	})

	findings := CheckPHPProcesses(context.Background(), &config.Config{}, nil)
	if len(findings) != 0 {
		t.Errorf("no PHP procs should return 0 findings, got %d", len(findings))
	}
}

func TestEvaluateExecStampsDetectionTime(t *testing.T) {
	before := time.Now()
	findings := EvaluateExec(1001, 4242, "gsocket", "/tmp/gsocket", "bash")
	after := time.Now()
	if len(findings) == 0 {
		t.Fatal("expected a suspicious exec finding")
	}
	for _, finding := range findings {
		if finding.Timestamp.Before(before) || finding.Timestamp.After(after) {
			t.Fatalf("live exec finding %q timestamp = %v, want current detection time", finding.Check, finding.Timestamp)
		}
	}
}
