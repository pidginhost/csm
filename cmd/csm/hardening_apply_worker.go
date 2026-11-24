package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/pidginhost/csm/internal/checks"
	"github.com/pidginhost/csm/internal/config"
	"github.com/pidginhost/csm/internal/daemon"
)

func runHardeningApplyWorker() {
	os.Exit(hardeningApplyWorker(os.Geteuid(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr, applyHardeningWithConfig))
}

// hardeningApplyWorker applies one hardening request for a root caller and
// writes the results to stdout. The daemon starts it outside its sandbox,
// which leaves the files the fixes change read-only.
func hardeningApplyWorker(euid int, args []string, in io.Reader, out, errOut io.Writer, apply func(string, []string) ([]checks.HardeningFixResult, error)) int {
	if euid != 0 || !hardeningWorkerArgs(checks.HardeningApplyWorkerCommand, args) {
		_, _ = fmt.Fprintln(errOut, "hardening apply worker requires root and reads one request from stdin")
		return 1
	}
	if err := checks.HandleHardeningApply(in, out, apply); err != nil {
		_, _ = fmt.Fprintln(errOut, err)
		return 1
	}
	return 0
}

func hardeningWorkerArgs(command string, args []string) bool {
	switch len(args) {
	case 1:
		return args[0] == command
	case 5:
		return hardeningWorkerArgs(command, args[:3]) && args[3] == "--config-dir" && filepath.IsAbs(args[4])
	case 3:
		return args[0] == command && args[1] == "--config" && args[2] != ""
	}
	return false
}

func applyHardeningWithConfig(category string, names []string) ([]checks.HardeningFixResult, error) {
	cfg, err := loadHardeningWorkerConfig()
	if err != nil {
		return nil, err
	}
	return checks.ApplyHardening(cfg, category, names)
}

// loadHardeningWorkerConfig loads the configuration the daemon passed and
// installs its platform overrides, so a worker sees the host as the daemon
// does.
func loadHardeningWorkerConfig() (*config.Config, error) {
	var cfg *config.Config
	var err error
	if len(os.Args) == 6 && os.Args[5] == defaultConfDir {
		// An absent packaged conf.d is valid on installations without drop-ins.
		cfg, err = config.LoadWithDirOptions(os.Args[3], defaultConfDir, secretFreeLoadOptions)
	} else {
		cfg, err = tryLoadConfigLiteWith(secretFreeLoadOptions)
	}
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}
	if !daemon.InstallPlatformOverrides(cfg) {
		return nil, fmt.Errorf("cannot apply the configured platform overrides")
	}
	return cfg, nil
}
