package main

import (
	"fmt"
	"io"
	"os"

	"github.com/pidginhost/csm/internal/checks"
)

func runHardeningApplyWorker() {
	os.Exit(hardeningApplyWorker(os.Geteuid(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr, applyHardeningWithConfig))
}

// hardeningApplyWorker applies one hardening request for a root caller and
// writes the results to stdout. The daemon starts it outside its sandbox,
// which leaves the files the fixes change read-only.
func hardeningApplyWorker(euid int, args []string, in io.Reader, out, errOut io.Writer, apply func(string, []string) ([]checks.HardeningFixResult, error)) int {
	if euid != 0 || !hardeningApplyWorkerArgs(args) {
		_, _ = fmt.Fprintln(errOut, "hardening apply worker requires root and reads one request from stdin")
		return 1
	}
	if err := checks.HandleHardeningApply(in, out, apply); err != nil {
		_, _ = fmt.Fprintln(errOut, err)
		return 1
	}
	return 0
}

func hardeningApplyWorkerArgs(args []string) bool {
	switch len(args) {
	case 1:
		return args[0] == checks.HardeningApplyWorkerCommand
	case 3:
		return args[0] == checks.HardeningApplyWorkerCommand && args[1] == "--config" && args[2] != ""
	}
	return false
}

func applyHardeningWithConfig(category string, names []string) ([]checks.HardeningFixResult, error) {
	cfg, err := tryLoadConfigLiteWith(secretFreeLoadOptions)
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}
	return checks.ApplyHardening(cfg, category, names)
}
