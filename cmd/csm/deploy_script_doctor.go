package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// deployScriptSearchPaths are the directories an operator copy of a deploy
// script realistically lives in. The shipped copy under /opt/csm is refreshed
// by every upgrade; the others are maintained by hand and drift silently.
var deployScriptSearchPaths = []string{"/opt/csm", "/root", "/usr/local/sbin", "/usr/local/bin"}

// maxDeployScriptBytes bounds what this check will read. The shipped scripts
// are tens of kilobytes.
const maxDeployScriptBytes = 1 << 20

// deployScriptDoctorChecks reports deploy scripts on this host that can install
// a release without verifying its signature. Versions released before
// verification became mandatory warn and continue when no verifier is present,
// and an operator copy is never upgraded in place, so the regression is
// invisible until it has already installed something unverified. When every
// script verifies, the OK line names them so the operator sees the check ran.
func deployScriptDoctorChecks() []DoctorCheck {
	var checked, stale []string
	seen := make(map[string]bool)
	for _, dir := range deployScriptSearchPaths {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, ".sh") || !strings.Contains(name, "deploy") {
				continue
			}
			path := filepath.Join(dir, name)
			resolved, err := filepath.EvalSymlinks(path)
			if err != nil {
				resolved = path
			}
			if seen[resolved] {
				continue
			}
			seen[resolved] = true
			verifies, skips := deployScriptVerification(path)
			if !verifies {
				continue
			}
			checked = append(checked, path)
			if skips {
				stale = append(stale, path)
			}
		}
	}
	const checkName = "deploy scripts verify releases"
	if len(checked) == 0 {
		return nil
	}
	if len(stale) == 0 {
		return []DoctorCheck{{Name: checkName, Status: "ok", Message: "checked " + strings.Join(checked, ", ")}}
	}
	return []DoctorCheck{{
		Name:    checkName,
		Status:  "fail",
		Message: fmt.Sprintf("these deploy scripts can install an unverified release: %s", strings.Join(stale, ", ")),
		Fix: "replace each with the current scripts/deploy-gitlab.sh or scripts/deploy.sh from the release, " +
			"keeping any local registry credentials, then re-run doctor",
	}}
}

// deployScriptVerification reports whether a script performs release
// verification and whether it retains a path that continues when it cannot.
func deployScriptVerification(path string) (verifies, skips bool) {
	// #nosec G304 -- Fixed operator directories are scanned; the path is not caller-supplied.
	file, err := os.Open(path)
	if err != nil {
		return false, false
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxDeployScriptBytes {
		return false, false
	}
	data, err := io.ReadAll(io.LimitReader(file, maxDeployScriptBytes))
	if err != nil {
		return false, false
	}
	body := string(data)
	if !strings.Contains(body, "verify_signature") {
		return false, false
	}
	return true, strings.Contains(body, "skipping signature check") ||
		strings.Contains(body, "skipping signature verification")
}
