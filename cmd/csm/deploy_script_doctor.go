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
// invisible until it has already installed something unverified.
func deployScriptDoctorChecks() []DoctorCheck {
	var stale []string
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
			if deployScriptSkipsVerification(path) {
				stale = append(stale, path)
			}
		}
	}
	if len(stale) == 0 {
		return nil
	}
	return []DoctorCheck{{
		Name:    "deploy scripts verify releases",
		Status:  "fail",
		Message: fmt.Sprintf("these deploy scripts can install an unverified release: %s", strings.Join(stale, ", ")),
		Fix: "replace each with the current scripts/deploy-gitlab.sh or scripts/deploy.sh from the release, " +
			"keeping any local registry credentials, then re-run doctor",
	}}
}

// deployScriptSkipsVerification reports whether a script both performs release
// verification and retains a path that continues when it cannot verify.
func deployScriptSkipsVerification(path string) bool {
	// #nosec G304 -- Fixed operator directories are scanned; the path is not caller-supplied.
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxDeployScriptBytes {
		return false
	}
	data, err := io.ReadAll(io.LimitReader(file, maxDeployScriptBytes))
	if err != nil {
		return false
	}
	body := string(data)
	if !strings.Contains(body, "verify_signature") {
		return false
	}
	return strings.Contains(body, "skipping signature check") ||
		strings.Contains(body, "skipping signature verification")
}
