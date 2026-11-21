package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// deployScriptSearchPaths are the directories an operator copy of a deploy
// script realistically lives in. The shipped copy under /opt/csm is refreshed
// by every upgrade; the others are maintained by hand and drift silently.
var deployScriptSearchPaths = []string{"/opt/csm", "/root", "/usr/local/sbin", "/usr/local/bin"}

// maxDeployScriptBytes bounds what this check will read. The shipped scripts
// are tens of kilobytes.
const maxDeployScriptBytes = 1 << 20

// Exact copies have the release's tested verification behavior. A marker in
// arbitrary shell code cannot establish that the verifier is ever called.
// Store digests so the internal deploy script stays out of distributed binaries.
func deployScriptStatus(path, resolved string, data []byte) string {
	switch fmt.Sprintf("%x", sha256.Sum256(data)) {
	case "1c814b437a4e990c630ccd7de01006f46ec563b2d7357e296af9a73506dff1d6", // deploy.sh
		"3feeddd9638cd0ef56f8b22495691d64db6255bdd01483da20bb1990ecc8177c": // deploy-gitlab.sh
		return "ok"
	}
	body := string(data)
	hasVerifier := strings.Contains(body, "verify_signature")
	namedCSM := hasVerifier && strings.Contains(filepath.Base(path), "csm")
	if path != "/opt/csm/deploy.sh" && resolved != "/opt/csm/deploy.sh" && !namedCSM &&
		!strings.Contains(body, "# Continuous Security Monitor") && !strings.Contains(body, "CSM_SIGNING_KEY_PEM") {
		return ""
	}
	if hasVerifier && (strings.Contains(body, "skipping signature check") || strings.Contains(body, "skipping signature verification")) {
		return "fail"
	}
	return "warn"
}

func deployScriptDoctorChecks() []DoctorCheck {
	var current, stale, unknown, unread []string
	seen := make(map[string]bool)
	for _, dir := range deployScriptSearchPaths {
		entries, err := os.ReadDir(dir)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			unread = append(unread, strconv.Quote(dir))
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, ".sh") || !strings.Contains(name, "deploy") {
				continue
			}
			path := filepath.Join(dir, name)
			label := strconv.Quote(path)
			resolved, err := filepath.EvalSymlinks(path)
			if err != nil {
				unread = append(unread, label)
				continue
			}
			if seen[resolved] {
				continue
			}
			data, err := readBoundedFile(resolved, maxDeployScriptBytes)
			if err != nil {
				unread = append(unread, label)
				continue
			}
			switch deployScriptStatus(path, resolved, data) {
			case "ok":
				current = append(current, label)
			case "fail":
				stale = append(stale, label)
			case "warn":
				unknown = append(unknown, label)
			default:
				continue
			}
			seen[resolved] = true
		}
	}

	check := DoctorCheck{Name: "deploy scripts verify releases", Status: "warn"}
	var messages, fixes []string
	if len(stale) > 0 {
		check.Status = "fail"
		messages = append(messages, "these deploy scripts can install an unverified release: "+strings.Join(stale, ", "))
		fixes = append(fixes, "replace each stale script with the matching scripts/deploy.sh or scripts/deploy-gitlab.sh from the release, keeping any local registry credentials")
	}
	if len(unknown) > 0 {
		messages = append(messages, "release verification unconfirmed for nonmatching copies: "+strings.Join(unknown, ", "))
		fixes = append(fixes, "compare the nonmatching scripts with the release copies")
	}
	if len(unread) > 0 {
		messages = append(messages, "could not inspect: "+strings.Join(unread, ", "))
		fixes = append(fixes, "check directory access, symlink targets, and whether each script is a readable regular file of at most 1 MiB")
	}
	switch {
	case len(messages) > 0:
		check.Message = strings.Join(messages, ". ")
		check.Fix = strings.Join(fixes, ", then ") + ", then re-run doctor"
	case len(current) > 0:
		check.Status = "ok"
		check.Message = "checked " + strings.Join(current, ", ")
	default:
		return nil
	}
	return []DoctorCheck{check}
}
