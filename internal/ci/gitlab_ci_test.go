package ci

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRepoPublishProtectsYaraForgeMirror(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", ".gitlab-ci.yml"))
	if err != nil {
		t.Fatalf("read .gitlab-ci.yml: %v", err)
	}
	ci := string(body)

	repoPublish := gitlabJobBlock(t, ci, "repo:publish")
	for _, want := range []string{
		"rsync -avz --delete --filter 'P /yara-forge/***' \\",
		"dist/repo-out/ \\",
		`"${MIRROR_USER}@${MIRROR_HOST}:${MIRROR_PATH}"`,
	} {
		if !strings.Contains(repoPublish, want) {
			t.Fatalf("repo:publish missing %q", want)
		}
	}
	if strings.Contains(repoPublish, "--exclude '/yara-forge/'") {
		t.Fatal("repo:publish must use a receiver-side protect filter, not a source-side exclude")
	}

	yaraMirror := gitlabJobBlock(t, ci, "yara-forge-mirror")
	if !strings.Contains(yaraMirror, `"${MIRROR_USER}@${MIRROR_HOST}:/yara-forge/"`) {
		t.Fatal("yara-forge-mirror remote path changed without updating repo:publish protection")
	}
}

func gitlabJobBlock(t *testing.T, ci, name string) string {
	t.Helper()

	lines := strings.Split(ci, "\n")
	inJob := false
	var out strings.Builder
	for _, line := range lines {
		if line == name+":" {
			inJob = true
			continue
		}
		if !inJob {
			continue
		}
		if isTopLevelYAMLKey(line) {
			break
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	if !inJob {
		t.Fatalf("%s job not found", name)
	}
	return out.String()
}

func isTopLevelYAMLKey(line string) bool {
	if line == "" || strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
		return false
	}
	return strings.HasSuffix(line, ":")
}
