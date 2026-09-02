package checks

import (
	"path/filepath"
	"strings"
)

// repoMetadataMarkers lists the files whose presence proves that a directory
// named like a version-control store is one, so the walker can surface the
// exposure without descending into thousands of objects.
func repoMetadataMarkers(dirName string) []string {
	switch strings.ToLower(dirName) {
	case ".git":
		return []string{"HEAD"}
	case ".svn":
		return []string{"wc.db", "entries"}
	default:
		return nil
	}
}

// isRepoMetadataDir reports whether dir is a version-control store.
func isRepoMetadataDir(dir string) bool {
	return len(repoMetadataMarkers(filepath.Base(dir))) > 0
}

// classifyExposedPath classifies a candidate by its full path: a marker file
// inside a repository directory is the repository's exposure, whatever the
// file is called; every other candidate is classified by name.
func classifyExposedPath(path string) exposedClass {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	for _, marker := range repoMetadataMarkers(filepath.Base(dir)) {
		if strings.EqualFold(base, marker) {
			return classRepoMetadata
		}
	}
	return classifyExposedFile(base)
}
