package daemon

import (
	"path/filepath"
	"regexp"
	"strings"
)

// atomicWriteStageRE matches the `.temp.<digits>.<rest>` filename pattern
// emitted by cPanel's fileTransfer service and similar atomic-write
// helpers. The digits are a nanosecond timestamp; <rest> is the original
// basename that will be rename(2)d into place.
var atomicWriteStageRE = regexp.MustCompile(`^\.temp\.\d+\..+`)

// looksLikeAtomicWriteStage reports whether a base filename matches the
// atomic-write staging convention `.temp.<digits>.<name>`. Pass the
// basename, not the full path.
func looksLikeAtomicWriteStage(name string) bool {
	return atomicWriteStageRE.MatchString(name)
}

// atomicWriteRenameCandidate maps cPanel's .temp.<timestamp>.<name> staging
// path to its intended final path. It is only a location hint: the probe must
// still validate content or the destination identity before trusting it.
func atomicWriteRenameCandidate(path string) string {
	base := filepath.Base(path)
	if !looksLikeAtomicWriteStage(base) {
		return ""
	}
	rest := strings.TrimPrefix(base, ".temp.")
	dot := strings.IndexByte(rest, '.')
	if dot < 0 || dot == len(rest)-1 {
		return ""
	}
	name := rest[dot+1:]
	if name == "." || name == ".." {
		return ""
	}
	return filepath.Join(filepath.Dir(path), name)
}

// atomicWriteContentPath supplies a type and checksum lookup hint without
// changing the descriptor or the reported location of the file being scanned.
func atomicWriteContentPath(path string) string {
	if candidate := atomicWriteRenameCandidate(path); candidate != "" {
		return candidate
	}
	return path
}
