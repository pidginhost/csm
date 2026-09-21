//go:build !linux

package daemon

// wireAncestryProvenance has nothing to install off Linux: the ancestry walk
// reads procfs, and the daemon paths that consume it are Linux-only.
func wireAncestryProvenance() {}
