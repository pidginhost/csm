//go:build !linux

package safepath

// Non-Linux development hosts keep their system-managed temporary-directory
// aliases. The daemon's Linux target pins the full root ancestry without links.
func openTargetRoot(path string) (*Dir, error) { return OpenDir(path) }
