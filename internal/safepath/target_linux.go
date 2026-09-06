//go:build linux

package safepath

func openTargetRoot(path string) (*Dir, error) { return OpenDirNoFollow(path) }
