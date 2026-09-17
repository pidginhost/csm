package checks

import (
	"io"
	"os"
	"testing"
)

// Descriptor readers need real regular files while discovery and query tests
// retain their logical account paths.
type cmsConfigFixtureOS struct {
	OS
	dir string
}

func (o *cmsConfigFixtureOS) Open(path string) (*os.File, error) {
	data, err := o.ReadFile(path)
	if err != nil {
		return nil, err
	}
	file, err := os.CreateTemp(o.dir, "config-")
	if err != nil {
		return nil, err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return nil, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func withCMSConfigOS(t *testing.T, provider OS) {
	t.Helper()
	withMockOS(t, &cmsConfigFixtureOS{OS: provider, dir: t.TempDir()})
}
