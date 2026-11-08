//go:build !linux

package safepath

import "os"

func (d *Dir) Stat(name string) (os.FileInfo, error) {
	f, err := d.OpenFile(name, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.Stat()
}
