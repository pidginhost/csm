package checks

import (
	"context"
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

const maxCMSConfigBytes = 1 << 20

var errCMSConfigTooLarge = errors.New("CMS configuration exceeds the read limit")

// Configuration paths belong to tenants. Open without following the final
// symlink or waiting for a FIFO writer, then validate the opened object.
func openCMSConfig(path string) (*os.File, error) {
	if fs, production := osFS.(realOS); production {
		return fs.openRegularFile(path, unix.O_NOFOLLOW)
	}
	file, err := osFS.Open(path)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, errNonRegularFile
	}
	return file, nil
}

func readCMSConfig(ctx context.Context, path string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, err := openCMSConfig(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if before.Size() > maxCMSConfigBytes {
		return nil, errCMSConfigTooLarge
	}
	data, err := io.ReadAll(io.LimitReader(cmsConfigReader{ctx: ctx, file: file}, maxCMSConfigBytes+1))
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if len(data) > maxCMSConfigBytes {
		return nil, errCMSConfigTooLarge
	}
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !sameFileSnapshot(before, after) || int64(len(data)) != before.Size() {
		return nil, errFileChanged
	}
	return data, nil
}

type cmsConfigReader struct {
	ctx  context.Context
	file *os.File
}

func (r cmsConfigReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.file.Read(p)
}
