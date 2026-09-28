package checks

import (
	"context"
	"errors"
	"io"
	"os"
)

const maxCMSConfigBytes = 1 << 20

var errCMSConfigTooLarge = errors.New("CMS configuration exceeds the read limit")

func readCMSConfig(ctx context.Context, path string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, err := openTenantRegularFile(path)
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
