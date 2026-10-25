//go:build !linux

package workerproc

import "errors"

func (memoryCgroup) watchOOM() (*oomWatch, error) {
	return nil, errors.New("oom notifications need Linux")
}
