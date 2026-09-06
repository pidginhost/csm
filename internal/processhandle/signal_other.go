//go:build !linux

package processhandle

import "syscall"

type handle struct{}

func openHandle(int) (*handle, error)       { return nil, ErrUnsupported }
func (*handle) close()                      {}
func (*handle) alive() error                { return ErrUnsupported }
func (*handle) signal(syscall.Signal) error { return ErrUnsupported }

func probe() error { return ErrUnsupported }
