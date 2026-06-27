//go:build linux

package firewall

import "fmt"

type ipProtectedError struct {
	msg string
}

func (e ipProtectedError) Error() string {
	return e.msg
}

func (e ipProtectedError) Unwrap() error {
	return ErrIPProtected
}

func ipProtectedErrorf(format string, args ...any) error {
	return ipProtectedError{msg: fmt.Sprintf(format, args...)}
}
