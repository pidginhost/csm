//go:build !linux

package parseworker

import (
	"context"
	"errors"
	"net"
)

// Serve needs memfd, which only Linux has.
func Serve(context.Context, *net.UnixConn) error {
	return errors.New("parseworker: requires Linux")
}
