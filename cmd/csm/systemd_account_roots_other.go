//go:build !linux

package main

import "fmt"

func serviceRootWritable(_ uint32, _ string) (bool, error) {
	return false, fmt.Errorf("live service mount inspection requires Linux")
}
