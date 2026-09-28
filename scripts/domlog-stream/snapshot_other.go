//go:build !linux && !darwin

package main

import "os"

// Refuse snapshots where the platform's change time is not checked.
func sameInputChangeTime(_, _ os.FileInfo) bool { return false }
