package mcp_test

import "os"

func mkdirAll(dir string) error { return os.MkdirAll(dir, 0o700) }

func removeAllIfOurs(dir string) error { return os.RemoveAll(dir) }
