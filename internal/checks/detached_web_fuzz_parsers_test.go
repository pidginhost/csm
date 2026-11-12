package checks

import (
	"strconv"
	"strings"
	"testing"
)

func FuzzUnixListener(f *testing.F) {
	for _, path := range []string{"/run/php-fpm/pool.sock", "@php pool", " /tmp/worker\tpool (deleted)", "", "\n", "\x00"} {
		f.Add(path)
	}
	f.Fuzz(func(t *testing.T, path string) {
		// The proc table is split into rows before parsing; names containing
		// newlines cannot round-trip as a single record.
		if strings.Contains(path, "\n") {
			return
		}
		prefix := "0000: 00000002 00000000 00010000 0001 01 42 "
		inode, got, ok := parseUnixListener(prefix + path)
		if path == "" {
			if ok {
				t.Fatal("unnamed listener accepted")
			}
		} else if !ok || inode != "42" || got != path {
			t.Fatalf("socket name changed: inode=%q path=%q ok=%v", inode, got, ok)
		}
		if _, _, listening := parseUnixListener(strings.Replace(prefix, "00010000", "00000000", 1) + path); listening {
			t.Fatal("connected socket accepted as listener")
		}
		inode, got, ok = parseUnixListener(path)
		if ok {
			n, err := strconv.ParseUint(inode, 10, 64)
			if err != nil || n == 0 || got == "" {
				t.Fatalf("invalid listener identity: %q %q", inode, got)
			}
		}
	})
}

func FuzzShellCommand(f *testing.F) {
	for _, tail := range []string{"", "-c\x00script\x00", "sh\x00", "\xff\x00", " sh "} {
		f.Add(tail)
	}
	f.Fuzz(func(t *testing.T, tail string) {
		for _, exe := range []string{"/bin/busybox", "/bin/busybox (deleted)"} {
			if isShellCommand(exe, []byte("busybox\x00wget\x00"+tail)) || isShellCommand(exe, []byte("sleep\x00"+tail)) {
				t.Fatal("arguments turned a non-shell applet into a shell")
			}
			if !isShellCommand(exe, []byte("busybox\x00sh\x00"+tail)) || !isShellCommand(exe, []byte("/bin/ash\x00"+tail)) {
				t.Fatal("arguments changed a shell applet's classification")
			}
			_ = isShellCommand(exe, []byte(tail))
		}
		if isShellCommand("/usr/bin/curl", []byte(tail)) {
			t.Fatal("command line overrode the executable")
		}
	})
}
