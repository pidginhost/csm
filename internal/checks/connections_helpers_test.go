package checks

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// --- parseHex6Addr ----------------------------------------------------

func TestParseHex6AddrLoopback(t *testing.T) {
	// ::1 in /proc/net/tcp6 little-endian format: 00000000000000000000000001000000
	ip, port := parseHex6Addr("00000000000000000000000001000000:0050")
	if ip == nil {
		t.Fatal("expected non-nil IP")
	}
	if !ip.Equal(net.ParseIP("::1")) {
		t.Errorf("ip = %s, want ::1", ip)
	}
	if port != 80 {
		t.Errorf("port = %d, want 80", port)
	}
}

func TestParseHex6AddrNoColon(t *testing.T) {
	ip, _ := parseHex6Addr("nocolon")
	if ip != nil {
		t.Errorf("malformed should return nil IP, got %s", ip)
	}
}

func TestParseHex6AddrShortHex(t *testing.T) {
	ip, _ := parseHex6Addr("0000:0050")
	if ip != nil {
		t.Errorf("short hex should return nil IP, got %s", ip)
	}
}

// --- readFileHead (connections.go) ------------------------------------

func TestReadFileHead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	_ = os.WriteFile(path, []byte("hello world, this is a longer string"), 0644)

	got := readFileHead(path, 5)
	if string(got) != "hello" {
		t.Errorf("got %q, want hello", got)
	}
}

func TestReadFileHeadMissing(t *testing.T) {
	got := readFileHead(filepath.Join(t.TempDir(), "nope"), 100)
	if got != nil {
		t.Errorf("missing file should return nil, got %v", got)
	}
}

// --- hashFileContent / hashBytes (helpers.go) -------------------------

func TestHashFileContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	_ = os.WriteFile(path, []byte("hello"), 0644)

	h, err := hashFileContent(path)
	if err != nil {
		t.Fatalf("hashFileContent: %v", err)
	}
	if len(h) != 64 {
		t.Errorf("hash length = %d, want 64", len(h))
	}
}

func TestHashFileContentMissing(t *testing.T) {
	_, err := hashFileContent(filepath.Join(t.TempDir(), "nope"))
	if err == nil {
		t.Error("missing file should return error")
	}
}

func TestHashBytes(t *testing.T) {
	h := hashBytes([]byte("hello"))
	if len(h) != 64 {
		t.Errorf("hash length = %d, want 64", len(h))
	}
	// Same input → same hash
	if h != hashBytes([]byte("hello")) {
		t.Error("deterministic hash should be equal")
	}
	// Different input → different hash
	if h == hashBytes([]byte("world")) {
		t.Error("different input should produce different hash")
	}
}
