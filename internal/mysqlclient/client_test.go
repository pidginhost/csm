package mysqlclient

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

func resetRootForTest(t *testing.T) {
	t.Helper()
	rootMu.Lock()
	if rootDB != nil {
		_ = rootDB.Close()
	}
	rootDB = nil
	rootPath = "/root/.my.cnf"
	rootMu.Unlock()
	t.Cleanup(func() {
		rootMu.Lock()
		if rootDB != nil {
			_ = rootDB.Close()
		}
		rootDB = nil
		rootPath = "/root/.my.cnf"
		rootMu.Unlock()
	})
}

func parsedDSN(t *testing.T, creds Creds) *mysql.Config {
	t.Helper()
	cfg, err := mysql.ParseDSN(creds.dsn())
	if err != nil {
		t.Fatalf("ParseDSN(%q): %v", creds.dsn(), err)
	}
	return cfg
}

func TestCredsDSNParsesWordPressPortHost(t *testing.T) {
	tests := map[string]string{
		"127.0.0.1:3307":  "127.0.0.1:3307",
		"localhost:3307":  "localhost:3307",
		"db.example:3308": "db.example:3308",
	}
	for host, wantAddr := range tests {
		cfg := parsedDSN(t, Creds{
			User:     "u",
			Password: "p",
			Host:     host,
			DBName:   "wp",
		})
		if cfg.Net != "tcp" {
			t.Fatalf("host %q network = %q, want tcp", host, cfg.Net)
		}
		if cfg.Addr != wantAddr {
			t.Fatalf("host %q addr = %q, want %s", host, cfg.Addr, wantAddr)
		}
	}
}

func TestCredsDSNParsesUnixSocketHost(t *testing.T) {
	for _, host := range []string{"/tmp/mysql.sock", "localhost:/tmp/mysql.sock", "localhost:3306:/tmp/mysql.sock"} {
		cfg := parsedDSN(t, Creds{
			User:     "u",
			Password: "p",
			Host:     host,
			DBName:   "wp",
		})
		if cfg.Net != "unix" {
			t.Fatalf("host %q network = %q, want unix", host, cfg.Net)
		}
		if cfg.Addr != "/tmp/mysql.sock" {
			t.Fatalf("host %q addr = %q, want /tmp/mysql.sock", host, cfg.Addr)
		}
	}
}

func TestLoadRootCredsHonorsSocket(t *testing.T) {
	resetRootForTest(t)
	path := filepath.Join(t.TempDir(), ".my.cnf")
	writeRootCnf(t, path, "[client]\nuser=root\npassword='secret'\nsocket=/tmp/custom-mysql.sock\n")
	SetRootCnfPath(path)

	creds, err := loadRootCreds()
	if err != nil {
		t.Fatalf("loadRootCreds: %v", err)
	}
	cfg := parsedDSN(t, creds)
	if cfg.Net != "unix" {
		t.Fatalf("network = %q, want unix", cfg.Net)
	}
	if cfg.Addr != "/tmp/custom-mysql.sock" {
		t.Fatalf("addr = %q, want /tmp/custom-mysql.sock", cfg.Addr)
	}
}

func TestRootSingletonDoesNotDeadlockLoadingCreds(t *testing.T) {
	resetRootForTest(t)
	path := filepath.Join(t.TempDir(), ".my.cnf")
	writeRootCnf(t, path, "[client]\nuser=root\npassword=secret\n")
	SetRootCnfPath(path)

	done := make(chan error, 1)
	go func() {
		_, err := RootDB()
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("rootSingleton: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("rootSingleton deadlocked while loading root credentials")
	}
}

func writeRootCnf(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
