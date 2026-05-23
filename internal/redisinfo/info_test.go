package redisinfo

import (
	"testing"

	"github.com/redis/go-redis/v9"
)

func resetRedisInfoForTest(t *testing.T) {
	t.Helper()
	mu.Lock()
	if defaultDB != nil {
		_ = defaultDB.Close()
	}
	defaultDB = nil
	clientBuilt = false
	addr = defaultAddr
	password = ""
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		if defaultDB != nil {
			_ = defaultDB.Close()
		}
		defaultDB = nil
		clientBuilt = false
		addr = defaultAddr
		password = ""
		mu.Unlock()
	})
}

func TestParseMemoryInfo(t *testing.T) {
	used, max := parseMemoryInfo("# Memory\r\nused_memory:10485760\r\nmaxmemory:33554432\r\n")
	if used != 10485760 || max != 33554432 {
		t.Fatalf("parseMemoryInfo = used %d max %d, want used 10485760 max 33554432", used, max)
	}
}

func TestParseKeyspaceInfo(t *testing.T) {
	total := parseKeyspaceInfo("# Keyspace\r\ndb0:keys=7,expires=1,avg_ttl=0\r\ndb2:keys=5,expires=0,avg_ttl=0\r\n")
	if total != 12 {
		t.Fatalf("parseKeyspaceInfo = %d, want 12", total)
	}
}

func TestClientRebuildsAfterClearingInjectedClient(t *testing.T) {
	resetRedisInfoForTest(t)

	injected := redis.NewClient(&redis.Options{Addr: "127.0.0.1:6391"})
	t.Cleanup(func() { _ = injected.Close() })
	SetClientForTest(injected)
	if got := client(); got != injected {
		t.Fatalf("client() = %p, want injected %p", got, injected)
	}

	SetClientForTest(nil)
	SetAddr("127.0.0.1:6392", "")
	rebuilt := client()
	if rebuilt == nil {
		t.Fatal("client() after clearing injected client returned nil")
	}
	if rebuilt == injected {
		t.Fatal("client() reused injected client after SetClientForTest(nil)")
	}
	if got := rebuilt.Options().Addr; got != "127.0.0.1:6392" {
		t.Fatalf("rebuilt client addr = %q, want 127.0.0.1:6392", got)
	}
}

func TestClientOptionsSupportUnixSocketAndPassword(t *testing.T) {
	resetRedisInfoForTest(t)

	SetAddr("/tmp/csm-redis.sock", "secret")
	c := client()
	opts := c.Options()
	if opts.Network != "unix" {
		t.Fatalf("network = %q, want unix", opts.Network)
	}
	if opts.Addr != "/tmp/csm-redis.sock" {
		t.Fatalf("addr = %q, want /tmp/csm-redis.sock", opts.Addr)
	}
	if opts.Password != "secret" {
		t.Fatalf("password = %q, want secret", opts.Password)
	}
}

func TestClientUsesRedisCLIAuthEnvironment(t *testing.T) {
	resetRedisInfoForTest(t)
	t.Setenv("REDISCLI_AUTH", "env-secret")

	c := client()
	if got := c.Options().Password; got != "env-secret" {
		t.Fatalf("password = %q, want env-secret", got)
	}
}
